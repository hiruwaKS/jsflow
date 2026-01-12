#!/usr/bin/env python3
"""Run jsflow on secbench dataset and evaluate results."""

import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Tuple

# Map CWE IDs to jsflow vulnerability types
CWE_TO_VULN_TYPE = {
    "CWE-22": "path_traversal",
    "CWE-78": "os_command",
    "CWE-94": "code_exec",
    "CWE-471": "proto_pollution",
}

SECBENCH_DIR = Path("evaluation/explodejs-datasets/secbench-dataset")


def find_secbench_cases() -> List[Tuple[str, str]]:
    """Find all secbench test cases."""
    cases = []
    for cwe_id in CWE_TO_VULN_TYPE:
        cwe_dir = SECBENCH_DIR / cwe_id
        if cwe_dir.exists():
            cases.extend((cwe_id, name) for name in os.listdir(cwe_dir)
                        if (cwe_dir / name).is_dir())
    return sorted(cases)


DEFAULT_TIMEOUT = 30

_RUNNING_PGIDS: set[int] = set()
_RUNNING_PGIDS_LOCK = threading.Lock()


def _register_pgid(pgid: int) -> None:
    with _RUNNING_PGIDS_LOCK:
        _RUNNING_PGIDS.add(pgid)


def _unregister_pgid(pgid: int) -> None:
    with _RUNNING_PGIDS_LOCK:
        _RUNNING_PGIDS.discard(pgid)


def _kill_pgid(pgid: int, sig: signal.Signals) -> None:
    try:
        os.killpg(pgid, sig)
    except ProcessLookupError:
        # Already exited.
        return


def _terminate_proc_group(proc: subprocess.Popen, *, grace_seconds: float = 2.0) -> None:
    """
    Best-effort terminate a subprocess and anything it spawned.

    We start each subprocess in its own session/process-group (start_new_session=True),
    so killing by pgid should reliably reap its children too.
    """
    if proc.poll() is not None:
        return

    pgid = proc.pid
    _kill_pgid(pgid, signal.SIGTERM)

    deadline = time.time() + max(0.0, grace_seconds)
    while time.time() < deadline:
        if proc.poll() is not None:
            return
        time.sleep(0.05)

    # Still alive: hard kill.
    _kill_pgid(pgid, signal.SIGKILL)


def kill_all_running_subprocesses(*, grace_seconds: float = 1.0) -> None:
    with _RUNNING_PGIDS_LOCK:
        pgids = list(_RUNNING_PGIDS)

    # Try graceful first, then hard-kill.
    for pgid in pgids:
        _kill_pgid(pgid, signal.SIGTERM)

    deadline = time.time() + max(0.0, grace_seconds)
    while time.time() < deadline:
        with _RUNNING_PGIDS_LOCK:
            if not _RUNNING_PGIDS:
                return
        time.sleep(0.05)

    with _RUNNING_PGIDS_LOCK:
        pgids = list(_RUNNING_PGIDS)
    for pgid in pgids:
        _kill_pgid(pgid, signal.SIGKILL)


def run_jsflow(file_path: str, vuln_type: str, timeout: int = DEFAULT_TIMEOUT) -> Tuple[bool, float, str]:
    """Run jsflow on a file."""
    cmd = ["python3", "-m", "jsflow", "-t", vuln_type, "-q", file_path]
    start_time = time.time()
    proc: subprocess.Popen | None = None
    try:
        # start_new_session=True ensures a dedicated process group on POSIX,
        # so we can terminate the full tree on timeout/Ctrl+C.
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        _register_pgid(proc.pid)
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _terminate_proc_group(proc, grace_seconds=2.0)
            # Drain pipes (best-effort); process is terminated at this point.
            try:
                stdout, stderr = proc.communicate(timeout=2.0)
            except Exception:
                stdout, stderr = "", ""
            return False, time.time() - start_time, "Timeout"

        elapsed_time = time.time() - start_time
        output = (stdout or "") + (stderr or "")
        clean_output = re.sub(r"\x1b\[[0-9;]*m", "", output)
        detected = "Detection: successful" in clean_output or "success:" in clean_output
        return detected, elapsed_time, output
    except KeyboardInterrupt:
        if proc is not None:
            _terminate_proc_group(proc, grace_seconds=0.5)
        raise
    except Exception as e:
        if proc is not None:
            _terminate_proc_group(proc, grace_seconds=0.5)
        return False, time.time() - start_time, str(e)
    finally:
        if proc is not None:
            _unregister_pgid(proc.pid)


def process_case(cwe_id: str, case_name: str, timeout: int = DEFAULT_TIMEOUT) -> Dict:
    """Process a single test case."""
    vuln_type = CWE_TO_VULN_TYPE[cwe_id]
    case_dir = SECBENCH_DIR / cwe_id / case_name
    src_file = case_dir / "src" / "index.js"

    if not src_file.exists():
        src_dir = case_dir / "src"
        if src_dir.exists() and (js_files := list(src_dir.glob("*.js"))):
            src_file = js_files[0]
        else:
            return {
                "cwe": cwe_id,
                "case": case_name,
                "file": None,
                "vuln_type": vuln_type,
                "detected": False,
                "time": 0,
                "status": "error",
            }

    print(f"Analyzing: {cwe_id}/{case_name} ({vuln_type})")
    detected, elapsed_time, output = run_jsflow(str(src_file), vuln_type, timeout)

    status = "success"
    if elapsed_time >= timeout or (isinstance(output, str) and "Timeout" in output):
        status = "timeout"
    elif isinstance(output, str) and output.startswith("Traceback"):
        status = "error"

    print(f"  {cwe_id}/{case_name}: {elapsed_time:.1f}s, detected={detected}, status={status}")

    return {
        "cwe": cwe_id,
        "case": case_name,
        "file": str(src_file),
        "vuln_type": vuln_type,
        "detected": detected,
        "time": elapsed_time,
        "status": status,
    }


def evaluate_secbench(max_workers: int = None, timeout: int = DEFAULT_TIMEOUT):
    """Run jsflow on secbench dataset and collect metrics."""
    cases = find_secbench_cases()
    results = {
        "total_cases": len(cases),
        "by_cwe": {cwe: {"total": 0, "detected": 0, "timeout": 0, "error": 0, "times": []}
                   for cwe in CWE_TO_VULN_TYPE},
        "cases": [],
        "detection_summary": {"true_positive": 0, "false_negative": 0, "timeout": 0, "error": 0},
        "times": [],
    }

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(process_case, cwe_id, case_name, timeout): (cwe_id, case_name)
            for cwe_id, case_name in cases
        }

        try:
            for future in as_completed(futures):
                try:
                    case_result = future.result()
                except Exception as e:
                    cwe_id, case_name = futures[future]
                    print(f"Error processing {cwe_id}/{case_name}: {e}")
                    case_result = {
                        "cwe": cwe_id,
                        "case": case_name,
                        "file": None,
                        "vuln_type": CWE_TO_VULN_TYPE.get(cwe_id, "unknown"),
                        "detected": False,
                        "time": 0,
                        "status": "error",
                    }

                cwe_id = case_result["cwe"]
                status = case_result["status"]
                cwe_stats = results["by_cwe"][cwe_id]

                cwe_stats["total"] += 1
                if status == "timeout":
                    cwe_stats["timeout"] += 1
                    results["detection_summary"]["timeout"] += 1
                elif status == "error":
                    cwe_stats["error"] += 1
                    results["detection_summary"]["error"] += 1
                else:
                    cwe_stats["times"].append(case_result["time"])
                    results["times"].append(case_result["time"])

                if case_result["detected"]:
                    cwe_stats["detected"] += 1
                    results["detection_summary"]["true_positive"] += 1
                elif status == "success":
                    results["detection_summary"]["false_negative"] += 1

                results["cases"].append(case_result)
        except KeyboardInterrupt:
            # Cancel pending jobs and kill any running subprocess trees.
            for f in futures:
                f.cancel()
            kill_all_running_subprocesses(grace_seconds=0.5)
            # Don't block on worker threads; they'll unwind once procs die.
            executor.shutdown(wait=False, cancel_futures=True)
            raise

    return results


def print_metrics(results: Dict):
    """Print evaluation metrics."""
    print("\n" + "=" * 60)
    print("JSFLOW SECBENCH EVALUATION RESULTS")
    print("=" * 60)

    s = results["detection_summary"]
    tp, fn, timeout, errors = s["true_positive"], s["false_negative"], s["timeout"], s["error"]
    analyzed = tp + fn
    recall = tp / analyzed if analyzed > 0 else 0

    print(f"\nOverall: {results['total_cases']} cases | TP: {tp} | FN: {fn} | "
          f"Timeouts: {timeout} | Errors: {errors}")
    if analyzed > 0:
        print(f"Recall: {recall:.2%} ({tp}/{analyzed})")

    if results["times"]:
        times = results["times"]
        print(f"Time: avg={sum(times)/len(times):.1f}s, min={min(times):.1f}s, max={max(times):.1f}s")

    print("\nPer-CWE:")
    for cwe_id, data in results["by_cwe"].items():
        if data["total"] == 0:
            continue
        recall_pct = data["detected"] / data["total"] if data["total"] > 0 else 0
        avg_time = sum(data["times"]) / len(data["times"]) if data["times"] else 0
        print(f"  {cwe_id} ({CWE_TO_VULN_TYPE[cwe_id]}): "
              f"{data['detected']}/{data['total']} ({recall_pct:.1%}), "
              f"timeouts={data['timeout']}, errors={data['error']}"
              + (f", avg_time={avg_time:.1f}s" if avg_time > 0 else ""))

    if fn > 0:
        missed = [f"{c['cwe']}/{c['case']}" for c in results["cases"]
                  if c["status"] == "success" and not c["detected"]]
        print(f"\nMissed ({len(missed)}): {', '.join(missed)}")


def save_results(results: Dict, output_file: str = "secbench_results.json"):
    """Save evaluation results to a JSON file."""
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to {output_file}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run jsflow on secbench dataset")
    parser.add_argument("-j", "--jobs", type=int, default=None,
                        help="Number of parallel jobs (default: CPU count)")
    parser.add_argument("-t", "--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help=f"Timeout per case in seconds (default: {DEFAULT_TIMEOUT})")
    args = parser.parse_args()

    os.chdir(Path(__file__).parent.parent)
    try:
        results = evaluate_secbench(max_workers=args.jobs, timeout=args.timeout)
        print_metrics(results)
        save_results(results)
    except KeyboardInterrupt:
        kill_all_running_subprocesses(grace_seconds=0.5)
        print("\nInterrupted (Ctrl+C). Killed running analyses.", file=sys.stderr)
        raise
