"""
This module is used to store the list of vulnerable function signatures.
"""

signature_lists = {
    "os_command": [
        "sink_hqbpillvul_execFile",
        "sink_hqbpillvul_exec",
        "sink_hqbpillvul_execSync",
        "sink_hqbpillvul_spawn",
        "sink_hqbpillvul_spawnSync",
        "sink_hqbpillvul_execa_shell",
        "sink_hqbpillvul_shelljs_exec",
    ],
    "os_command_strict": [
        "sink_hqbpillvul_exec",
        "sink_hqbpillvul_execSync",
        "sink_hqbpillvul_execa_shell",
        "sink_hqbpillvul_shelljs_exec",
    ],
    # XSS sinks (http response emission)
    # - sink_hqbpillvul_* are modeled sinks used by builtin stubs
    # - res.send/write/end are common Express/Node patterns that may appear
    #   as dummy function names in graphs when the response object is a wildcard
    "xss": [
        "sink_hqbpillvul_http_write",
        "sink_hqbpillvul_http_setHeader",
        "res.send",
        "res.write",
        "res.end",
    ],
    "proto_pollution": ["merge", "extend", "clone", "parse"],
    "code_exec": [
        "Function",
        "eval",
        # "sink_hqbpillvul_execFile",
        # 'sink_hqbpillvul_exec',
        # 'sink_hqbpillvul_execSync',
        "sink_hqbpillvul_eval",
    ],
    # NoSQL sinks. In modeled MongoDB stubs we emit sink_hqbpillvul_nosql; in
    # simple samples (e.g. tests) the query API can show up directly as `find`.
    "nosql": ["sink_hqbpillvul_nosql", "find"],
    "sanitation": ["parseInt"],
    # Path traversal sinks: either modeled sinks or direct fs read calls.
    "path_traversal": [
        "pipe",
        "sink_hqbpillvul_http_write",
        "sink_hqbpillvul_fs_read",
        "fs.readFile",
        "fs.readFileSync",
    ],
}


def get_all_sign_list():
    """
    return a list of all the signature functions
    """
    res = []
    for key, value in signature_lists.items():
        res += value

    return res
