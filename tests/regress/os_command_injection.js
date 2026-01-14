
// OS Command Injection Benchmarks (Enriched)
const childProcess = require("child_process");

// 1. exec
function runCommand(req) {
  const cmd = req.query.cmd;
  // Vulnerable: Shell execution
  childProcess.exec(cmd);
}

// 2. execFile
function runExecFile(req) {
  const file = req.query.file;
  // Vulnerable: If file is controlled, can execute arbitrary binary
  childProcess.execFile(file, ["arg1"], (err, stdout) => {});
}

// 3. spawn (shell: true)
function runSpawnShell(req) {
  const cmd = req.query.cmd;
  // Vulnerable: Shell execution enabled
  childProcess.spawn(cmd, [], { shell: true });
}

// 4. Argument Injection (spawn without shell)
function runSpawnArgs(req) {
  const arg = req.query.arg;
  // Vulnerable: Argument injection (e.g. --checkpoint-action=exec=sh) if binary allows
  childProcess.spawn("tar", ["cf", "archive.tar", arg]);
}

// 5. Template Injection in Command
function runTemplate(req) {
    const input = req.query.input;
    // Vulnerable
    childProcess.exec(`echo ${input}`);
}

module.exports = { 
  runCommand,
  runExecFile,
  runSpawnShell,
  runSpawnArgs,
  runTemplate
};
