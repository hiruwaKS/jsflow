const childProcess = require("child_process");

// Whitelisted commands only; helps check precision (should stay clean).
function runSafeCommand(req) {
  const allowlist = new Set(["ls", "pwd"]);
  if (!allowlist.has(req.query.cmd)) return;
  const cmd = req.query.cmd;
  childProcess.exec(cmd);
}

module.exports = { runSafeCommand };
