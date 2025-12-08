const childProcess = require("child_process");

// User-controlled command hits exec without checks (should be flagged).
function runCommand(req) {
  const cmd = req.query.cmd;
  childProcess.exec(cmd);
}

module.exports = { runCommand };
