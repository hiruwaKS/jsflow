const fs = require("fs");

// Reads file directly from user path (should be flagged for traversal).
function readFile(req) {
  const userPath = req.query.file;
  fs.readFile(userPath, () => {});
}

module.exports = { readFile };
