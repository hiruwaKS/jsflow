
// Path Traversal Benchmarks (Enriched)
const fs = require("fs");
const path = require("path");

function readFile(req) {
  // Vulnerable: Absolute path or relative path traversal
  const userPath = req.query.file;
  fs.readFile(userPath, () => {});
}

function readFileJoin(req) {
  // Vulnerable: path.join allows ../ traversal from root
  const filename = req.query.filename;
  const filePath = path.join("/var/www/uploads", filename);
  fs.readFile(filePath, () => {});
}

function readFileResolve(req) {
  // Vulnerable: path.resolve treats absolute paths in arguments as root
  const filename = req.query.filename;
  const filePath = path.resolve("/var/www/uploads", filename);
  fs.readFile(filePath, () => {});
}

function readFileSafe(req) {
  const filename = req.query.filename;
  const root = "/var/www/uploads";
  const filePath = path.join(root, filename);
  
  // Safe: Check if resolved path is within root
  if (filePath.startsWith(root)) {
    fs.readFile(filePath, () => {});
  }
}

function readFileNullByte(req) {
    // Vulnerable: Null byte injection (older Node versions or some systems)
    const userPath = req.query.file + "\u0000.txt";
    fs.readFile(userPath, () => {});
}

module.exports = { 
  readFile,
  readFileJoin,
  readFileResolve,
  readFileSafe,
  readFileNullByte
};
