const fs = require("fs");
const path = require("path");

// Normalizes and constrains reads to a fixed directory (should stay clean).
function readSafe(req) {
  const base = "/var/app/data";
  const requested = path.normalize(req.query.file || "");
  const full = path.join(base, requested);
  if (!full.startsWith(base)) return;
  fs.readFile(full, () => {});
}

module.exports = { readSafe };
