// Escapes user input before sending to response (should stay clean).
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function handler(req, res) {
  const name = escapeHtml(req.query.name);
  res.send(`<h1>Hello ${name}</h1>`);
}

module.exports = { handler, escapeHtml };
