// Uses eval on user input (should be flagged for code execution).
function runUserCode(req) {
  const src = req.body.code;
  return eval(src);
}

module.exports = { runUserCode };
