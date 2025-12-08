// Reflects user input into response without sanitization (should be flagged).
function handler(req, res) {
  const name = req.query.name;
  res.send(`<h1>Hello ${name}</h1>`);
}

module.exports = { handler };
