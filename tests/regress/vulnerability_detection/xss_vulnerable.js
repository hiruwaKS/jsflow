
// Reflected XSS Benchmarks (Enriched)

function handler(req, res) {
  const name = req.query.name;
  // Context: HTML Body
  res.send(`<h1>Hello ${name}</h1>`);
}

function attributeInjection(req, res) {
  const color = req.query.color;
  // Context: Attribute (e.g. "><script>...")
  res.send(`<div style="color: ${color}">Text</div>`);
}

function scriptContext(req, res) {
  const data = req.query.data;
  // Context: Inside Script (dangerous even with some escaping)
  res.send(`<script>var userData = '${data}';</script>`);
}

function hrefInjection(req, res) {
  const url = req.query.url;
  // Context: href (javascript:...)
  res.send(`<a href="${url}">Link</a>`);
}

function storedXss(req, res, db) {
    // Simulating stored XSS
    db.find({ id: 1 }, (err, user) => {
        // user.bio comes from DB, but if it was tainted before, it is now.
        // If analysis tracks DB sources as tainted, this is vulnerable.
        res.send(`<div>${user.bio}</div>`);
    });
}

module.exports = { 
    handler,
    attributeInjection,
    scriptContext,
    hrefInjection,
    storedXss
};
