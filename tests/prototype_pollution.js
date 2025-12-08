// Recursive merge that trusts user input, enabling prototype pollution.
function merge(target, source) {
  for (const key in source) {
    const value = source[key];
    if (value && typeof value === "object") {
      if (!target[key]) target[key] = {};
      merge(target[key], value);
    } else {
      target[key] = value;
    }
  }
  return target;
}

function applyPayload(req) {
  const payload = req.body;
  const config = {};
  return merge(config, payload);
}

module.exports = { merge, applyPayload };
