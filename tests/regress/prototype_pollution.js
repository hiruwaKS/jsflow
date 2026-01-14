
// Prototype Pollution Benchmarks (Enriched)

// 1. Classic Recursive Merge (Vulnerable)
// Vulnerable to: { "__proto__": { "isAdmin": true } }
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

// 2. Constructor Prototype Pollution (Vulnerable)
// Vulnerable to: { "constructor": { "prototype": { "isAdmin": true } } }
function mergeConstructor(target, source) {
    for (let key in source) {
        if (typeof target[key] === 'object' && typeof source[key] === 'object') {
            mergeConstructor(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// 3. Safe Merge (Denylist)
function mergeSafe(target, source) {
  for (const key in source) {
    // Safe: Explicitly blocks dangerous keys
    if (key === "__proto__" || key === "constructor" || key === "prototype") {
        continue;
    }
    const value = source[key];
    if (value && typeof value === "object") {
      if (!target[key]) target[key] = {};
      mergeSafe(target[key], value);
    } else {
      target[key] = value;
    }
  }
  return target;
}

// 4. Safe Object (Map-like)
function safeMapUsage(req) {
    // Safe: Object.create(null) has no prototype
    const map = Object.create(null);
    const key = req.body.key;
    const value = req.body.value;
    map[key] = value; // Safe even if key is "__proto__"
    return map.isAdmin; // undefined
}

// 5. Lodash-like set (Vulnerable Simplified)
function setPath(obj, path, value) {
    const keys = path.split('.');
    let current = obj;
    for (let i = 0; i < keys.length - 1; i++) {
        // Vulnerable if path is ["__proto__", "polluted"]
        if (!current[keys[i]]) current[keys[i]] = {};
        current = current[keys[i]];
    }
    current[keys[keys.length - 1]] = value;
}

function testSetPath(req) {
    const obj = {};
    setPath(obj, req.query.path, req.query.val);
}

module.exports = { 
    merge, 
    applyPayload, 
    mergeConstructor, 
    mergeSafe, 
    safeMapUsage,
    setPath,
    testSetPath
};
