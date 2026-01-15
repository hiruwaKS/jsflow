
// Code Execution Benchmarks (Enriched)

const vm = require('vm');

// 1. eval
function runUserCode(req) {
  const src = req.body.code;
  return eval(src); // Vulnerable
}

// 2. Function constructor
function dynamicFunction(req) {
  const body = req.body.code;
  const func = new Function(body); // Vulnerable
  func();
}

// 3. vm module
function vmExecution(req) {
  const code = req.body.code;
  vm.runInNewContext(code, {}); // Vulnerable
}

// 4. Indirect eval (often handled differently by engines)
function indirectEval(req) {
  const code = req.body.code;
  const gEval = eval;
  gEval(code); // Vulnerable
}

module.exports = { 
  runUserCode,
  dynamicFunction,
  vmExecution,
  indirectEval
};
