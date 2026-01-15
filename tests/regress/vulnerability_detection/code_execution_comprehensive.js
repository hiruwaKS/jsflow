// Comprehensive Code Execution Benchmarks (CWE-94)
// Covers eval, Function constructor, setTimeout/setInterval, VM, and real-world patterns

const vm = require('vm');

// eval() patterns
function eval_simple(req) {
    const code = req.query.code;
    // VULNERABLE: Direct eval
    eval(code);
}

function eval_concat(req) {
    const prefix = "console.log('";
    const userCode = req.query.msg;
    const suffix = "')";
    // VULNERABLE: Eval with concatenation
    eval(prefix + userCode + suffix);
}

function eval_template(req) {
    const userCode = req.query.code;
    // VULNERABLE: Template literal in eval
    const template = `console.log('${userCode}')`;
    eval(template);
}

// Function constructor
function func_constructor(req) {
    const userCode = req.query.code;
    // VULNERABLE: Function constructor
    const func = new Function(userCode);
    func();
}

function func_constructor_with_args(req) {
    const userCode = req.query.body;
    const arg = req.query.arg;
    // VULNERABLE: Function constructor with user-controlled body
    const func = new Function('arg', userCode);
    func(arg);
}

// setTimeout/setInterval with string argument
function timeout_string(req) {
    const userCode = req.query.code;
    // VULNERABLE: setTimeout with string argument
    setTimeout(userCode, 1000);
}

function interval_string(req) {
    const userCode = req.query.code;
    // VULNERABLE: setInterval with string argument
    setInterval(userCode, 1000);
}

function setImmediate_string(req) {
    const userCode = req.query.code;
    // VULNERABLE: setImmediate with string argument
    setImmediate(userCode);
}

// VM module
function vm_runInContext(req) {
    const userCode = req.query.code;
    const sandbox = {};
    // VULNERABLE: VM execution
    vm.runInContext(userCode, sandbox);
}

function vm_runInNewContext(req) {
    const userCode = req.query.code;
    const sandbox = { console };
    // VULNERABLE: VM execution
    vm.runInNewContext(userCode, sandbox);
}

function vm_script(req) {
    const userCode = req.query.code;
    // VULNERABLE: VM script execution
    const script = new vm.Script(userCode);
    script.runInNewContext();
}

// Dynamic require
function dynamic_require(req) {
    const moduleName = req.query.module;
    // VULNERABLE: Dynamic require
    const module = require(moduleName);
}

// Global object manipulation
function global_pollution(req) {
    const propName = req.query.prop;
    const value = req.query.value;
    // VULNERABLE: Global object pollution
    global[propName] = value;
}

// Safe patterns
function eval_safe_const(req) {
    const userCode = req.query.code;
    // SAFE: Only evaluating constant
    const safe = JSON.stringify(userCode);
    eval(`const code = ${safe}; console.log(code);`);
}

function timeout_function(req) {
    const userCode = req.query.code;
    // SAFE: setTimeout with function
    setTimeout(() => console.log(userCode), 1000);
}

function vm_runInContext_safe(req) {
    const userCode = req.query.code;
    const sandbox = { console, require: () => {} };
    // SAFE: VM with restricted sandbox
    vm.runInContext(userCode, sandbox);
}

module.exports = {
    eval_simple, eval_concat, eval_template,
    func_constructor, func_constructor_with_args,
    timeout_string, interval_string, setImmediate_string,
    vm_runInContext, vm_runInNewContext, vm_script,
    dynamic_require, global_pollution,
    eval_safe_const, timeout_function, vm_runInContext_safe
};
