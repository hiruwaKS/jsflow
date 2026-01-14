
// Recall Benchmarks: VM and Timers
// Covering dynamic code execution through VM module and global timers.

const vm = require('vm');

// 1. setTimeout with String (Code Injection)
function testSetTimeout(req) {
    const code = req.body.code;
    // Vulnerable: String argument acts like eval()
    setTimeout(code, 1000);
}

// 2. setInterval with String
function testSetInterval(req) {
    const code = req.body.code;
    // Vulnerable
    setInterval(code, 1000);
}

// 3. setImmediate with String (Node.js specific, usually safe but worth checking if supported/polyfilled improperly)
// Note: Node.js setImmediate usually doesn't support string eval, but some environments might.
// We focus on standard eval sinks here.

// 4. VM Script Execution
function testVmScript(req) {
    const code = req.body.code;
    const script = new vm.Script(code);
    // Vulnerable: Running compiled script
    script.runInThisContext();
}

// 5. VM Context creation with unsafe sandbox
function testVmContext(req) {
    const input = req.body.input;
    const sandbox = { 
        unsafe: input // Tainted value available in sandbox
    };
    vm.createContext(sandbox);
    // Vulnerable if code inside uses 'unsafe' to exploit host, 
    // but here the code itself is static "unsafe". 
    // This tests if taint flows INTO the sandbox.
    vm.runInContext("unsafe", sandbox); 
}

// 6. Function Constructor (Indirect)
function testFunctionCtor(req) {
    const code = req.body.code;
    const Func = Function;
    const f = new Func(code);
    f();
}

// 7. Constructor of Constructor (The "constructor" property access attack)
function testConstructorAttack(req) {
    const input = req.body.input;
    // Payload: "alert(1)"
    // Execution: "".constructor.constructor("alert(1)")()
    const func = "".constructor.constructor(input);
    func();
}

module.exports = {
    testSetTimeout,
    testSetInterval,
    testVmScript,
    testVmContext,
    testFunctionCtor,
    testConstructorAttack
};
