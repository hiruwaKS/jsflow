
// Precision Benchmarks: Context Sensitivity
// Analyzers must distinguish between different invocations of the same function.

const childProcess = require('child_process');

// 1. Identity Function (Polymorphism)
function identity(val) {
    return val;
}

function testIdentity(req) {
    const safe = identity("echo safe");
    const tainted = identity(req.query.cmd);
    
    childProcess.exec(safe);    // Safe
    // childProcess.exec(tainted); // Vulnerable
}

// 2. Context-Sensitive Sanitizer
function runner(cmd, mode) {
    if (mode === 'safe') {
        childProcess.exec("echo safe");
    } else {
        childProcess.exec(cmd);
    }
}

function testRunner(req) {
    runner(req.query.cmd, 'safe'); // Safe
    // runner(req.query.cmd, 'unsafe'); // Vulnerable
}

// 3. Object Context (this)
class Executor {
    constructor(cmd) {
        this.cmd = cmd;
    }
    
    run() {
        childProcess.exec(this.cmd);
    }
}

function testClassContext(req) {
    const safeExec = new Executor("ls");
    const unsafeExec = new Executor(req.query.cmd);
    
    safeExec.run();   // Safe
    // unsafeExec.run(); // Vulnerable
}

// 4. Factory Function
function createExecutor(cmd) {
    return function() {
        childProcess.exec(cmd);
    };
}

function testFactory(req) {
    const safeRun = createExecutor("date");
    const unsafeRun = createExecutor(req.query.cmd);
    
    safeRun();   // Safe
    // unsafeRun(); // Vulnerable
}

// 5. Shared Helper with Callback
function executeWithCallback(data, callback) {
    callback(data);
}

function testCallback(req) {
    // Call 1: Safe data
    executeWithCallback("safe", (d) => {
        childProcess.exec(d); // Safe
    });
    
    // Call 2: Tainted data (Vulnerable context, not included here to keep this file purely about precision/false positives if analyzed correctly, or mixed)
    // To prove precision, we show a case that *looks* tainted if context is merged.
    
    const safeData = "safe";
    const taintedData = req.query.cmd;
    
    executeWithCallback(safeData, (d) => {
        childProcess.exec(d); // Safe
    });
}

module.exports = {
    testIdentity,
    testRunner,
    testClassContext,
    testFactory,
    testCallback
};
