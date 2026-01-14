
// Precision Benchmarks: Flow Sensitivity
// Analyzers must respect the order of operations and variable updates.

const childProcess = require('child_process');

// 1. Simple Reassignment (Strong Update)
function reassignment(req) {
    let cmd = req.query.cmd; // Tainted
    cmd = "echo safe";       // Overwritten with safe value
    childProcess.exec(cmd);  // Safe
}

// 2. Conditional Reassignment (Must handle split paths correctly)
function conditionalReassignment(req) {
    let cmd = req.query.cmd;
    let isSafe = true;
    
    if (isSafe) {
        cmd = "ls -l";
    }
    
    // Analyzer must know 'isSafe' is true OR merge correctly if it can't determine
    // But here, it's explicitly safe.
    childProcess.exec(cmd); // Safe
}

// 3. Loop Reassignment
function loopReassignment(req) {
    let cmd = req.query.cmd;
    for (let i = 0; i < 5; i++) {
        cmd = "echo " + i;
    }
    // After loop, cmd is "echo 4" (Safe)
    childProcess.exec(cmd);
}

// 4. Variable Swapping
function swap(req) {
    let a = req.query.cmd; // Tainted
    let b = "echo safe";   // Safe
    
    let temp = a;
    a = b;
    b = temp;
    
    childProcess.exec(a); // Safe (was b)
    // childProcess.exec(b); // Vulnerable (was a)
}

// 5. Function Parameter Reassignment (Local scope)
function paramReassign(cmd) {
    cmd = "safe";
    childProcess.exec(cmd); // Safe
}

function testParamReassign(req) {
    paramReassign(req.query.cmd);
}

// 6. Closure Variable Update
function closureUpdate(req) {
    let cmd = req.query.cmd;
    
    function sanitize() {
        cmd = "safe";
    }
    
    sanitize();
    childProcess.exec(cmd); // Safe
}

module.exports = {
    reassignment,
    conditionalReassignment,
    loopReassignment,
    swap,
    testParamReassign,
    closureUpdate
};
