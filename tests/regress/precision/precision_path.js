
// Precision Benchmarks: Path Sensitivity
// Analyzers must understand predicates and control flow dependencies.

const childProcess = require('child_process');

// 1. Correlated Conditions
function correlated(req) {
    const cmd = req.query.cmd;
    let isSafe = false;
    
    if (cmd === "safe") {
        isSafe = true;
    }
    
    if (isSafe) {
        // Safe: cmd must be "safe" to enter here
        childProcess.exec(cmd);
    }
}

// 2. Guard Variables
function guardVariable(req) {
    const cmd = req.query.cmd;
    let safe = false;
    
    if (isValid(cmd)) {
        safe = true;
    }
    
    if (safe) {
        childProcess.exec(cmd); // Safe (assuming isValid implies safety)
    }
}

function isValid(str) {
    return str === "ls";
}

// 3. Switch Case Fallthrough
function switchCase(req) {
    const type = req.query.type;
    const cmd = req.query.cmd;
    
    switch (type) {
        case 'SAFE':
            childProcess.exec("ls"); // Safe
            break;
        case 'UNSAFE':
            // childProcess.exec(cmd); // Vulnerable
            break;
        default:
            // Safe default
            childProcess.exec("echo error");
    }
}

// 4. Complex Boolean Logic
function complexLogic(req) {
    const cmd = req.query.cmd;
    const isAdmin = false;
    const isLocal = true;
    
    // Short-circuit evaluation
    if (isAdmin && isLocal) {
        // Unreachable in this context
        childProcess.exec(cmd); 
    }
    
    if (isLocal || isAdmin) {
        // Reachable, but let's say we sanitize in the block
        const safe = "echo hi";
        childProcess.exec(safe);
    }
}

// 5. Negated Conditions
function negated(req) {
    const cmd = req.query.cmd;
    if (cmd !== "ls") {
        return;
    }
    // Safe: cmd must be "ls"
    childProcess.exec(cmd);
}

// 6. Type Checks as Guards
function typeGuard(req) {
    const cmd = req.query.cmd;
    if (typeof cmd === "number") {
        // Safe: Numbers generally can't inject shell commands in this context
        // (assuming exec coerces safely or fails)
        childProcess.exec("sleep " + cmd);
    }
}

module.exports = {
    correlated,
    guardVariable,
    switchCase,
    complexLogic,
    negated,
    typeGuard
};
