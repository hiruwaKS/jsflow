
// Precision Traps: Scenarios that often cause False Positives

const childProcess = require('child_process');

// 1. Unreachable Code (Dead Code)
function deadCode(req) {
    const cmd = req.query.cmd;
    if (false) {
        // Safe: This line is never executed
        childProcess.exec(cmd);
    }
}

// 2. Impossible Conditions
function impossibleCondition(req) {
    const cmd = req.query.cmd;
    const x = 10;
    if (x > 100) {
        // Safe: 10 is never > 100
        childProcess.exec(cmd);
    }
}

// 3. Shadowing / Mock Sinks
function mockSink(req) {
    const cmd = req.query.cmd;
    
    // This 'exec' is a local function, not child_process.exec
    function exec(c) {
        console.log("Mock execution: " + c);
    }
    
    // Safe: Calls the local mock
    exec(cmd); 
}

// 4. Sanitization via Control Flow
function controlFlowSanitization(req) {
    const color = req.query.color;
    let safeColor = "blue";
    
    if (color === "red") {
        safeColor = "red";
    } else if (color === "green") {
        safeColor = "green";
    }
    
    // Safe: safeColor can only be "blue", "red", or "green"
    // The original tainted 'color' string is never used directly
    childProcess.exec("echo " + safeColor);
}

// 5. Property Sanitization
function propertySanitization(req) {
    const input = req.query.sort;
    const allowed = {
        "asc": "ASC",
        "desc": "DESC"
    };
    
    // Safe: lookup returns trusted value or undefined
    const safeSort = allowed[input]; 
    
    if (safeSort) {
        // Safe: safeSort comes from the 'allowed' values
        childProcess.exec("echo " + safeSort);
    }
}

// 6. Type Coercion Safety
function typeSafety(req) {
    const id = req.query.id;
    // Safe: +id coerces to number. Even if NaN, it's not a shell command injection.
    // (Assuming simple echo context, not something where NaN is dangerous)
    childProcess.exec("sleep " + (+id)); 
}

module.exports = {
    deadCode,
    impossibleCondition,
    mockSink,
    controlFlowSanitization,
    propertySanitization,
    typeSafety
};
