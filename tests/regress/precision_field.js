
// Precision Benchmarks: Field Sensitivity
// Analyzers must track properties of objects individually.

const childProcess = require('child_process');

// 1. Independent Properties
function independentProps(req) {
    const obj = {};
    obj.tainted = req.query.cmd;
    obj.safe = "ls";
    
    childProcess.exec(obj.safe); // Safe
    // childProcess.exec(obj.tainted); // Vulnerable
}

// 2. Nested Objects
function nestedObjects(req) {
    const config = {
        core: {
            cmd: "ls",
            user: req.query.user // Tainted
        }
    };
    
    childProcess.exec(config.core.cmd); // Safe
}

// 3. Array Indices
function arrayIndices(req) {
    const arr = ["ls", req.query.cmd];
    
    childProcess.exec(arr[0]); // Safe
    // childProcess.exec(arr[1]); // Vulnerable
}

// 4. Dynamic Access with Constant Keys
function dynamicAccess(req) {
    const obj = {
        safe: "ls",
        tainted: req.query.cmd
    };
    
    const key = "safe";
    childProcess.exec(obj[key]); // Safe
}

// 5. Object Destructuring (Field Selection)
function destructuring(req) {
    const data = {
        x: req.query.cmd,
        y: "echo safe"
    };
    
    const { y } = data;
    childProcess.exec(y); // Safe
}

// 6. Object.assign (Partial Taint)
function objectAssign(req) {
    const safeObj = { cmd: "ls" };
    const taintedObj = { data: req.query.cmd };
    
    const merged = Object.assign({}, safeObj, taintedObj);
    
    childProcess.exec(merged.cmd); // Safe
    // childProcess.exec(merged.data); // Vulnerable
}

module.exports = {
    independentProps,
    nestedObjects,
    arrayIndices,
    dynamicAccess,
    destructuring,
    objectAssign
};
