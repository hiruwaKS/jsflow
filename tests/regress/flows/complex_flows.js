
// Complex Data Flow Benchmarks

const fs = require('fs');

// 1. Flow through Class Properties
class Handler {
    constructor(input) {
        this.input = input;
    }

    process() {
        this.sanitized = "safe";
        this.unsafe = this.input;
    }

    execute() {
        // Vulnerable: Usage of this.unsafe
        eval(this.unsafe);
    }

    executeSafe() {
        // Safe: Usage of this.sanitized
        eval(this.sanitized);
    }
}

function testClassFlow(req) {
    const h = new Handler(req.query.code);
    h.process();
    h.execute(); // Vulnerable
    h.executeSafe(); // Safe
}

// 2. Flow through Closures
function createExecutor(cmd) {
    return function() {
        // Vulnerable: cmd captured from outer scope
        require('child_process').exec(cmd);
    };
}

function testClosureFlow(req) {
    const executor = createExecutor(req.query.cmd);
    executor();
}

// 3. Flow through Array Methods
function testArrayFlow(req) {
    const inputs = [req.query.a, req.query.b, "safe_constant"];
    
    // Map transforms but preserves taint
    const commands = inputs.map(i => "echo " + i);
    
    commands.forEach(cmd => {
        // Vulnerable: 2/3 inputs are tainted
        require('child_process').exec(cmd);
    });
}

// 4. Object Destructuring and Spread
function testDestructuring(req) {
    const data = {
        safe: "echo hello",
        unsafe: req.query.cmd
    };

    const { unsafe } = data;
    // Vulnerable
    require('child_process').exec(unsafe);

    const { safe } = data;
    // Safe
    require('child_process').exec(safe);
}

module.exports = {
    testClassFlow,
    testClosureFlow,
    testArrayFlow,
    testDestructuring
};
