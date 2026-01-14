
// Async Context Benchmarks (Recall)

const childProcess = require('child_process');
const fs = require('fs');

// 1. Basic Async/Await
async function asyncAwait(req) {
    const cmd = req.query.cmd;
    const result = await Promise.resolve(cmd);
    // Vulnerable: Taint propagates through Promise resolution
    childProcess.exec(result);
}

// 2. Promise Chain
function promiseChain(req) {
    const cmd = req.query.cmd;
    Promise.resolve(cmd)
        .then(val => {
            return "echo " + val;
        })
        .then(finalCmd => {
            // Vulnerable: Taint propagates through chain
            childProcess.exec(finalCmd);
        });
}

// 3. Async Iteration
async function asyncIteration(req) {
    const cmds = [req.query.cmd1, req.query.cmd2];
    
    for await (const cmd of cmds) {
        // Vulnerable: Taint propagates in loop
        childProcess.exec(cmd);
    }
}

// 4. Mixed Callbacks and Promises
function mixedAsync(req) {
    const cmd = req.query.cmd;
    
    new Promise((resolve) => {
        fs.stat('.', () => {
            resolve(cmd);
        });
    }).then(tainted => {
        // Vulnerable: Taint survives callback -> promise -> then
        childProcess.exec(tainted);
    });
}

// 5. Unawaited Promise (Race Condition / Fire-and-forget)
function fireAndForget(req) {
    const cmd = req.query.cmd;
    // Vulnerable: Even if not awaited, execution happens
    async function background() {
        await new Promise(r => setTimeout(r, 10));
        childProcess.exec(cmd);
    }
    background();
}

module.exports = {
    asyncAwait,
    promiseChain,
    asyncIteration,
    mixedAsync,
    fireAndForget
};
