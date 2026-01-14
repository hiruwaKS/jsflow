
// Recall Benchmarks: Worker Threads and Clusters
// Covering code execution via IPC and thread instantiation.

const { Worker } = require('worker_threads');
const cluster = require('cluster');

// 1. Worker Thread Evaluation
function testWorkerEval(req) {
    const code = req.body.code;
    // Vulnerable: eval: true allows code execution
    new Worker(code, { eval: true });
}

// 2. Worker Data Injection
function testWorkerData(req) {
    const cmd = req.body.cmd;
    // Worker script that executes workerData
    const workerScript = `
        const { workerData } = require('worker_threads');
        require('child_process').exec(workerData);
    `;
    // Vulnerable: Passing tainted data to worker that executes it
    new Worker(workerScript, { 
        eval: true,
        workerData: cmd 
    });
}

// 3. Cluster Fork Environment Injection
function testClusterFork(req) {
    const shellPayload = req.body.payload;
    
    // Vulnerable: Environment variables injection can lead to RCE
    // e.g., NODE_OPTIONS='--require /tmp/malicious.js'
    cluster.fork({
        NODE_OPTIONS: shellPayload
    });
}

// 4. Cluster IPC Code Execution
function testClusterIPC(req) {
    const cmd = req.body.cmd;
    
    if (cluster.isMaster) {
        const worker = cluster.fork();
        // Sending tainted command to worker
        worker.send({ cmd: cmd });
    } else {
        process.on('message', (msg) => {
            if (msg.cmd) {
                // Vulnerable: Worker executing received message
                require('child_process').exec(msg.cmd);
            }
        });
    }
}

module.exports = {
    testWorkerEval,
    testWorkerData,
    testClusterFork,
    testClusterIPC
};
