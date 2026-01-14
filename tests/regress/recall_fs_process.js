
// Recall Benchmarks: FileSystem and Process
// Covering less common but dangerous sinks in fs and process modules.

const fs = require('fs');
const process = require('process');

// 1. File Write (Arbitrary File Write / Overwrite)
function testWriteFile(req) {
    const data = req.body.data;
    const path = req.body.path;
    
    // Vulnerable: User controls path and content
    fs.writeFile(path, data, (err) => {});
}

// 2. File Append (Log Poisoning / Config Injection)
function testAppendFile(req) {
    const data = req.body.data;
    // Vulnerable: Injecting into potentially sensitive files
    fs.appendFile('/var/log/app.log', data, (err) => {});
}

// 3. File Deletion (Denial of Service)
function testUnlink(req) {
    const path = req.body.path;
    // Vulnerable: Deleting arbitrary files
    fs.unlink(path, (err) => {});
}

// 4. Permission Modification
function testChmod(req) {
    const path = req.body.path;
    // Vulnerable: Making sensitive files world-readable/writable
    fs.chmod(path, 0o777, (err) => {});
}

// 5. Ownership Modification
function testChown(req) {
    const path = req.body.path;
    const uid = parseInt(req.body.uid);
    // Vulnerable: Changing file ownership
    fs.chown(path, uid, 1000, (err) => {});
}

// 6. Symlink Creation (Privilege Escalation potential)
function testSymlink(req) {
    const target = req.body.target;
    const path = req.body.path;
    // Vulnerable: Creating links to sensitive files
    fs.symlink(target, path, (err) => {});
}

// 7. Process Termination (DoS)
function testProcessKill(req) {
    const pid = req.body.pid;
    // Vulnerable: Killing arbitrary processes
    process.kill(pid, 'SIGTERM');
}

// 8. Module Loading (Code Execution)
function testDlopen(req) {
    const path = req.body.path;
    // Vulnerable: Loading arbitrary native addons
    process.dlopen({ exports: {} }, path);
}

// 9. Sync Variants (should also be caught)
function testSyncVariants(req) {
    const path = req.body.path;
    fs.writeFileSync(path, "data"); // Vulnerable
    fs.unlinkSync(path);            // Vulnerable
}

module.exports = {
    testWriteFile,
    testAppendFile,
    testUnlink,
    testChmod,
    testChown,
    testSymlink,
    testProcessKill,
    testDlopen,
    testSyncVariants
};
