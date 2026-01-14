
// Sanitization Benchmarks

const { exec } = require('child_process');

// Mock sanitizer
function escapeShell(cmd) {
    if (typeof cmd !== 'string') return '';
    return cmd.replace(/[`;&|<>]/g, '');
}

function vulnerableNoSanitization(req) {
    const cmd = req.query.cmd;
    exec(cmd); // Vulnerable
}

function safeCustomSanitizer(req) {
    const cmd = req.query.cmd;
    const safeCmd = escapeShell(cmd);
    exec(safeCmd); // Safe
}

function incorrectSanitizer(req) {
    const cmd = req.query.cmd;
    // Flawed: Only replaces first occurrence
    const safeCmd = cmd.replace(';', ''); 
    exec(safeCmd); // Vulnerable (e.g. "ls; rm -rf /; echo done")
}

function conditionalSanitization(req) {
    let cmd = req.query.cmd;
    if (cmd.includes('safe')) {
        // Not a real sanitizer, just a check
        exec(cmd); // Vulnerable
    }
}

function reassignSanitization(req) {
    let cmd = req.query.cmd;
    cmd = escapeShell(cmd);
    exec(cmd); // Safe
}

module.exports = {
    vulnerableNoSanitization,
    safeCustomSanitizer,
    incorrectSanitizer,
    conditionalSanitization,
    reassignSanitization
};
