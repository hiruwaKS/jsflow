
// Recall Benchmarks: HTTP, Zlib, Util, REPL, and others
// Covering miscellaneous built-in sinks and propagation.

const http = require('http');
const zlib = require('zlib');
const util = require('util');
const repl = require('repl');
const querystring = require('querystring');

// 1. HTTP Response Splitting / Header Injection
function testHeaderInjection(req, res) {
    const val = req.query.val;
    // Vulnerable: Setting arbitrary headers
    res.setHeader('X-Custom', val); 
    // If val contains "\r\nSet-Cookie: ...", it's a vulnerability
}

// 2. HTTP Request Splitting (Client)
function testRequestSplitting(req) {
    const method = req.query.method;
    // Vulnerable: Method injection
    http.request({
        method: method,
        host: 'example.com'
    });
}

// 3. Zlib DoS (Zip Bomb) - Logical vulnerability
function testZlibDecompression(req) {
    const data = req.body.data;
    // Vulnerable: Decompressing untrusted large chunks without size limits
    zlib.unzip(data, (err, buffer) => {
        // ...
    });
}

// 4. Util.format Propagation
function testUtilFormat(req) {
    const input = req.query.input;
    // Taint propagates through formatting
    const formatted = util.format('Command: %s', input);
    require('child_process').exec(formatted); // Vulnerable
}

// 5. QueryString Parse Propagation
function testQueryString(req) {
    const raw = req.body.raw; // "cmd=ls"
    const parsed = querystring.parse(raw);
    // Vulnerable
    require('child_process').exec(parsed.cmd);
}

// 6. REPL Start (Code Execution)
function testRepl(req) {
    const input = req.body.code;
    const r = repl.start({
        input: input, // If input is a stream controlling REPL
        output: process.stdout,
        eval: (cmd, context, filename, callback) => {
             // Custom eval might be safe, but default REPL is dangerous if input is controlled
             // Here we demonstrate a custom eval that just runs it
             callback(null, eval(cmd)); 
        }
    });
}

// 7. Inspector (Code Execution)
const inspector = require('inspector');
function testInspector(req) {
    // Vulnerable: Opening inspector on public IP/port
    const port = req.body.port;
    inspector.open(port, '0.0.0.0'); 
}

module.exports = {
    testHeaderInjection,
    testRequestSplitting,
    testZlibDecompression,
    testUtilFormat,
    testQueryString,
    testRepl,
    testInspector
};
