
// Recall Benchmarks: Data Structures and Propagation
// Covering taint propagation through standard Node.js structures.

const EventEmitter = require('events');
const { Readable } = require('stream');

// 1. Buffer Propagation
function testBuffer(req) {
    const input = req.body.input;
    const buf1 = Buffer.from(input); // Tainted
    const buf2 = Buffer.from("safe");
    
    const combined = Buffer.concat([buf1, buf2]); // Tainted
    
    require('child_process').exec(combined.toString()); // Vulnerable
}

// 2. Stream Propagation
function testStream(req) {
    const input = req.body.input;
    const source = new Readable();
    source.push(input);
    source.push(null);
    
    let data = '';
    source.on('data', (chunk) => {
        data += chunk; // Tainted propagation
    });
    
    source.on('end', () => {
        require('child_process').exec(data); // Vulnerable
    });
}

// 3. EventEmitter Propagation
function testEventEmitter(req) {
    const input = req.body.input;
    const emitter = new EventEmitter();
    
    emitter.on('event', (msg) => {
        require('child_process').exec(msg); // Vulnerable
    });
    
    emitter.emit('event', input); // Passing taint
}

// 4. Map Propagation
function testMap(req) {
    const input = req.body.input;
    const map = new Map();
    map.set('key', input);
    
    const val = map.get('key');
    require('child_process').exec(val); // Vulnerable
}

// 5. Set Propagation (Iteration)
function testSet(req) {
    const input = req.body.input;
    const set = new Set();
    set.add(input);
    
    for (const item of set) {
        require('child_process').exec(item); // Vulnerable
    }
}

// 6. JSON Serialization
function testJSON(req) {
    const input = req.body.input;
    const obj = { cmd: input };
    const str = JSON.stringify(obj); // Tainted string
    
    const parsed = JSON.parse(str); // Tainted object
    require('child_process').exec(parsed.cmd); // Vulnerable
}

module.exports = {
    testBuffer,
    testStream,
    testEventEmitter,
    testMap,
    testSet,
    testJSON
};
