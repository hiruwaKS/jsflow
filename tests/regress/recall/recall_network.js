
// Recall Benchmarks: Network (TCP/UDP)
// Covering network sinks beyond standard HTTP.

const net = require('net');
const dgram = require('dgram');

// 1. TCP Connection (SSRF / Port Scanning)
function testTcpConnect(req) {
    const host = req.body.host;
    const port = req.body.port;
    const client = new net.Socket();
    
    // Vulnerable: Arbitrary connection
    client.connect(port, host, () => {
        client.write('Hello');
    });
}

// 2. UDP Send (SSRF / Amplification)
function testUdpSend(req) {
    const host = req.body.host;
    const port = req.body.port;
    const msg = req.body.msg;
    const client = dgram.createSocket('udp4');
    
    // Vulnerable: Sending data to arbitrary UDP service
    client.send(msg, port, host, (err) => {
        client.close();
    });
}

// 3. DNS Lookup (Information Disclosure / SSRF)
const dns = require('dns');
function testDnsLookup(req) {
    const hostname = req.body.hostname;
    // Vulnerable: Resolving arbitrary hostnames (internal network scanning)
    dns.lookup(hostname, (err, address, family) => {});
}

// 4. Server Listen (Port Binding)
function testServerListen(req) {
    const port = req.body.port;
    const server = net.createServer();
    // Vulnerable: Binding to attacker-controlled port (DoS)
    server.listen(port);
}

module.exports = {
    testTcpConnect,
    testUdpSend,
    testDnsLookup,
    testServerListen
};
