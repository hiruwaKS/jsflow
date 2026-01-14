
// Server-Side Request Forgery (SSRF) Benchmarks

const http = require('http');
const axios = require('axios');

function vulnerableHttp(req) {
    const url = req.query.url;
    // Vulnerability: Arbitrary URL access
    http.get(url, (res) => {
        console.log(res.statusCode);
    });
}

async function vulnerableAxios(req) {
    const url = req.body.target;
    // Vulnerability: Arbitrary URL access
    return await axios.get(url);
}

function safeAllowlist(req) {
    const url = req.query.url;
    const allowedDomains = ['https://api.example.com', 'https://cdn.example.com'];
    
    // Safe: Strict allowlist check
    if (allowedDomains.includes(url)) {
        http.get(url, (res) => {
            console.log(res.statusCode);
        });
    }
}

function safeUrlParse(req) {
    const userUrl = req.query.url;
    try {
        const parsed = new URL(userUrl);
        // Safe: Protocol and Host validation
        if (parsed.protocol === 'https:' && parsed.hostname === 'trusted.com') {
            http.get(userUrl, (res) => {
                console.log(res.statusCode);
            });
        }
    } catch (e) {
        // Invalid URL
    }
}

function incompleteCheck(req) {
    const userUrl = req.query.url;
    // Vulnerable: Weak check (bypassable with trusted.com.evil.com)
    if (userUrl.startsWith('https://trusted.com')) {
        http.get(userUrl, (res) => {
            console.log(res.statusCode);
        });
    }
}

module.exports = {
    vulnerableHttp,
    vulnerableAxios,
    safeAllowlist,
    safeUrlParse,
    incompleteCheck
};
