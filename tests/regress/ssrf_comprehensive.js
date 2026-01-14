// Comprehensive SSRF Benchmarks (CWE-918)
// Covers HTTP requests, DNS rebinding, and real-world patterns

const http = require('http');
const https = require('https');
const axios = require('axios');

// Basic SSRF patterns
function ssrf_simple(req) {
    const url = req.query.url;
    // VULNERABLE: Direct user-controlled URL
    return http.get(url);
}

function ssrf_template(req) {
    const endpoint = req.query.endpoint;
    const baseUrl = 'https://api.example.com';
    // VULNERABLE: Template literal URL
    const url = `${baseUrl}/${endpoint}`;
    return axios.get(url);
}

function ssrf_concat(req) {
    const protocol = req.query.protocol;
    const host = req.query.host;
    // VULNERABLE: URL concatenation
    const url = `${protocol}://${host}/data`;
    return https.get(url);
}

// Internal network access
function ssrf_localhost(req) {
    const url = req.query.url;
    // VULNERABLE: Can access localhost/internal
    return axios.get(url);
}

function ssrf_private_ips(req) {
    const url = req.query.url;
    // VULNERABLE: Can access private IPs
    return http.get(url);
}

function ssrf_aws_metadata(req) {
    const url = req.query.url;
    // VULNERABLE: Can access AWS metadata
    return axios.get(url);
}

// URL parsing bypasses
function ssrf_url_parse_bypass(req) {
    const url = req.query.url;
    // VULNERABLE: URL parsing trickery
    const parsed = new URL(url);
    return http.get(`http://${parsed.hostname}${parsed.pathname}`);
}

function ssrf_fragment(req) {
    const url = req.query.url;
    // VULNERABLE: URL fragment bypass
    const cleanUrl = url.split('#')[0];
    return axios.get(cleanUrl);
}

function ssrf_at_sign(req) {
    const url = req.query.url;
    // VULNERABLE: @ sign bypass
    return axios.get(`https://trusted.com@${url}`);
}

// Protocol bypass
function ssrf_protocol_relative(req) {
    const path = req.query.path;
    // VULNERABLE: Protocol-relative URL
    return axios.get(`//${path}`);
}

function ssrf_file_protocol(req) {
    const url = req.query.url;
    // VULNERABLE: file:// protocol
    return axios.get(url);
}

// Real-world patterns
function ssrf_webhook(req) {
    const webhookUrl = req.query.webhook;
    const data = req.body;
    // VULNERABLE: User-controlled webhook
    return axios.post(webhookUrl, data);
}

function ssrf_pdf_gen(req) {
    const fileUrl = req.query.url;
    // VULNERABLE: PDF generator with user URL
    return axios.get(`http://pdf-service.com/generate?url=${fileUrl}`);
}

function ssrf_image_fetch(req) {
    const imageUrl = req.query.url;
    // VULNERABLE: Image proxy with user URL
    return axios.get(`http://image-proxy.com/fetch?url=${imageUrl}`);
}

function ssrf_xml_parser(req) {
    const xmlUrl = req.query.xml;
    // VULNERABLE: XXE/SSRF via XML
    return axios.get(xmlUrl);
}

// DNS rebinding
function ssrf_dns_rebinding(req) {
    const host = req.query.host;
    // VULNERABLE: DNS rebinding attack
    return axios.get(`http://${host}/data`);
}

// Safe patterns
function ssrf_safe_whitelist(req) {
    const url = req.query.url;
    const parsed = new URL(url);
    const allowedHosts = ['api.example.com', 'cdn.example.com'];

    // SAFE: Host whitelist validation
    if (!allowedHosts.includes(parsed.hostname)) {
        throw new Error('Invalid host');
    }

    return axios.get(url);
}

function ssrf_safe_regex(req) {
    const url = req.query.url;
    // SAFE: URL validation with regex
    if (!/^https:\/\/(api|cdn)\.example\.com\//.test(url)) {
        throw new Error('Invalid URL');
    }

    return axios.get(url);
}

module.exports = {
    ssrf_simple, ssrf_template, ssrf_concat,
    ssrf_localhost, ssrf_private_ips, ssrf_aws_metadata,
    ssrf_url_parse_bypass, ssrf_fragment, ssrf_at_sign,
    ssrf_protocol_relative, ssrf_file_protocol,
    ssrf_webhook, ssrf_pdf_gen, ssrf_image_fetch, ssrf_xml_parser,
    ssrf_dns_rebinding,
    ssrf_safe_whitelist, ssrf_safe_regex
};
