// Comprehensive Path Traversal Benchmarks (CWE-22)
// Covers fs operations, path manipulation, and real-world patterns

const fs = require('fs');
const path = require('path');

// Basic vulnerable patterns
function path_simple(req) {
    const filename = req.query.file;
    // VULNERABLE: Direct user-controlled path
    const content = fs.readFileSync(filename, 'utf8');
    return content;
}

function path_template(req) {
    const filename = req.query.file;
    // VULNERABLE: Template literal
    const filepath = `/var/www/files/${filename}`;
    return fs.readFileSync(filepath, 'utf8');
}

function path_join(req) {
    const filename = req.query.file;
    // VULNERABLE: path.join doesn't normalize ../
    const filepath = path.join('/var/www', filename);
    return fs.readFileSync(filepath, 'utf8');
}

function path_resolve(req) {
    const filename = req.query.file;
    // VULNERABLE: path.resolve doesn't prevent traversal
    const filepath = path.resolve('/var/www', filename);
    return fs.readFileSync(filepath, 'utf8');
}

// Classic traversal patterns
function traversal_dotdot(req) {
    const file = req.query.file;
    // VULNERABLE: ../ traversal
    const filepath = `/app/${file}`;
    return fs.readFileSync(filepath);
}

function traversal_dotdot_encoded(req) {
    const file = req.query.file;
    // VULNERABLE: URL-encoded traversal
    const filepath = `/app/${file}`;
    return fs.readFileSync(filepath);
}

function traversal_double_encoding(req) {
    const file = req.query.file;
    // VULNERABLE: Double encoding
    const filepath = `/app/${file}`;
    return fs.readFileSync(filepath);
}

function traversal_utf8(req) {
    const file = req.query.file;
    // VULNERABLE: UTF-8 encoding bypass
    const filepath = `/app/${file}`;
    return fs.readFileSync(filepath);
}

// Path manipulation attacks
function traversal_null_byte(req) {
    const file = req.query.file;
    // VULNERABLE: Null byte injection
    const filepath = `/app/${file}\x00.txt`;
    return fs.readFileSync(filepath);
}

function traversal_absolute(req) {
    const file = req.query.file;
    // VULNERABLE: Absolute path bypass
    const filepath = `/app/${file}`;
    return fs.readFileSync(filepath);
}

function traversal_long(req) {
    const file = req.query.file;
    // VULNERABLE: Long path bypass
    const filepath = `/app/${file}`;
    return fs.readFileSync(filepath);
}

// Real-world patterns
function realworld_avatar(req) {
    const userId = req.params.id;
    // VULNERABLE: Avatar download with user input
    return fs.readFileSync(`/uploads/avatars/${userId}.jpg`);
}

function realworld_download(req) {
    const filename = req.query.file;
    // VULNERABLE: File download endpoint
    return res.download(`/downloads/${filename}`);
}

function realworld_backup(req) {
    const backupFile = req.query.file;
    // VULNERABLE: Backup restoration
    return fs.readFileSync(`/backups/${backupFile}`);
}

function realworld_config(req) {
    const configFile = req.query.config;
    // VULNERABLE: Configuration file access
    return fs.readFileSync(`/configs/${configFile}`);
}

// Safe patterns
function path_safe_normalize(req) {
    const filename = req.query.file;
    // SAFE: Proper normalization
    const filepath = path.normalize(path.join('/app', filename));
    const resolved = path.resolve(filepath);

    if (!resolved.startsWith('/app/')) {
        throw new Error('Invalid path');
    }

    return fs.readFileSync(resolved);
}

function path_safe_whitelist(req) {
    const filename = req.query.file;
    const allowed = ['readme.txt', 'config.json', 'data.csv'];

    // SAFE: Whitelist validation
    if (!allowed.includes(filename)) {
        throw new Error('File not allowed');
    }

    return fs.readFileSync(path.join('/app', filename));
}

module.exports = {
    path_simple, path_template, path_join, path_resolve,
    traversal_dotdot, traversal_dotdot_encoded,
    traversal_double_encoding, traversal_utf8,
    traversal_null_byte, traversal_absolute, traversal_long,
    realworld_avatar, realworld_download, realworld_backup, realworld_config,
    path_safe_normalize, path_safe_whitelist
};
