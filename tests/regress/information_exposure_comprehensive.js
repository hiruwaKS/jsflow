// Comprehensive Information Exposure Benchmarks (CWE-200)
// Covers information leakage through various vectors

const fs = require('fs');
const http = require('http');

// ============================================================================
// PART 1: Sensitive Data Exposure
// ============================================================================

function expose_password(req, res) {
    const password = 'super_secret_password';
    // VULNERABLE: Password in logs/error messages
    console.log(`User password: ${password}`);
    res.json({ message: 'User created' });
}

function expose_api_key(req, res) {
    const apiKey = process.env.API_KEY;
    // VULNERABLE: API key in error response
    try {
        someOperation();
    } catch (error) {
        res.status(500).json({
            error: error.message,
            debug_info: { apiKey }
        });
    }
}

function expose_database_connection(req, res) {
    const dbConfig = {
        host: 'localhost',
        username: 'admin',
        password: 'secret123'
    };
    // VULNERABLE: Database credentials in response
    res.json({ connection: dbConfig });
}

function expose_session_secret(req, res) {
    const sessionSecret = 'very_secret_session_key';
    // VULNERABLE: Session secret in HTML comments
    res.send(`<!-- Session key: ${sessionSecret} --><h1>Welcome</h1>`);
}

function expose_encryption_key(req, res) {
    const encryptionKey = 'aes256_encryption_key_here';
    // VULNERABLE: Encryption key in JavaScript variable
    res.send(`<script>const ENCRYPTION_KEY = '${encryptionKey}';</script>`);
}

// ============================================================================
// PART 2: Stack Trace Exposure
// ============================================================================

function stack_trace_exposure(req, res) {
    const userId = req.params.id;
    try {
        const user = database.getUser(userId);
        res.json(user);
    } catch (error) {
        // VULNERABLE: Full stack trace in response
        res.status(500).send(`
            <h1>Error</h1>
            <pre>${error.stack}</pre>
        `);
    }
}

function debug_mode_exposure(req, res) {
    const isDebug = process.env.DEBUG === 'true';
    if (isDebug) {
        // VULNERABLE: Debug information in production
        res.json({
            debug: true,
            env: process.env,
            config: appConfig
        });
    }
}

function error_details_exposure(req, res) {
    try {
        riskyOperation();
    } catch (error) {
        // VULNERABLE: Detailed error information
        res.status(500).json({
            message: 'An error occurred',
            error: {
                name: error.name,
                message: error.message,
                stack: error.stack,
                code: error.code
            }
        });
    }
}

// ============================================================================
// PART 3: Source Code Exposure
// ============================================================================

function source_code_exposure(req, res) {
    const filename = req.params.file;
    // VULNERABLE: Arbitrary source file access
    const source = fs.readFileSync(`./src/${filename}`, 'utf8');
    res.send(source);
}

function backup_file_exposure(req, res) {
    const backupFile = req.params.backup;
    // VULNERABLE: Backup file access
    const backup = fs.readFileSync(`./backups/${backupFile}`, 'utf8');
    res.send(backup);
}

function git_file_exposure(req, res) {
    const gitFile = req.params.file;
    // VULNERABLE: .git file access
    const content = fs.readFileSync(`./.git/${gitFile}`, 'utf8');
    res.send(content);
}

function config_file_exposure(req, res) {
    const configFile = req.params.config;
    // VULNERABLE: Config file access
    const config = fs.readFileSync(`./config/${configFile}`, 'utf8');
    res.send(config);
}

function env_file_exposure(req, res) {
    const envFile = req.params.file;
    // VULNERABLE: .env file access
    const env = fs.readFileSync(`./.env`, 'utf8');
    res.send(env);
}

// ============================================================================
// PART 4: Header Information Exposure
// ============================================================================

function expose_server_version(req, res) {
    // VULNERABLE: Server version in headers
    res.setHeader('Server', 'Express/4.17.1 Node.js/14.15.0');
    res.send('Hello');
}

function expose_x_powered_by(req, res) {
    // VULNERABLE: Technology stack in headers
    res.setHeader('X-Powered-By', 'Express');
    res.send('Hello');
}

function expose_x_aspnet_version(req, res) {
    // VULNERABLE: ASP.NET version (if applicable)
    res.setHeader('X-AspNet-Version', '4.0.30319');
    res.send('Hello');
}

function expose_debug_info(req, res) {
    // VULNERABLE: Debug information in headers
    res.setHeader('X-Debug', 'mode=debug,version=1.2.3');
    res.send('Hello');
}

// ============================================================================
// PART 5: Comment Exposure
// ============================================================================

function html_comment_exposure(req, res) {
    const password = process.env.DB_PASSWORD;
    // VULNERABLE: Sensitive data in HTML comments
    res.send(`
        <!-- Database password: ${password} -->
        <h1>Page content</h1>
    `);
}

function js_comment_exposure(req, res) {
    const apiKey = process.env.API_KEY;
    // VULNERABLE: API key in JavaScript comments
    res.send(`<script>
        // API Key: ${apiKey}
        const app = init();
    </script>`);
}

function css_comment_exposure(req, res) {
    const secret = process.env.SECRET_KEY;
    // VULNERABLE: Secret in CSS comments
    res.send(`<style>
        /* Secret key: ${secret} */
        body { background: white; }
    </style>`);
}

// ============================================================================
// PART 6: HTTP Parameter Pollution
// ============================================================================

function http_parameter_pollution(req, res) {
    const data = req.body;
    // VULNERABLE: HTTP parameter pollution
    // If client sends "id=1&id=2", may expose both values
    res.json({ received: data.id });
}

function header_injection_exposure(req, res) {
    const debugHeader = req.headers['x-debug'];
    // VULNERABLE: Debug header exposes information
    if (debugHeader) {
        res.json({
            debug: debugHeader,
            internal: appConfig
        });
    }
}

function host_header_exposure(req, res) {
    const host = req.headers.host;
    // VULNERABLE: Host header exposes internal URLs
    res.send(`<a href="http://${host}/admin">Admin</a>`);
}

// ============================================================================
// PART 7: Logging Exposure
// ============================================================================

function log_sensitive_data(req, res) {
    const creditCard = req.body.card;
    // VULNERABLE: Sensitive data in logs
    logger.info(`Processing payment for card: ${creditCard}`);
    res.json({ status: 'processed' });
}

function log_password(req, res) {
    const password = req.body.password;
    // VULNERABLE: Password in logs
    logger.debug(`Login attempt with password: ${password}`);
    res.json({ status: 'success' });
}

function log_personal_info(req, res) {
    const ssn = req.body.ssn;
    const dob = req.body.dob;
    // VULNERABLE: PII in logs
    logger.info(`User registered with SSN: ${ssn}, DOB: ${dob}`);
    res.json({ status: 'registered' });
}

// ============================================================================
// PART 8: Safe Patterns - Precision Testing
// ============================================================================

function safe_error_handling(req, res) {
    try {
        riskyOperation();
    } catch (error) {
        // SAFE: Generic error message
        res.status(500).json({
            message: 'An error occurred'
        });
    }
}

function safe_no_debug_headers(req, res) {
    // SAFE: No debug headers in production
    if (process.env.NODE_ENV === 'production') {
        res.removeHeader('X-Powered-By');
        res.removeHeader('X-Debug');
    }
    res.send('Hello');
}

function safe_sanitized_logs(req, res) {
    const password = req.body.password;
    // SAFE: Don't log sensitive data
    logger.info('Login attempt', {
        username: req.body.username
        // Password NOT logged
    });
    res.json({ status: 'success' });
}

function safe_no_stack_trace(req, res) {
    try {
        riskyOperation();
    } catch (error) {
        // SAFE: No stack trace in production
        if (process.env.NODE_ENV === 'production') {
            res.status(500).json({
                message: 'An error occurred'
            });
        } else {
            // Only in development
            res.status(500).json({
                message: error.message,
                stack: error.stack
            });
        }
    }
}

function safe_no_source_exposure(req, res) {
    const filename = req.params.file;
    // SAFE: Whitelist of allowed files
    const allowedFiles = ['index.js', 'app.js', 'config.js'];
    if (!allowedFiles.includes(filename)) {
        return res.status(404).send('File not found');
    }
    const source = fs.readFileSync(`./src/${filename}`, 'utf8');
    res.send(source);
}

function safe_no_backup_access(req, res) {
    const backupFile = req.params.backup;
    // SAFE: Deny backup file access
    if (backupFile.startsWith('.backup') || backupFile.endsWith('.bak')) {
        return res.status(403).send('Backup files not accessible');
    }
    res.status(404).send('File not found');
}

module.exports = {
    // Part 1: Sensitive Data
    expose_password,
    expose_api_key,
    expose_database_connection,
    expose_session_secret,
    expose_encryption_key,

    // Part 2: Stack Trace
    stack_trace_exposure,
    debug_mode_exposure,
    error_details_exposure,

    // Part 3: Source Code
    source_code_exposure,
    backup_file_exposure,
    git_file_exposure,
    config_file_exposure,
    env_file_exposure,

    // Part 4: Headers
    expose_server_version,
    expose_x_powered_by,
    expose_x_aspnet_version,
    expose_debug_info,

    // Part 5: Comments
    html_comment_exposure,
    js_comment_exposure,
    css_comment_exposure,

    // Part 6: HTTP Pollution
    http_parameter_pollution,
    header_injection_exposure,
    host_header_exposure,

    // Part 7: Logging
    log_sensitive_data,
    log_password,
    log_personal_info,

    // Part 8: Safe Patterns
    safe_error_handling,
    safe_no_debug_headers,
    safe_sanitized_logs,
    safe_no_stack_trace,
    safe_no_source_exposure,
    safe_no_backup_access
};
