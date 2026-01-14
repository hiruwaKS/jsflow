// Comprehensive SSTI (Server-Side Template Injection) Benchmarks
// Covers template injection in popular JavaScript template engines

// ============================================================================
// PART 1: Handlebars (hbs) SSTI
// ============================================================================

function handlebars_basic_injection(req) {
    const template = req.body.template;
    const Handlebars = require('handlebars');
    // VULNERABLE: User controls template source
    const compiled = Handlebars.compile(template);
    const result = compiled({});
    return result;
}

function handlebars_helper_injection(req) {
    const username = req.query.user;
    const Handlebars = require('handlebars');
    // VULNERABLE: User input in template string
    const template = `Hello {{${username}}}`;
    const compiled = Handlebars.compile(template);
    return compiled({});
}

function handlebars_partial_injection(req) {
    const partial = req.body.partial;
    const Handlebars = require('handlebars');
    // VULNERABLE: User controls partial name
    const template = `{{> ${partial}}}`;
    const compiled = Handlebars.compile(template);
    return compiled({});
}

// ============================================================================
// PART 2: EJS SSTI
// ============================================================================

function ejs_render_unsafe(req) {
    const template = req.body.template;
    const ejs = require('ejs');
    // VULNERABLE: User controls template source
    const result = ejs.render(template, {});
    return result;
}

function ejs_render_file_user_controlled(req) {
    const filename = req.query.file;
    const ejs = require('ejs');
    // VULNERABLE: User controls template file path
    const result = ejs.renderFile(filename, {});
    return result;
}

function ejs_options_bypass(req) {
    const template = req.body.template;
    const ejs = require('ejs');
    // VULNERABLE: Disabling escapes with options
    const result = ejs.render(template, {}, { escape: false });
    return result;
}

// ============================================================================
// PART 3: Pug SSTI
// ============================================================================

function pug_basic_injection(req) {
    const template = req.body.template;
    const pug = require('pug');
    // VULNERABLE: User controls template source
    const compiled = pug.compile(template);
    return compiled({});
}

function pug_include_user_controlled(req) {
    const file = req.query.include;
    const pug = require('pug');
    // VULNERABLE: User controls include path
    const template = `include ${file}`;
    const compiled = pug.compile(template);
    return compiled({});
}

// ============================================================================
// PART 4: Mustache SSTI
// ============================================================================

function mustache_basic_injection(req) {
    const template = req.body.template;
    const Mustache = require('mustache');
    // VULNERABLE: User controls template
    const result = Mustache.render(template, {});
    return result;
}

function mustache_partial_injection(req) {
    const partial = req.body.partial;
    const Mustache = require('mustache');
    // VULNERABLE: User controls partial name
    const template = `{{> ${partial}}}`;
    const result = Mustache.render(template, {});
    return result;
}

// ============================================================================
// PART 5: Nunjucks SSTI
// ============================================================================

function nunjucks_basic_injection(req) {
    const template = req.body.template;
    const nunjucks = require('nunjucks');
    // VULNERABLE: User controls template source
    const result = nunjucks.renderString(template, {});
    return result;
}

function nunjucks_loader_injection(req) {
    const template = req.body.template;
    const loaderPath = req.query.path;
    const nunjucks = require('nunjucks');
    // VULNERABLE: User controls loader path
    const loader = new nunjucks.FileSystemLoader(loaderPath);
    const env = new nunjucks.Environment(loader);
    return env.renderString(template, {});
}

function nunjucks_filter_injection(req) {
    const template = `{{ user | ${req.query.filter} }}`;
    const nunjucks = require('nunjucks');
    // VULNERABLE: User controls filter name
    const env = new nunjucks.Environment(new nunjucks.FileSystemLoader('views'));
    return env.renderString(template, {});
}

// ============================================================================
// PART 6: Advanced SSTI Vectors
// ============================================================================

function ssti_expression_injection(req) {
    const input = req.query.input;
    const Handlebars = require('handlebars');
    // VULNERABLE: Expression-based injection
    const template = `{{#if ${input}}}True{{/if}}`;
    const compiled = Handlebars.compile(template);
    return compiled({});
}

function ssti_whitespace_bypass(req) {
    const input = req.query.input;
    const pug = require('pug');
    // VULNERABLE: Whitespace bypass in some engines
    const template = `include ${input}   `;
    const compiled = pug.compile(template);
    return compiled({});
}

function ssti_precomputed_template(req) {
    const templateName = req.query.template;
    const nunjucks = require('nunjucks');
    // VULNERABLE: User selects from precomputed templates
    const templates = {
        'safe': 'Hello user',
        'dangerous': '{{process.mainModule.require("child_process").execSync("whoami").toString()}}'
    };
    return nunjucks.renderString(templates[templateName] || templates['safe'], {});
}

// ============================================================================
// PART 7: Real-World SSTI Patterns
// ============================================================================

function real_world_email_template(req) {
    const userTemplate = req.body.emailTemplate;
    const ejs = require('ejs');
    // VULNERABLE: Email template with user content
    const email = ejs.render(userTemplate, { user: req.user });
    return email;
}

function real_world_pdf_generation(req) {
    const htmlTemplate = req.body.html;
    const pug = require('pug');
    // VULNERABLE: PDF generator with user template
    const html = pug.render(htmlTemplate);
    return generatePDF(html);
}

function real_world_report_template(req) {
    const reportTemplate = req.query.report;
    const Handlebars = require('handlebars');
    // VULNERABLE: Report generation with user template
    const report = Handlebars.compile(reportTemplate);
    return report({ data: req.body });
}

// ============================================================================
// PART 8: Safe Patterns - Precision Testing
// ============================================================================

function handlebars_safe_context(req) {
    const username = req.query.user;
    const Handlebars = require('handlebars');
    // SAFE: Predefined template with user data
    const template = 'Hello {{username}}';
    const compiled = Handlebars.compile(template);
    return compiled({ username });
}

function ejs_safe_with_validation(req) {
    const templateName = req.body.template;
    const allowedTemplates = ['email', 'welcome', 'alert'];
    const ejs = require('ejs');
    // SAFE: Whitelist validation of templates
    if (!allowedTemplates.includes(templateName)) {
        return 'Invalid template';
    }
    return ejs.renderFile(templateName, { user: req.user });
}

function pug_safe_user_data_only(req) {
    const username = req.query.user;
    const pug = require('pug');
    // SAFE: User data only, not template structure
    const template = 'p Hello #{user} p';
    const compiled = pug.compile(template);
    return compiled({ user: username });
}

function nunjucks_safe_autoescape(req) {
    const username = req.query.user;
    const nunjucks = require('nunjucks');
    // SAFE: Autoescape enabled by default
    const template = 'Hello {{ username }}';
    return nunjucks.renderString(template, { username });
}

module.exports = {
    // Part 1: Handlebars
    handlebars_basic_injection,
    handlebars_helper_injection,
    handlebars_partial_injection,

    // Part 2: EJS
    ejs_render_unsafe,
    ejs_render_file_user_controlled,
    ejs_options_bypass,

    // Part 3: Pug
    pug_basic_injection,
    pug_include_user_controlled,

    // Part 4: Mustache
    mustache_basic_injection,
    mustache_partial_injection,

    // Part 5: Nunjucks
    nunjucks_basic_injection,
    nunjucks_loader_injection,
    nunjucks_filter_injection,

    // Part 6: Advanced Vectors
    ssti_expression_injection,
    ssti_whitespace_bypass,
    ssti_precomputed_template,

    // Part 7: Real-World
    real_world_email_template,
    real_world_pdf_generation,
    real_world_report_template,

    // Part 8: Safe Patterns
    handlebars_safe_context,
    ejs_safe_with_validation,
    pug_safe_user_data_only,
    nunjucks_safe_autoescape
};
