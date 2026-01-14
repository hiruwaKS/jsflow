
// Comprehensive Cross-Site Scripting (XSS) Benchmarks (CWE-79)
// Covers stored, reflected, and DOM-based XSS with multiple contexts

const express = require('express');
const app = express();

// ============================================================================
// PART 1: Reflected XSS - Basic Patterns
// ============================================================================

// 1.1. Direct String Concatenation in Response
function xss_reflected_simple_concat(req, res) {
    const userInput = req.query.name;
    // VULNERABLE: Direct concatenation in HTML
    res.send(`<h1>Hello ${userInput}</h1>`);
}

// 1.2. Template Literal in Response
function xss_reflected_template_literal(req, res) {
    const userInput = req.query.name;
    // VULNERABLE: Template literal
    res.send(`<h1>Hello ${userInput}</h1>`);
}

// 1.3. Multiple Injection Points
function xss_reflected_multi_point(req, res) {
    const name = req.query.name;
    const email = req.query.email;
    // VULNERABLE: Multiple concatenations
    res.send(`
        <h1>${name}</h1>
        <p>Email: ${email}</p>
    `);
}

// 1.4. HTML Attribute Injection
function xss_reflected_attribute(req, res) {
    const userInput = req.query.search;
    // VULNERABLE: User input in HTML attribute
    res.send(`<input type="text" value="${userInput}">`);
}

// 1.5. Event Handler Injection
function xss_reflected_event_handler(req, res) {
    const userInput = req.query.action;
    // VULNERABLE: User input in event handler
    res.send(`<button onclick="${userInput}">Click</button>`);
}

// 1.6. JavaScript Context Injection
function xss_reflected_script_context(req, res) {
    const userInput = req.query.data;
    // VULNERABLE: User input in <script> tag
    res.send(`<script>const userData = "${userInput}";</script>`);
}

// 1.7. URL Injection
function xss_reflected_url(req, res) {
    const userInput = req.query.link;
    // VULNERABLE: User input in href attribute
    res.send(`<a href="${userInput}">Click here</a>`);
}

// 1.8. Style Attribute Injection
function xss_reflected_style(req, res) {
    const userInput = req.query.color;
    // VULNERABLE: User input in style attribute (expression)
    res.send(`<div style="color: ${userInput}">Text</div>`);
}

// 1.9. src Attribute Injection
function xss_reflected_src(req, res) {
    const userInput = req.query.img;
    // VULNERABLE: User input in src attribute
    res.send(`<img src="${userInput}">`);
}

// 1.10. IFrame Injection
function xss_reflected_iframe(req, res) {
    const userInput = req.query.url;
    // VULNERABLE: User input in iframe src
    res.send(`<iframe src="${userInput}"></iframe>`);
}

// ============================================================================
// PART 2: Stored XSS Patterns
// ============================================================================

// 2.1. Stored in Database (mock)
function xss_stored_comment(req, res) {
    const comment = req.body.comment;
    // VULNERABLE: Store unsanitized comment
    db.comments.insert({ comment });

    // Later retrieval and display
    const allComments = db.comments.find();
    res.render('comments', { comments: allComments });
}

// 2.2. Stored in User Profile
function xss_stored_profile(req, res) {
    const bio = req.body.bio;
    // VULNERABLE: Store unsanitized bio
    db.users.update(req.user.id, { bio });

    // Display on profile page
    const user = db.users.findById(req.user.id);
    res.render('profile', { user });
}

// 2.3. Stored in Message
function xss_stored_message(req, res) {
    const message = req.body.message;
    const recipient = req.body.recipient;

    // VULNERABLE: Store and display message
    db.messages.insert({
        from: req.user.id,
        to: recipient,
        message,
        timestamp: Date.now()
    });

    // Display in inbox
    const messages = db.messages.findByRecipient(recipient);
    res.render('inbox', { messages });
}

// ============================================================================
// PART 3: DOM-based XSS Patterns
// ============================================================================

// 3.1. InnerHTML Assignment
function xss_dom_innerhtml(req, res) {
    const userInput = req.query.content;

    // VULNERABLE: Setting innerHTML
    res.send(`
        <script>
            document.getElementById('content').innerHTML = '${userInput}';
        </script>
        <div id="content"></div>
    `);
}

// 3.2. Document.write
function xss_dom_write(req, res) {
    const userInput = req.query.data;

    // VULNERABLE: Using document.write
    res.send(`
        <script>
            document.write('${userInput}');
        </script>
    `);
}

// 3.3. eval() with User Input
function xss_dom_eval(req, res) {
    const userInput = req.query.code;

    // VULNERABLE: eval with user input
    res.send(`
        <script>
            eval('${userInput}');
        </script>
    `);
}

// 3.4. setTimeout with String Argument
function xss_dom_settimeout(req, res) {
    const userInput = req.query.alert;

    // VULNERABLE: setTimeout with string argument
    res.send(`
        <script>
            setTimeout('${userInput}', 1000);
        </script>
    `);
}

// 3.5. location.hash Usage
function xss_dom_location_hash(req, res) {
    res.send(`
        <script>
            const data = location.hash.substring(1);
            document.getElementById('output').innerHTML = data;
        </script>
        <div id="output"></div>
    `);
}

// 3.6. location.search Usage
function xss_dom_location_search(req, res) {
    res.send(`
        <script>
            const params = new URLSearchParams(location.search);
            document.getElementById('output').textContent = params.get('data');
        </script>
        <div id="output"></div>
    `);
}

// 3.7. postMessage Handler
function xss_dom_postmessage(req, res) {
    res.send(`
        <script>
            window.addEventListener('message', (event) => {
                document.getElementById('output').innerHTML = event.data;
            });
        </script>
        <div id="output"></div>
    `);
}

// ============================================================================
// PART 4: Context-Specific XSS Patterns
// ============================================================================

// 4.1. HTML Body Context
function xss_context_html_body(req, res) {
    const content = req.query.content;
    // VULNERABLE: Direct insertion in HTML body
    res.send(`<body>${content}</body>`);
}

// 4.2. HTML Attribute Context
function xss_context_html_attribute(req, res) {
    const input = req.query.input;
    // VULNERABLE: Unquoted attribute
    res.send(`<div class=${input}>Content</div>`);
}

// 4.3. JavaScript String Context
function xss_context_js_string(req, res) {
    const value = req.query.value;
    // VULNERABLE: JS string without escaping quotes
    res.send(`<script>var value = "${value}";</script>`);
}

// 4.4. URL Context
function xss_context_url(req, res) {
    const redirect = req.query.redirect;
    // VULNERABLE: URL in location
    res.send(`<script>window.location = "${redirect}";</script>`);
}

// 4.5. CSS Context
function xss_context_css(req, res) {
    const style = req.query.style;
    // VULNERABLE: CSS expression
    res.send(`<div style="background: ${style}"></div>`);
}

// ============================================================================
// PART 5: Filter Evasion Patterns
// ============================================================================

// 5.1. Case Variation
function xss_filter_case(req, res) {
    const userInput = req.query.input;
    // VULNERABLE: Case variations bypass simple filters
    res.send(`<script>${userInput}</script>`);
}

// 5.2. Encoding Evasion
function xss_filter_encoding(req, res) {
    const userInput = req.query.input;
    // VULNERABLE: Hex/unicode encoding
    res.send(`<img src=x onerror="alert('${userInput}')">`);
}

// 5.3. Tag Closure Bypass
function xss_filter_closure(req, res) {
    const userInput = req.query.text;
    // VULNERABLE: Closing previous tag
    res.send(`<img src="${userInput}">`);
}

// 5.4. Comment Bypass
function xss_filter_comment(req, res) {
    const userInput = req.query.payload;
    // VULNERABLE: Using comments to hide script tags
    res.send(`<!-- ${userInput} -->`);
}

// 5.5. Null Bytes
function xss_filter_null_bytes(req, res) {
    const userInput = req.query.input;
    // VULNERABLE: Null byte bypass
    res.send(`<img src=x onerror="${userInput}\x00">`);
}

// ============================================================================
// PART 6: Safe Patterns - Precision Testing
// ============================================================================

// 6.1. Using textContent (DOM XSS safe)
function xss_safe_textcontent(req, res) {
    const userInput = req.query.content;

    // SAFE: textContent treats input as text, not HTML
    res.send(`
        <script>
            document.getElementById('content').textContent = '${userInput}';
        </script>
        <div id="content"></div>
    `);
}

// 6.2. HTML Entity Encoding
function xss_safe_entity_encode(req, res) {
    const userInput = req.query.name;

    // SAFE: HTML entity encoding
    const encoded = encodeURIComponent(userInput);
    res.send(`<h1>Hello ${encoded}</h1>`);
}

// 6.3. Using a Sanitization Library
function xss_safe_sanitizer(req, res) {
    const sanitizeHtml = require('sanitize-html');
    const userInput = req.query.content;

    // SAFE: Using dedicated sanitizer
    const safe = sanitizeHtml(userInput);
    res.send(`<div>${safe}</div>`);
}

// 6.4. Template Engine with Auto-escaping
function xss_safe_template_engine(req, res) {
    const userInput = req.query.name;

    // SAFE: EJS auto-escapes by default
    res.render('template', { name: userInput });
}

// 6.5. Proper Context-Aware Escaping
function xss_safe_context_aware(req, res) {
    const userInput = req.query.value;

    // SAFE: Escape quotes for JS context
    const safe = userInput.replace(/'/g, "\\'").replace(/"/g, '\\"');
    res.send(`<script>const value = "${safe}";</script>`);
}

// 6.6. Content Security Policy (CSP) Mitigation
function xss_safe_csp(req, res) {
    const userInput = req.query.content;

    // SAFE: CSP mitigates XSS (though code is still vulnerable)
    res.set('Content-Security-Policy', "script-src 'self'");
    res.send(`<script>alert('${userInput}')</script>`);
}

// 6.7. HttpOnly Cookie (Prevents session theft)
function xss_safe_httponly(req, res) {
    const userInput = req.query.session;

    // SAFE: HttpOnly cookie not accessible via XSS
    res.cookie('session', userInput, { httpOnly: true });
    res.send('Cookie set');
}

// 6.8. Attribute Value Encoding
function xss_safe_attribute_encode(req, res) {
    const userInput = req.query.value;

    // SAFE: HTML entity encode for attributes
    const safe = userInput
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');

    res.send(`<input value="${safe}">`);
}

// 6.9. URL Validation
function xss_safe_url_validation(req, res) {
    const userInput = req.query.url;
    const url = new URL(userInput);

    // SAFE: Validate URL protocol
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
        return res.status(400).send('Invalid URL');
    }

    res.send(`<a href="${userInput}">Link</a>`);
}

// 6.10. Whitelist Validation
function xss_safe_whitelist(req, res) {
    const userInput = req.query.color;
    const allowedColors = ['red', 'green', 'blue', 'black', 'white'];

    // SAFE: Whitelist validation
    if (!allowedColors.includes(userInput)) {
        return res.status(400).send('Invalid color');
    }

    res.send(`<div style="color: ${userInput}">Text</div>`);
}

// ============================================================================
// PART 7: Real-World Application Patterns
// ============================================================================

// 7.1. Search Functionality
function xss_realworld_search(req, res) {
    const query = req.query.q;

    // VULNERABLE: Display search query in results
    res.render('search', {
        query,
        results: searchDatabase(query)
    });
}

function searchDatabase(query) {
    return []; // Mock search
}

// 7.2. Error Page with User Input
function xss_realworld_error(req, res) {
    const errorMessage = req.query.error;

    // VULNERABLE: Display error message
    res.render('error', { errorMessage });
}

// 7.3. User Profile Page
function xss_realworld_profile(req, res) {
    const userId = req.params.id;
    const user = db.users.findById(userId);

    // VULNERABLE: Display user data
    res.render('profile', { user });
}

// 7.4. Comment System
function xss_realworld_comments(req, res) {
    const postId = req.params.id;
    const comments = db.comments.findByPostId(postId);

    // VULNERABLE: Display comments
    res.render('post', { comments });
}

// 7.5. Redirect Functionality
function xss_realworld_redirect(req, res) {
    const next = req.query.next;

    // VULNERABLE: Open redirect leading to XSS
    res.redirect(next);
}

// 7.6. File Upload with Filename
function xss_realworld_filename(req, res) {
    const file = req.file;
    const filename = file.originalname;

    // VULNERABLE: Display filename
    res.render('upload', { filename });
}

// 7.7. Social Media Status Update
function xss_realworld_status(req, res) {
    const status = req.body.status;

    // VULNERABLE: Store and display status
    db.users.updateStatus(req.user.id, status);
    res.redirect('/profile');
}

// 7.8. Chat Application
function xss_realworld_chat(req, res) {
    const message = req.body.message;

    // VULNERABLE: WebSocket or HTTP chat message
    chat.broadcast({
        user: req.user.username,
        message
    });

    res.json({ success: true });
}

// 7.9. Email Preview
function xss_realworld_email(req, res) {
    const emailId = req.params.id;
    const email = db.emails.findById(emailId);

    // VULNERABLE: Display email content
    res.render('email', { email });
}

// 7.10. Form Autocomplete
function xss_realworld_autocomplete(req, res) {
    const term = req.query.term;

    // VULNERABLE: Return unsanitized suggestions
    const suggestions = db.suggestions.search(term);
    res.json({ suggestions });
}

// ============================================================================
// PART 8: Complex Flow Scenarios
// ============================================================================

// 8.1. Flow Through Multiple Functions
function xss_flow_multi_function(req, res) {
    const name = req.query.name;
    const formatted = formatName(name);
    const decorated = decorateName(formatted);

    res.send(`<h1>${decorated}</h1>`);
}

function formatName(name) {
    return name.trim();
}

function decorateName(name) {
    return `<strong>${name}</strong>`;
}

// 8.2. Flow Through Object Properties
function xss_flow_object(req, res) {
    const data = req.query;

    res.send(`
        <h1>${data.title}</h1>
        <p>${data.content}</p>
    `);
}

// 8.3. Flow Through Array Operations
function xss_flow_array(req, res) {
    const items = req.query.items;

    items.forEach(item => {
        res.write(`<div>${item}</div>`);
    });
    res.end();
}

// 8.4. Flow Through Conditional Logic
function xss_flow_conditional(req, res) {
    const message = req.query.message;
    const isAdmin = req.query.admin === 'true';

    if (isAdmin) {
        res.send(`<div class="admin">${message}</div>`);
    } else {
        res.send(`<div class="user">${message}</div>`);
    }
}

// 8.5. Flow Through Loops with Sanitization Attempt
function xss_flow_loop_sanitized(req, res) {
    const inputs = req.query.inputs;

    inputs.forEach(input => {
        // Broken sanitization - only replaces first <script>
        const sanitized = input.replace('<script>', '');
        res.write(`<div>${sanitized}</div>`);
    });
    res.end();
}

// ============================================================================
// PART 9: Framework-Specific Patterns
// ============================================================================

// 9.1. Express.js - res.send()
function xss_express_send(req, res) {
    const content = req.query.content;

    // VULNERABLE: Express doesn't escape by default
    res.send(`<div>${content}</div>`);
}

// 9.2. Express.js - res.json()
function xss_express_json(req, res) {
    const data = {
        content: req.query.content
    };

    // VULNERABLE: JSON consumed by eval or similar in client
    res.json(data);
}

// 9.3. Express.js - res.render() with unsafe locals
function xss_express_render(req, res) {
    const content = req.query.content;

    // VULNERABLE: Template with unsafe locals
    res.render('template', { content });
}

// 9.4. Next.js - dangerouslySetInnerHTML
function xss_nextjs_dangerous(req, res) {
    const html = req.query.html;

    // VULNERABLE: Using dangerouslySetInnerHTML
    res.send(`
        <div dangerouslySetInnerHTML={{ __html: '${html}' }}></div>
    `);
}

// 9.5. React - dangerouslySetInnerHTML pattern
function xss_react_dangerous(req, res) {
    const html = req.query.html;

    // VULNERABLE: React dangerouslySetInnerHTML
    res.send(`
        <script>
            ReactDOM.createRoot(document.getElementById('root')).render(
                React.createElement('div', {
                    dangerouslySetInnerHTML: { __html: '${html}' }
                })
            );
        </script>
        <div id="root"></div>
    `);
}

// ============================================================================
// PART 10: Advanced XSS Techniques
// ============================================================================

// 10.1. Self-XSS via localStorage
function xss_self_localstorage(req, res) {
    const stored = localStorage.getItem('user_input');

    res.send(`
        <script>
            const data = '${stored}';
            document.write(data);
        </script>
    `);
}

// 10.2. XSS via URL Fragment
function xss_url_fragment(req, res) {
    res.send(`
        <script>
            window.onload = function() {
                const fragment = window.location.hash.substring(1);
                document.getElementById('output').innerHTML = fragment;
            }
        </script>
        <div id="output"></div>
    `);
}

// 10.3. XSS via PostMessage
function xss_postmessage_child(req, res) {
    res.send(`
        <script>
            window.addEventListener('message', function(event) {
                document.body.innerHTML = event.data;
            });
        </script>
    `);
}

// 10.4. XSS via WebSocket
function xss_websocket(req, res) {
    res.send(`
        <script>
            const ws = new WebSocket('ws://localhost:8080');
            ws.onmessage = function(event) {
                document.body.innerHTML += event.data;
            };
        </script>
    `);
}

// 10.5. XSS via JSONP
function xss_jsonp(req, res) {
    const callback = req.query.callback;
    const data = { message: 'test' };

    // VULNERABLE: JSONP callback with user input
    res.send(`${callback}(${JSON.stringify(data)})`);
}

// 10.6. Clickjacking + XSS
function xss_clickjacking(req, res) {
    const content = req.query.content;

    res.send(`
        <div style="position:absolute;opacity:0.0">
            ${content}
        </div>
        <button>Click me</button>
    `);
}

// 10.7. XSS via SVG
function xss_svg(req, res) {
    const payload = req.query.payload;

    res.send(`
        <svg xmlns="http://www.w3.org/2000/svg">
            <text onload="${payload}">Test</text>
        </svg>
    `);
}

// 10.8. CSS Expression (IE)
function xss_css_expression(req, res) {
    const color = req.query.color;

    res.send(`<div style="background-color: expression('${color}')"></div>`);
}

// 10.9. Data URI XSS
function xss_data_uri(req, res) {
    const html = req.query.html;

    res.send(`
        <iframe src="data:text/html;charset=utf-8,${html}"></iframe>
    `);
}

// 10.10. Meta Refresh XSS
function xss_meta_refresh(req, res) {
    const url = req.query.url;

    res.send(`<meta http-equiv="refresh" content="0; url='${url}'">`);
}

module.exports = {
    // Part 1: Reflected XSS
    xss_reflected_simple_concat,
    xss_reflected_template_literal,
    xss_reflected_multi_point,
    xss_reflected_attribute,
    xss_reflected_event_handler,
    xss_reflected_script_context,
    xss_reflected_url,
    xss_reflected_style,
    xss_reflected_src,
    xss_reflected_iframe,

    // Part 2: Stored XSS
    xss_stored_comment,
    xss_stored_profile,
    xss_stored_message,

    // Part 3: DOM-based XSS
    xss_dom_innerhtml,
    xss_dom_write,
    xss_dom_eval,
    xss_dom_settimeout,
    xss_dom_location_hash,
    xss_dom_location_search,
    xss_dom_postmessage,

    // Part 4: Context-Specific
    xss_context_html_body,
    xss_context_html_attribute,
    xss_context_js_string,
    xss_context_url,
    xss_context_css,

    // Part 5: Filter Evasion
    xss_filter_case,
    xss_filter_encoding,
    xss_filter_closure,
    xss_filter_comment,
    xss_filter_null_bytes,

    // Part 6: Safe Patterns
    xss_safe_textcontent,
    xss_safe_entity_encode,
    xss_safe_sanitizer,
    xss_safe_template_engine,
    xss_safe_context_aware,
    xss_safe_csp,
    xss_safe_httponly,
    xss_safe_attribute_encode,
    xss_safe_url_validation,
    xss_safe_whitelist,

    // Part 7: Real-World Patterns
    xss_realworld_search,
    searchDatabase,
    xss_realworld_error,
    xss_realworld_profile,
    xss_realworld_comments,
    xss_realworld_redirect,
    xss_realworld_filename,
    xss_realworld_status,
    xss_realworld_chat,
    xss_realworld_email,
    xss_realworld_autocomplete,

    // Part 8: Complex Flow
    xss_flow_multi_function,
    formatName,
    decorateName,
    xss_flow_object,
    xss_flow_array,
    xss_flow_conditional,
    xss_flow_loop_sanitized,

    // Part 9: Framework-Specific
    xss_express_send,
    xss_express_json,
    xss_express_render,
    xss_nextjs_dangerous,
    xss_react_dangerous,

    // Part 10: Advanced Techniques
    xss_self_localstorage,
    xss_url_fragment,
    xss_postmessage_child,
    xss_websocket,
    xss_jsonp,
    xss_clickjacking,
    xss_svg,
    xss_css_expression,
    xss_data_uri,
    xss_meta_refresh
};
