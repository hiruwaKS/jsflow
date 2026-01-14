// Comprehensive CSRF Benchmarks (CWE-352)
// Covers Cross-Site Request Forgery attacks and defenses

const express = require('express');
const cookieParser = require('cookie-parser');

// ============================================================================
// PART 1: Basic CSRF Vulnerabilities
// ============================================================================

function csrf_vulnerable_no_token(req, res) {
    const action = req.body.action;
    const amount = req.body.amount;
    // VULNERABLE: No CSRF protection at all
    // Attacker can trick victim into making this request
    performTransfer(action, amount);
    res.json({ success: true });
}

function csrf_vulnerable_state_change(req, res) {
    const newEmail = req.body.email;
    // VULNERABLE: State-changing request without CSRF protection
    updateEmail(req.user.id, newEmail);
    res.json({ success: true });
}

function csrf_vulnerable_password_change(req, res) {
    const newPassword = req.body.password;
    // VULNERABLE: Password change without CSRF protection
    changePassword(req.user.id, newPassword);
    res.json({ success: true });
}

// ============================================================================
// PART 2: Token-Based Defenses Bypasses
// ============================================================================

function csrf_cookie_token_no_origin(req, res) {
    const token = req.body.csrf_token;
    const cookieToken = req.cookies.csrf_token;
    // VULNERABLE: Token in cookie but no origin validation
    // Attacker can set cookie via subdomain, XSS, etc.
    if (token === cookieToken) {
        performAction(req.body);
        res.json({ success: true });
    }
}

function csrf_header_token_no_origin(req, res) {
    const token = req.headers['x-csrf-token'];
    const sessionToken = req.session.csrfToken;
    // VULNERABLE: Header token but no origin validation
    if (token === sessionToken) {
        performAction(req.body);
        res.json({ success: true });
    }
}

function csrf_weak_token_predictable(req, res) {
    const token = req.body.csrf_token;
    const sessionToken = req.session.csrfToken;
    // VULNERABLE: Predictable CSRF tokens (timestamp-based)
    // Token might be: Date.now() or similar
    if (token === sessionToken) {
        performAction(req.body);
        res.json({ success: true });
    }
}

function csrf_token_reuse(req, res) {
    const token = req.body.csrf_token;
    // VULNERABLE: CSRF tokens not rotated
    // Same token used for entire session
    if (token === req.session.csrfToken) {
        performAction(req.body);
        res.json({ success: true });
    }
}

// ============================================================================
// PART 3: SameSite Cookie Bypass
// ============================================================================

function csrf_samesite_none(req, res) {
    res.cookie('session', sessionId, {
        sameSite: 'none',
        secure: false
    });
    // VULNERABLE: SameSite=None allows CSRF
    res.json({ success: true });
}

function csrf_no_samesite(req, res) {
    res.cookie('session', sessionId, {
        // VULNERABLE: No SameSite attribute
        secure: false
    });
    res.json({ success: true });
}

function csrf_samesite_lax_on_get(req, res) {
    // VULNERABLE: SameSite=Lax vulnerable on GET requests
    const action = req.query.action;
    if (action === 'change_password') {
        changePassword(req.user.id, req.body.newPassword);
    }
    res.json({ success: true });
}

// ============================================================================
// PART 4: Origin/Referer Bypasses
// ============================================================================

function csrf_weak_origin_check(req, res) {
    const origin = req.headers.origin;
    // VULNERABLE: Weak origin check (partial match)
    if (origin && origin.includes('example.com')) {
        performAction(req.body);
        res.json({ success: true });
    }
}

function csrf_referer_only(req, res) {
    const referer = req.headers.referer;
    // VULNERABLE: Only checking Referer header
    // Can be bypassed via meta refresh, etc.
    if (referer && referer.startsWith('https://example.com')) {
        performAction(req.body);
        res.json({ success: true });
    }
}

function csrf_missing_origin_header(req, res) {
    // VULNERABLE: No Origin header on cross-origin requests
    // Some browsers don't send Origin on same-site POST
    if (!req.headers.origin) {
        // Might be same-site, but not CSRF-protected
        performAction(req.body);
        res.json({ success: true });
    }
}

// ============================================================================
// PART 5: JSONP CSRF
// ============================================================================

function jsonp_csrf_vulnerable(req, res) {
    const callback = req.query.callback;
    const action = req.query.action;
    const amount = req.query.amount;
    // VULNERABLE: JSONP can be used for CSRF
    res.send(`${callback}({ success: true, action: '${action}', amount: ${amount} })`);
}

function jsonp_sensitive_action(req, res) {
    const callback = req.query.callback;
    const data = req.query;
    // VULNERABLE: Sensitive action via JSONP
    deleteAccount(data.userId);
    res.send(`${callback}({ deleted: true })`);
}

function jsonp_no_callback_validation(req, res) {
    const callback = req.query.callback;
    const action = req.query.action;
    // VULNERABLE: No callback validation (XSS + CSRF)
    const sanitized = callback.replace(/[^\w.]/g, '');
    res.send(`${sanitized}({ action: '${action}' })`);
}

// ============================================================================
// PART 6: GET CSRF
// ============================================================================

function get_csrf_vulnerable(req, res) {
    const action = req.query.action;
    const newEmail = req.query.email;
    // VULNERABLE: CSRF via GET request
    // More easily exploitable (img tag, script tag, etc.)
    updateEmail(req.user.id, newEmail);
    res.redirect('/account');
}

function get_csrf_state_change(req, res) {
    const deleteAccount = req.query.delete;
    // VULNERABLE: Dangerous action via GET
    if (deleteAccount === 'true') {
        deleteAccount(req.user.id);
        res.redirect('/home');
    }
}

function get_csrf_file_upload(req, res) {
    const fileUrl = req.query.file;
    // VULNERABLE: File upload via GET (unusual but possible)
    const fileContent = fetchFile(fileUrl);
    res.send('File uploaded');
}

// ============================================================================
// PART 7: Advanced CSRF Vectors
// ============================================================================

function csrf_via_file_upload(req, res) {
    const file = req.file;
    // VULNERABLE: CSRF via multipart/form-data
    // Some browsers allow file upload POSTs without same-site cookie restrictions
    if (file) {
        processFile(file);
        res.json({ success: true });
    }
}

function csrf_timing_attack(req, res) {
    const timestamp = Date.now();
    const token = generateToken(timestamp);
    // VULNERABLE: Timing-based token prediction
    if (req.body.token === token) {
        performAction(req.body);
        res.json({ success: true });
    }
}

function csrf_cookie_tossing(req, res) {
    const sessionCookie = req.cookies.session;
    // VULNERABLE: Cookie tossing via subdomain
    // Attacker can set cookie on victim's subdomain
    if (sessionCookie) {
        const session = decodeSession(sessionCookie);
        performAction(session.userId);
        res.json({ success: true });
    }
}

// ============================================================================
// PART 8: Safe Patterns - Precision Testing
// ============================================================================

function csrf_safe_double_submit(req, res) {
    const token = req.body.csrf_token;
    const sessionToken = req.session.csrfToken;
    const submitCount = req.session.submitCount || 0;
    // SAFE: Double-submit cookie pattern
    if (token !== sessionToken) {
        return res.status(403).send('Invalid CSRF token');
    }
    if (submitCount > 1) {
        return res.status(403).send('Form already submitted');
    }
    req.session.submitCount = submitCount + 1;
    performAction(req.body);
    res.json({ success: true });
}

function csrf_safe_origin_validation(req, res) {
    const origin = req.headers.origin;
    const allowedOrigins = ['https://example.com', 'https://www.example.com'];
    const token = req.body.csrf_token;
    // SAFE: Strict origin validation
    if (!allowedOrigins.includes(origin)) {
        return res.status(403).send('Invalid origin');
    }
    if (token !== req.session.csrfToken) {
        return res.status(403).send('Invalid CSRF token');
    }
    performAction(req.body);
    res.json({ success: true });
}

function csrf_safe_strict_samesite(req, res) {
    const token = req.body.csrf_token;
    // SAFE: Strict SameSite with CSRF token
    res.cookie('session', sessionId, {
        sameSite: 'strict',
        secure: true,
        httpOnly: true
    });
    if (token !== req.session.csrfToken) {
        return res.status(403).send('Invalid CSRF token');
    }
    performAction(req.body);
    res.json({ success: true });
}

function csrf_safe_referer_origin(req, res) {
    const origin = req.headers.origin;
    const referer = req.headers.referer;
    const token = req.body.csrf_token;
    const allowedOrigins = ['https://example.com'];
    // SAFE: Both origin and referer validation
    if (!origin || !referer) {
        return res.status(403).send('Missing origin/referer');
    }
    if (!allowedOrigins.includes(origin) ||
        !referer.startsWith('https://example.com')) {
        return res.status(403).send('Invalid origin/referer');
    }
    if (token !== req.session.csrfToken) {
        return res.status(403).send('Invalid CSRF token');
    }
    performAction(req.body);
    res.json({ success: true });
}

function csrf_safe_custom_header(req, res) {
    const customHeader = req.headers['x-requested-with'];
    const token = req.body.csrf_token;
    // SAFE: Custom header validation
    if (customHeader !== 'XMLHttpRequest') {
        return res.status(403).send('Missing custom header');
    }
    if (token !== req.session.csrfToken) {
        return res.status(403).send('Invalid CSRF token');
    }
    performAction(req.body);
    res.json({ success: true });
}

function csrf_safe_state_token(req, res) {
    const stateToken = req.body.state;
    const sessionState = req.session.state;
    const action = req.body.action;
    // SAFE: One-time state token (OAuth-like)
    if (stateToken !== sessionState || sessionState.used) {
        return res.status(403).send('Invalid or expired state token');
    }
    sessionState.used = true;
    performAction(action);
    res.json({ success: true });
}

function csrf_safe_jsonp_validation(req, res) {
    const callback = req.query.callback;
    const action = req.query.action;
    // SAFE: Validate callback and limit dangerous actions
    const safeCallback = callback.replace(/[^\w]/g, '');
    const allowedActions = ['getUser', 'getProfile'];
    if (!allowedActions.includes(action)) {
        return res.status(400).send('Invalid action');
    }
    res.send(`${safeCallback}({ data: getDataForAction(action) })`);
}

function csrf_safe_get_to_post_redirect(req, res) {
    const action = req.query.action;
    // SAFE: Convert GET to POST with CSRF protection
    if (action === 'change_password') {
        // Redirect to POST form with CSRF token
        const csrfToken = generateCSRFToken();
        res.redirect('/change_password?csrf_token=' + csrfToken);
        return;
    }
    res.status(400).send('Invalid action');
}

// ============================================================================
// PART 9: Real-World CSRF Scenarios
// ============================================================================

function real_world_password_reset_csrf(req, res) {
    const email = req.body.email;
    const newPassword = req.body.newPassword;
    // VULNERABLE: Password reset without CSRF protection
    if (!req.session.resetToken || req.session.resetToken !== req.body.token) {
        return res.status(400).send('Invalid token');
    }
    resetPassword(email, newPassword);
    res.json({ success: true });
}

function real_world_admin_action_csrf(req, res) {
    const action = req.body.action;
    const targetUser = req.body.userId;
    // VULNERABLE: Admin action without CSRF protection
    if (!req.user.isAdmin) {
        return res.status(403).send('Not admin');
    }
    performAdminAction(action, targetUser);
    res.json({ success: true });
}

function real_world_social_media_like(req, res) {
    const postId = req.body.postId;
    // VULNERABLE: Social media action without CSRF
    likePost(req.user.id, postId);
    res.json({ success: true });
}

function real_world_e_commerce_add_cart(req, res) {
    const productId = req.body.productId;
    const quantity = req.body.quantity;
    // VULNERABLE: E-commerce action without CSRF
    addToCart(req.user.id, productId, quantity);
    res.json({ success: true });
}

function real_world_payment_csrf(req, res) {
    const amount = req.body.amount;
    const recipient = req.body.recipient;
    // VULNERABLE: Payment without CSRF protection
    makePayment(req.user.id, recipient, amount);
    res.json({ success: true });
}

module.exports = {
    // Part 1: Basic Vulnerabilities
    csrf_vulnerable_no_token,
    csrf_vulnerable_state_change,
    csrf_vulnerable_password_change,

    // Part 2: Token Bypasses
    csrf_cookie_token_no_origin,
    csrf_header_token_no_origin,
    csrf_weak_token_predictable,
    csrf_token_reuse,

    // Part 3: SameSite
    csrf_samesite_none,
    csrf_no_samesite,
    csrf_samesite_lax_on_get,

    // Part 4: Origin/Referer
    csrf_weak_origin_check,
    csrf_referer_only,
    csrf_missing_origin_header,

    // Part 5: JSONP
    jsonp_csrf_vulnerable,
    jsonp_sensitive_action,
    jsonp_no_callback_validation,

    // Part 6: GET CSRF
    get_csrf_vulnerable,
    get_csrf_state_change,
    get_csrf_file_upload,

    // Part 7: Advanced Vectors
    csrf_via_file_upload,
    csrf_timing_attack,
    csrf_cookie_tossing,

    // Part 8: Safe Patterns
    csrf_safe_double_submit,
    csrf_safe_origin_validation,
    csrf_safe_strict_samesite,
    csrf_safe_referer_origin,
    csrf_safe_custom_header,
    csrf_safe_state_token,
    csrf_safe_jsonp_validation,
    csrf_safe_get_to_post_redirect,

    // Part 9: Real-World
    real_world_password_reset_csrf,
    real_world_admin_action_csrf,
    real_world_social_media_like,
    real_world_e_commerce_add_cart,
    real_world_payment_csrf
};
