// Comprehensive JWT Manipulation Benchmarks
// Covers JSON Web Token security issues and bypasses

const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// ============================================================================
// PART 1: None Algorithm (alg=none) Attacks
// ============================================================================

function jwt_none_algorithm(req) {
    const token = req.cookies.jwt;
    // VULNERABLE: Accepts "none" algorithm
    const decoded = jwt.verify(token, 'secret', { algorithms: ['none', 'HS256'] });
    if (decoded.admin) {
        return 'admin_access';
    }
}

function jwt_none_algorithm_bypass(req) {
    const header = {
        alg: 'none',
        typ: 'JWT'
    };
    const payload = { admin: true, user: req.user.id };
    // VULNERABLE: Manually crafting JWT with none algorithm
    const token = jwt.sign(payload, 'secret', { header });
    return token;
}

function jwt_algorithm_confusion(req) {
    const token = req.cookies.jwt;
    // VULNERABLE: Algorithm confusion (HS256 vs RS256)
    const publicKey = getPublicKey();
    try {
        // Attacker signs with HS256 but claims RS256
        const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
        return decoded;
    } catch (error) {
        // If HS256 used with public key, verification fails
        const decoded = jwt.verify(token, 'sharedSecret', { algorithms: ['HS256'] });
        return decoded;
    }
}

// ============================================================================
// PART 2: Weak Secret / Key Issues
// ============================================================================

function jwt_weak_secret(req) {
    const password = req.body.password;
    // VULNERABLE: Hardcoded weak secret
    const token = jwt.sign({ user: req.user.id }, 'weak_password_123');
    return token;
}

function jwt_secret_disclosure(req) {
    const userId = req.body.userId;
    // VULNERABLE: Secret exposed in response
    const token = jwt.sign({ userId }, process.env.JWT_SECRET);
    res.json({ token, secret: process.env.JWT_SECRET }); // Leaks secret
}

function jwt_predictable_secret(req) {
    const userId = req.body.userId;
    // VULNERABLE: Secret derived from user info
    const secret = userId + '_secret_key_2024';
    const token = jwt.sign({ userId }, secret);
    return token;
}

// ============================================================================
// PART 3: Token Issues
// ============================================================================

function jwt_no_expiration(req) {
    const userId = req.body.userId;
    // VULNERABLE: JWT never expires
    const token = jwt.sign({ userId, admin: false }, 'secret');
    return token;
}

function jwt_long_expiration(req) {
    const userId = req.body.userId;
    // VULNERABLE: Expiration time too long (years)
    const token = jwt.sign({ userId }, 'secret', { expiresIn: '10y' });
    return token;
}

function jwt_expiration_bypass(req) {
    const token = req.cookies.jwt;
    // VULNERABLE: Ignoring expiration check
    const decoded = jwt.decode(token); // decode without verify
    if (decoded.userId) {
        return 'access_granted';
    }
}

// ============================================================================
// PART 4: Payload Manipulation
// ============================================================================

function jwt_role_escalation(req) {
    const token = req.cookies.jwt;
    // VULNERABLE: Role claim manipulation
    const decoded = jwt.verify(token, 'secret');
    if (decoded.role === 'admin') {
        return 'admin_dashboard';
    }
}

function jwt_missing_critical_claims(req) {
    const token = req.cookies.jwt;
    // VULNERABLE: Missing critical claims (iss, aud, jti)
    const decoded = jwt.verify(token, 'secret');
    if (!decoded.iss || !decoded.aud) {
        // No issuer/audience validation
        return decoded;
    }
}

function jwt_jti_reuse(req) {
    const userId = req.body.userId;
    // VULNERABLE: Reusing JWT ID (jti) allows replay
    const jti = 'static-jti-value'; // Should be unique per token
    const token = jwt.sign({ userId }, 'secret', { jwtid: jti });
    return token;
}

// ============================================================================
// PART 5: Signature Forgery
// ============================================================================

function jwt_weak_signing_key(req) {
    const userId = req.body.userId;
    // VULNERABLE: Key derived from public info
    const key = md5(userId + 'salt'); // Weak key generation
    const token = jwt.sign({ userId, admin: true }, key);
    return token;
}

function jwt_key_confusion(req) {
    const token = req.cookies.jwt;
    // VULNERABLE: Using wrong key for verification
    const wrongKey = 'wrong_secret';
    const correctKey = process.env.JWT_SECRET;
    try {
        jwt.verify(token, wrongKey);
    } catch (error) {
        // Fallback to correct key allows forgery
        const decoded = jwt.verify(token, correctKey);
        return decoded;
    }
}

function jwt_algorithm_none_with_signature(req) {
    const payload = { admin: true, user: req.user.id };
    // VULNERABLE: Adding signature with none algorithm
    const header = { alg: 'none' };
    const signature = 'signature'; // Ignored due to none algorithm
    const token = `${base64(header)}.${base64(payload)}.${signature}`;
    return token;
}

// ============================================================================
// PART 6: Header Manipulation
// ============================================================================

function jwt_header_injection(req) {
    const payload = { user: req.user.id };
    // VULNERABLE: Custom header injection
    const header = {
        alg: 'HS256',
        typ: 'JWT',
        injected: req.headers['x-custom-header'] // Tainted header
    };
    const token = jwt.sign(payload, 'secret', { header });
    return token;
}

function jwt_keyid_confusion(req) {
    const payload = { user: req.user.id };
    const keyid = req.query.keyid;
    // VULNERABLE: kid (key ID) from user input
    const header = {
        alg: 'HS256',
        kid: keyid // Select attacker-controlled key
    };
    const token = jwt.sign(payload, 'secret', { header });
    return token;
}

function jwt_critical_algorithm(req) {
    const payload = { user: req.user.id };
    // VULNERABLE: Critical algorithm (RSA with small key size)
    const header = {
        alg: 'RS256',
        'crit': ['exp', 'sub', 'nbf']
    };
    const token = jwt.sign(payload, getWeakRSAPrivateKey(), { header });
    return token;
}

// ============================================================================
// PART 7: Decoding Issues
// ============================================================================

function jwt_decode_without_verify(req) {
    const token = req.cookies.jwt;
    // VULNERABLE: Decoding without signature verification
    const decoded = jwt.decode(token); // No verification!
    if (decoded.admin) {
        return 'admin_access';
    }
}

function jwt_base64_decode_manipulation(req) {
    const token = req.cookies.jwt;
    // VULNERABLE: Manual base64 manipulation
    const parts = token.split('.');
    const payload = Buffer.from(parts[1], 'base64').toString('utf8');
    const modifiedPayload = JSON.parse(payload);
    modifiedPayload.admin = true;
    const newPayload = Buffer.from(JSON.stringify(modifiedPayload)).toString('base64');
    const forgedToken = `${parts[0]}.${newPayload}.${parts[2]}`;
    return forgedToken;
}

// ============================================================================
// PART 8: Real-World JWT Attacks
// ============================================================================

function jwt_blind_token(req) {
    const token = req.cookies.jwt;
    // VULNERABLE: Blind token without verification
    // Some apps just check token exists
    if (token) {
        return getSession(token);
    }
}

function jwt_jti_bypass(req) {
    const userId = req.body.userId;
    // VULNERABLE: Not validating JWT ID (jti)
    const jti = userId + '-jti';
    const token = jwt.sign({ userId, jti }, 'secret');
    return token;
}

function jwt_issuer_bypass(req) {
    const token = req.cookies.jwt;
    // VULNERABLE: Not validating issuer (iss) claim
    const decoded = jwt.verify(token, 'secret');
    // Accepts tokens from any issuer
    return decoded;
}

function jwt_audience_bypass(req) {
    const token = req.cookies.jwt;
    // VULNERABLE: Not validating audience (aud) claim
    const decoded = jwt.verify(token, 'secret');
    // Accepts tokens for any audience
    return decoded;
}

// ============================================================================
// PART 9: Safe Patterns - Precision Testing
// ============================================================================

function jwt_safe_strong_algorithm(req) {
    const userId = req.body.userId;
    // SAFE: Strong algorithm (RS256 with 2048-bit key)
    const privateKey = getStrongRSAPrivateKey();
    const token = jwt.sign({ userId }, privateKey, { algorithm: 'RS256' });
    return token;
}

function jwt_safe_verify_signature(req) {
    const token = req.cookies.jwt;
    // SAFE: Proper signature verification
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded.userId) {
        throw new Error('Invalid token');
    }
    return decoded;
}

function jwt_safe_check_expiration(req) {
    const token = req.cookies.jwt;
    // SAFE: Check expiration
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
        maxAge: 3600 // 1 hour max
    });
    return decoded;
}

function jwt_safe_validate_issuer(req) {
    const token = req.cookies.jwt;
    // SAFE: Validate issuer
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
        issuer: 'https://example.com'
    });
    return decoded;
}

function jwt_safe_validate_audience(req) {
    const token = req.cookies.jwt;
    // SAFE: Validate audience
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
        audience: 'https://api.example.com'
    });
    return decoded;
}

function jwt_safe_strong_secret(req) {
    const userId = req.body.userId;
    // SAFE: Strong secret from environment
    const secret = process.env.JWT_SECRET; // Not hardcoded
    const token = jwt.sign({ userId }, secret);
    return token;
}

function jwt_safe_unique_jti(req) {
    const userId = req.body.userId;
    // SAFE: Unique JWT ID per token
    const jti = crypto.randomBytes(16).toString('hex');
    const token = jwt.sign({ userId }, 'secret', { jwtid: jti });
    return token;
}

module.exports = {
    // Part 1: None Algorithm
    jwt_none_algorithm,
    jwt_none_algorithm_bypass,
    jwt_algorithm_confusion,

    // Part 2: Weak Secret
    jwt_weak_secret,
    jwt_secret_disclosure,
    jwt_predictable_secret,

    // Part 3: Token Issues
    jwt_no_expiration,
    jwt_long_expiration,
    jwt_expiration_bypass,

    // Part 4: Payload Manipulation
    jwt_role_escalation,
    jwt_missing_critical_claims,
    jwt_jti_reuse,

    // Part 5: Signature Forgery
    jwt_weak_signing_key,
    jwt_key_confusion,
    jwt_algorithm_none_with_signature,

    // Part 6: Header Manipulation
    jwt_header_injection,
    jwt_keyid_confusion,
    jwt_critical_algorithm,

    // Part 7: Decoding Issues
    jwt_decode_without_verify,
    jwt_base64_decode_manipulation,

    // Part 8: Real-World
    jwt_blind_token,
    jwt_jti_bypass,
    jwt_issuer_bypass,
    jwt_audience_bypass,

    // Part 9: Safe Patterns
    jwt_safe_strong_algorithm,
    jwt_safe_verify_signature,
    jwt_safe_check_expiration,
    jwt_safe_validate_issuer,
    jwt_safe_validate_audience,
    jwt_safe_strong_secret,
    jwt_safe_unique_jti
};
