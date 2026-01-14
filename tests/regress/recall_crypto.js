
// Recall Benchmarks: Crypto
// Covering cryptographic misuse and taint propagation in crypto operations.

const crypto = require('crypto');

// 1. Weak Hashing Algorithms
function testWeakHash(req) {
    const data = req.body.data;
    // Vulnerable: MD5 is considered weak for collision resistance
    const hash = crypto.createHash('md5');
    hash.update(data);
    return hash.digest('hex');
}

// 2. Weak Cipher Mode (ECB)
function testWeakCipher(req) {
    const data = req.body.data;
    const key = Buffer.alloc(32); // Hardcoded/Weak key handling separate issue, but here testing algo
    // Vulnerable: ECB mode is insecure
    const cipher = crypto.createCipheriv('aes-256-ecb', key, null);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

// 3. Insecure Randomness (Propagation Check)
function testPseudoRandom(req) {
    // Math.random() is not cryptographically secure
    // If used for security tokens, it's a vulnerability.
    const token = Math.random().toString(36); 
    // Sink: Returning weak token to user
    return { token: token };
}

// 4. Hardcoded Keys / Secrets (Taint Source)
function testHardcodedSecret(req) {
    // If this flows to a sink, it's a leak
    const secret = "super_secret_password_123";
    require('child_process').exec("echo " + secret); // Leak via command args
}

// 5. Taint Propagation through Encryption
function testEncryptionPropagation(req) {
    const cmd = req.body.cmd;
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    
    // Encrypt tainted data
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(cmd, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    // Decrypt it back
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    // Vulnerable: Taint should survive round-trip
    require('child_process').exec(decrypted);
}

// 6. Timing Attack (Side Channel) - Advanced
function testTimingSafe(req) {
    const userInput = req.body.token;
    const secret = "correct_token";
    
    // Vulnerable: String comparison leaks timing information
    if (userInput === secret) {
        return true;
    }
    
    // Safe: Constant time comparison
    const bufA = Buffer.from(userInput);
    const bufB = Buffer.from(secret);
    if (bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB)) {
        return true;
    }
}

module.exports = {
    testWeakHash,
    testWeakCipher,
    testPseudoRandom,
    testHardcodedSecret,
    testEncryptionPropagation,
    testTimingSafe
};
