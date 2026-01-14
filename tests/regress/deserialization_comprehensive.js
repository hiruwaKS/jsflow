// Comprehensive Deserialization Benchmarks (CWE-502)
// Covers unsafe deserialization in Node.js with multiple formats and patterns

const yaml = require('js-yaml');
const xml2js = require('xml2js');

// ============================================================================
// PART 1: JSON Deserialization
// ============================================================================

function json_parse_unsafe(req) {
    const jsonData = req.body.data;
    // VULNERABLE: Parsing untrusted JSON without validation
    const parsed = JSON.parse(jsonData);
    return parsed.user;
}

function json_parse_prototype_pollution(req) {
    const jsonData = req.body.data;
    // VULNERABLE: JSON.parse can pollute prototype
    const parsed = JSON.parse(jsonData);
    return parsed.isAdmin; // Polluted via {"__proto__": {"isAdmin": true}}
}

function json_parse_with_function(req) {
    const jsonData = req.body.data;
    // VULNERABLE: JSON can contain malicious values
    const parsed = JSON.parse(jsonData);
    if (typeof parsed.func === 'function') {
        parsed.func();
    }
}

function json_streaming_parse(req) {
    const jsonStream = req.body.stream;
    // VULNERABLE: Streaming JSON without validation
    const chunks = [];
    for await (const chunk of jsonStream) {
        const parsed = JSON.parse(chunk.toString());
        chunks.push(parsed);
    }
    return chunks;
}

// ============================================================================
// PART 2: YAML Deserialization (js-yaml)
// ============================================================================

function yaml_load_unsafe(req) {
    const yamlData = req.body.yaml;
    // VULNERABLE: Loading untrusted YAML
    const parsed = yaml.load(yamlData);
    return parsed.user;
}

function yaml_load_implicit_types(req) {
    const yamlData = req.body.yaml;
    // VULNERABLE: js-yaml uses implicit type conversion
    const parsed = yaml.load(yamlData);
    // Can execute arbitrary JS if !!js/function used
    return parsed;
}

function yaml_load_with_tags(req) {
    const yamlData = req.body.yaml;
    // VULNERABLE: Custom YAML tags can execute code
    const parsed = yaml.load(yamlData);
    return parsed;
}

function yaml_load_prototype_pollution(req) {
    const yamlData = req.body.yaml;
    // VULNERABLE: YAML can pollute prototype
    const parsed = yaml.load(yamlData);
    return parsed.isAdmin;
}

// ============================================================================
// PART 3: XML Deserialization (xxe)
// ============================================================================

function xml2js_parse_unsafe(req) {
    const xmlData = req.body.xml;
    // VULNERABLE: Parsing untrusted XML without options
    xml2js.parseString(xmlData, (err, result) => {
        if (err) throw err;
        return result;
    });
}

function xml2js_xxe(req) {
    const xmlData = req.body.xml;
    // VULNERABLE: XXE - reading external entity
    const maliciousXml = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>`;
    xml2js.parseString(maliciousXml, (err, result) => {
        return result;
    });
}

function xml2js_parameter_entity(req) {
    const entityFile = req.query.entity;
    // VULNERABLE: Parameter entity injection
    const maliciousXml = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "${entityFile}">]>
<root><data>&xxe;</data></root>`;
    xml2js.parseString(maliciousXml, (err, result) => {
        return result;
    });
}

// ============================================================================
// PART 4: Binary Deserialization
// ============================================================================

function msgpack_decode_unsafe(req) {
    const buffer = req.body.data;
    // VULNERABLE: Decoding untrusted msgpack
    const msgpack = require('msgpack-lite');
    const decoded = msgpack.decode(buffer);
    return decoded.user;
}

function protobuf_decode_unsafe(req) {
    const buffer = req.body.data;
    // VULNERABLE: Decoding untrusted protobuf
    const protobuf = require('protobufjs');
    const decoded = protobuf.decode(buffer);
    return decoded;
}

// ============================================================================
// PART 5: Advanced Serialization Formats
// ============================================================================

function node_cerialize_unsafe(req) {
    const buffer = req.body.data;
    // VULNERABLE: Node-serialize (CVE-2017-5941)
    const nodeSerialize = require('node-serialize');
    const obj = nodeSerialize.unserialize(buffer);
    return obj.user;
}

function superjson_unsafe(req) {
    const json = req.body.data;
    // VULNERABLE: superjson with dangerous functions
    const superjson = require('superjson');
    const parsed = superjson.parse(json);
    return parsed.user;
}

function bson_deserialize_unsafe(req) {
    const buffer = req.body.data;
    // VULNERABLE: BSON deserialization
    const bson = require('bson');
    const parsed = bson.deserialize(buffer);
    return parsed.user;
}

// ============================================================================
// PART 6: Object Injection Patterns
// ============================================================================

function object_merge_recursive(req) {
    const userConfig = req.body.config;
    const defaultConfig = {};
    // VULNERABLE: Recursive merge can pollute prototype
    function merge(target, source) {
        for (const key in source) {
            if (source[key] && typeof source[key] === 'object') {
                if (!target[key]) target[key] = {};
                merge(target[key], source[key]);
            } else {
                target[key] = source[key];
            }
        }
    }
    merge(defaultConfig, userConfig);
    return defaultConfig.isAdmin;
}

function object_assign_recursive(req) {
    const userConfig = req.body.config;
    const defaultConfig = {};
    // VULNERABLE: Recursive Object.assign
    Object.assign(defaultConfig, userConfig);
    return defaultConfig.isAdmin;
}

function lodash_merge_unsafe(req) {
    const userConfig = req.body.config;
    const defaultConfig = {};
    // VULNERABLE: Lodash merge (older versions vulnerable)
    const _ = require('lodash');
    const merged = _.merge(defaultConfig, userConfig);
    return merged.isAdmin;
}

// ============================================================================
// PART 7: Format-Specific Attacks
// ============================================================================

function json_cve_2017_9338(req) {
    const json = req.body.data;
    // VULNERABLE: Prototype pollution via __proto__
    const malicious = { "__proto__": { "isAdmin": true } };
    const merged = Object.assign({}, JSON.parse(json), malicious);
    return merged.isAdmin;
}

function yaml_cve_2017_7498(req) {
    const yamlData = req.body.yaml;
    // VULNERABLE: !!js/function in YAML
    const malicious = `
!!js/function >
(function() { require('child_process').exec('rm -rf /') })
`;
    const parsed = yaml.load(malicious);
    return parsed;
}

function node_serialize_cve_2017_5941(req) {
    const malicious = {
        username: "_$$ND_FUNC$$_function(){require('child_process').exec('rm -rf /')}"
    };
    // VULNERABLE: Function code execution via IIFE
    const nodeSerialize = require('node-serialize');
    const serialized = nodeSerialize.serialize(malicious);
    const deserialized = nodeSerialize.unserialize(serialized);
}

// ============================================================================
// PART 8: Safe Patterns - Precision Testing
// ============================================================================

function json_parse_schema_validation(req) {
    const jsonData = req.body.data;
    // SAFE: Schema validation before parsing
    const Ajv = require('ajv');
    const ajv = new Ajv();
    const schema = {
        type: 'object',
        properties: {
            user: { type: 'string' },
            isAdmin: { type: 'boolean' }
        },
        additionalProperties: false
    };

    const validate = ajv.compile(schema);
    const parsed = JSON.parse(jsonData);
    if (!validate(parsed)) {
        throw new Error('Invalid JSON');
    }

    return parsed;
}

function yaml_load_safe_options(req) {
    const yamlData = req.body.yaml;
    // SAFE: Disable dangerous YAML features
    const safeConfig = {
        schema: 'failsafe',
        json: true
    };
    const parsed = yaml.load(yamlData, safeConfig);
    return parsed;
}

function xml2js_safe_options(req) {
    const xmlData = req.body.xml;
    // SAFE: Disable external entities and DTDs
    const options = {
        explicitCharkey: false,
        trim: true,
        ignoreAttrs: false,
        mergeAttrs: false,
        explicitRoot: false,
        explicitArray: false,
        charkey: '@',
        tagNameProcessor: (name) => name,
        attrNameProcessor: (name) => name,
        valueProcessors: [],
        attrValueProcessors: [],
        tagNameProcessors: [],
        parseTrueNumberOnly: false,
        parseNodeValue: true,
        numParseOptions: null,
        attrValueProcessors: [],
        cdataPropName: '__cdata',
        explicitChildren: false,
        preserveChildrenOrder: false,
        charsAsChildren: false
    };
    xml2js.parseString(xmlData, options, (err, result) => {
        return result;
    });
}

function object_merge_safe(req) {
    const userConfig = req.body.config;
    const defaultConfig = {};
    // SAFE: Denylist dangerous keys
    function mergeSafe(target, source) {
        const dangerousKeys = ['__proto__', 'constructor', 'prototype'];
        for (const key in source) {
            if (dangerousKeys.includes(key)) continue;
            if (source[key] && typeof source[key] === 'object') {
                if (!target[key]) target[key] = {};
                mergeSafe(target[key], source[key]);
            } else {
                target[key] = source[key];
            }
        }
    }
    mergeSafe(defaultConfig, userConfig);
    return defaultConfig;
}

// ============================================================================
// PART 9: Real-World Deserialization Vulnerabilities
// ============================================================================

function cve_2017_5941_pattern(req) {
    const userData = req.body.user;
    // VULNERABLE: node-serialize IIFE execution
    const exploit = {
        rce: "_$$ND_FUNC$$_function(){require('child_process').exec('whoami')}"
    };
    const nodeSerialize = require('node-serialize');
    return nodeSerialize.serialize(exploit);
}

function cve_2017_7498_pattern(req) {
    const yamlConfig = req.body.yaml;
    // VULNERABLE: js-yaml function execution
    const malicious = `
function: !!js/function >
    (function() {
        const cp = require('child_process');
        cp.exec('id');
    })
`;
    const parsed = yaml.load(malicious);
}

function cve_2021_21300_pattern(req) {
    const userData = req.body;
    // VULNERABLE: Type confusion in parameterized queries
    // When deserialized object is used in query
    const parsed = JSON.parse(JSON.stringify(userData));
    // If parsed is array instead of object, causes confusion
    const id = Array.isArray(parsed) ? parsed : parsed.id;
    return id;
}

function real_world_session_deserialize(req) {
    const sessionData = req.body.session;
    // VULNERABLE: Session deserialization
    const parsed = JSON.parse(sessionData);
    if (parsed.isAdmin === true) {
        return 'admin_access';
    }
}

function real_world_cache_poison(req) {
    const cacheKey = req.query.key;
    const cacheData = req.body.data;
    // VULNERABLE: Cache deserialization
    const cached = JSON.parse(cacheData);
    if (cached.__proto__) {
        // Prototype pollution in cache
        return cached.__proto__.isAdmin;
    }
}

module.exports = {
    // Part 1: JSON
    json_parse_unsafe,
    json_parse_prototype_pollution,
    json_parse_with_function,
    json_streaming_parse,

    // Part 2: YAML
    yaml_load_unsafe,
    yaml_load_implicit_types,
    yaml_load_with_tags,
    yaml_load_prototype_pollution,

    // Part 3: XML
    xml2js_parse_unsafe,
    xml2js_xxe,
    xml2js_parameter_entity,

    // Part 4: Binary
    msgpack_decode_unsafe,
    protobuf_decode_unsafe,

    // Part 5: Advanced Formats
    node_cerialize_unsafe,
    superjson_unsafe,
    bson_deserialize_unsafe,

    // Part 6: Object Injection
    object_merge_recursive,
    object_assign_recursive,
    lodash_merge_unsafe,

    // Part 7: Format-Specific Attacks
    json_cve_2017_9338,
    yaml_cve_2017_7498,
    node_serialize_cve_2017_5941,

    // Part 8: Safe Patterns
    json_parse_schema_validation,
    yaml_load_safe_options,
    xml2js_safe_options,
    object_merge_safe,

    // Part 9: Real-World CVEs
    cve_2017_5941_pattern,
    cve_2017_7498_pattern,
    cve_2021_21300_pattern,
    real_world_session_deserialize,
    real_world_cache_poison
};
