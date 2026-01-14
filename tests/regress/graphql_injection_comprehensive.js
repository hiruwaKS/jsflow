// Comprehensive GraphQL Injection Benchmarks
// Covers NoSQL, authorization bypass, and introspection attacks in GraphQL

const { buildSchema, graphql } = require('graphql');

// ============================================================================
// PART 1: Basic GraphQL Injection Patterns
// ============================================================================

function graphql_string_concatenation(req) {
    const username = req.body.username;
    const password = req.body.password;
    // VULNERABLE: String concatenation in query
    const query = `query {
        user(username: "${username}", password: "${password}") {
            id
        }
    }`;
    return executeGraphQL(query);
}

function graphql_template_literal(req) {
    const field = req.query.field;
    // VULNERABLE: Template literal in query
    const query = `query { user { ${field} } }`;
    return executeGraphQL(query);
}

function graphql_dynamic_query(req) {
    const query = req.body.query;
    // VULNERABLE: User controls entire query
    return executeGraphQL(query);
}

// ============================================================================
// PART 2: NoSQL Injection in GraphQL
// ============================================================================

function graphql_nosql_operator_injection(req) {
    const username = req.body.username;
    // VULNERABLE: NoSQL operator injection ($ne, $gt, etc.)
    const query = `query { users(where: { username: { $ne: "${username}" } }) { id }`;
    return executeGraphQL(query);
}

function graphql_regex_injection(req) {
    const pattern = req.query.pattern;
    // VULNERABLE: Regex injection
    const query = `query { users(where: { username: { $regex: "${pattern}" } }) { id } }`;
    return executeGraphQL(query);
}

function graphql_in_operator_injection(req) {
    const username = req.body.username;
    // VULNERABLE: $in operator injection
    const query = `query { users(where: { username: { $in: ["${username}"] } }) { id } }`;
    return executeGraphQL(query);
}

// ============================================================================
// PART 3: GraphQL Introspection Attacks
// ============================================================================

function graphql_introspection_dump(req) {
    // VULNERABLE: Full schema introspection
    const query = `
        query {
            __schema {
                queryType { name, fields { name, type { name, fields { name } } } }
            }
        }
    `;
    return executeGraphQL(query);
}

function graphql_hidden_fields(req) {
    // VULNERABLE: Discover hidden internal fields
    const query = `query {
        __type(name: "User") {
            fields(includeDeprecated: true) {
                name
                isDeprecated
                deprecationReason
            }
        }
    }`;
    return executeGraphQL(query);
}

function graphql_directives(req) {
    // VULNERABLE: Enumerate directives
    const query = `query {
        __schema { directives { name, description } }
    }`;
    return executeGraphQL(query);
}

// ============================================================================
// PART 4: Authorization Bypass
// ============================================================================

function graphql_nested_mutation(req) {
    const userId = req.params.id;
    // VULNERABLE: IDOR via nested mutation
    const query = `mutation {
        updateUser(id: ${userId}, input: { email: "attacker@email.com" }) {
            email
        }
    }`;
    return executeGraphQL(query);
}

function graphql_alias_overwrite(req) {
    const targetUser = req.query.target;
    // VULNERABLE: Alias-based authorization bypass
    const query = `mutation {
        updateCurrent: updateUser(id: ${req.user.id}, input: { admin: true }) {
            admin
        }
        target: updateUser(id: ${targetUser}, input: { admin: true }) {
            admin
        }
    }`;
    const result = executeGraphQL(query);
    // Attacker updates victim as admin
    return result.target.admin;
}

function graphql_batch_attacks(req) {
    const operations = req.body.operations;
    // VULNERABLE: Batch operations for authorization bypass
    const query = operations.map(op => `
        mutation ${op.name} { ${op.field} }
    `).join('');
    return executeGraphQL(query);
}

// ============================================================================
// PART 5: Denial of Service (DoS)
// ============================================================================

function graphql_nested_query_dos(req) {
    const depth = parseInt(req.query.depth) || 10;
    // VULNERABLE: Deeply nested query
    const nested = ' { user '.repeat(depth);
    const query = `query${nested} { id }`;
    return executeGraphQL(query);
}

function graphql_field_dos(req) {
    // VULNERABLE: Requesting many fields
    const largeFields = Array(1000).fill('').map((_, i) => `field${i}: id`);
    const query = `query { user { ${largeFields.join(', ')} } }`;
    return executeGraphQL(query);
}

function graphql_circular_query(req) {
    // VULNERABLE: Circular reference in fragments
    const query = `
        query {
            user { friends { friends { friends { friends { id } } } } }
        }
    `;
    return executeGraphQL(query);
}

// ============================================================================
// PART 6: GraphQL IDOR and Information Disclosure
// ============================================================================

function graphql_idor_user_info(req) {
    const userId = req.params.id;
    // VULNERABLE: Direct object reference without auth check
    const query = `query { user(id: ${userId}) { email, passwordHash, ssn, creditCard } }`;
    return executeGraphQL(query);
}

function graphql_connection_idor(req) {
    const userId = req.query.userId;
    // VULNERABLE: Connection-based IDOR
    const query = `query { userConnection(first: 1) { edges { node { email } } } }`;
    return executeGraphQL(query);
}

function graphql_internal_error(req) {
    // VULNERABLE: Error message leaks internal info
    const query = `query { invalidType { nonexistentField } }`;
    const result = executeGraphQL(query);
    return result; // May expose internal schema
}

// ============================================================================
// PART 7: CSRF via GraphQL
// ============================================================================

function graphql_csrf_mutation(req) {
    const mutation = req.body.mutation;
    // VULNERABLE: CSRF via GraphQL mutation
    const query = `mutation { ${mutation} }`;
    return executeGraphQL(query);
}

function graphql_csrf_file_upload(req) {
    const uploadQuery = `
        mutation($file: Upload!) {
            singleUpload(file: $file) { id, filename }
        }
    `;
    // VULNERABLE: CSRF via file upload mutation
    return executeGraphQL(uploadQuery);
}

// ============================================================================
// PART 8: Safe Patterns - Precision Testing
// ============================================================================

function graphql_safe_parameterized(req) {
    const userId = req.params.id;
    // SAFE: Using variables (parameterized)
    const query = `query GetUser($userId: ID!) { user(id: $userId) { email } }`;
    return executeGraphQL(query, { userId });
}

function graphql_safe_whitelist_fields(req) {
    const allowedFields = ['id', 'username', 'email'];
    const requestedFields = req.body.fields;
    // SAFE: Whitelist validation of fields
    const validFields = requestedFields.filter(f => allowedFields.includes(f));
    const query = `query { user { ${validFields.join(', ')} } }`;
    return executeGraphQL(query);
}

function graphql_safe_depth_limit(req) {
    const query = req.body.query;
    // SAFE: Enforce query depth limit
    const maxDepth = 5;
    const depth = analyzeQueryDepth(query);
    if (depth > maxDepth) {
        throw new Error('Query too deep');
    }
    return executeGraphQL(query);
}

function graphql_safe_auth_check(req) {
    const userId = req.params.id;
    const currentUserId = req.user.id;
    // SAFE: Explicit authorization check
    if (userId !== currentUserId) {
        throw new Error('Unauthorized');
    }
    const query = `query GetUser($userId: ID!) { user(id: $userId) { email } }`;
    return executeGraphQL(query, { userId });
}

function graphql_safe_no_introspection(req) {
    const userQuery = req.body.query;
    // SAFE: Disable introspection in production
    if (process.env.NODE_ENV === 'production') {
        throw new Error('Introspection disabled');
    }
    return executeGraphQL(userQuery);
}

function graphql_safe_rate_limit(req) {
    const query = req.body.query;
    // SAFE: Rate limiting
    if (checkRateLimit(req.ip)) {
        throw new Error('Rate limit exceeded');
    }
    return executeGraphQL(query);
}

module.exports = {
    // Part 1: Basic Injection
    graphql_string_concatenation,
    graphql_template_literal,
    graphql_dynamic_query,

    // Part 2: NoSQL Injection
    graphql_nosql_operator_injection,
    graphql_regex_injection,
    graphql_in_operator_injection,

    // Part 3: Introspection
    graphql_introspection_dump,
    graphql_hidden_fields,
    graphql_directives,

    // Part 4: Authorization Bypass
    graphql_nested_mutation,
    graphql_alias_overwrite,
    graphql_batch_attacks,

    // Part 5: DoS
    graphql_nested_query_dos,
    graphql_field_dos,
    graphql_circular_query,

    // Part 6: IDOR
    graphql_idor_user_info,
    graphql_connection_idor,
    graphql_internal_error,

    // Part 7: CSRF
    graphql_csrf_mutation,
    graphql_csrf_file_upload,

    // Part 8: Safe Patterns
    graphql_safe_parameterized,
    graphql_safe_whitelist_fields,
    graphql_safe_depth_limit,
    graphql_safe_auth_check,
    graphql_safe_no_introspection,
    graphql_safe_rate_limit
};
