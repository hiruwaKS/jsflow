
// Comprehensive SQL Injection Benchmarks (CWE-89)
// Covers multiple database libraries, injection patterns, and real-world scenarios

const pg = require('pg');
const mysql = require('mysql2/promise');
const sqlite3 = require('sqlite3').verbose();

// ============================================================================
// PART 1: Postgres (pg) Library Benchmarks
// ============================================================================

// 1.1. Basic Vulnerable Patterns - Direct Concatenation
function pg_vulnerable_simple_concat(req) {
    const userInput = req.query.id;
    // VULNERABLE: Direct string concatenation
    const query = "SELECT * FROM users WHERE id = '" + userInput + "'";
    return pgClient.query(query);
}

function pg_vulnerable_template_literal(req) {
    const userInput = req.query.id;
    // VULNERABLE: Template literal
    const query = `SELECT * FROM users WHERE id = '${userInput}'`;
    return pgClient.query(query);
}

function pg_vulnerable_addition(req) {
    const userInput = req.query.id;
    const prefix = "SELECT * FROM users WHERE id = '";
    const suffix = "'";
    // VULNERABLE: String addition
    const query = prefix + userInput + suffix;
    return pgClient.query(query);
}

// 1.2. Complex Queries with Multiple Input Points
function pg_vulnerable_multi_concat(req) {
    const id = req.query.id;
    const name = req.query.name;
    const email = req.query.email;
    // VULNERABLE: Multiple concatenations
    const query = `SELECT * FROM users WHERE id = '${id}' AND name = '${name}' OR email = '${email}'`;
    return pgClient.query(query);
}

function pg_vulnerable_where_clause(req) {
    const condition = req.query.condition;
    // VULNERABLE: User controls entire WHERE clause
    const query = `SELECT * FROM users WHERE ${condition}`;
    return pgClient.query(query);
}

// 1.3. Subquery Injection
function pg_vulnerable_subquery(req) {
    const userInput = req.query.id;
    // VULNERABLE: Nested query with concatenation
    const innerQuery = "SELECT name FROM departments WHERE id = '" + userInput + "'";
    const outerQuery = `SELECT * FROM users WHERE department IN (${innerQuery})`;
    return pgClient.query(outerQuery);
}

function pg_vulnerable_union_based(req) {
    const userInput = req.query.search;
    // VULNERABLE: UNION-based injection point
    const query = "SELECT * FROM products WHERE name LIKE '%" + userInput + "%'";
    return pgClient.query(query);
}

// 1.4. JOIN Injection
function pg_vulnerable_join(req) {
    const userInput = req.query.table;
    // VULNERABLE: Table name injection
    const query = `SELECT u.*, d.name as dept_name FROM users u JOIN ${userInput} d ON u.dept_id = d.id`;
    return pgClient.query(query);
}

function pg_vulnerable_on_clause(req) {
    const userInput = req.query.condition;
    // VULNERABLE: JOIN condition injection
    const query = `SELECT * FROM orders o JOIN customers c ON ${userInput}`;
    return pgClient.query(query);
}

// 1.5. ORDER BY / GROUP BY Injection
function pg_vulnerable_order_by(req) {
    const userInput = req.query.sort;
    // VULNERABLE: ORDER BY clause
    const query = `SELECT * FROM users ORDER BY ${userInput}`;
    return pgClient.query(query);
}

function pg_vulnerable_group_by(req) {
    const userInput = req.query.group;
    // VULNERABLE: GROUP BY clause
    const query = `SELECT category, COUNT(*) FROM products GROUP BY ${userInput}`;
    return pgClient.query(query);
}

// 1.6. LIMIT / OFFSET Injection
function pg_vulnerable_limit(req) {
    const userInput = req.query.limit;
    // VULNERABLE: LIMIT clause
    const query = `SELECT * FROM users LIMIT ${userInput}`;
    return pgClient.query(query);
}

// 1.7. UPDATE Statement Injection
function pg_vulnerable_update(req) {
    const userId = req.query.id;
    const newName = req.query.name;
    // VULNERABLE: UPDATE with concatenation
    const query = `UPDATE users SET name = '${newName}' WHERE id = ${userId}`;
    return pgClient.query(query);
}

function pg_vulnerable_update_multi_column(req) {
    const userId = req.query.id;
    const name = req.query.name;
    const email = req.query.email;
    // VULNERABLE: Multiple columns
    const query = `UPDATE users SET name = '${name}', email = '${email}' WHERE id = ${userId}`;
    return pgClient.query(query);
}

// 1.8. DELETE Statement Injection
function pg_vulnerable_delete(req) {
    const userId = req.query.id;
    // VULNERABLE: DELETE with concatenation
    const query = `DELETE FROM users WHERE id = ${userId}`;
    return pgClient.query(query);
}

function pg_vulnerable_delete_cascade(req) {
    const condition = req.query.condition;
    // VULNERABLE: DELETE with user-controlled condition
    const query = `DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE ${condition})`;
    return pgClient.query(query);
}

// 1.9. INSERT Statement Injection
function pg_vulnerable_insert(req) {
    const name = req.query.name;
    const email = req.query.email;
    // VULNERABLE: INSERT with concatenation
    const query = `INSERT INTO users (name, email) VALUES ('${name}', '${email}')`;
    return pgClient.query(query);
}

function pg_vulnerable_insert_multi_row(req) {
    const values = req.query.values;
    // VULNERABLE: Multi-row INSERT
    const query = `INSERT INTO users (name, email) VALUES ${values}`;
    return pgClient.query(query);
}

// 1.10. Time-Based Blind Injection
function pg_vulnerable_time_blind(req) {
    const userInput = req.query.id;
    // VULNERABLE: Time-based blind injection
    const query = `SELECT * FROM users WHERE id = '${userInput}' AND pg_sleep(5)`;
    return pgClient.query(query);
}

// ============================================================================
// PART 2: Safe Patterns - Precision Testing (Should NOT be flagged)
// ============================================================================

function pg_safe_parameterized(req) {
    const userInput = req.query.id;
    // SAFE: Parameterized query
    const query = "SELECT * FROM users WHERE id = $1";
    return pgClient.query(query, [userInput]);
}

function pg_safe_multiple_params(req) {
    const name = req.query.name;
    const email = req.query.email;
    // SAFE: Multiple parameters
    const query = "SELECT * FROM users WHERE name = $1 AND email = $2";
    return pgClient.query(query, [name, email]);
}

function pg_safe_named_params(req) {
    const userInput = req.query.id;
    // SAFE: Named parameters
    const query = "SELECT * FROM users WHERE id = $id";
    return pgClient.query(query, { id: userInput });
}

function pg_safe_explicit_cast(req) {
    const userInput = req.query.id;
    // SAFE: Explicit type casting to number
    const id = parseInt(userInput, 10);
    if (isNaN(id)) throw new Error("Invalid ID");
    const query = `SELECT * FROM users WHERE id = ${id}`;
    return pgClient.query(query);
}

function pg_safe_whitelist(req) {
    const userInput = req.query.sort;
    const allowedColumns = ['name', 'email', 'created_at'];
    // SAFE: Whitelist validation
    if (!allowedColumns.includes(userInput)) {
        throw new Error("Invalid sort column");
    }
    const query = `SELECT * FROM users ORDER BY ${userInput}`;
    return pgClient.query(query);
}

function pg_safe_regex_validation(req) {
    const userInput = req.query.id;
    // SAFE: Regex validation for numeric ID
    if (!/^\d+$/.test(userInput)) {
        throw new Error("Invalid ID");
    }
    const query = `SELECT * FROM users WHERE id = ${userInput}`;
    return pgClient.query(query);
}

function pg_safe_orm_like(req) {
    const userInput = req.query.id;
    // SAFE: Using ORM-like builder (mocked)
    const builder = {
        where: (condition, value) => ({
            select: (fields) => ({
                query: () => `SELECT ${fields} FROM users WHERE ${condition} = $1`,
                params: [value]
            })
        })
    };
    const result = builder.where('id', userInput).select('*');
    return pgClient.query(result.query(), result.params);
}

// ============================================================================
// PART 3: Complex Flow Scenarios
// ============================================================================

// 3.1. Flow Through Variables
function pg_flow_variable_reassignment(req) {
    let userInput = req.query.id;
    // Tainted
    userInput = userInput.trim();
    // Still tainted
    const query = `SELECT * FROM users WHERE id = '${userInput}'`;
    return pgClient.query(query); // VULNERABLE
}

function pg_flow_variable_reassignment_safe(req) {
    let userInput = req.query.id;
    userInput = userInput.trim();
    // Sanitization (mock)
    userInput = userInput.replace(/'/g, "''"); // Proper escaping
    // Still tainted in static analysis, but actually safe
    const query = `SELECT * FROM users WHERE id = '${userInput}'`;
    return pgClient.query(query); // SAFE
}

// 3.2. Flow Through Functions
function pg_flow_function(req) {
    const id = req.query.id;
    const formattedId = formatUserId(id);
    const query = `SELECT * FROM users WHERE id = '${formattedId}'`;
    return pgClient.query(query); // VULNERABLE
}

function formatUserId(id) {
    return id.trim();
}

// 3.3. Flow Through Objects
function pg_flow_object_property(req) {
    const userInput = req.query;
    const query = `SELECT * FROM users WHERE id = '${userInput.id}'`;
    return pgClient.query(query); // VULNERABLE
}

function pg_flow_object_property_safe(req) {
    const userInput = req.query;
    // SAFE: Using parameterized query
    const query = "SELECT * FROM users WHERE id = $1";
    return pgClient.query(query, [userInput.id]);
}

// 3.4. Flow Through Array Operations
function pg_flow_array_map(req) {
    const ids = req.query.ids.split(',');
    const queries = ids.map(id => `SELECT * FROM users WHERE id = '${id}'`);
    // Each query is vulnerable
    return queries.map(q => pgClient.query(q)); // VULNERABLE
}

// 3.5. Flow Through Conditional Logic
function pg_flow_conditional(req) {
    const id = req.query.id;
    let query;

    if (id.includes('admin')) {
        // Both branches are vulnerable
        query = `SELECT * FROM admins WHERE id = '${id}'`;
    } else {
        query = `SELECT * FROM users WHERE id = '${id}'`;
    }

    return pgClient.query(query); // VULNERABLE
}

// 3.6. Flow Through Loops
function pg_flow_loop(req) {
    const ids = req.query.ids;
    const results = [];

    for (const id of ids) {
        const query = `SELECT * FROM users WHERE id = '${id}'`;
        results.push(pgClient.query(query));
    }

    return Promise.all(results); // VULNERABLE
}

// ============================================================================
// PART 4: Edge Cases and Anti-Patterns
// ============================================================================

// 4.1. Dynamic Property Access
function pg_anti_dynamic_property(req) {
    const table = req.query.table;
    const column = req.query.column;
    const value = req.query.value;
    // VULNERABLE: Dynamic table and column names
    const query = `SELECT * FROM ${table} WHERE ${column} = '${value}'`;
    return pgClient.query(query);
}

// 4.2. String Splitting and Joining
function pg_anti_split_join(req) {
    const input = req.query.ids;
    const ids = input.split(',');
    const idList = ids.map(id => `'${id}'`).join(',');
    // VULNERABLE: IN clause with concatenation
    const query = `SELECT * FROM users WHERE id IN (${idList})`;
    return pgClient.query(query);
}

// 4.3. String Encoding/Decoding
function pg_anti_encoding(req) {
    const input = req.query.encoded_id;
    const decoded = Buffer.from(input, 'base64').toString('utf-8');
    // VULNERABLE: Decoded input in query
    const query = `SELECT * FROM users WHERE id = '${decoded}'`;
    return pgClient.query(query);
}

// 4.4. JSON Parsing
function pg_anti_json_parse(req) {
    const jsonInput = req.body;
    const data = JSON.parse(jsonInput);
    // VULNERABLE: JSON property in query
    const query = `SELECT * FROM users WHERE id = '${data.id}'`;
    return pgClient.query(query);
}

// 4.5. Eval Alternative - Function Constructor
function pg_anti_function_constructor(req) {
    const column = req.query.column;
    const columnGetter = new Function('obj', `return obj.${column}`);
    // VULNERABLE: Dynamic column access
    const user = { name: 'test', email: 'test@test.com' };
    const value = columnGetter(user);
    const query = `SELECT * FROM users WHERE name = '${value}'`;
    return pgClient.query(query);
}

// ============================================================================
// PART 5: Context-Sensitivity Tests
// ============================================================================

// 5.1. Variable Scope - Same Variable, Different Contexts
function pg_context_same_variable(req) {
    let id = req.query.id;

    // First usage - vulnerable
    const query1 = `SELECT * FROM users WHERE id = '${id}'`;
    const result1 = pgClient.query(query1);

    // Sanitize (not real sanitization, just assignment)
    id = "safe_value";

    // Second usage - safe (strong update)
    const query2 = `SELECT * FROM users WHERE id = '${id}'`;
    const result2 = pgClient.query(query2);

    return [result1, result2];
}

// 5.2. Variable Aliasing
function pg_context_aliasing(req) {
    const userInput = req.query.id;
    const id1 = userInput;
    const id2 = id1;
    // VULNERABLE: Both point to tainted value
    const query = `SELECT * FROM users WHERE id = '${id2}'`;
    return pgClient.query(query);
}

// ============================================================================
// PART 6: Async Flow Tests
// ============================================================================

// 6.1. Promise Chain
function pg_async_promise_chain(req) {
    const id = req.query.id;

    return Promise.resolve(id)
        .then(userId => {
            const query = `SELECT * FROM users WHERE id = '${userId}'`;
            return pgClient.query(query);
        });
}

// 6.2. Async/Await
async function pg_async_await(req) {
    const id = req.query.id;
    await someAsyncOperation();
    const query = `SELECT * FROM users WHERE id = '${id}'`;
    return pgClient.query(query);
}

async function someAsyncOperation() {
    return new Promise(resolve => setTimeout(resolve, 10));
}

// 6.3. Callback Hell
function pg_async_callback(req, callback) {
    const id = req.query.id;
    fetchUserData(id, (err, data) => {
        if (err) return callback(err);
        const query = `SELECT * FROM users WHERE id = '${data.id}'`;
        pgClient.query(query, callback);
    });
}

function fetchUserData(id, callback) {
    setTimeout(() => callback(null, { id }), 10);
}

// ============================================================================
// PART 7: MySQL Library Benchmarks (Similar patterns for MySQL)
// ============================================================================

function mysql_vulnerable_concat(req) {
    const userInput = req.query.id;
    // VULNERABLE: MySQL concatenation
    const query = "SELECT * FROM users WHERE id = '" + userInput + "'";
    return mysqlPool.query(query);
}

function mysql_safe_parameterized(req) {
    const userInput = req.query.id;
    // SAFE: Parameterized query
    const query = "SELECT * FROM users WHERE id = ?";
    return mysqlPool.query(query, [userInput]);
}

// ============================================================================
// PART 8: Real-World CVE-Inspired Patterns
// ============================================================================

// 8.1. CVE-2021-21300 - Type confusion in parameterized queries
function cve_21300_pattern(req) {
    const id = req.query.id;
    const name = req.query.name;
    // VULNERABLE: Type coercion issue with array parameter
    const query = "SELECT * FROM users WHERE id IN ($1) AND name = $2";
    return pgClient.query(query, [[id], name]); // Array injection
}

// 8.2. Common ORM misuse pattern
function orm_misuse_pattern(req) {
    const id = req.query.id;
    // VULNERABLE: Raw SQL in ORM query
    const query = `SELECT * FROM users WHERE id = ${id}`;
    return pgClient.query(query);
}

// 8.3. Search functionality pattern
function search_pattern(req) {
    const searchTerm = req.query.q;
    // VULNERABLE: Full text search with concatenation
    const query = `SELECT * FROM products WHERE name LIKE '%${searchTerm}%' OR description LIKE '%${searchTerm}%'`;
    return pgClient.query(query);
}

// 8.4. Authentication bypass pattern
function auth_bypass_pattern(req) {
    const username = req.query.username;
    const password = req.query.password;
    // VULNERABLE: SQL injection in auth
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    return pgClient.query(query);
}

// 8.5. Stored procedure pattern
function stored_procedure_pattern(req) {
    const userId = req.query.id;
    // VULNERABLE: Stored procedure call with concatenation
    const query = `CALL get_user_details('${userId}')`;
    return pgClient.query(query);
}

module.exports = {
    // Part 1: Vulnerable Postgres Patterns
    pg_vulnerable_simple_concat,
    pg_vulnerable_template_literal,
    pg_vulnerable_addition,
    pg_vulnerable_multi_concat,
    pg_vulnerable_where_clause,
    pg_vulnerable_subquery,
    pg_vulnerable_union_based,
    pg_vulnerable_join,
    pg_vulnerable_on_clause,
    pg_vulnerable_order_by,
    pg_vulnerable_group_by,
    pg_vulnerable_limit,
    pg_vulnerable_update,
    pg_vulnerable_update_multi_column,
    pg_vulnerable_delete,
    pg_vulnerable_delete_cascade,
    pg_vulnerable_insert,
    pg_vulnerable_insert_multi_row,
    pg_vulnerable_time_blind,

    // Part 2: Safe Patterns
    pg_safe_parameterized,
    pg_safe_multiple_params,
    pg_safe_named_params,
    pg_safe_explicit_cast,
    pg_safe_whitelist,
    pg_safe_regex_validation,
    pg_safe_orm_like,

    // Part 3: Complex Flow Scenarios
    pg_flow_variable_reassignment,
    pg_flow_variable_reassignment_safe,
    pg_flow_function,
    formatUserId,
    pg_flow_object_property,
    pg_flow_object_property_safe,
    pg_flow_array_map,
    pg_flow_conditional,
    pg_flow_loop,

    // Part 4: Edge Cases
    pg_anti_dynamic_property,
    pg_anti_split_join,
    pg_anti_encoding,
    pg_anti_json_parse,
    pg_anti_function_constructor,

    // Part 5: Context-Sensitivity
    pg_context_same_variable,
    pg_context_aliasing,

    // Part 6: Async Flow
    pg_async_promise_chain,
    pg_async_await,
    someAsyncOperation,
    pg_async_callback,
    fetchUserData,

    // Part 7: MySQL
    mysql_vulnerable_concat,
    mysql_safe_parameterized,

    // Part 8: Real-World CVE Patterns
    cve_21300_pattern,
    orm_misuse_pattern,
    search_pattern,
    auth_bypass_pattern,
    stored_procedure_pattern
};
