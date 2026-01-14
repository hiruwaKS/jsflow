
// SQL Injection Benchmarks

const pg = require('pg');
const client = new pg.Client();

async function vulnerableQuery(req) {
    const userInput = req.query.id;
    // Vulnerability: Direct concatenation
    const query = "SELECT * FROM users WHERE id = '" + userInput + "'";
    return await client.query(query);
}

async function vulnerableTemplateLiteral(req) {
    const userInput = req.query.id;
    // Vulnerability: Template literal
    const query = `SELECT * FROM users WHERE id = '${userInput}'`;
    return await client.query(query);
}

async function safeParameterized(req) {
    const userInput = req.query.id;
    // Safe: Parameterized query
    const query = "SELECT * FROM users WHERE id = $1";
    return await client.query(query, [userInput]);
}

async function safeCast(req) {
    const userInput = req.query.id;
    // Safe: Explicit cast (assuming integer ID)
    const id = parseInt(userInput, 10);
    const query = `SELECT * FROM users WHERE id = ${id}`;
    return await client.query(query);
}

module.exports = {
    vulnerableQuery,
    vulnerableTemplateLiteral,
    safeParameterized,
    safeCast
};
