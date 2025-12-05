# Vulnerability Types

## OS Command Injection

Detects unsafe execution of user-controlled input through functions like:
- `child_process.exec()`, `child_process.execFile()`, `child_process.spawn()`
- `child_process.execSync()`, `child_process.execFileSync()`
- `os.system()` (if modeled)

**Example vulnerable pattern:**
```javascript
const userInput = req.query.cmd;
child_process.exec(userInput); // Vulnerable!
```

## Cross-Site Scripting (XSS)

Identifies paths where user input reaches HTTP response writing functions without proper sanitization:
- `res.send()`, `res.write()`, `res.end()` in Express.js
- `response.writeHead()` with user-controlled content
- DOM manipulation functions that write user input

**Example vulnerable pattern:**
```javascript
const userInput = req.query.name;
res.send(`<h1>Hello ${userInput}</h1>`); // Vulnerable!
```

## Code Execution

Detects use of dynamic code execution with user input:
- `eval()` function
- `Function()` constructor
- `setTimeout()` / `setInterval()` with string arguments
- `vm.runInContext()` and similar Node.js VM functions

**Example vulnerable pattern:**
```javascript
const userCode = req.body.code;
eval(userCode); // Vulnerable!
```

## Prototype Pollution

Identifies operations that can modify JavaScript object prototypes through functions like:
- `merge()`, `extend()`, `clone()`, `assign()`
- `set()` operations with `__proto__` or `constructor.prototype`
- Property access patterns that traverse prototype chains

**Example vulnerable pattern:**
```javascript
const userInput = {__proto__: {isAdmin: true}};
Object.assign({}, userInput); // Prototype pollution!
```

## Internal Property Tampering

Detects modifications to internal object properties that could affect program behavior:
- Modifications to `__proto__`, `constructor`, `prototype`
- Changes to internal object properties used by frameworks
- Property writes that could affect other objects through prototype chains

## Path Traversal

Identifies paths where user-controlled URLs reach file operations without sanitization:
- `fs.readFile()`, `fs.writeFile()`, `fs.unlink()` with user input
- `path.join()` misuse
- File operations with unsanitized user-provided paths

**Example vulnerable pattern:**
```javascript
const userPath = req.query.file;
fs.readFile(userPath, 'utf8', callback); // Vulnerable to ../../../etc/passwd
```

## NoSQL Injection

Detects unsafe NoSQL query construction with user input:
- MongoDB query operations with user input
- Mongoose queries without proper sanitization
- Direct object injection into query builders

**Example vulnerable pattern:**
```javascript
const userQuery = req.body.query;
db.users.find(userQuery); // Vulnerable to {$ne: null} injection
```
