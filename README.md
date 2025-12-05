# FAST (jsflow)

**FAST** is a static analysis tool for JavaScript that performs vulnerability detection through symbolic execution and object graph generation. The core analysis engine is implemented in the `jsflow` module.

## Overview

jsflow is a JavaScript static analysis framework that:

- **Generates Object Property Graphs (OPG)** from JavaScript source code
- **Performs symbolic execution** to track data flows and control flows
- **Detects vulnerabilities** including:
  - OS command injection
  - Cross-site scripting (XSS)
  - Code execution vulnerabilities
  - Prototype pollution
  - Internal property tampering
  - Path traversal
  - NoSQL injection
- **Exports analysis results** to CSV/TSV format for further processing
- **Supports module analysis** for npm packages

## Architecture

The jsflow module consists of several key components:

### Core Modules

- **`graph.py`**: Implements the `Graph` class, which maintains a NetworkX-based multi-digraph representing the code structure, data flows, and control flows
- **`opgen.py`**: Operation generator that performs AST traversal and symbolic execution
- **`launcher.py`**: Main entry point and command-line interface
- **`vul_checking.py`**: Vulnerability detection engine that applies trace rules to identify security issues
- **`trace_rule.py`**: Defines trace rules for vulnerability pattern matching
- **`solver.py`**: Constraint solver for path analysis
- **`modeled_js_builtins.py`**: Models JavaScript built-in functions and objects
- **`modeled_builtin_modules.py`**: Models Node.js built-in modules (fs, child_process, etc.)

### Supporting Modules

- **`logger.py`**: Logging utilities with file and console output support
- **`helpers.py`**: Utility functions for JavaScript value handling
- **`utilities.py`**: Data structures and utilities for branch tracking
- **`esprima.py`**: JavaScript parser interface
- **`vul_func_lists.py`**: Lists of vulnerable function signatures

## Installation

```bash
pip install -r requirements.txt
```

### Dependencies

- `networkx` (~=2.4): Graph data structure
- `z3-solver` (~=4.8.8.0): Constraint solving
- `sty` (~=1.0.0rc0): Terminal styling
- `func_timeout` (~=4.3.5): Function timeout handling
- `tqdm` (~=4.48.2): Progress bars

## Usage

### Command Line Interface

```bash
# Analyze a JavaScript file
python -m jsflow input.js

# Analyze with specific vulnerability type
python -m jsflow -t os_command input.js

# Check for prototype pollution
python -m jsflow -P input.js

# Module mode (analyze as npm module)
python -m jsflow -m input.js

# Exit when vulnerability is found
python -m jsflow -q -t xss input.js

# Print logs to console
python -m jsflow -p input.js
```

### Command Line Options

- `-p, --print`: Print logs to console instead of file
- `-t, --vul-type`: Set vulnerability type (`os_command`, `xss`, `code_exec`, `proto_pollution`, `path_traversal`, `nosql`)
- `-P, --prototype-pollution`: Check for prototype pollution
- `-I, --int-prop-tampering`: Check for internal property tampering
- `-m, --module`: Module mode (treat input as npm module)
- `-q, --exit`: Exit when vulnerability is found
- `-s, --single-branch`: Single branch mode (no path explosion)
- `-a, --run-all`: Run all exported functions
- `-f, --function-timeout`: Time limit for function execution (seconds)
- `-c, --call-limit`: Limit on call statement depth (default: 3)
- `-e, --entry-func`: Specify entry function name
- `-F, --nfb, --no-file-based`: Disable file-based analysis
- `-C, --rcf, --rough-control-flow`: Enable rough control flow analysis
- `-D, --rcd, --rough-call-distance`: Enable rough call distance
- `-X, --exploit, --auto-exploit`: Enable automatic exploit generation
- `-1, --coarse-only`: Coarse analysis only

### Programmatic Usage

```python
from jsflow.launcher import unittest_main
from jsflow.graph import Graph

# Analyze a file
result, graph = unittest_main(
    file_path='input.js',
    vul_type='os_command'
)

# Access the graph
print(f"Total statements: {graph.get_total_num_statements()}")
print(f"Covered statements: {len(graph.covered_stat)}")
```

## How It Works

1. **Parsing**: JavaScript source code is parsed into an Abstract Syntax Tree (AST) using Esprima
2. **Graph Construction**: The AST is converted into a graph structure with nodes representing:
   - AST nodes (statements, expressions, functions)
   - Objects and their properties
   - Scopes and variables
3. **Symbolic Execution**: The tool simulates program execution, tracking:
   - Object property accesses and modifications
   - Function calls and returns
   - Control flow paths
   - Data flow from sources to sinks
4. **Vulnerability Detection**: Trace rules are applied to identify paths from user input (sources) to vulnerable sinks
5. **Path Reporting**: Vulnerable paths are reported with line numbers and code snippets

## Output

Analysis results are saved in timestamped directories under `logs/`:

- `run_log.log`: Main execution log
- `graph_log.log`: Graph construction details
- `opg_nodes.tsv`: Object property graph nodes
- `opg_rels.tsv`: Object property graph relationships
- `proto_pollution.log`: Prototype pollution findings (if detected)
- `int_prop_tampering.log`: Internal property tampering findings (if detected)
- `vul_func_names.csv`: Detected vulnerable functions

## Vulnerability Types

### OS Command Injection
Detects unsafe execution of user-controlled input through functions like `exec()`, `spawn()`, `execFile()`.

### Cross-Site Scripting (XSS)
Identifies paths where user input reaches HTTP response writing functions without proper sanitization.

### Code Execution
Detects use of `eval()`, `Function()` constructor, or command execution with user input.

### Prototype Pollution
Identifies operations that can modify JavaScript object prototypes through functions like `merge()`, `extend()`, `clone()`.

### Internal Property Tampering
Detects modifications to internal object properties that could affect program behavior.

### Path Traversal
Identifies paths where user-controlled URLs reach file operations without sanitization.

### NoSQL Injection
Detects unsafe NoSQL query construction with user input.

## Limitations

- **Path Explosion**: Complex programs may generate many execution paths
- **Dynamic Features**: Highly dynamic JavaScript code may not be fully analyzed
- **False Positives**: Some detected paths may not be exploitable in practice
- **Performance**: Large codebases may require significant analysis time

## Contributing

When contributing to jsflow:

1. Follow the existing code style
2. Add docstrings to new functions and classes
3. Update this README for significant changes
4. Test with various JavaScript code samples

## License

[Add license information here]

## References

- Based on Object Property Graph (OPG) analysis
- Uses Esprima for JavaScript parsing
- NetworkX for graph operations
- Z3 for constraint solving

