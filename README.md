# jsflow

**jsflow** is a static analysis tool for JavaScript that performs vulnerability detection and exploit generation through object graph generation. The core analysis engine is implemented in the `jsflow` module.

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

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed architecture information.

## Installation

### System Requirements

- **Node.js and npm**: Required for JavaScript AST parsing dependencies
- **Python 3**: Required for the core analysis engine
- **pip**: Python package manager

### Installation Steps

1. **Clone the repository** (if not already done):
   ```bash
   git clone <repository-url>
   cd jsflow
   ```

2. **Install npm dependencies** (for Esprima AST parser):
   ```bash
   cd esprima-csv && npm install && cd ..
   ```
   
   This installs:
   - `esprima` (^4.0.1): JavaScript parser
   - `commander` (^3.0.2): Command-line interface utilities
   - `ansicolor` (^1.1.84): Terminal color output

3. **Set up Python virtual environment** (recommended):
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

4. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

Alternatively, you can use the provided installation script:
```bash
./install.sh
```

This script will automatically:
- Install npm dependencies in `esprima-csv/`
- Create a Python virtual environment if it doesn't exist
- Activate the virtual environment
- Install all Python dependencies

### Python Dependencies

- `networkx` (~=2.4): Graph data structure library
- `z3-solver` (~=4.8.8.0): Constraint solving for path analysis
- `sty` (~=1.0.0rc0): Terminal styling and formatting
- `func_timeout` (~=4.3.5): Function timeout handling
- `tqdm` (~=4.48.2): Progress bars for long-running operations
- `setuptools`: Package building utilities

### Node.js Dependencies

- `esprima` (^4.0.1): JavaScript parser for AST generation
- `commander` (^3.0.2): Command-line interface framework
- `ansicolor` (^1.1.84): Terminal color formatting

## Quick Start

```bash
# Analyze a JavaScript file
python -m jsflow input.js

# Analyze with specific vulnerability type
python -m jsflow -t os_command input.js

# Check for prototype pollution
python -m jsflow -P input.js
```

See [docs/USAGE.md](docs/USAGE.md) for detailed usage instructions, examples, and advanced configuration.

## Documentation

- **[Architecture](docs/ARCHITECTURE.md)**: Detailed architecture, how it works, and output format
- **[Usage Guide](docs/USAGE.md)**: Command-line options, programmatic usage, examples, and advanced configuration
- **[Vulnerability Types](docs/VULNERABILITIES.md)**: Detailed information about each vulnerability type with examples
- **[Troubleshooting](docs/TROUBLESHOOTING.md)**: Limitations, common issues, debugging tips, and references

