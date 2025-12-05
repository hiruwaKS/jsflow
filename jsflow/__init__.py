"""
jsflow: A Static Analysis Framework for JavaScript Vulnerability Detection

jsflow is a static analysis tool that performs symbolic execution on JavaScript
code to detect security vulnerabilities. It generates Object Property Graphs (OPG)
from JavaScript source code and analyzes data flows to identify potential security
issues.

Key Features:
    - Object Property Graph generation from JavaScript AST
    - Symbolic execution with path tracking
    - Vulnerability detection (OS command injection, XSS, prototype pollution, etc.)
    - Support for npm module analysis
    - Export to CSV/TSV for further analysis

Main Components:
    - Graph: Core graph data structure for representing code
    - opgen: Operation generator for AST traversal and symbolic execution
    - vul_checking: Vulnerability detection engine
    - trace_rule: Pattern matching rules for vulnerability detection
    - solver: Constraint solver for path analysis

Usage:
    Command line:
        python -m jsflow input.js -t os_command
    
    Programmatic:
        from jsflow.launcher import unittest_main
        result, graph = unittest_main('input.js', vul_type='os_command')

Example:
    >>> from jsflow.launcher import unittest_main
    >>> result, graph = unittest_main('test.js', vul_type='xss')
    >>> print(f"Vulnerabilities found: {len(result)}")
"""

__version__ = "1.0.0"
__all__ = [
    'Graph',
    'launcher',
    'opgen',
    'vul_checking',
    'trace_rule',
    'solver',
    'logger',
    'helpers',
    'utilities',
]
