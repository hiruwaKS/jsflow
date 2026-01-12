Core Components
===============

This section covers the core analysis components and frameworks in jsflow.

jsflow provides several core modules that work together to perform static analysis of JavaScript code. These components handle parsing, graph construction, symbolic execution, and vulnerability detection.

Overview
--------

At a glance:

* **Graph** (``jsflow.core.graph``): Core graph data structure for representing JavaScript code analysis
* **Operation Generator** (``jsflow.core.opgen``): AST traversal and static analysis engine
* **Solver** (``jsflow.core.solver``): Constraint solving using Z3 for path analysis and exploit generation
* **Trace Rules** (``jsflow.core.trace_rule``): Pattern matching rules for vulnerability detection
* **Esprima Interface** (``jsflow.core.esprima``): JavaScript parser interface

.. toctree::
   :maxdepth: 2

   graph
   opgen
   solver
   trace_rule
   esprima

API Reference
-------------

For detailed API documentation, please refer to the source code and docstrings within each module. The main classes and functions include:

* **Graph**: Core graph data structure (jsflow.core.graph)
* **OperationVisitor**: AST traversal and operation generation (jsflow.core.opgen)
* **TraceRule**: Vulnerability detection patterns (jsflow.core.trace_rule)
* **Solver**: Constraint solving interface (jsflow.core.solver)
* **Esprima Interface**: JavaScript parsing interface (jsflow.core.esprima)