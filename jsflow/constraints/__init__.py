"""
Constraint reconstruction helpers built on top of CONTRIBUTES_TO edges.

This package offers a small IR plus builders/encoders so callers can derive
symbolic expressions from the analysis graph without modifying the legacy
solver. Typical usage:

    from jsflow.constraints import build_expressions, encode_to_z3
    exprs = build_expressions(G, target_obj_ids)
    for target, expr in exprs.items():
        solver = z3.Solver()
        term = encode_to_z3(expr, solver)
        ...

The builder walks CONTRIBUTES_TO edges backward from sink objects, groups
operands using the recorded operation tuple (op, group-id, index), and
produces an expression DAG. The encoder then translates that DAG into z3 terms
with reasonable fallbacks for unknown operations.
"""

from .engine import (
    Expression,
    ConstString,
    ConstNumber,
    Symbol,
    Concat,
    Add,
    Sub,
    Choice,
    UnknownOp,
    Condition,
    TrueCondition,
    FalseCondition,
    Predicate,
    NamedCondition,
    NotCondition,
    AndCondition,
    OrCondition,
    PathConstraint,
    build_expressions,
    encode_to_z3,
    build_path_constraints,
    encode_condition,
    encode_path_constraint,
    solve_path_sensitive,
)

__all__ = [
    "Expression",
    "ConstString",
    "ConstNumber",
    "Symbol",
    "Concat",
    "Add",
    "Sub",
    "Choice",
    "UnknownOp",
    "Condition",
    "TrueCondition",
    "FalseCondition",
    "Predicate",
    "NamedCondition",
    "NotCondition",
    "AndCondition",
    "OrCondition",
    "PathConstraint",
    "build_expressions",
    "encode_to_z3",
    "build_path_constraints",
    "encode_condition",
    "encode_path_constraint",
    "solve_path_sensitive",
]
