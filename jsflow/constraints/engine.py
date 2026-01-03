"""
Constraint engine for building and encoding expression DAGs to Z3.
"""

import logging
import itertools
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import z3

from ..utilities import wildcard

logger = logging.getLogger(__name__)


# --- Expression IR ---------------------------------------------------------


@dataclass
class Expression:
    """Base expression class."""
    tainted: bool = False


@dataclass
class ConstString(Expression):
    """Constant string expression."""
    value: str = ""


@dataclass
class ConstNumber(Expression):
    """Constant number expression."""
    value: float = 0.0


@dataclass
class Symbol(Expression):
    """Symbol expression representing a graph node."""
    node_id: str = ""
    type_hint: Optional[str] = None  # 'string' | 'number' | None


@dataclass
class Concat(Expression):
    """String concatenation expression."""
    parts: List[Expression] = field(default_factory=list)  # strings


@dataclass
class Add(Expression):
    """Numeric addition expression."""
    terms: List[Expression] = field(default_factory=list)  # numbers


@dataclass
class Sub(Expression):
    """Numeric subtraction expression."""
    left: Expression = None
    right: Expression = None


@dataclass
class Choice(Expression):
    """Choice expression representing multiple options."""
    options: List[Expression] = field(default_factory=list)


@dataclass
class UnknownOp(Expression):
    """Unknown operation expression."""
    op: str = "unknown"
    args: List[Expression] = field(default_factory=list)


# --- Builder ---------------------------------------------------------------


def _node_type(G, node_id):
    return G.get_node_attr(node_id).get("type")


def _node_value(G, node_id):
    return G.get_node_attr(node_id).get("code")


def _node_taint(G, node_id):
    return bool(G.get_node_attr(node_id).get("tainted"))


def build_expressions(
    G, target_obj_ids, contains: bool = True
) -> Dict[str, Expression]:
    """
    Build expression DAGs for each target object by following CONTRIBUTES_TO edges.

    Args:
        G: Graph instance.
        target_obj_ids: Iterable of target object node IDs.
        contains: Whether sink values should be modeled as "contains" instead of equality.
                  (The flag is preserved on Symbols for callers to decide how to use it.)
    Returns:
        dict mapping target obj id -> Expression
    """
    memo: Dict[str, Expression] = {}

    def build(node_id: str) -> Expression:
        if node_id in memo:
            return memo[node_id]

        node_tainted = _node_taint(G, node_id)
        node_type = _node_type(G, node_id)
        node_value = _node_value(G, node_id)

        in_edges = G.get_in_edges(node_id, edge_type="CONTRIBUTES_TO")

        if not in_edges:
            expr = _leaf_expr(node_id, node_type, node_value, node_tainted)
            memo[node_id] = expr
            return expr

        grouped = _group_contributors(in_edges)
        options: List[Expression] = []
        for (op, _group), sources in grouped.items():
            # ensure deterministic ordering by index
            sources = sorted(sources, key=lambda s: s[1])
            child_exprs = [build(src) for src, _idx in sources]
            expr = _op_to_expr(op, child_exprs, node_tainted)
            options.append(expr)

        if not options:
            expr = _leaf_expr(node_id, node_type, node_value, node_tainted)
        elif len(options) == 1:
            expr = options[0]
        else:
            expr = Choice(options=options, tainted=node_tainted)

        memo[node_id] = expr
        return expr

    return {t: build(str(t)) for t in target_obj_ids}


def _leaf_expr(node_id, node_type, node_value, tainted):
    if node_type == "string" and node_value not in (None, wildcard):
        return ConstString(value=str(node_value), tainted=tainted)
    if node_type == "number" and node_value not in (None, wildcard):
        try:
            return ConstNumber(value=float(node_value), tainted=tainted)
        except (TypeError, ValueError):
            pass
    return Symbol(node_id=str(node_id), type_hint=node_type, tainted=tainted)


def _group_contributors(in_edges) -> Dict[Tuple[str, str], List[Tuple[str, int]]]:
    """
    Groups contributors by (op, group-id) and keeps operand index.
    Edge format: (src, dst, data) where data may hold 'opt' = (op, rnd, idx).
    """
    grouped: Dict[Tuple[str, str], List[Tuple[str, int]]] = {}
    for src, _dst, data in in_edges:
        opt = data.get("opt")
        if not opt or len(opt) < 3:
            key = ("unknown", "none")
            idx = len(grouped.get(key, []))
        else:
            op, group, idx = opt[0], opt[1], opt[2]
            key = (op, group)
        grouped.setdefault(key, []).append((src, int(idx)))
    return grouped


def _op_to_expr(op: str, args: List[Expression], tainted: bool) -> Expression:
    op = op or "unknown"
    if op == "string_concat":
        return Concat(parts=args, tainted=tainted)
    if op == "numeric_add":
        return Add(terms=args, tainted=tainted)
    if op == "unknown_add":
        # Could be string or numeric; represent as choice
        return Choice(
            options=[
                Concat(parts=args, tainted=tainted),
                Add(terms=args, tainted=tainted),
            ],
            tainted=tainted,
        )
    if op == "sub":
        if len(args) == 2:
            return Sub(left=args[0], right=args[1], tainted=tainted)
        if args:
            # fall back to left-associative subtraction
            head, *rest = args
            return Sub(
                left=head, right=Add(terms=rest, tainted=tainted), tainted=tainted
            )
    if op == "array_join":
        return Concat(parts=args, tainted=tainted)
    return UnknownOp(op=op, args=args, tainted=tainted)


# --- Z3 encoding -----------------------------------------------------------


class _SymbolCache:
    """Cache for mixed symbols."""
    def __init__(self):
        self.cache: Dict[str, "_MixedSymbol"] = {}
        self.counter = itertools.count()

    def get(self, node_id: str, type_hint: Optional[str] = None) -> "_MixedSymbol":
        if node_id not in self.cache:
            self.cache[node_id] = _MixedSymbol(node_id, type_hint)
        return self.cache[node_id]

    def fresh(self, prefix="u") -> "_MixedSymbol":
        idx = next(self.counter)
        return _MixedSymbol(f"{prefix}{idx}", None)


class _MixedSymbol:
    """
    Holds both string and numeric views for a value. If a type_hint is given,
    only that view is created.
    """

    def __init__(self, name: str, type_hint: Optional[str] = None):
        self._number = None
        self._string = None
        if type_hint == "number":
            self._number = z3.Real(f"n{name}")
        elif type_hint == "string":
            self._string = z3.String(f"s{name}")
        else:
            self._number = z3.Real(f"n{name}")
            self._string = z3.String(f"s{name}")

    @property
    def number(self):
        return self._number

    @property
    def string(self):
        return self._string


def encode_to_z3(
    expr: Expression, solver: z3.Solver, cache: Optional[_SymbolCache] = None
):
    """
    Convert an Expression DAG to a z3 term and add necessary constraints.
    Returns the primary term (string or number) for the expression.
    """
    cache = cache or _SymbolCache()
    return _encode(expr, solver, cache)[0]


def _encode(expr: Expression, solver: z3.Solver, cache: _SymbolCache):
    """
    Returns (term, kind) where kind is 'string' or 'number'.
    """
    if isinstance(expr, ConstString):
        return z3.StringVal(expr.value), "string"
    if isinstance(expr, ConstNumber):
        return z3.RealVal(expr.value), "number"
    if isinstance(expr, Symbol):
        sym = cache.get(expr.node_id, expr.type_hint)
        if expr.type_hint == "number":
            return sym.number, "number"
        if expr.type_hint == "string":
            return sym.string, "string"
        # Unknown: prefer string if available
        return (sym.string or sym.number), (
            "string" if sym.string is not None else "number"
        )
    if isinstance(expr, Concat):
        parts = [_require_string(_encode(p, solver, cache)) for p in expr.parts]
        if len(parts) == 1:
            return parts[0], "string"
        return z3.Concat(*parts), "string"
    if isinstance(expr, Add):
        terms = [_require_number(_encode(t, solver, cache)) for t in expr.terms]
        if len(terms) == 1:
            return terms[0], "number"
        return z3.Sum(terms), "number"
    if isinstance(expr, Sub):
        left = _require_number(_encode(expr.left, solver, cache))
        right = _require_number(_encode(expr.right, solver, cache))
        return left - right, "number"
    if isinstance(expr, Choice):
        # Create a fresh symbol and constrain it to equal one of the options
        first_term, first_kind = _encode(expr.options[0], solver, cache)
        sym = cache.fresh(prefix="choice")
        target = sym.string if first_kind == "string" else sym.number
        ors = []
        for option in expr.options:
            term, kind = _encode(option, solver, cache)
            if kind == "string" and target is not sym.string:
                # prefer string if any option is string
                target = sym.string or sym.number
            ors.append(target == term)
        solver.add(z3.Or(*ors))
        kind = "string" if target is sym.string else "number"
        return target, kind
    if isinstance(expr, UnknownOp):
        sym = cache.fresh(prefix=expr.op or "u")
        if sym.string is not None:
            return sym.string, "string"
        return sym.number, "number"

    # Fallback: treat as fresh symbol
    sym = cache.fresh(prefix="u")
    return (sym.string or sym.number), (
        "string" if sym.string is not None else "number"
    )


def _require_string(encoded):
    term, kind = encoded
    if kind != "string":
        # Coerce numbers to strings for concat if needed
        return z3.IntToStr(term) if isinstance(term, z3.ArithRef) else z3.StringVal("")
    return term


def _require_number(encoded):
    term, kind = encoded
    if kind != "number":
        # Coerce strings to numbers best-effort; fall back to fresh symbol
        if isinstance(term, z3.SeqRef):
            return z3.RealVal(0)
    return term
