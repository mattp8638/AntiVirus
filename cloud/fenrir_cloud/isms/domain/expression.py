"""A small, deterministic JSONLogic subset used by applicability rules.

Packs store rule conditions as JSONLogic. Only the operators in ``OPERATORS`` are supported, so every rule is easy to
review, cannot loop and evaluates the same way in the validator, the engine and any export.

The semantics follow the standalone ISMS engine exactly, including JavaScript's loose equality and comparison rules,
because rules were written against it. ``tests/test_isms_parity.py`` checks this against outputs recorded from it.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from typing import Any, Mapping

# Operator name to its allowed argument count (min, max).
OPERATORS: dict[str, tuple[int, float]] = {
    "var": (1, 2),
    "==": (2, 2),
    "!=": (2, 2),
    "===": (2, 2),
    "!==": (2, 2),
    "<": (2, 2),
    "<=": (2, 2),
    ">": (2, 2),
    ">=": (2, 2),
    "!": (1, 1),
    "!!": (1, 1),
    "and": (1, math.inf),
    "or": (1, math.inf),
    "in": (2, 2),
    "if": (3, 3),
}
SUPPORTED_OPERATORS = tuple(OPERATORS)

Answers = Mapping[str, Any]
_MISSING = object()


@dataclass
class ExpressionIssue:
    path: str
    message: str


@dataclass
class ParsedExpression:
    issues: list[ExpressionIssue] = field(default_factory=list)
    variables: list[str] = field(default_factory=list)  # question ids read through "var"


class ExpressionError(ValueError):
    pass


def _args(node: dict, op: str) -> list:
    raw = node[op]
    return raw if isinstance(raw, list) else [raw]


def _fmt_arity(n: float) -> str:
    return "Infinity" if n == math.inf else str(int(n))


def parse_expression(expression: Any = _MISSING) -> ParsedExpression:
    """Checks the structure of an expression and collects the variables it reads."""
    issues: list[ExpressionIssue] = []
    variables: set[str] = set()

    def visit(node: Any, path: str) -> None:
        if isinstance(node, list):
            for i, child in enumerate(node):
                visit(child, f"{path}[{i}]")
            return
        if not isinstance(node, dict):
            return  # literal
        if len(node) != 1:
            issues.append(ExpressionIssue(path, f"an operator node must have exactly one key, found {len(node)}"))
            return
        op = next(iter(node))
        arity = OPERATORS.get(op)
        if arity is None:
            issues.append(ExpressionIssue(path, f'unsupported operator "{op}"'))
            return
        args = _args(node, op)
        if not arity[0] <= len(args) <= arity[1]:
            issues.append(ExpressionIssue(
                path, f'operator "{op}" takes {_fmt_arity(arity[0])} to {_fmt_arity(arity[1])} arguments, '
                      f"found {len(args)}"))
            return
        if op == "var":
            name = args[0]
            if not isinstance(name, str) or not name:
                issues.append(ExpressionIssue(path, '"var" must name a question ID as a non-empty string'))
                return
            variables.add(name)
            if len(args) == 2:
                visit(args[1], f"{path}.var[1]")
            return
        for i, arg in enumerate(args):
            visit(arg, f"{path}.{op}[{i}]")

    if expression is _MISSING:
        issues.append(ExpressionIssue("$", "expression is missing"))
    else:
        visit(expression, "$")
    return ParsedExpression(issues, sorted(variables))


# JavaScript value semantics -------------------------------------------------------------------------------------

def _js_type(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, (int, float)):
        return "number"
    if isinstance(v, str):
        return "string"
    return "object"  # lists and dicts


def _js_number_str(n: float | int) -> str:
    if isinstance(n, float):
        if math.isnan(n):
            return "NaN"
        if math.isinf(n):
            return "Infinity" if n > 0 else "-Infinity"
        if n.is_integer() and abs(n) < 1e21:
            return str(int(n))
        return repr(n)
    return str(n)


def _js_string(v: Any) -> str:
    t = _js_type(v)
    if t == "null":
        return "null"
    if t == "boolean":
        return "true" if v else "false"
    if t == "number":
        return _js_number_str(v)
    if t == "string":
        return v
    if isinstance(v, list):
        return ",".join("" if x is None else _js_string(x) for x in v)
    return "[object Object]"


def _js_number(v: Any) -> float:
    t = _js_type(v)
    if t == "null":
        return 0.0
    if t == "boolean":
        return 1.0 if v else 0.0
    if t == "number":
        return float(v)
    if t == "string":
        s = v.strip()
        if not s:
            return 0.0
        try:
            if s.lower().startswith(("0x", "0o", "0b")):
                return float(int(s, 0))
            if s in ("Infinity", "+Infinity"):
                return math.inf
            if s == "-Infinity":
                return -math.inf
            if "_" in s or any(c.isalpha() and c not in "eE" for c in s):
                return math.nan
            return float(s)
        except ValueError:
            return math.nan
    if isinstance(v, list):
        return _js_number(_js_string(v))
    return math.nan


def _canonical(v: Any) -> Any:
    """Normalizes numbers the way JSON.stringify writes them (1.0 and 1 are the same value in JavaScript)."""
    if isinstance(v, bool) or v is None or isinstance(v, str):
        return v
    if isinstance(v, float) and v.is_integer():
        return int(v)
    if isinstance(v, list):
        return [_canonical(x) for x in v]
    if isinstance(v, dict):
        return {k: _canonical(x) for k, x in v.items()}
    return v


def _stringify(v: Any) -> str:
    return json.dumps(_canonical(v), separators=(",", ":"), ensure_ascii=False)


def truthy(v: Any) -> bool:
    if isinstance(v, list):
        return len(v) > 0
    if isinstance(v, dict):
        return True
    if isinstance(v, float) and math.isnan(v):
        return False
    return bool(v)


def _loose_equals(a: Any, b: Any) -> bool:
    if a is None or b is None:
        return a is None and b is None
    ta, tb = _js_type(a), _js_type(b)
    if ta == tb:
        return _stringify(a) == _stringify(b)
    if ta == "boolean" or tb == "boolean":
        return _js_number(a) == _js_number(b)
    return _js_string(a) == _js_string(b)


def _compare(op: str, a: Any, b: Any) -> bool:
    if _js_type(a) not in ("number", "string") or _js_type(b) not in ("number", "string"):
        return False
    if not (isinstance(a, str) and isinstance(b, str)):
        a, b = _js_number(a), _js_number(b)  # NaN compares false either way, as in JavaScript
    if op == "<":
        return a < b
    if op == "<=":
        return a <= b
    if op == ">":
        return a > b
    return a >= b


def evaluate(expression: Any, answers: Answers) -> Any:
    """Evaluates an expression against profile answers. Raises ExpressionError on invalid input."""
    parsed = parse_expression(expression)
    if parsed.issues:
        raise ExpressionError("; ".join(f"{i.path}: {i.message}" for i in parsed.issues))
    return _run(expression, answers)


def _run(node: Any, answers: Answers) -> Any:
    if isinstance(node, list):
        return [_run(n, answers) for n in node]
    if not isinstance(node, dict):
        return node
    op = next(iter(node))
    args = _args(node, op)

    def val(i: int) -> Any:
        return _run(args[i], answers)

    if op == "var":
        answer = answers.get(args[0])
        if answer is None:
            return val(1) if len(args) == 2 else None
        return answer
    if op == "==":
        return _loose_equals(val(0), val(1))
    if op == "!=":
        return not _loose_equals(val(0), val(1))
    if op == "===":
        return _js_type(a := val(0)) == _js_type(b := val(1)) and _stringify(a) == _stringify(b)
    if op == "!==":
        return not (_js_type(a := val(0)) == _js_type(b := val(1)) and _stringify(a) == _stringify(b))
    if op in ("<", "<=", ">", ">="):
        return _compare(op, val(0), val(1))
    if op == "!":
        return not truthy(val(0))
    if op == "!!":
        return truthy(val(0))
    if op == "and":
        last: Any = True
        for i in range(len(args)):
            last = val(i)
            if not truthy(last):
                return last
        return last
    if op == "or":
        last = False
        for i in range(len(args)):
            last = val(i)
            if truthy(last):
                return last
        return last
    if op == "in":
        needle, hay = val(0), val(1)
        if isinstance(hay, list):
            return any(_loose_equals(h, needle) for h in hay)
        if isinstance(hay, str) and isinstance(needle, str):
            return needle in hay
        return False
    return val(1) if truthy(val(0)) else val(2)  # "if"


def matches(expression: Any, answers: Answers) -> bool:
    """Evaluates and coerces the result to a boolean."""
    return truthy(evaluate(expression, answers))
