"""Calculator guard and evaluator: arithmetic on an allowlisted AST, no eval().

The expression is parsed with Python's own `ast` module, every node is checked
against an allowlist, and the tree is evaluated by walking it. Limits keep the
work small: input length, node count, nesting depth, literal size, exponent
size and the size of every intermediate result.
"""
from __future__ import annotations

import ast
import math
import re
from dataclasses import dataclass

MAX_CALC_CHARS = 200
MAX_NODES = 60
MAX_DEPTH = 20
MAX_ABS = 1e15        # any literal or intermediate result above this is refused
MAX_EXPONENT = 64

ALLOWED_CHARS = re.compile(r"[0-9A-Za-z_ \t.,+\-*/%()]*")
# Hex/octal/binary literals, complex literals and digit separators are valid
# Python but not ordinary arithmetic; refusing them keeps the JS port simple.
NUMBER_FORMAT = re.compile(r"\b0[xXoObB][0-9a-fA-F]|\d[jJ]\b|\d_\d")

FUNCTIONS = {
    "abs": (1, 1),
    "round": (1, 2),
    "min": (2, 10),
    "max": (2, 10),
    "sqrt": (1, 1),
    "log": (1, 2),
}
CONSTANTS = {"pi": math.pi, "e": math.e}
BIN_OPS = (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod, ast.Pow)
UNARY_OPS = (ast.UAdd, ast.USub)


class CalcBlocked(Exception):
    def __init__(self, rule: str, detail: str):
        super().__init__(detail)
        self.rule = rule
        self.detail = detail


@dataclass
class CalcVerdict:
    allowed: bool
    rule: str
    detail: str
    value: float | int | None = None


def check_and_eval(expr: str) -> CalcVerdict:
    try:
        tree = parse(expr)
        value = _eval(tree.body)
    except CalcBlocked as e:
        return CalcVerdict(False, e.rule, e.detail)
    if isinstance(value, float) and value.is_integer() and abs(value) < 2**53:
        value = int(value)
    return CalcVerdict(True, "calc.ok", "arithmetic only", value=value)


def parse(expr: str) -> ast.Expression:
    if len(expr) > MAX_CALC_CHARS:
        raise CalcBlocked("calc.too_long", f"{len(expr)} characters, limit is {MAX_CALC_CHARS}")
    if not expr.strip():
        raise CalcBlocked("calc.empty", "empty expression")
    if not ALLOWED_CHARS.fullmatch(expr):
        bad = next(c for c in expr if not ALLOWED_CHARS.fullmatch(c))
        raise CalcBlocked("calc.bad_chars", f"character {bad!r} is not allowed; use digits, + - * / // % ** ( ) and a few functions")
    if NUMBER_FORMAT.search(expr):
        raise CalcBlocked("calc.number_format", "only plain decimal numbers are allowed")
    try:
        tree = ast.parse(expr.strip(), mode="eval")
    except (SyntaxError, ValueError, RecursionError, MemoryError) as e:
        raise CalcBlocked("calc.syntax", f"could not parse: {getattr(e, 'msg', str(e))}")
    _validate(tree.body)
    nodes = _count(tree.body)
    if nodes > MAX_NODES:
        raise CalcBlocked("calc.too_many_nodes", f"{nodes} nodes, limit is {MAX_NODES}")
    depth = _depth(tree.body)
    if depth > MAX_DEPTH:
        raise CalcBlocked("calc.too_deep", f"nesting depth {depth}, limit is {MAX_DEPTH}")
    return tree


def _validate(node: ast.AST) -> None:
    """Pre-order, left to right. Raises on the first node that is not allowed."""
    if isinstance(node, ast.BinOp):
        if not isinstance(node.op, BIN_OPS):
            raise CalcBlocked("calc.node_not_allowed", f"operator {type(node.op).__name__} is not allowed")
        _validate(node.left)
        _validate(node.right)
    elif isinstance(node, ast.UnaryOp):
        if not isinstance(node.op, UNARY_OPS):
            raise CalcBlocked("calc.node_not_allowed", f"operator {type(node.op).__name__} is not allowed")
        _validate(node.operand)
    elif isinstance(node, ast.Constant):
        if isinstance(node.value, bool) or not isinstance(node.value, (int, float)):
            raise CalcBlocked("calc.node_not_allowed", f"constant {node.value!r} is not a number")
        if abs(node.value) > MAX_ABS:
            raise CalcBlocked("calc.number_too_large", f"literal above {MAX_ABS:.0e}")
    elif isinstance(node, ast.Name):
        if node.id not in CONSTANTS:
            raise CalcBlocked("calc.unknown_name", f"unknown name {node.id!r}; allowed constants: pi, e")
    elif isinstance(node, ast.Call):
        if not isinstance(node.func, ast.Name):
            raise CalcBlocked("calc.node_not_allowed", "only direct calls to allowlisted functions are allowed")
        if node.func.id not in FUNCTIONS:
            raise CalcBlocked("calc.function_not_allowed", f"function {node.func.id!r} is not allowed; allowed: {', '.join(FUNCTIONS)}")
        if node.keywords:
            raise CalcBlocked("calc.node_not_allowed", "keyword arguments are not allowed")
        lo, hi = FUNCTIONS[node.func.id]
        for a in node.args:
            if isinstance(a, ast.Starred):
                raise CalcBlocked("calc.node_not_allowed", "argument unpacking is not allowed")
        if not lo <= len(node.args) <= hi:
            raise CalcBlocked("calc.bad_arity", f"{node.func.id}() takes {lo}-{hi} arguments, got {len(node.args)}")
        for a in node.args:
            _validate(a)
    else:
        raise CalcBlocked("calc.node_not_allowed", f"{type(node).__name__} is not allowed in arithmetic")


def _count(node: ast.AST) -> int:
    if isinstance(node, ast.BinOp):
        return 1 + _count(node.left) + _count(node.right)
    if isinstance(node, ast.UnaryOp):
        return 1 + _count(node.operand)
    if isinstance(node, ast.Call):
        return 1 + sum(_count(a) for a in node.args)
    return 1


def _depth(node: ast.AST) -> int:
    if isinstance(node, ast.BinOp):
        return 1 + max(_depth(node.left), _depth(node.right))
    if isinstance(node, ast.UnaryOp):
        return 1 + _depth(node.operand)
    if isinstance(node, ast.Call):
        return 1 + max((_depth(a) for a in node.args), default=0)
    return 1


def _check_size(v: float | int) -> float | int:
    if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
        raise CalcBlocked("calc.result_too_large", "result is not a finite number")
    if abs(v) > MAX_ABS:
        raise CalcBlocked("calc.result_too_large", f"intermediate result above {MAX_ABS:.0e}")
    return v


def _eval(node: ast.AST) -> float | int:
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return CONSTANTS[node.id]
    if isinstance(node, ast.UnaryOp):
        v = _eval(node.operand)
        return -v if isinstance(node.op, ast.USub) else +v
    if isinstance(node, ast.BinOp):
        a = _eval(node.left)
        b = _eval(node.right)
        op = node.op
        try:
            if isinstance(op, ast.Add):
                r = a + b
            elif isinstance(op, ast.Sub):
                r = a - b
            elif isinstance(op, ast.Mult):
                r = a * b
            elif isinstance(op, ast.Div):
                r = a / b
            elif isinstance(op, ast.FloorDiv):
                r = a // b
            elif isinstance(op, ast.Mod):
                r = a % b
            else:  # Pow
                if abs(b) > MAX_EXPONENT:
                    raise CalcBlocked("calc.exponent_too_large", f"exponent {b} is above {MAX_EXPONENT}")
                if a < 0 and float(b) != int(b):
                    raise CalcBlocked("calc.math_domain", "negative number to a fractional power")
                r = a ** b
        except ZeroDivisionError:
            raise CalcBlocked("calc.division_by_zero", "division by zero")
        except OverflowError:
            raise CalcBlocked("calc.result_too_large", "result overflowed")
        return _check_size(r)
    if isinstance(node, ast.Call):
        args = [_eval(a) for a in node.args]
        name = node.func.id
        if name == "abs":
            return abs(args[0])
        if name == "min":
            return min(args)
        if name == "max":
            return max(args)
        if name == "sqrt":
            if args[0] < 0:
                raise CalcBlocked("calc.math_domain", "sqrt of a negative number")
            return math.sqrt(args[0])
        if name == "log":
            x = args[0]
            if x <= 0 or (len(args) == 2 and (args[1] <= 0 or args[1] == 1)):
                raise CalcBlocked("calc.math_domain", "log needs a positive number and a positive base other than 1")
            return math.log(x) if len(args) == 1 else math.log(x) / math.log(args[1])
        if name == "round":
            if len(args) == 2:
                nd = args[1]
                if float(nd) != int(nd) or abs(nd) > 10:
                    raise CalcBlocked("calc.math_domain", "round() digits must be an integer between -10 and 10")
                return round(args[0], int(nd))
            return round(args[0])
    raise CalcBlocked("calc.node_not_allowed", f"{type(node).__name__} is not allowed")
