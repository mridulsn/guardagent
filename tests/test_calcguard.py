import pytest

from guardagent.calcguard import check_and_eval


CALC_VALUES = [
    ("1 + 2 * 3", 7),
    ("(289 * 3) * 0.95", 823.65),
    ("15/100*2340 + 12.5/100*980", 473.5),
    ("2 ** 10", 1024),
    ("2 ** -1", 0.5),
    ("-2 ** 2", -4),
    ("7 // 2", 3),
    ("-7 // 2", -4),
    ("7 % -3", -2),
    ("round(2.5)", 2),
    ("round(3.14159, 2)", 3.14),
    ("max(1, 5, 3) - min(4, 2)", 3),
    ("abs(-3) + sqrt(16)", 7),
    ("log(e)", 1),
    ("log(8, 2)", 3),
    ("pi * 2", 6.283185307179586),
    (".5 + 1.", 1.5),
    ("1e3 + 1E+2", 1100),
]


@pytest.mark.parametrize("expr,value", CALC_VALUES)
def test_values(expr, value):
    v = check_and_eval(expr)
    assert v.allowed, v
    assert v.value == pytest.approx(value)


CALC_BLOCKED = [
    ("", "calc.empty"),
    ("   ", "calc.empty"),
    ("1+" * 150 + "1", "calc.too_long"),
    ("__import__('os').system('ls')", "calc.bad_chars"),
    ("[1, 2]", "calc.bad_chars"),
    ("{1: 2}", "calc.bad_chars"),
    ("1 < 2", "calc.bad_chars"),
    ("x = 1", "calc.bad_chars"),
    ("lambda: 1", "calc.bad_chars"),
    ("\u0661 + \u0661", "calc.bad_chars"),       # Arabic-Indic digits
    ("1\u200b+1", "calc.bad_chars"),
    ("2 ^ 3", "calc.bad_chars"),
    ("0x10 + 1", "calc.number_format"),
    ("1j * 1j", "calc.number_format"),
    ("1_000 * 2", "calc.number_format"),
    ("0b101", "calc.number_format"),
    ("1 +", "calc.syntax"),
    ("2pi", "calc.syntax"),
    ("1.real", "calc.syntax"),
    ("(1).real", "calc.node_not_allowed"),
    ("(1).__class__", "calc.node_not_allowed"),
    ("1, 2", "calc.node_not_allowed"),
    ("()", "calc.node_not_allowed"),
    ("True + 1", "calc.node_not_allowed"),
    ("None", "calc.node_not_allowed"),
    ("not 1", "calc.node_not_allowed"),
    ("1 and 2", "calc.node_not_allowed"),
    ("1 if 1 else 2", "calc.node_not_allowed"),
    ("max(*(1, 2))", "calc.node_not_allowed"),
    ("x + 1", "calc.unknown_name"),
    ("__builtins__", "calc.unknown_name"),
    ("eval(1)", "calc.function_not_allowed"),
    ("__import__(1)", "calc.function_not_allowed"),
    ("pow(2, 3)", "calc.function_not_allowed"),
    ("max(1)", "calc.bad_arity"),
    ("sqrt()", "calc.bad_arity"),
    ("+".join(["1"] * 61), "calc.too_many_nodes"),
    ("-" * 25 + "1", "calc.too_deep"),
    ("1000000000000000000", "calc.number_too_large"),
    ("9**9**9", "calc.exponent_too_large"),
    ("10 ** 100", "calc.exponent_too_large"),
    ("2 ** 64 * 2", "calc.result_too_large"),
    ("10**15 * 10", "calc.result_too_large"),
    ("999999999999999.0 ** 64", "calc.result_too_large"),
    ("1 / 0", "calc.division_by_zero"),
    ("5 % 0", "calc.division_by_zero"),
    ("0 ** -1", "calc.division_by_zero"),
    ("sqrt(-1)", "calc.math_domain"),
    ("log(0)", "calc.math_domain"),
    ("log(8, 1)", "calc.math_domain"),
    ("(-8) ** 0.5", "calc.math_domain"),
    ("round(1.5, 0.5)", "calc.math_domain"),
]


@pytest.mark.parametrize("expr,rule", CALC_BLOCKED)
def test_blocked(expr, rule):
    v = check_and_eval(expr)
    assert not v.allowed
    assert v.rule == rule, v
