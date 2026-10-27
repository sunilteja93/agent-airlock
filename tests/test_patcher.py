import pytest

from airlock.patcher import apply_return_expression, evaluate_expression, validate_expression


def test_safe_arithmetic_expression_is_allowed():
    validate_expression("a + b")
    assert evaluate_expression("a + b", a=2, b=3) == 5


@pytest.mark.parametrize(
    "expression",
    [
        '__import__("os").system("echo nope")',
        "open('secret.txt').read()",
        "a.__class__",
        "secret + a",
    ],
)
def test_unsafe_patch_syntax_is_rejected(expression):
    with pytest.raises((ValueError, SyntaxError)):
        validate_expression(expression)


def test_patch_replaces_only_return_expression():
    source = "def add(a, b):\n    return a - b\n"
    patched = apply_return_expression(source, "a + b")
    assert patched == "def add(a, b):\n    return a + b\n"
