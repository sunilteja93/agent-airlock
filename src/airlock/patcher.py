"""Muse-assisted patch generation with a narrow deterministic execution boundary."""

import ast
import json
import re

from airlock.meta_client import complete


ALLOWED_EXPR_NODES = (
    ast.Expression,
    ast.BinOp,
    ast.Name,
    ast.Load,
    ast.Constant,
    ast.Add,
    ast.Sub,
    ast.Mult,
    ast.Div,
    ast.FloorDiv,
    ast.Mod,
    ast.Pow,
    ast.USub,
    ast.UnaryOp,
)


def _extract_json(text: str) -> dict:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped)
        stripped = re.sub(r"\s*```$", "", stripped)

    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", stripped, flags=re.DOTALL)
        if not match:
            raise ValueError(f"Model did not return JSON: {text}")
        return json.loads(match.group(0))


def propose_return_expression(*, goal: str, source: str) -> str:
    """Ask Muse for the smallest repair to the demo arithmetic function."""
    prompt = f"""
You are repairing a tiny Python function inside a security demo.

USER GOAL:
{goal}

CURRENT FILE:
{source}

Return ONLY JSON with this exact shape:
{{"return_expression":"a Python expression using only a, b, numbers, and arithmetic operators"}}

Do not return imports, function calls, attribute access, statements, Markdown, or prose.
""".strip()

    data = _extract_json(complete(prompt))
    expression = data.get("return_expression")
    if not isinstance(expression, str) or not expression.strip():
        raise ValueError("Muse did not provide a return_expression.")
    return expression.strip()


def validate_expression(expression: str) -> ast.Expression:
    """Reject anything outside the demo sandbox expression language."""
    tree = ast.parse(expression, mode="eval")

    for node in ast.walk(tree):
        if not isinstance(node, ALLOWED_EXPR_NODES):
            raise ValueError(f"Disallowed syntax in patch: {type(node).__name__}")
        if isinstance(node, ast.Name) and node.id not in {"a", "b"}:
            raise ValueError(f"Disallowed name in patch: {node.id}")

    return tree


def apply_return_expression(source: str, expression: str) -> str:
    """Replace the return expression after validation."""
    validate_expression(expression)
    lines = source.splitlines()
    replaced = False

    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("return "):
            indent = line[: len(line) - len(line.lstrip())]
            lines[index] = f"{indent}return {expression}"
            replaced = True
            break

    if not replaced:
        raise ValueError("Demo source contains no return statement to replace.")

    return "\n".join(lines) + "\n"


def evaluate_expression(expression: str, *, a: int, b: int) -> int | float:
    """Execute only the validated arithmetic expression with no builtins."""
    tree = validate_expression(expression)
    code = compile(tree, "<airlock-expression>", "eval")
    return eval(code, {"__builtins__": {}}, {"a": a, "b": b})
