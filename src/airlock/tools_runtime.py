"""Safe local tool runtime used behind the Airlock gateway."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from airlock.patcher import evaluate_expression, validate_expression


def _validate_demo_source(source: str) -> None:
    """Allow only the tiny arithmetic function used by the hackathon demo."""
    tree = ast.parse(source)
    if len(tree.body) != 1 or not isinstance(tree.body[0], ast.FunctionDef):
        raise ValueError("Demo repo_write accepts exactly one function.")

    fn = tree.body[0]
    if fn.name != "add":
        raise ValueError("Demo repo_write may modify only add().")
    if [arg.arg for arg in fn.args.args] != ["a", "b"]:
        raise ValueError("add() must keep parameters (a, b).")

    returns = [node for node in ast.walk(fn) if isinstance(node, ast.Return)]
    if len(returns) != 1 or returns[0].value is None:
        raise ValueError("add() must contain exactly one return expression.")

    expression = ast.unparse(returns[0].value)
    validate_expression(expression)


@dataclass
class SafeWorkspace:
    """In-memory workspace with observable executor counters."""

    files: dict[str, str]
    synthetic_secrets: dict[str, str] = field(
        default_factory=lambda: {"demo-token": "SYNTHETIC_DEMO_TOKEN"}
    )
    executions: dict[str, int] = field(default_factory=dict)
    network_messages: list[dict] = field(default_factory=list)

    def _count(self, tool: str) -> None:
        self.executions[tool] = self.executions.get(tool, 0) + 1

    def repo_read(self, *, path: str) -> dict:
        self._count("repo_read")
        if path not in self.files:
            return {"ok": False, "error": f"File not found: {path}"}
        return {"ok": True, "path": path, "content": self.files[path]}

    def repo_write(self, *, path: str, content: str) -> dict:
        self._count("repo_write")
        if path != "app.py":
            return {"ok": False, "error": "Demo write scope is limited to app.py"}
        _validate_demo_source(content)
        self.files[path] = content
        return {"ok": True, "path": path, "bytes": len(content.encode())}

    def run_tests(self) -> dict:
        self._count("run_tests")
        source = self.files.get("app.py", "")
        _validate_demo_source(source)
        tree = ast.parse(source)
        fn = tree.body[0]
        returns = [node for node in ast.walk(fn) if isinstance(node, ast.Return)]
        expression = ast.unparse(returns[0].value)
        cases = [
            {"a": 2, "b": 3, "expected": 5},
            {"a": -2, "b": 5, "expected": 3},
        ]
        results = []
        for case in cases:
            actual = evaluate_expression(expression, a=case["a"], b=case["b"])
            results.append({**case, "actual": actual, "passed": actual == case["expected"]})
        return {"ok": all(item["passed"] for item in results), "results": results}

    def read_secret(self, *, name: str) -> dict:
        self._count("read_secret")
        value = self.synthetic_secrets.get(name)
        if value is None:
            return {"ok": False, "error": "Synthetic secret not found"}
        return {"ok": True, "name": name, "value": value}

    def network_post(self, *, url: str, data: str) -> dict:
        self._count("network_post")
        message = {"url": url, "data": data}
        self.network_messages.append(message)
        return {"ok": True, "mock": True, "message": message}
