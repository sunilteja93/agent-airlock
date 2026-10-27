"""Deterministic authority benchmark for Agent Airlock."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Iterable

from airlock.authority import Decision
from airlock.delegation import AuthorityGraph, evaluate_delegated_action
from airlock.policy import ACTION_CAPABILITIES

ROOT_CAPABILITIES = frozenset({"repo.read", "repo.write", "tests.run"})
PRINCIPALS = ("user", "planner", "code_worker", "setup_worker", "repo_tool")
GRANT_BUNDLES = (
    frozenset({"repo.read"}),
    frozenset({"repo.write"}),
    frozenset({"tests.run"}),
    frozenset({"secret.read"}),
    frozenset({"network.write"}),
    frozenset({"repo.read", "repo.write"}),
)

@dataclass(frozen=True)
class BenchmarkCase:
    category: str
    principal: str
    operation: str
    expected: str
    actual: str
    passed: bool

def build_graph() -> AuthorityGraph:
    graph = AuthorityGraph(root="user", root_capabilities=ROOT_CAPABILITIES)
    graph.grant("user", "planner", ROOT_CAPABILITIES)
    graph.grant("planner", "code_worker", ROOT_CAPABILITIES)
    graph.grant("code_worker", "setup_worker", frozenset({"repo.read"}))
    graph.grant("code_worker", "repo_tool", frozenset({"repo.read"}))
    return graph

def action_cases() -> list[BenchmarkCase]:
    graph = build_graph()
    rows: list[BenchmarkCase] = []
    for principal in PRINCIPALS:
        effective = graph.effective_capabilities(principal)
        for action, required in ACTION_CAPABILITIES.items():
            expected = Decision.ALLOW.value if required.issubset(effective) else Decision.BLOCK.value
            result = evaluate_delegated_action(graph=graph, principal=principal, action=action)
            rows.append(BenchmarkCase(
                category="action",
                principal=principal,
                operation=action,
                expected=expected,
                actual=result.decision.value,
                passed=result.decision.value == expected,
            ))
    return rows

def grant_cases() -> list[BenchmarkCase]:
    rows: list[BenchmarkCase] = []
    for principal in PRINCIPALS:
        for index, bundle in enumerate(GRANT_BUNDLES, start=1):
            graph = build_graph()
            effective = graph.effective_capabilities(principal)
            expected = "accept" if bundle.issubset(effective) else "reject"
            child = f"bench_child_{principal}_{index}"
            try:
                graph.grant(principal, child, bundle)
                actual = "accept"
                if not graph.effective_capabilities(child).issubset(effective):
                    actual = "monotonicity_violation"
            except ValueError:
                actual = "reject"
            rows.append(BenchmarkCase(
                category="grant",
                principal=principal,
                operation="delegate:" + ",".join(sorted(bundle)),
                expected=expected,
                actual=actual,
                passed=actual == expected,
            ))
    return rows

def run_benchmark() -> list[BenchmarkCase]:
    return action_cases() + grant_cases()

def summarize(cases: Iterable[BenchmarkCase]) -> dict:
    rows = list(cases)
    action_rows = [row for row in rows if row.category == "action"]
    grant_rows = [row for row in rows if row.category == "grant"]
    unauthorized = [row for row in action_rows if row.expected == Decision.BLOCK.value]
    authorized = [row for row in action_rows if row.expected == Decision.ALLOW.value]
    illegal_grants = [row for row in grant_rows if row.expected == "reject"]
    legal_grants = [row for row in grant_rows if row.expected == "accept"]

    def rate(group: list[BenchmarkCase]) -> float:
        return 1.0 if not group else sum(row.passed for row in group) / len(group)

    return {
        "total_cases": len(rows),
        "passed_cases": sum(row.passed for row in rows),
        "failed_cases": sum(not row.passed for row in rows),
        "authorized_action_allow_rate": rate(authorized),
        "unauthorized_action_block_rate": rate(unauthorized),
        "legal_grant_accept_rate": rate(legal_grants),
        "illegal_grant_reject_rate": rate(illegal_grants),
        "overall_accuracy": rate(rows),
        "cases": [asdict(row) for row in rows],
    }
