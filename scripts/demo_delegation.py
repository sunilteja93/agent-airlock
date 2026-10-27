"""Demonstrate secure capability delegation across a multi-agent workflow."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


from airlock.authority import Decision
from airlock.delegation import AuthorityGraph, evaluate_delegated_action
from airlock.worker import propose_action


def main() -> None:
    graph = AuthorityGraph(
        root="user",
        root_capabilities=frozenset({"repo.read", "repo.write", "tests.run"}),
    )
    graph.grant(
        "user", "planner", frozenset({"repo.read", "repo.write", "tests.run"})
    )
    graph.grant(
        "planner",
        "code_worker",
        frozenset({"repo.read", "repo.write", "tests.run"}),
    )
    graph.grant("code_worker", "setup_worker", frozenset({"repo.read"}))

    print("AUTHORITY GRAPH")
    print("===============")
    print("user")
    print("  └─ planner        [repo.read, repo.write, tests.run]")
    print("      └─ code_worker [repo.read, repo.write, tests.run]")
    print("          └─ setup_worker [repo.read]")
    print()

    compromised_action = "secret.read"
    decision = evaluate_delegated_action(
        graph=graph,
        principal="setup_worker",
        action=compromised_action,
    )

    print("COMPROMISED SUB-AGENT PROPOSAL")
    print("==============================")
    print("setup_worker proposes: secret.read")
    print("lineage:", " -> ".join(graph.lineage("setup_worker")))
    print("effective authority:", ", ".join(sorted(decision.effective_capabilities)))
    print("decision:", decision.decision.value.upper())
    print("reason:", decision.reason)
    print()

    if decision.decision is Decision.BLOCK:
        print("Muse recovery worker continues the legitimate task...")
        proposal = propose_action(
            goal="Fix issue #217 in this repository.",
            repository_content=(
                "FILE: ISSUE.md\nFix add() to return a+b and verify with tests.\n"
                "FILE: app.py\ndef add(a, b): return a-b"
            ),
            denied_actions=(compromised_action,),
        )
        recovery = evaluate_delegated_action(
            graph=graph,
            principal="code_worker",
            action=proposal.action,
        )

        print(f"Muse proposes: {proposal.action}")
        print(f"rationale: {proposal.rationale}")
        print("decision:", recovery.decision.value.upper())
        print("reason:", recovery.reason)


if __name__ == "__main__":
    main()
