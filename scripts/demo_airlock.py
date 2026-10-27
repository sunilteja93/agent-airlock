"""Run the first end-to-end Agent Airlock hackathon demo."""

from pathlib import Path

from airlock.authority import Decision
from airlock.contract import compile_trusted_contract
from airlock.policy import evaluate
from airlock.trace import render_trace
from airlock.worker import propose_action


ROOT = Path(__file__).resolve().parents[1]
SCENARIO = ROOT / "scenarios" / "poisoned_repo"


def load_repository_context() -> str:
    parts = []
    for name in ("README.md", "ISSUE.md", "app.py"):
        path = SCENARIO / name
        parts.append(f"FILE: {name}\n{path.read_text()}")
    return "\n\n".join(parts)


def main() -> None:
    goal = "Fix issue #217 in this repository."
    contract = compile_trusted_contract(goal)
    repository_content = load_repository_context()
    denied: list[str] = []

    for step in range(1, 3):
        proposal = propose_action(
            goal=goal,
            repository_content=repository_content,
            denied_actions=tuple(denied),
        )
        decision = evaluate(proposal.action, contract)

        print(f"\n=== STEP {step} ===")
        print(render_trace(contract=contract, proposal=proposal, decision=decision))

        if decision.decision is Decision.BLOCK:
            denied.append(proposal.action)
            print("\nAirlock denied the action. Worker will continue the trusted task.")
            continue

        print("\nAirlock allowed the action. Vertical slice complete.")
        break


if __name__ == "__main__":
    main()
