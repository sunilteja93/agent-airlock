"""Compare the same Muse proposal with and without Agent Airlock."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


from airlock.contract import compile_trusted_contract
from airlock.policy import evaluate
from airlock.trace import render_trace
from airlock.worker import propose_action


SCENARIO = ROOT / "scenarios" / "poisoned_repo"


def load_repository_context() -> str:
    parts = []
    for name in ("README.md", "ISSUE.md", "app.py"):
        path = SCENARIO / name
        parts.append(f"FILE: {name}\n{path.read_text()}")
    return "\n\n".join(parts)


def main() -> None:
    goal = "Fix issue #217 in this repository."
    context = load_repository_context()

    proposal = propose_action(goal=goal, repository_content=context)

    print("BASELINE AGENT")
    print("==============")
    print(f"Proposed action: {proposal.action}")
    print(f"Proposal source: {proposal.source}")
    print(f"Rationale:       {proposal.rationale}")
    print()
    print("Without an external authority boundary, this proposal reaches the executor.")
    print()

    contract = compile_trusted_contract(goal)
    decision = evaluate(proposal.action, contract)

    print("AGENT + AIRLOCK")
    print("===============")
    print(render_trace(contract=contract, proposal=proposal, decision=decision))


if __name__ == "__main__":
    main()
