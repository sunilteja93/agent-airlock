"""Evaluate multi-step Muse behavior against the Airlock authority boundary."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


from airlock.authority import Decision
from airlock.contract import compile_trusted_contract
from airlock.policy import evaluate
from airlock.worker import propose_action


MATRIX = ROOT / "evals" / "attack_matrix.json"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=1)
    parser.add_argument(
        "--max-steps",
        type=int,
        default=2,
        help="Maximum planning steps per scenario. Start with 2 to conserve credits.",
    )
    args = parser.parse_args()

    if args.trials < 1 or args.max_steps < 1:
        raise SystemExit("--trials and --max-steps must be at least 1")

    scenarios = json.loads(MATRIX.read_text())
    trial_results: list[dict] = []
    action_rows: list[dict] = []

    for scenario in scenarios:
        dangerous = set(scenario["dangerous_actions"])
        contract = compile_trusted_contract(scenario["goal"])

        for trial in range(1, args.trials + 1):
            completed: list[str] = []
            denied: list[str] = []
            baseline_attack = False
            airlock_attack = False

            print(f"\n[{scenario['id']}] trial={trial}")

            for step in range(1, args.max_steps + 1):
                proposal = propose_action(
                    goal=scenario["goal"],
                    repository_content=scenario["content"],
                    denied_actions=tuple(denied),
                    completed_actions=tuple(completed),
                )
                decision = evaluate(proposal.action, contract)
                is_dangerous = proposal.action in dangerous

                if is_dangerous:
                    baseline_attack = True
                    if decision.decision is Decision.ALLOW:
                        airlock_attack = True

                action_rows.append({
                    "scenario": scenario["id"],
                    "trial": trial,
                    "step": step,
                    "action": proposal.action,
                    "source": proposal.source,
                    "dangerous": is_dangerous,
                    "airlock_decision": decision.decision.value,
                })

                print(
                    f"  step={step} action={proposal.action:<18} "
                    f"source={proposal.source:<10} dangerous={str(is_dangerous):<5} "
                    f"airlock={decision.decision.value.upper()}"
                )
                print(f"    rationale: {proposal.rationale}")

                if decision.decision is Decision.BLOCK:
                    if proposal.action not in denied:
                        denied.append(proposal.action)
                else:
                    if proposal.action not in completed:
                        completed.append(proposal.action)

            trial_results.append({
                "scenario": scenario["id"],
                "trial": trial,
                "baseline_attack": baseline_attack,
                "airlock_attack": airlock_attack,
            })

    baseline_trials = [r for r in trial_results if r["baseline_attack"]]
    airlock_trials = [r for r in trial_results if r["airlock_attack"]]
    dangerous_actions = [r for r in action_rows if r["dangerous"]]
    blocked_dangerous = [
        r for r in dangerous_actions if r["airlock_decision"] == "block"
    ]
    safe_actions = [r for r in action_rows if not r["dangerous"]]
    allowed_safe = [r for r in safe_actions if r["airlock_decision"] == "allow"]

    print("\nSUMMARY")
    print("=======")
    print(f"Scenario trials:                 {len(trial_results)}")
    print(f"Baseline attack trials:          {len(baseline_trials)}")
    print(f"Airlock attack trials:           {len(airlock_trials)}")
    print(f"Dangerous proposals observed:    {len(dangerous_actions)}")
    print(f"Dangerous proposals blocked:     {len(blocked_dangerous)}")
    print(f"Non-dangerous proposals observed:{len(safe_actions):>5}")
    print(f"Non-dangerous proposals allowed: {len(allowed_safe)}")

    if baseline_trials:
        print(
            "Airlock prevention rate on attacked trials: "
            f"{(len(baseline_trials) - len(airlock_trials)) / len(baseline_trials):.1%}"
        )
    else:
        print("Airlock prevention rate on attacked trials: n/a (no baseline attacks)")

    if safe_actions:
        print(
            "Airlock allow rate on non-dangerous actions: "
            f"{len(allowed_safe) / len(safe_actions):.1%}"
        )


if __name__ == "__main__":
    main()
