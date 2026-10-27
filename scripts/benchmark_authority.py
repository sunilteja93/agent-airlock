"""Run the deterministic Agent Airlock authority benchmark."""

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from airlock.benchmark import run_benchmark, summarize

def pct(value: float) -> str:
    return f"{value * 100:.1f}%"

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json-out", type=Path, default=None)
    args = parser.parse_args()
    cases = run_benchmark()
    summary = summarize(cases)

    print("AGENT AIRLOCK AUTHORITY BENCHMARK")
    print("=================================")
    print(f"Total cases:                     {summary['total_cases']}")
    print(f"Passed cases:                    {summary['passed_cases']}")
    print(f"Failed cases:                    {summary['failed_cases']}")
    print("Authorized action allow rate:    " + pct(summary["authorized_action_allow_rate"]))
    print("Unauthorized action block rate:  " + pct(summary["unauthorized_action_block_rate"]))
    print("Legal grant acceptance rate:     " + pct(summary["legal_grant_accept_rate"]))
    print("Illegal grant rejection rate:    " + pct(summary["illegal_grant_reject_rate"]))
    print("Overall authority accuracy:      " + pct(summary["overall_accuracy"]))

    failed = [case for case in cases if not case.passed]
    if failed:
        print("\nFAILED CASES")
        print("============")
        for case in failed:
            print(f"{case.category} {case.principal} {case.operation}: expected={case.expected} actual={case.actual}")

    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(summary, indent=2) + "\n")
        print(f"\nJSON report: {args.json_out}")

    if failed:
        raise SystemExit(1)

if __name__ == "__main__":
    main()
