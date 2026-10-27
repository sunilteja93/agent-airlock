"""Run randomized Agent Airlock authority fuzzing."""

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from airlock.fuzz import run_fuzz


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--graphs", type=int, default=10_000)
    parser.add_argument("--seed", type=int, default=20261027)
    parser.add_argument("--json-out", type=Path, default=None)
    args = parser.parse_args()

    result = run_fuzz(graphs=args.graphs, seed=args.seed)

    print("AGENT AIRLOCK RANDOMIZED AUTHORITY FUZZ")
    print("=======================================")
    print(f"Seed:                    {result.seed}")
    print(f"Random graphs:           {result.graphs}")
    print(f"Principals generated:    {result.principals}")
    print(f"Delegation edges checked:{result.edges_checked:>8}")
    print(f"Action checks:           {result.actions_checked}")
    print(f"Illegal grants checked:  {result.illegal_grants_checked}")
    print(f"Invariant failures:      {result.failures}")

    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(result.as_dict(), indent=2) + "\n")
        print(f"JSON report:             {args.json_out}")

    if result.failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
