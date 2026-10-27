# Authority Benchmark

Agent Airlock evaluates one explicit security property:

> Authority may stay the same or decrease as it is delegated, but it must not increase without a valid upstream grant.

The deterministic benchmark contains 60 cases and makes no model API calls.

## Action authorization

Thirty cases evaluate six tool actions across five principals:
`user`, `planner`, `code_worker`, `setup_worker`, and `repo_tool`.

Authorized repository operations must be allowed. Secret and network operations
that are outside a principal capability set must be blocked.

## Delegation authorization

Thirty cases attempt six capability grants from each of the same five principals.
Legal subset grants must be accepted. Grants containing authority the parent does
not possess must be rejected.

Every accepted child grant is also checked for the monotonicity invariant:

`child effective authority ⊆ parent effective authority`

## Running

```bash
python scripts/benchmark_authority.py
```

To save a machine-readable report:

```bash
python scripts/benchmark_authority.py --json-out evals/results/authority_benchmark.json
```

These measurements test Airlock authority enforcement. They are not a claim that
Airlock prevents every possible agent security failure.
