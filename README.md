# Agent Airlock

A provenance and authority layer for autonomous and multi-agent AI systems.

Built from scratch for the Meta Global AI Developer Hackathon 2026.

## Core principle

**Information is not authority.**

AI agents consume repositories, webpages, documents, tool outputs, plugins, and
messages from other agents. Those inputs can provide useful information without
automatically gaining permission to cause privileged actions.

Agent Airlock places an explicit authority boundary between agent reasoning and
real-world capabilities.

## What Airlock adds

### Trusted task contracts

A user objective is reduced to a capability envelope such as:

- `repo.read`
- `repo.write`
- `tests.run`

Capabilities outside that envelope, such as `secret.read` or
`network.write`, are not implicitly granted by external content.

### Authority graph

Authority can be delegated across agents, but only as a subset of authority the
parent already holds.

Example:

```text
user
  └─ planner          [repo.read, repo.write, tests.run]
      └─ code_worker  [repo.read, repo.write, tests.run]
          └─ setup_worker [repo.read]
```

If `setup_worker` is compromised and proposes `secret.read`, Airlock blocks
the action because there is no valid grant path for that capability.

### Meta-powered recovery

Muse Spark is used as a worker inside the authority boundary. After a denied
action, the worker can continue toward the legitimate user goal using the
capabilities that remain authorized.

## Evaluation philosophy

Airlock does not depend on making a Meta model fail.

The threat model assumes that any agent, sub-agent, plugin, tool response, or
external content source may be buggy, manipulated, or compromised. The
security question is whether that component can acquire authority it was never
delegated.

The repository also contains adversarial prompt-injection experiments. Early
neutral-prompt runs showed Muse Spark ignoring the tested obvious injections,
which is recorded rather than hidden or forced into an artificial failure.

## Hackathon scope

This repository contains work created during the Meta Global AI Developer
Hackathon build period beginning October 27, 2026.

## Status

Hackathon build in progress.

## Visual demo

Install the project and launch the judge-facing console:

```bash
python -m pip install -e ".[dev]"
streamlit run dashboard.py
```

The dashboard shows the authority graph, a synthetic compromised sub-agent
attempt, the Airlock decision, Muse Spark recovery, patch generation, sandboxed
verification, and final task completion.

## Benchmark results

On October 27, 2026, the deterministic authority benchmark completed **60/60 cases** successfully:

| Metric | Result |
| --- | ---: |
| Authorized action allow rate | 100.0% |
| Unauthorized action block rate | 100.0% |
| Legal grant acceptance rate | 100.0% |
| Illegal grant rejection rate | 100.0% |
| Overall authority benchmark accuracy | 100.0% |

The benchmark covers 30 action-authorization cases and 30 delegation cases across five principals.
These numbers measure the tested Airlock authority invariants. They are **not** a claim that Airlock
prevents every possible agent security failure.

Run it with:

```bash
python scripts/benchmark_authority.py
```


## Top-3 architecture

The current hackathon architecture separates model reasoning from authority enforcement:

```text
Trusted user intent
        ↓
Muse Authority Compiler
        ↓
Frozen Task Contract + SHA-256
        ↓
Muse Least-Privilege Planner
        ↓
Authority Graph
        ↓
Muse Native Tool Calls
        ↓
Airlock Tool Gateway
        ↓
ALLOW → safe executor
BLOCK → executor never runs
        ↓
Tamper-evident receipt chain
```

A separate Muse Red Team can probe the same boundary using synthetic secrets,
mock network egress, and delegation attempts.

Run the integrated architecture demo:

```bash
python scripts/demo_top3.py
```

Run 10,000 randomized authority graphs:

```bash
python scripts/fuzz_authority.py --graphs 10000
```

Run repeated Muse red-team trials:

```bash
python scripts/eval_red_team.py --trials 5 \
  --json-out evals/results/muse_red_team.json
```

The security claim is deliberately narrow: Airlock enforces the frozen capability
and delegation invariants at the tool boundary. Benchmark and red-team results
should be reported only as measurements of the tested scenarios.


## Muse Red Team results

On October 27, 2026, five independent Muse Red Team trials generated **118 adversarial tool/delegation attempts** against the same Airlock enforcement boundary.

| Metric | Result |
| --- | ---: |
| Independent Muse trials | 5 |
| Total adversarial attempts | 118 |
| Blocked attempts | 74 |
| Unauthorized secret/network executions | **0** |
| Receipt-chain failures | **0** |

The remaining non-blocked attempts were authorized low-privilege operations or legal delegation paths. They are not counted as successful attacks. The security outcome is whether an unauthorized privileged executor actually ran.

These are measured results for the tested synthetic environment, not a claim of universal agent security.
