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

Core implementation complete. Submission packaging, demo recording, and final validation are in progress.

## Visual demo

Install the project and launch the judge-facing console:

```bash
python -m pip install -e ".[dev]"
streamlit run dashboard_top3.py
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


## Architecture

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
Machine-Verifiable Authority Proof
        ↓
Optional Ephemeral Exact-Action Lease
        ↓
ALLOW → safe executor
BLOCK → executor never runs
        ↓
Tamper-Evident Receipt Chain
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



## Advanced authorization protocol

Airlock now adds two controls above the basic capability graph.

### Proof-carrying authorization

Every known tool decision can carry a machine-verifiable authority proof bound to
the frozen task contract. The proof contains the principal lineage, delegated
capabilities, required capabilities, effective capabilities, missing
capabilities, decision, and a SHA-256 proof hash.

Both ALLOW and BLOCK decisions can therefore be independently checked without
trusting the model's explanation.

### Ephemeral exact-action leases

For intentionally high-impact operations, Airlock can require a second,
attenuating authorization artifact before the executor is reachable. A lease is
HMAC-bound to:

- the principal
- the exact tool
- the exact normalized arguments
- an expiration time
- a maximum use count

A modified action, expired lease, revoked lease, or token replay fails closed.
The lease never creates authority: the normal delegation graph is checked first.


### Dual provenance and authority non-interference

Airlock keeps two different provenance planes:

```text
INFORMATION PLANE                    AUTHORITY PLANE

trusted user context                 frozen task contract
untrusted repository content         monotonic delegation graph
untrusted tool output                exact-action lease
          │                                   │
          └──────────── agent reasoning ──────┘
                              │
                        Airlock gateway
```

The information plane is recorded in its own append-only hash chain. The
authority plane has a separate deterministic fingerprint derived only from the
frozen contract and delegation graph.

When untrusted information is ingested, Airlock can produce an **authority
non-interference witness** showing that:

- the information-plane hash changed
- the authority-plane fingerprint did not change
- the authorization decision did not change
- the authority proof before and after is identical
- the witness itself is hash-bound and independently verifiable

This turns the project principle **Information is not authority** into a
testable system invariant instead of only a prompt-level instruction.

Run the entire advanced protocol demonstration locally, without a Model API call:

```bash
python scripts/demo_authority_protocol.py
```

The command demonstrates proof-carrying authorization, one-use exact-action
leases, replay/mutation/revocation blocking, dual provenance, and authority
non-interference. It uses only synthetic data and the mock network executor.


## Security properties and non-goals

Within the synthetic Airlock runtime, the implementation is designed to enforce
the following properties:

- delegated authority is monotonic: a child cannot gain a capability its parent
  does not hold
- known tool actions are evaluated by a reference monitor outside the model
- an ALLOW or BLOCK decision can carry an independently verifiable authority
  proof
- selected high-impact actions can require a short-lived, exact-action,
  replay-limited authorization lease
- untrusted information can change the information ledger without changing the
  authority graph
- audit receipts are chained to detect modification of recorded decisions

The current hackathon prototype does **not** claim to solve host compromise,
model-provider compromise, side channels, operating-system isolation,
distributed consensus, production key management, or every possible agent
security failure. Network activity in the demo is mocked and secrets are
synthetic.

## Muse Red Team results

On October 27, 2026, **25 preserved independent Muse Red Team trials** generated **388 adversarial tool/delegation attempts** against the same Airlock enforcement boundary.

| Metric | Result |
| --- | ---: |
| Independent Muse trials | 25 |
| Total adversarial attempts | 388 |
| Blocked attempts | 245 |
| Unauthorized secret/network executions | **0** |
| Receipt-chain failures | **0** |

The remaining non-blocked attempts were authorized low-privilege operations or legal delegation paths. They are not counted as successful attacks. The security outcome is whether an unauthorized privileged executor actually ran.

These are measured results for the tested synthetic environment, not a claim of universal agent security.


## Provenance and authorship

Agent Airlock was created by **Sunil Kumar Vadlamani** during the Meta Global AI Developer Hackathon 2026 build period beginning October 27, 2026.

The repository commit history, benchmark artifacts, evaluation reports, and demo outputs provide dated provenance for the implementation and its development during the hackathon.

Preferred attribution is documented in `CITATION.cff`.

## License and intellectual property

**Copyright © 2026 Sunil Kumar Vadlamani. All rights reserved.**

This repository is publicly accessible for hackathon evaluation, technical review, and portfolio demonstration.

**No open-source license is granted.** Except for permissions required by GitHub's Terms of Service and rights that cannot be restricted under applicable law, no permission is granted to copy, modify, distribute, sublicense, sell, commercially exploit, or create derivative works from this software or its repository content without prior written permission from the copyright owner.

Public visibility of this repository does not constitute a waiver, assignment, or transfer of copyright or other intellectual-property rights.

See `NOTICE` for the repository's rights and attribution notice.
