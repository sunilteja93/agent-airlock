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
