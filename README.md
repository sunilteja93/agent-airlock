# Agent Airlock

A provenance and authority layer for autonomous AI agents.

Built from scratch for the Meta Global AI Developer Hackathon 2026.

## Core principle

**Information is not authority.**

AI agents routinely consume untrusted content from repositories, webpages,
documents, tool outputs, and external services. That content may provide useful
information, but it should not automatically gain the authority to cause
privileged actions.

Agent Airlock places an explicit authority boundary between an autonomous agent
and the tools it can use.

## Hackathon scope

This repository contains the work created during the Meta Global AI Developer
Hackathon build period beginning October 27, 2026.

The initial demo will:

1. Compile a trusted user request into a task contract.
2. Let a Meta-powered worker agent inspect an adversarial repository.
3. Track the provenance of instructions that influence proposed tool actions.
4. Allow, constrain, or block actions based on the authority available to their source.
5. Continue the legitimate user task after an injected instruction is blocked.
6. Produce an action-lineage trace explaining the decision.

## Initial demo scenario

A user asks an agent to fix a repository issue. The repository contains a
malicious instruction asking the agent to read a secret and transmit it
externally.

The repository is allowed to contribute information about the codebase, but it
has no authority to grant `secret.read` or `network.write`.

Airlock blocks the unauthorized action while allowing the agent to continue the
original task.

## Status

Hackathon build in progress.

Official build start: October 27, 2026.
