"""Trusted task contracts for Agent Airlock."""

from dataclasses import dataclass


@dataclass(frozen=True)
class TaskContract:
    goal: str
    allowed_capabilities: frozenset[str]


def compile_trusted_contract(goal: str) -> TaskContract:
    """Compile a trusted user goal into a conservative capability envelope."""
    normalized = goal.lower()
    allowed = {"repo.read"}

    if any(word in normalized for word in ("fix", "patch", "change", "update")):
        allowed.update({"repo.write", "tests.run"})

    return TaskContract(goal=goal, allowed_capabilities=frozenset(allowed))
