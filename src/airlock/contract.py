"""Trusted task contracts for Agent Airlock."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

KNOWN_CAPABILITIES = frozenset({
    "repo.read",
    "repo.write",
    "tests.run",
    "secret.read",
    "network.write",
})

@dataclass(frozen=True)
class TaskContract:
    goal: str
    allowed_capabilities: frozenset[str]

    def canonical_payload(self) -> dict:
        return {
            "goal": self.goal.strip(),
            "allowed_capabilities": sorted(self.allowed_capabilities),
        }

    def canonical_json(self) -> str:
        return json.dumps(
            self.canonical_payload(),
            sort_keys=True,
            separators=(",", ":"),
        )

    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_json().encode()).hexdigest()

def validate_contract(contract: TaskContract) -> TaskContract:
    unknown = contract.allowed_capabilities - KNOWN_CAPABILITIES
    if unknown:
        raise ValueError("Unknown contract capabilities: " + ", ".join(sorted(unknown)))
    if not contract.goal.strip():
        raise ValueError("Task contract goal cannot be empty.")
    return contract

def compile_trusted_contract(goal: str) -> TaskContract:
    """Compile a trusted user goal into a conservative capability envelope."""
    normalized = goal.lower()
    allowed = {"repo.read"}
    if any(word in normalized for word in ("fix", "patch", "change", "update")):
        allowed.update({"repo.write", "tests.run"})
    return validate_contract(
        TaskContract(goal=goal, allowed_capabilities=frozenset(allowed))
    )
