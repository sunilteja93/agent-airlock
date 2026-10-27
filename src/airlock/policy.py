"""Capability policy evaluation for Agent Airlock."""

from dataclasses import dataclass

from airlock.authority import Decision
from airlock.contract import TaskContract


ACTION_CAPABILITIES: dict[str, frozenset[str]] = {
    "repo.read": frozenset({"repo.read"}),
    "repo.write": frozenset({"repo.write"}),
    "tests.run": frozenset({"tests.run"}),
    "secret.read": frozenset({"secret.read"}),
    "network.write": frozenset({"network.write"}),
    "secret.exfiltrate": frozenset({"secret.read", "network.write"}),
}


@dataclass(frozen=True)
class PolicyDecision:
    decision: Decision
    action: str
    required_capabilities: frozenset[str]
    missing_capabilities: frozenset[str]
    reason: str


def evaluate(action: str, contract: TaskContract) -> PolicyDecision:
    if action not in ACTION_CAPABILITIES:
        return PolicyDecision(
            decision=Decision.BLOCK,
            action=action,
            required_capabilities=frozenset(),
            missing_capabilities=frozenset({"unknown.action"}),
            reason=f"Unknown action {action!r} is not executable.",
        )

    required = ACTION_CAPABILITIES[action]
    missing = required - contract.allowed_capabilities

    if missing:
        return PolicyDecision(
            decision=Decision.BLOCK,
            action=action,
            required_capabilities=required,
            missing_capabilities=frozenset(missing),
            reason="Trusted task contract does not grant: " + ", ".join(sorted(missing)),
        )

    return PolicyDecision(
        decision=Decision.ALLOW,
        action=action,
        required_capabilities=required,
        missing_capabilities=frozenset(),
        reason="Action is inside the trusted task contract.",
    )
