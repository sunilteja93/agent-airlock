"""Core authority primitives for Agent Airlock."""

from dataclasses import dataclass, field
from enum import Enum


class Decision(str, Enum):
    ALLOW = "allow"
    CONSTRAIN = "constrain"
    BLOCK = "block"


@dataclass(frozen=True)
class Source:
    name: str
    trusted: bool
    capabilities: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class ProposedAction:
    name: str
    required_capabilities: frozenset[str]
    source: Source


@dataclass(frozen=True)
class AuthorityDecision:
    decision: Decision
    missing_capabilities: frozenset[str]
    reason: str


def authorize(action: ProposedAction) -> AuthorityDecision:
    """Authorize an action against the capabilities held by its originating source."""
    missing = action.required_capabilities - action.source.capabilities

    if missing:
        return AuthorityDecision(
            decision=Decision.BLOCK,
            missing_capabilities=frozenset(missing),
            reason=(
                f"{action.source.name} cannot authorize: "
                + ", ".join(sorted(missing))
            ),
        )

    return AuthorityDecision(
        decision=Decision.ALLOW,
        missing_capabilities=frozenset(),
        reason=f"{action.source.name} has the required authority.",
    )
