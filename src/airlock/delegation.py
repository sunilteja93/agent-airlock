"""Delegation-aware authority graph for multi-agent systems."""

from dataclasses import dataclass

from airlock.authority import Decision
from airlock.policy import ACTION_CAPABILITIES


@dataclass(frozen=True)
class Grant:
    parent: str
    child: str
    capabilities: frozenset[str]


@dataclass(frozen=True)
class DelegationDecision:
    decision: Decision
    principal: str
    action: str
    effective_capabilities: frozenset[str]
    missing_capabilities: frozenset[str]
    reason: str


class AuthorityGraph:
    """Track capability grants from a root principal through delegated agents."""

    def __init__(self, root: str, root_capabilities: frozenset[str]):
        self.root = root
        self.root_capabilities = root_capabilities
        self._grants: dict[str, Grant] = {}

    def grant(self, parent: str, child: str, capabilities: frozenset[str]) -> None:
        if child == self.root:
            raise ValueError("Cannot delegate authority back to the root principal.")
        if child in self._grants:
            raise ValueError(f"Principal {child!r} already has a parent grant.")

        parent_caps = self.effective_capabilities(parent)
        excessive = capabilities - parent_caps
        if excessive:
            raise ValueError(
                f"{parent!r} cannot delegate capabilities it does not hold: "
                + ", ".join(sorted(excessive))
            )

        self._grants[child] = Grant(
            parent=parent,
            child=child,
            capabilities=frozenset(capabilities),
        )

    def grant_for(self, principal: str) -> Grant | None:
        """Return the direct parent grant for a delegated principal."""
        return self._grants.get(principal)

    def effective_capabilities(self, principal: str) -> frozenset[str]:
        if principal == self.root:
            return self.root_capabilities

        grant = self._grants.get(principal)
        if grant is None:
            return frozenset()

        parent_caps = self.effective_capabilities(grant.parent)
        return frozenset(grant.capabilities & parent_caps)

    def lineage(self, principal: str) -> tuple[str, ...]:
        if principal == self.root:
            return (self.root,)

        chain = [principal]
        current = principal
        seen = set()

        while current != self.root:
            if current in seen:
                raise ValueError("Cycle detected in authority graph.")
            seen.add(current)

            grant = self._grants.get(current)
            if grant is None:
                return tuple(reversed(chain))

            current = grant.parent
            chain.append(current)

        return tuple(reversed(chain))


def evaluate_delegated_action(
    *,
    graph: AuthorityGraph,
    principal: str,
    action: str,
) -> DelegationDecision:
    required = ACTION_CAPABILITIES.get(action)
    if required is None:
        return DelegationDecision(
            decision=Decision.BLOCK,
            principal=principal,
            action=action,
            effective_capabilities=graph.effective_capabilities(principal),
            missing_capabilities=frozenset({"unknown.action"}),
            reason=f"Unknown action {action!r} is not executable.",
        )

    effective = graph.effective_capabilities(principal)
    missing = required - effective

    if missing:
        return DelegationDecision(
            decision=Decision.BLOCK,
            principal=principal,
            action=action,
            effective_capabilities=effective,
            missing_capabilities=frozenset(missing),
            reason=(
                f"{principal} has no delegated authority for: "
                + ", ".join(sorted(missing))
            ),
        )

    return DelegationDecision(
        decision=Decision.ALLOW,
        principal=principal,
        action=action,
        effective_capabilities=effective,
        missing_capabilities=frozenset(),
        reason=f"{principal} holds the required delegated authority.",
    )
