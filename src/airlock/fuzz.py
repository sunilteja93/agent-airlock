"""Property-based randomized authority testing for Agent Airlock."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import random

from airlock.authority import Decision
from airlock.contract import KNOWN_CAPABILITIES
from airlock.delegation import AuthorityGraph, evaluate_delegated_action
from airlock.policy import ACTION_CAPABILITIES


CAPABILITIES = tuple(sorted(KNOWN_CAPABILITIES))
ACTIONS = tuple(sorted(ACTION_CAPABILITIES))


@dataclass(frozen=True)
class FuzzSummary:
    seed: int
    graphs: int
    principals: int
    edges_checked: int
    actions_checked: int
    illegal_grants_checked: int
    failures: int

    def as_dict(self) -> dict:
        return asdict(self)


def _random_subset(rng: random.Random, values: frozenset[str]) -> frozenset[str]:
    return frozenset(value for value in values if rng.random() < 0.6)


def run_fuzz(
    *,
    graphs: int = 10_000,
    seed: int = 20261027,
    min_agents: int = 2,
    max_agents: int = 20,
) -> FuzzSummary:
    if graphs < 1:
        raise ValueError("graphs must be at least 1")
    if min_agents < 2 or max_agents < min_agents:
        raise ValueError("invalid agent bounds")

    rng = random.Random(seed)
    principals_total = 0
    edges_checked = 0
    actions_checked = 0
    illegal_grants_checked = 0
    failures = 0

    for graph_index in range(graphs):
        root_caps = frozenset(
            cap for cap in CAPABILITIES if rng.random() < 0.7
        )
        if not root_caps:
            root_caps = frozenset({rng.choice(CAPABILITIES)})

        graph = AuthorityGraph(root="user", root_capabilities=root_caps)
        principals = ["user"]
        parents: dict[str, str] = {}

        count = rng.randint(min_agents, max_agents)
        for node_index in range(1, count):
            parent = rng.choice(principals)
            parent_caps = graph.effective_capabilities(parent)
            delegated = _random_subset(rng, parent_caps)
            child = f"g{graph_index}_agent_{node_index}"
            graph.grant(parent, child, delegated)
            principals.append(child)
            parents[child] = parent

        principals_total += len(principals)

        for child, parent in parents.items():
            child_caps = graph.effective_capabilities(child)
            parent_caps = graph.effective_capabilities(parent)
            edges_checked += 1
            if not child_caps.issubset(parent_caps):
                failures += 1

        for principal in principals:
            action = rng.choice(ACTIONS)
            required = ACTION_CAPABILITIES[action]
            effective = graph.effective_capabilities(principal)
            expected = (
                Decision.ALLOW
                if required.issubset(effective)
                else Decision.BLOCK
            )
            actual = evaluate_delegated_action(
                graph=graph,
                principal=principal,
                action=action,
            ).decision
            actions_checked += 1
            if actual is not expected:
                failures += 1

        candidate_parents = [
            principal
            for principal in principals
            if graph.effective_capabilities(principal) != KNOWN_CAPABILITIES
        ]
        if candidate_parents:
            parent = rng.choice(candidate_parents)
            parent_caps = graph.effective_capabilities(parent)
            missing = tuple(sorted(KNOWN_CAPABILITIES - parent_caps))
            if missing:
                illegal_capability = rng.choice(missing)
                legal_subset = _random_subset(rng, parent_caps)
                attempted = frozenset(set(legal_subset) | {illegal_capability})
                illegal_child = f"g{graph_index}_illegal_child"

                illegal_grants_checked += 1
                try:
                    graph.grant(parent, illegal_child, attempted)
                except ValueError:
                    pass
                else:
                    failures += 1

    return FuzzSummary(
        seed=seed,
        graphs=graphs,
        principals=principals_total,
        edges_checked=edges_checked,
        actions_checked=actions_checked,
        illegal_grants_checked=illegal_grants_checked,
        failures=failures,
    )
