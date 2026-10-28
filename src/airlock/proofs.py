"""Machine-verifiable authority proofs for Agent Airlock."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Any

from airlock.authority import Decision
from airlock.delegation import AuthorityGraph
from airlock.policy import ACTION_CAPABILITIES


@dataclass(frozen=True)
class ProofGrant:
    parent: str
    child: str
    capabilities: tuple[str, ...]


@dataclass(frozen=True)
class AuthorityProof:
    principal: str
    action: str
    root: str
    root_capabilities: tuple[str, ...]
    lineage: tuple[str, ...]
    grants: tuple[ProofGrant, ...]
    required_capabilities: tuple[str, ...]
    effective_capabilities: tuple[str, ...]
    missing_capabilities: tuple[str, ...]
    decision: str
    contract_hash: str | None
    proof_hash: str

    def canonical_payload(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("proof_hash")
        return data

    def export(self) -> dict[str, Any]:
        return asdict(self)


def _canonical_json(data: dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def _hash_payload(data: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(data).encode()).hexdigest()


def build_authority_proof(
    *,
    graph: AuthorityGraph,
    principal: str,
    action: str,
    contract_hash: str | None = None,
) -> AuthorityProof:
    required = ACTION_CAPABILITIES.get(action, frozenset({"unknown.action"}))
    effective = graph.effective_capabilities(principal)
    missing = required - effective
    decision = Decision.BLOCK.value if missing else Decision.ALLOW.value

    lineage = graph.lineage(principal)
    grants: list[ProofGrant] = []
    for child in lineage[1:]:
        grant = graph.grant_for(child)
        if grant is None:
            break
        grants.append(
            ProofGrant(
                parent=grant.parent,
                child=grant.child,
                capabilities=tuple(sorted(grant.capabilities)),
            )
        )

    base = {
        "principal": principal,
        "action": action,
        "root": graph.root,
        "root_capabilities": tuple(sorted(graph.root_capabilities)),
        "lineage": lineage,
        "grants": tuple(grants),
        "required_capabilities": tuple(sorted(required)),
        "effective_capabilities": tuple(sorted(effective)),
        "missing_capabilities": tuple(sorted(missing)),
        "decision": decision,
        "contract_hash": contract_hash,
    }
    draft = AuthorityProof(proof_hash="", **base)
    return AuthorityProof(
        proof_hash=_hash_payload(draft.canonical_payload()),
        **base,
    )


def verify_authority_proof(proof: AuthorityProof) -> bool:
    if _hash_payload(proof.canonical_payload()) != proof.proof_hash:
        return False
    if not proof.lineage:
        return False
    if proof.lineage[0] != proof.root or proof.lineage[-1] != proof.principal:
        return False
    if len(proof.grants) != max(0, len(proof.lineage) - 1):
        return False

    effective = frozenset(proof.root_capabilities)
    for index, grant in enumerate(proof.grants):
        if grant.parent != proof.lineage[index]:
            return False
        if grant.child != proof.lineage[index + 1]:
            return False
        granted = frozenset(grant.capabilities)
        if not granted <= effective:
            return False
        effective = frozenset(granted & effective)

    required = frozenset(proof.required_capabilities)
    missing = required - effective
    expected_decision = (
        Decision.BLOCK.value if missing else Decision.ALLOW.value
    )

    return (
        tuple(sorted(effective)) == proof.effective_capabilities
        and tuple(sorted(missing)) == proof.missing_capabilities
        and proof.decision == expected_decision
    )


def authority_proof_from_dict(data: dict[str, Any]) -> AuthorityProof:
    """Rehydrate an exported proof for independent verification."""
    grants = tuple(ProofGrant(**grant) for grant in data.get("grants", ()))
    return AuthorityProof(
        principal=data["principal"],
        action=data["action"],
        root=data["root"],
        root_capabilities=tuple(data["root_capabilities"]),
        lineage=tuple(data["lineage"]),
        grants=grants,
        required_capabilities=tuple(data["required_capabilities"]),
        effective_capabilities=tuple(data["effective_capabilities"]),
        missing_capabilities=tuple(data["missing_capabilities"]),
        decision=data["decision"],
        contract_hash=data.get("contract_hash"),
        proof_hash=data["proof_hash"],
    )
