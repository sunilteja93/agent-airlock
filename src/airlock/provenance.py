"""Dual provenance: separate information lineage from execution authority."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Any

from airlock.delegation import AuthorityGraph
from airlock.proofs import build_authority_proof, verify_authority_proof


INFO_GENESIS_HASH = "0" * 64


def _canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def _hash(data: Any) -> str:
    return hashlib.sha256(_canonical_json(data).encode()).hexdigest()


@dataclass(frozen=True)
class InformationRecord:
    sequence: int
    source_id: str
    source_type: str
    trust: str
    content_hash: str
    previous_hash: str
    record_hash: str

    def canonical_payload(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("record_hash")
        return data


class InformationLedger:
    """Append-only hash chain for information consumed by an agent."""

    def __init__(self) -> None:
        self.records: list[InformationRecord] = []

    @property
    def head_hash(self) -> str:
        return self.records[-1].record_hash if self.records else INFO_GENESIS_HASH

    def append(
        self,
        *,
        source_id: str,
        source_type: str,
        trust: str,
        content: str,
    ) -> InformationRecord:
        if trust not in {"trusted", "untrusted"}:
            raise ValueError("trust must be 'trusted' or 'untrusted'.")
        previous_hash = self.head_hash
        base = {
            "sequence": len(self.records) + 1,
            "source_id": source_id,
            "source_type": source_type,
            "trust": trust,
            "content_hash": hashlib.sha256(content.encode()).hexdigest(),
            "previous_hash": previous_hash,
        }
        record = InformationRecord(record_hash=_hash(base), **base)
        self.records.append(record)
        return record

    def verify(self) -> bool:
        previous = INFO_GENESIS_HASH
        for index, record in enumerate(self.records, start=1):
            if record.sequence != index:
                return False
            if record.previous_hash != previous:
                return False
            if _hash(record.canonical_payload()) != record.record_hash:
                return False
            previous = record.record_hash
        return True

    def export(self) -> list[dict[str, Any]]:
        return [asdict(record) for record in self.records]


def authority_fingerprint(
    *,
    graph: AuthorityGraph,
    contract_hash: str | None,
) -> str:
    """Hash only authority state, never model context or information content."""
    payload = {
        "root": graph.root,
        "root_capabilities": sorted(graph.root_capabilities),
        "grants": [
            {
                "parent": grant.parent,
                "child": grant.child,
                "capabilities": sorted(grant.capabilities),
            }
            for grant in graph.grants()
        ],
        "contract_hash": contract_hash,
    }
    return _hash(payload)


@dataclass(frozen=True)
class NonInterferenceWitness:
    principal: str
    action: str
    information_before_hash: str
    information_after_hash: str
    ingested_record_hash: str
    ingested_trust: str
    authority_before_hash: str
    authority_after_hash: str
    decision_before: str
    decision_after: str
    authority_proof_before_hash: str
    authority_proof_after_hash: str
    witness_hash: str

    def canonical_payload(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("witness_hash")
        return data


def ingest_with_noninterference_witness(
    *,
    ledger: InformationLedger,
    graph: AuthorityGraph,
    principal: str,
    action: str,
    source_id: str,
    source_type: str,
    trust: str,
    content: str,
    contract_hash: str | None,
) -> tuple[InformationRecord, NonInterferenceWitness]:
    """Ingest information and prove that authority state did not change."""
    info_before = ledger.head_hash
    authority_before = authority_fingerprint(
        graph=graph,
        contract_hash=contract_hash,
    )
    proof_before = build_authority_proof(
        graph=graph,
        principal=principal,
        action=action,
        contract_hash=contract_hash,
    )

    record = ledger.append(
        source_id=source_id,
        source_type=source_type,
        trust=trust,
        content=content,
    )

    authority_after = authority_fingerprint(
        graph=graph,
        contract_hash=contract_hash,
    )
    proof_after = build_authority_proof(
        graph=graph,
        principal=principal,
        action=action,
        contract_hash=contract_hash,
    )

    base = {
        "principal": principal,
        "action": action,
        "information_before_hash": info_before,
        "information_after_hash": ledger.head_hash,
        "ingested_record_hash": record.record_hash,
        "ingested_trust": trust,
        "authority_before_hash": authority_before,
        "authority_after_hash": authority_after,
        "decision_before": proof_before.decision,
        "decision_after": proof_after.decision,
        "authority_proof_before_hash": proof_before.proof_hash,
        "authority_proof_after_hash": proof_after.proof_hash,
    }
    witness = NonInterferenceWitness(
        witness_hash=_hash(base),
        **base,
    )
    return record, witness


def verify_noninterference_witness(
    *,
    witness: NonInterferenceWitness,
    ledger: InformationLedger,
    graph: AuthorityGraph,
    contract_hash: str | None,
) -> bool:
    if _hash(witness.canonical_payload()) != witness.witness_hash:
        return False
    if not ledger.verify():
        return False
    if ledger.head_hash != witness.information_after_hash:
        return False
    if not ledger.records:
        return False
    if ledger.records[-1].record_hash != witness.ingested_record_hash:
        return False
    if ledger.records[-1].previous_hash != witness.information_before_hash:
        return False
    if witness.information_before_hash == witness.information_after_hash:
        return False
    if witness.authority_before_hash != witness.authority_after_hash:
        return False
    if authority_fingerprint(graph=graph, contract_hash=contract_hash) != witness.authority_after_hash:
        return False

    proof = build_authority_proof(
        graph=graph,
        principal=witness.principal,
        action=witness.action,
        contract_hash=contract_hash,
    )
    if not verify_authority_proof(proof):
        return False
    return (
        proof.decision == witness.decision_after
        and witness.decision_before == witness.decision_after
        and proof.proof_hash == witness.authority_proof_after_hash
        and witness.authority_proof_before_hash == witness.authority_proof_after_hash
    )
