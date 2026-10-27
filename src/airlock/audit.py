"""Tamper-evident audit receipts for Agent Airlock."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Any


GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class AuditReceipt:
    sequence: int
    event_type: str
    contract_hash: str
    principal: str
    operation: str
    decision: str
    executed: bool
    reason: str
    payload: dict[str, Any]
    previous_hash: str
    receipt_hash: str

    def canonical_payload(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("receipt_hash")
        return data


def _canonical_json(data: dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def _hash_payload(data: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(data).encode()).hexdigest()


class ReceiptChain:
    """Append-only hash chain bound to one frozen task contract."""

    def __init__(self, *, contract_hash: str):
        if len(contract_hash) != 64:
            raise ValueError("contract_hash must be a SHA-256 hex digest.")
        self.contract_hash = contract_hash
        self.receipts: list[AuditReceipt] = []

    def append(
        self,
        *,
        event_type: str,
        principal: str,
        operation: str,
        decision: str,
        executed: bool,
        reason: str,
        payload: dict[str, Any],
    ) -> AuditReceipt:
        previous_hash = (
            self.receipts[-1].receipt_hash if self.receipts else GENESIS_HASH
        )
        base = {
            "sequence": len(self.receipts) + 1,
            "event_type": event_type,
            "contract_hash": self.contract_hash,
            "principal": principal,
            "operation": operation,
            "decision": decision,
            "executed": executed,
            "reason": reason,
            "payload": payload,
            "previous_hash": previous_hash,
        }
        receipt = AuditReceipt(receipt_hash=_hash_payload(base), **base)
        self.receipts.append(receipt)
        return receipt

    def verify(self) -> bool:
        previous_hash = GENESIS_HASH
        for index, receipt in enumerate(self.receipts, start=1):
            if receipt.sequence != index:
                return False
            if receipt.contract_hash != self.contract_hash:
                return False
            if receipt.previous_hash != previous_hash:
                return False
            if _hash_payload(receipt.canonical_payload()) != receipt.receipt_hash:
                return False
            previous_hash = receipt.receipt_hash
        return True

    def export(self) -> list[dict[str, Any]]:
        return [asdict(receipt) for receipt in self.receipts]
