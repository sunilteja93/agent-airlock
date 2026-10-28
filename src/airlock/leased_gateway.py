"""Optional exact-action lease boundary layered over the Airlock gateway."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from airlock.authority import Decision
from airlock.gateway import GatewayReceipt, ToolGateway
from airlock.leases import LeaseManager


@dataclass(frozen=True)
class LeaseGatewayReceipt:
    principal: str
    tool: str
    decision: str
    executed: bool
    reason: str
    lease_id: str | None
    gateway_receipt: GatewayReceipt | None
    audit_receipt_hash: str | None = None


class LeaseProtectedGateway:
    """Require an exact-action lease before selected high-impact tools.

    The lease is intentionally not an authority grant. After lease validation,
    the underlying ToolGateway still performs its normal authority-graph check.
    """

    def __init__(
        self,
        *,
        gateway: ToolGateway,
        lease_manager: LeaseManager,
        protected_tools: frozenset[str],
    ):
        self.gateway = gateway
        self.lease_manager = lease_manager
        self.protected_tools = protected_tools

    def _record_block(
        self,
        *,
        principal: str,
        tool: str,
        reason: str,
        lease_id: str | None,
        arguments: dict[str, Any],
    ) -> LeaseGatewayReceipt:
        audit_hash = None
        if self.gateway.receipt_chain is not None:
            audit = self.gateway.receipt_chain.append(
                event_type="lease_decision",
                principal=principal,
                operation=tool,
                decision=Decision.BLOCK.value,
                executed=False,
                reason=reason,
                payload={
                    "lease_id": lease_id,
                    "arguments": dict(arguments),
                },
            )
            audit_hash = audit.receipt_hash

        return LeaseGatewayReceipt(
            principal=principal,
            tool=tool,
            decision=Decision.BLOCK.value,
            executed=False,
            reason=reason,
            lease_id=lease_id,
            gateway_receipt=None,
            audit_receipt_hash=audit_hash,
        )

    def invoke(
        self,
        *,
        principal: str,
        tool: str,
        arguments: dict[str, Any],
        lease_token: str | None = None,
    ) -> LeaseGatewayReceipt:
        lease_id = None

        if tool in self.protected_tools:
            lease = self.lease_manager.consume(
                token=lease_token,
                principal=principal,
                tool=tool,
                arguments=arguments,
            )
            lease_id = lease.lease_id
            if not lease.allowed:
                return self._record_block(
                    principal=principal,
                    tool=tool,
                    reason=lease.reason,
                    lease_id=lease_id,
                    arguments=arguments,
                )

        receipt = self.gateway.invoke(
            principal=principal,
            tool=tool,
            arguments=arguments,
        )
        return LeaseGatewayReceipt(
            principal=principal,
            tool=tool,
            decision=receipt.decision,
            executed=receipt.executed,
            reason=receipt.reason,
            lease_id=lease_id,
            gateway_receipt=receipt,
            audit_receipt_hash=receipt.audit_receipt_hash,
        )
