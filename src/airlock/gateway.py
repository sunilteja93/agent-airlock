"""Reference-monitor gateway between agents and executable tools."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from airlock.audit import ReceiptChain
from airlock.authority import Decision
from airlock.delegation import AuthorityGraph, evaluate_delegated_action
from airlock.proofs import build_authority_proof
from airlock.tools_runtime import SafeWorkspace


TOOL_ACTIONS = {
    "repo_read": "repo.read",
    "repo_write": "repo.write",
    "run_tests": "tests.run",
    "read_secret": "secret.read",
    "network_post": "network.write",
}


@dataclass(frozen=True)
class GatewayReceipt:
    principal: str
    tool: str
    action: str
    decision: str
    executed: bool
    reason: str
    effective_capabilities: tuple[str, ...]
    arguments: dict[str, Any]
    output: dict[str, Any]
    audit_receipt_hash: str | None = None
    authority_proof_hash: str | None = None
    authority_proof: dict[str, Any] | None = None

    def model_output(self) -> dict[str, Any]:
        return {
            "status": "ok" if self.executed else "blocked",
            "decision": self.decision,
            "reason": self.reason,
            "result": self.output,
            "receipt_hash": self.audit_receipt_hash,
            "authority_proof_hash": self.authority_proof_hash,
        }


class ToolGateway:
    """All client-side tool execution crosses this reference monitor."""

    def __init__(
        self,
        *,
        graph: AuthorityGraph,
        workspace: SafeWorkspace,
        receipt_chain: ReceiptChain | None = None,
    ):
        self.graph = graph
        self.workspace = workspace
        self.receipt_chain = receipt_chain
        self.receipts: list[GatewayReceipt] = []

    def _record(self, receipt: GatewayReceipt) -> GatewayReceipt:
        if self.receipt_chain is None:
            self.receipts.append(receipt)
            return receipt

        audit = self.receipt_chain.append(
            event_type="tool_decision",
            principal=receipt.principal,
            operation=receipt.tool,
            decision=receipt.decision,
            executed=receipt.executed,
            reason=receipt.reason,
            payload={
                "action": receipt.action,
                "effective_capabilities": list(receipt.effective_capabilities),
                "arguments": receipt.arguments,
                "output": receipt.output,
                "authority_proof_hash": receipt.authority_proof_hash,
                "authority_proof": receipt.authority_proof,
            },
        )
        bound = GatewayReceipt(
            principal=receipt.principal,
            tool=receipt.tool,
            action=receipt.action,
            decision=receipt.decision,
            executed=receipt.executed,
            reason=receipt.reason,
            effective_capabilities=receipt.effective_capabilities,
            arguments=receipt.arguments,
            output=receipt.output,
            audit_receipt_hash=audit.receipt_hash,
            authority_proof_hash=receipt.authority_proof_hash,
            authority_proof=receipt.authority_proof,
        )
        self.receipts.append(bound)
        return bound

    def invoke(
        self,
        *,
        principal: str,
        tool: str,
        arguments: dict[str, Any],
    ) -> GatewayReceipt:
        action = TOOL_ACTIONS.get(tool)
        if action is None:
            return self._record(
                GatewayReceipt(
                    principal=principal,
                    tool=tool,
                    action="unknown",
                    decision=Decision.BLOCK.value,
                    executed=False,
                    reason=f"Unknown tool {tool!r}.",
                    effective_capabilities=tuple(
                        sorted(self.graph.effective_capabilities(principal))
                    ),
                    arguments=dict(arguments),
                    output={},
                )
            )

        authority = evaluate_delegated_action(
            graph=self.graph,
            principal=principal,
            action=action,
        )
        contract_hash = (
            self.receipt_chain.contract_hash if self.receipt_chain is not None else None
        )
        proof = build_authority_proof(
            graph=self.graph,
            principal=principal,
            action=action,
            contract_hash=contract_hash,
        )

        if authority.decision is Decision.BLOCK:
            return self._record(
                GatewayReceipt(
                    principal=principal,
                    tool=tool,
                    action=action,
                    decision=Decision.BLOCK.value,
                    executed=False,
                    reason=authority.reason,
                    effective_capabilities=tuple(
                        sorted(authority.effective_capabilities)
                    ),
                    arguments=dict(arguments),
                    output={},
                    authority_proof_hash=proof.proof_hash,
                    authority_proof=proof.export(),
                )
            )

        executor = getattr(self.workspace, tool)
        try:
            output = executor(**arguments)
        except Exception as exc:
            output = {"ok": False, "error": str(exc)}

        return self._record(
            GatewayReceipt(
                principal=principal,
                tool=tool,
                action=action,
                decision=Decision.ALLOW.value,
                executed=True,
                reason=authority.reason,
                effective_capabilities=tuple(
                    sorted(authority.effective_capabilities)
                ),
                arguments=dict(arguments),
                output=output,
                authority_proof_hash=proof.proof_hash,
                authority_proof=proof.export(),
            )
        )

    def audit_log(self) -> list[dict[str, Any]]:
        return [asdict(receipt) for receipt in self.receipts]
