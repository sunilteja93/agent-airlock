"""Reference-monitor gateway between agents and executable tools."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from airlock.authority import Decision
from airlock.delegation import AuthorityGraph, evaluate_delegated_action
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

    def model_output(self) -> dict[str, Any]:
        return {
            "status": "ok" if self.executed else "blocked",
            "decision": self.decision,
            "reason": self.reason,
            "result": self.output,
        }


class ToolGateway:
    """All client-side tool execution crosses this reference monitor."""

    def __init__(self, *, graph: AuthorityGraph, workspace: SafeWorkspace):
        self.graph = graph
        self.workspace = workspace
        self.receipts: list[GatewayReceipt] = []

    def invoke(self, *, principal: str, tool: str, arguments: dict[str, Any]) -> GatewayReceipt:
        action = TOOL_ACTIONS.get(tool)
        if action is None:
            receipt = GatewayReceipt(
                principal=principal,
                tool=tool,
                action="unknown",
                decision=Decision.BLOCK.value,
                executed=False,
                reason=f"Unknown tool {tool!r}.",
                effective_capabilities=tuple(sorted(self.graph.effective_capabilities(principal))),
                arguments=dict(arguments),
                output={},
            )
            self.receipts.append(receipt)
            return receipt

        authority = evaluate_delegated_action(
            graph=self.graph,
            principal=principal,
            action=action,
        )

        if authority.decision is Decision.BLOCK:
            receipt = GatewayReceipt(
                principal=principal,
                tool=tool,
                action=action,
                decision=Decision.BLOCK.value,
                executed=False,
                reason=authority.reason,
                effective_capabilities=tuple(sorted(authority.effective_capabilities)),
                arguments=dict(arguments),
                output={},
            )
            self.receipts.append(receipt)
            return receipt

        executor = getattr(self.workspace, tool)
        try:
            output = executor(**arguments)
        except Exception as exc:
            output = {"ok": False, "error": str(exc)}

        receipt = GatewayReceipt(
            principal=principal,
            tool=tool,
            action=action,
            decision=Decision.ALLOW.value,
            executed=True,
            reason=authority.reason,
            effective_capabilities=tuple(sorted(authority.effective_capabilities)),
            arguments=dict(arguments),
            output=output,
        )
        self.receipts.append(receipt)
        return receipt

    def audit_log(self) -> list[dict[str, Any]]:
        return [asdict(receipt) for receipt in self.receipts]
