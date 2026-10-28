"""Offline demo of Agent Airlock's verifiable authority protocol."""

from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from airlock.delegation import AuthorityGraph
from airlock.gateway import ToolGateway
from airlock.leased_gateway import LeaseProtectedGateway
from airlock.leases import LeaseManager
from airlock.proofs import build_authority_proof, verify_authority_proof
from airlock.tools_runtime import SafeWorkspace


def main() -> None:
    print("AGENT AIRLOCK — VERIFIABLE AUTHORITY PROTOCOL")
    print("=" * 52)

    graph = AuthorityGraph(
        root="user",
        root_capabilities=frozenset({"repo.read", "repo.write", "tests.run"}),
    )
    graph.grant(
        "user",
        "worker",
        frozenset({"repo.read", "repo.write", "tests.run"}),
    )

    allowed = build_authority_proof(
        graph=graph,
        principal="worker",
        action="repo.write",
        contract_hash="a" * 64,
    )
    denied = build_authority_proof(
        graph=graph,
        principal="worker",
        action="network.write",
        contract_hash="a" * 64,
    )

    print("\n1. PROOF-CARRYING AUTHORIZATION")
    print(f"repo.write decision: {allowed.decision.upper()}")
    print(f"repo.write proof valid: {verify_authority_proof(allowed)}")
    print(f"proof hash: {allowed.proof_hash}")
    print(f"network.write decision: {denied.decision.upper()}")
    print(f"missing capability: {', '.join(denied.missing_capabilities)}")
    print(f"network.write denial proof valid: {verify_authority_proof(denied)}")

    lease_graph = AuthorityGraph(
        root="user",
        root_capabilities=frozenset({"network.write"}),
    )
    lease_graph.grant("user", "worker", frozenset({"network.write"}))
    workspace = SafeWorkspace(
        files={"app.py": "def add(a, b):\n    return a + b\n"}
    )
    manager = LeaseManager(secret=b"airlock-offline-demo-signing-key")
    protected = LeaseProtectedGateway(
        gateway=ToolGateway(graph=lease_graph, workspace=workspace),
        lease_manager=manager,
        protected_tools=frozenset({"network_post"}),
    )

    approved = {
        "url": "https://example.invalid/approved",
        "data": "synthetic",
    }

    lease = protected.issue_lease(
        principal="worker",
        tool="network_post",
        arguments=approved,
        ttl_seconds=60,
        max_uses=1,
    )

    first = protected.invoke(
        principal="worker",
        tool="network_post",
        arguments=approved,
        lease_token=lease.token,
    )
    replay = protected.invoke(
        principal="worker",
        tool="network_post",
        arguments=approved,
        lease_token=lease.token,
    )

    mutation_lease = protected.issue_lease(
        principal="worker",
        tool="network_post",
        arguments=approved,
    )
    mutation = protected.invoke(
        principal="worker",
        tool="network_post",
        arguments={
            "url": "https://example.invalid/changed",
            "data": "synthetic",
        },
        lease_token=mutation_lease.token,
    )

    revoked_lease = protected.issue_lease(
        principal="worker",
        tool="network_post",
        arguments=approved,
    )
    manager.revoke(revoked_lease.token)
    revoked = protected.invoke(
        principal="worker",
        tool="network_post",
        arguments=approved,
        lease_token=revoked_lease.token,
    )

    print("\n2. EPHEMERAL EXACT-ACTION LEASE")
    print(f"first exact action: {'ALLOW' if first.executed else 'BLOCK'}")
    print(f"same-token replay: {'BLOCK' if not replay.executed else 'ALLOW'}")
    print(f"argument mutation: {'BLOCK' if not mutation.executed else 'ALLOW'}")
    print(f"revoked lease: {'BLOCK' if not revoked.executed else 'ALLOW'}")
    print(f"mock executor invocations: {workspace.executions.get('network_post', 0)}")

    passed = (
        verify_authority_proof(allowed)
        and verify_authority_proof(denied)
        and first.executed
        and not replay.executed
        and not mutation.executed
        and not revoked.executed
        and workspace.executions.get("network_post", 0) == 1
    )

    print("\n3. RESULT")
    print("PASS" if passed else "FAIL")
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
