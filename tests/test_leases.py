from airlock.delegation import AuthorityGraph
from airlock.gateway import ToolGateway
from airlock.leased_gateway import LeaseProtectedGateway
from airlock.leases import LeaseManager
from airlock.tools_runtime import SafeWorkspace


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def make_gateway(*, root_caps):
    graph = AuthorityGraph(root="user", root_capabilities=frozenset(root_caps))
    graph.grant("user", "worker", frozenset(root_caps))
    workspace = SafeWorkspace(files={"app.py": "def add(a, b):\n    return a + b\n"})
    base = ToolGateway(graph=graph, workspace=workspace)
    clock = FakeClock()
    manager = LeaseManager(secret=b"0123456789abcdef0123456789abcdef", clock=clock)
    protected = LeaseProtectedGateway(
        gateway=base,
        lease_manager=manager,
        protected_tools=frozenset({"network_post"}),
    )
    return protected, manager, workspace, clock


def test_exact_action_lease_allows_once_then_blocks_replay():
    protected, manager, workspace, _ = make_gateway(root_caps={"network.write"})
    args = {"url": "https://example.invalid/approved", "data": "synthetic"}
    lease = manager.issue(
        principal="worker",
        tool="network_post",
        arguments=args,
        ttl_seconds=30,
        max_uses=1,
    )

    first = protected.invoke(
        principal="worker",
        tool="network_post",
        arguments=args,
        lease_token=lease.token,
    )
    replay = protected.invoke(
        principal="worker",
        tool="network_post",
        arguments=args,
        lease_token=lease.token,
    )

    assert first.executed is True
    assert replay.executed is False
    assert "replay/use limit" in replay.reason
    assert workspace.executions["network_post"] == 1


def test_lease_is_bound_to_exact_arguments():
    protected, manager, workspace, _ = make_gateway(root_caps={"network.write"})
    approved = {"url": "https://example.invalid/approved", "data": "synthetic"}
    lease = manager.issue(
        principal="worker",
        tool="network_post",
        arguments=approved,
    )

    changed = protected.invoke(
        principal="worker",
        tool="network_post",
        arguments={"url": "https://example.invalid/changed", "data": "synthetic"},
        lease_token=lease.token,
    )

    assert changed.executed is False
    assert "exact action arguments" in changed.reason
    assert workspace.executions.get("network_post", 0) == 0


def test_expired_and_revoked_leases_fail_closed():
    protected, manager, workspace, clock = make_gateway(root_caps={"network.write"})
    args = {"url": "https://example.invalid/approved", "data": "synthetic"}

    expired = manager.issue(
        principal="worker",
        tool="network_post",
        arguments=args,
        ttl_seconds=1,
    )
    clock.now += 2
    expired_result = protected.invoke(
        principal="worker",
        tool="network_post",
        arguments=args,
        lease_token=expired.token,
    )
    assert expired_result.executed is False
    assert "expired" in expired_result.reason

    current = manager.issue(
        principal="worker",
        tool="network_post",
        arguments=args,
    )
    manager.revoke(current.token)
    revoked_result = protected.invoke(
        principal="worker",
        tool="network_post",
        arguments=args,
        lease_token=current.token,
    )
    assert revoked_result.executed is False
    assert "revoked" in revoked_result.reason
    assert workspace.executions.get("network_post", 0) == 0


def test_valid_lease_cannot_create_missing_authority():
    protected, manager, workspace, _ = make_gateway(root_caps={"repo.read"})
    args = {"url": "https://example.invalid/approved", "data": "synthetic"}
    lease = manager.issue(
        principal="worker",
        tool="network_post",
        arguments=args,
    )

    result = protected.invoke(
        principal="worker",
        tool="network_post",
        arguments=args,
        lease_token=lease.token,
    )

    assert result.executed is False
    assert result.gateway_receipt is not None
    assert result.gateway_receipt.decision == "block"
    assert workspace.executions.get("network_post", 0) == 0
