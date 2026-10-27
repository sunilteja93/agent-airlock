from airlock.authority import Decision
from airlock.delegation import AuthorityGraph
from airlock.gateway import ToolGateway
from airlock.tools_runtime import SafeWorkspace


def make_gateway():
    graph = AuthorityGraph(
        root="user",
        root_capabilities=frozenset({"repo.read", "repo.write", "tests.run"}),
    )
    graph.grant(
        "user",
        "code_worker",
        frozenset({"repo.read", "repo.write", "tests.run"}),
    )
    graph.grant("code_worker", "setup_worker", frozenset({"repo.read"}))
    workspace = SafeWorkspace(
        files={
            "app.py": "def add(a, b):\n    return a - b\n",
            "ISSUE.md": "Fix add so it returns a+b.",
        }
    )
    return ToolGateway(graph=graph, workspace=workspace), workspace


def test_blocked_secret_tool_never_executes():
    gateway, workspace = make_gateway()
    receipt = gateway.invoke(
        principal="setup_worker",
        tool="read_secret",
        arguments={"name": "demo-token"},
    )
    assert receipt.decision == Decision.BLOCK.value
    assert receipt.executed is False
    assert workspace.executions.get("read_secret", 0) == 0


def test_blocked_network_tool_never_executes():
    gateway, workspace = make_gateway()
    receipt = gateway.invoke(
        principal="setup_worker",
        tool="network_post",
        arguments={"url": "https://example.invalid/collect", "data": "demo"},
    )
    assert receipt.decision == Decision.BLOCK.value
    assert receipt.executed is False
    assert workspace.executions.get("network_post", 0) == 0
    assert workspace.network_messages == []


def test_authorized_read_executes():
    gateway, workspace = make_gateway()
    receipt = gateway.invoke(
        principal="setup_worker",
        tool="repo_read",
        arguments={"path": "ISSUE.md"},
    )
    assert receipt.decision == Decision.ALLOW.value
    assert receipt.executed is True
    assert workspace.executions["repo_read"] == 1


def test_authorized_write_and_tests_complete_task():
    gateway, workspace = make_gateway()
    write = gateway.invoke(
        principal="code_worker",
        tool="repo_write",
        arguments={"path": "app.py", "content": "def add(a, b):\n    return a + b\n"},
    )
    tests = gateway.invoke(
        principal="code_worker",
        tool="run_tests",
        arguments={},
    )
    assert write.executed is True
    assert tests.executed is True
    assert tests.output["ok"] is True
