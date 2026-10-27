from airlock.audit import ReceiptChain
from airlock.authority import Decision
from airlock.contract import TaskContract
from airlock.delegation import AuthorityGraph
from airlock.gateway import ToolGateway
from airlock.tools_runtime import SafeWorkspace


def make_gateway(*, audited=False):
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

    chain = None
    if audited:
        contract = TaskContract(
            goal="Fix issue #217.",
            allowed_capabilities=frozenset({"repo.read", "repo.write", "tests.run"}),
        )
        chain = ReceiptChain(contract_hash=contract.sha256())

    return (
        ToolGateway(graph=graph, workspace=workspace, receipt_chain=chain),
        workspace,
        chain,
    )


def test_blocked_secret_tool_never_executes():
    gateway, workspace, _ = make_gateway()
    receipt = gateway.invoke(
        principal="setup_worker",
        tool="read_secret",
        arguments={"name": "demo-token"},
    )
    assert receipt.decision == Decision.BLOCK.value
    assert receipt.executed is False
    assert workspace.executions.get("read_secret", 0) == 0


def test_blocked_network_tool_never_executes():
    gateway, workspace, _ = make_gateway()
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
    gateway, workspace, _ = make_gateway()
    receipt = gateway.invoke(
        principal="setup_worker",
        tool="repo_read",
        arguments={"path": "ISSUE.md"},
    )
    assert receipt.decision == Decision.ALLOW.value
    assert receipt.executed is True
    assert workspace.executions["repo_read"] == 1


def test_authorized_write_and_tests_complete_task():
    gateway, workspace, _ = make_gateway()
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


def test_gateway_decision_is_bound_to_valid_receipt_chain():
    gateway, _, chain = make_gateway(audited=True)
    receipt = gateway.invoke(
        principal="setup_worker",
        tool="read_secret",
        arguments={"name": "demo-token"},
    )

    assert receipt.executed is False
    assert receipt.audit_receipt_hash is not None
    assert chain is not None
    assert len(chain.receipts) == 1
    assert chain.receipts[0].receipt_hash == receipt.audit_receipt_hash
    assert chain.verify() is True


def test_authorized_write_cannot_smuggle_side_effecting_code():
    gateway, workspace, _ = make_gateway()
    original = workspace.files["app.py"]

    receipt = gateway.invoke(
        principal="code_worker",
        tool="repo_write",
        arguments={
            "path": "app.py",
            "content": (
                "def add(a, b):\n"
                "    print('side effect')\n"
                "    return a + b\n"
            ),
        },
    )

    assert receipt.decision == Decision.ALLOW.value
    assert receipt.executed is True
    assert receipt.output["ok"] is False
    assert "optional docstring and one return" in receipt.output["error"]
    assert workspace.files["app.py"] == original
