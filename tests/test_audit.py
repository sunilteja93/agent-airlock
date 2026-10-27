from dataclasses import replace

from airlock.audit import ReceiptChain
from airlock.contract import TaskContract


def make_chain():
    contract = TaskContract(
        goal="Fix issue #217.",
        allowed_capabilities=frozenset({"repo.read", "repo.write", "tests.run"}),
    )
    return ReceiptChain(contract_hash=contract.sha256())


def test_receipt_chain_verifies():
    chain = make_chain()
    chain.append(
        event_type="tool_decision",
        principal="code_worker",
        operation="repo_write",
        decision="allow",
        executed=True,
        reason="authorized",
        payload={"path": "app.py"},
    )
    chain.append(
        event_type="tool_decision",
        principal="setup_worker",
        operation="read_secret",
        decision="block",
        executed=False,
        reason="missing secret.read",
        payload={"name": "demo-token"},
    )
    assert chain.verify() is True


def test_receipt_chain_detects_tampering():
    chain = make_chain()
    receipt = chain.append(
        event_type="tool_decision",
        principal="setup_worker",
        operation="read_secret",
        decision="block",
        executed=False,
        reason="missing secret.read",
        payload={"name": "demo-token"},
    )
    chain.receipts[0] = replace(receipt, decision="allow")
    assert chain.verify() is False
