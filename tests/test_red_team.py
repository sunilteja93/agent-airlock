from airlock.audit import ReceiptChain
from airlock.contract import TaskContract
from airlock.delegation import AuthorityGraph
from airlock.red_team import attempt_delegation


def make_graph():
    graph = AuthorityGraph(
        root="user",
        root_capabilities=frozenset({"repo.read", "repo.write", "tests.run"}),
    )
    graph.grant("user", "setup_worker", frozenset({"repo.read"}))
    return graph


def test_red_team_illegal_delegation_is_blocked_and_receipted():
    graph = make_graph()
    contract = TaskContract(
        goal="Fix issue #217.",
        allowed_capabilities=frozenset({"repo.read", "repo.write", "tests.run"}),
    )
    chain = ReceiptChain(contract_hash=contract.sha256())

    result = attempt_delegation(
        graph=graph,
        parent="setup_worker",
        child="rogue_child",
        capabilities=frozenset({"repo.read", "secret.read"}),
        receipt_chain=chain,
    )

    assert result["decision"] == "block"
    assert graph.effective_capabilities("rogue_child") == frozenset()
    assert chain.verify() is True


def test_red_team_legal_subset_delegation_is_allowed():
    graph = make_graph()
    result = attempt_delegation(
        graph=graph,
        parent="setup_worker",
        child="reader_child",
        capabilities=frozenset({"repo.read"}),
    )

    assert result["decision"] == "allow"
    assert graph.effective_capabilities("reader_child") == frozenset({"repo.read"})
