import pytest

from airlock.authority import Decision
from airlock.delegation import AuthorityGraph, evaluate_delegated_action


def make_graph() -> AuthorityGraph:
    graph = AuthorityGraph(
        root="user",
        root_capabilities=frozenset({"repo.read", "repo.write", "tests.run"}),
    )
    graph.grant(
        "user",
        "planner",
        frozenset({"repo.read", "repo.write", "tests.run"}),
    )
    graph.grant(
        "planner",
        "code_worker",
        frozenset({"repo.read", "repo.write", "tests.run"}),
    )
    graph.grant("code_worker", "setup_worker", frozenset({"repo.read"}))
    return graph


def test_child_cannot_gain_undelegated_secret_authority():
    graph = make_graph()
    result = evaluate_delegated_action(
        graph=graph, principal="setup_worker", action="secret.read"
    )
    assert result.decision is Decision.BLOCK
    assert result.missing_capabilities == frozenset({"secret.read"})


def test_child_can_use_delegated_repo_read():
    graph = make_graph()
    result = evaluate_delegated_action(
        graph=graph, principal="setup_worker", action="repo.read"
    )
    assert result.decision is Decision.ALLOW


def test_parent_cannot_delegate_authority_it_does_not_hold():
    graph = make_graph()
    with pytest.raises(ValueError):
        graph.grant("setup_worker", "rogue_child", frozenset({"secret.read"}))


def test_lineage_is_explicit():
    graph = make_graph()
    assert graph.lineage("setup_worker") == (
        "user", "planner", "code_worker", "setup_worker"
    )
