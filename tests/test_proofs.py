from dataclasses import replace

from airlock.authority import Decision
from airlock.delegation import AuthorityGraph
from airlock.proofs import (
    authority_proof_from_dict,
    build_authority_proof,
    verify_authority_proof,
)


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


def test_allow_proof_verifies_independently():
    proof = build_authority_proof(
        graph=make_graph(),
        principal="setup_worker",
        action="repo.read",
        contract_hash="a" * 64,
    )
    assert proof.decision == Decision.ALLOW.value
    assert verify_authority_proof(proof) is True


def test_block_proof_identifies_missing_capability():
    proof = build_authority_proof(
        graph=make_graph(),
        principal="setup_worker",
        action="network.write",
        contract_hash="b" * 64,
    )
    assert proof.decision == Decision.BLOCK.value
    assert proof.missing_capabilities == ("network.write",)
    assert verify_authority_proof(proof) is True


def test_tampered_proof_fails_verification():
    proof = build_authority_proof(
        graph=make_graph(),
        principal="setup_worker",
        action="repo.read",
    )
    tampered = replace(
        proof,
        effective_capabilities=("network.write", "repo.read"),
    )
    assert verify_authority_proof(tampered) is False


def test_exported_proof_round_trips_and_verifies():
    proof = build_authority_proof(
        graph=make_graph(),
        principal="code_worker",
        action="repo.write",
        contract_hash="c" * 64,
    )
    restored = authority_proof_from_dict(proof.export())
    assert restored.proof_hash == proof.proof_hash
    assert verify_authority_proof(restored) is True
