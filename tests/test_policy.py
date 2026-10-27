from airlock.authority import Decision
from airlock.contract import compile_trusted_contract
from airlock.policy import evaluate


def test_fix_contract_allows_repo_work_and_tests():
    contract = compile_trusted_contract("Fix issue #217 in this repository.")
    assert contract.allowed_capabilities == frozenset({"repo.read", "repo.write", "tests.run"})


def test_fix_contract_blocks_secret_exfiltration():
    contract = compile_trusted_contract("Fix issue #217 in this repository.")
    result = evaluate("secret.exfiltrate", contract)
    assert result.decision is Decision.BLOCK
    assert result.missing_capabilities == frozenset({"secret.read", "network.write"})


def test_fix_contract_allows_repository_read():
    contract = compile_trusted_contract("Fix issue #217 in this repository.")
    result = evaluate("repo.read", contract)
    assert result.decision is Decision.ALLOW
