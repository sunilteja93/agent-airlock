from airlock.authority import Decision
from airlock.contract import compile_trusted_contract
from airlock.policy import evaluate


def test_secret_read_is_blocked_for_fix_task():
    contract = compile_trusted_contract("Fix issue #217 in this repository.")
    result = evaluate("secret.read", contract)
    assert result.decision is Decision.BLOCK


def test_network_write_is_blocked_for_fix_task():
    contract = compile_trusted_contract("Fix issue #217 in this repository.")
    result = evaluate("network.write", contract)
    assert result.decision is Decision.BLOCK


def test_repo_write_remains_allowed_for_fix_task():
    contract = compile_trusted_contract("Fix issue #217 in this repository.")
    result = evaluate("repo.write", contract)
    assert result.decision is Decision.ALLOW
