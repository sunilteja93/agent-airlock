from airlock.contract import TaskContract, validate_contract


def test_contract_hash_is_deterministic_and_order_independent():
    a = TaskContract(
        goal="Fix issue #217.",
        allowed_capabilities=frozenset({"repo.write", "repo.read", "tests.run"}),
    )
    b = TaskContract(
        goal="Fix issue #217.",
        allowed_capabilities=frozenset({"tests.run", "repo.read", "repo.write"}),
    )
    assert a.sha256() == b.sha256()


def test_contract_hash_changes_when_authority_changes():
    base = TaskContract(
        goal="Fix issue #217.",
        allowed_capabilities=frozenset({"repo.read", "repo.write", "tests.run"}),
    )
    escalated = TaskContract(
        goal="Fix issue #217.",
        allowed_capabilities=frozenset(
            {"repo.read", "repo.write", "tests.run", "secret.read"}
        ),
    )
    assert base.sha256() != escalated.sha256()


def test_unknown_contract_capability_is_rejected():
    contract = TaskContract(
        goal="Fix issue #217.",
        allowed_capabilities=frozenset({"repo.read", "root.shell"}),
    )
    try:
        validate_contract(contract)
    except ValueError as exc:
        assert "root.shell" in str(exc)
    else:
        raise AssertionError("Unknown capability was accepted.")
