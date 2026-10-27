from airlock.authority import Decision, ProposedAction, Source, authorize


def test_untrusted_repo_cannot_authorize_secret_exfiltration():
    readme = Source(
        name="README.md",
        trusted=False,
        capabilities=frozenset({"repo.read"}),
    )
    action = ProposedAction(
        name="exfiltrate_secret",
        required_capabilities=frozenset({"secret.read", "network.write"}),
        source=readme,
    )

    result = authorize(action)

    assert result.decision is Decision.BLOCK
    assert result.missing_capabilities == frozenset(
        {"secret.read", "network.write"}
    )


def test_source_can_authorize_declared_capability():
    user = Source(
        name="user",
        trusted=True,
        capabilities=frozenset({"tests.run"}),
    )
    action = ProposedAction(
        name="run_tests",
        required_capabilities=frozenset({"tests.run"}),
        source=user,
    )

    result = authorize(action)

    assert result.decision is Decision.ALLOW
