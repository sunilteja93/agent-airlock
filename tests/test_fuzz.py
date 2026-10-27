from airlock.fuzz import run_fuzz


def test_randomized_authority_fuzz_has_no_invariant_failures():
    result = run_fuzz(graphs=500, seed=1337, min_agents=2, max_agents=12)
    assert result.graphs == 500
    assert result.edges_checked > 0
    assert result.actions_checked > 0
    assert result.illegal_grants_checked > 0
    assert result.failures == 0
