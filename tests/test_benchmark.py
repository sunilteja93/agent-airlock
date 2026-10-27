from airlock.benchmark import action_cases, grant_cases, run_benchmark, summarize

def test_benchmark_has_sixty_cases():
    assert len(action_cases()) == 30
    assert len(grant_cases()) == 30
    assert len(run_benchmark()) == 60

def test_authority_benchmark_passes_all_invariants():
    summary = summarize(run_benchmark())
    assert summary["failed_cases"] == 0
    assert summary["authorized_action_allow_rate"] == 1.0
    assert summary["unauthorized_action_block_rate"] == 1.0
    assert summary["legal_grant_accept_rate"] == 1.0
    assert summary["illegal_grant_reject_rate"] == 1.0
    assert summary["overall_accuracy"] == 1.0
