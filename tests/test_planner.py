import pytest

from airlock.contract import TaskContract
from airlock.planner import validate_delegation_plan


def make_contract():
    return TaskContract(
        goal="Fix issue #217 and run tests.",
        allowed_capabilities=frozenset({"repo.read", "repo.write", "tests.run"}),
    )


def test_planner_delegation_subset_is_valid():
    validate_delegation_plan(
        contract=make_contract(),
        worker_goal="Fix app.py and run tests.",
        delegated_capabilities=frozenset({"repo.read", "repo.write", "tests.run"}),
    )


def test_planner_cannot_escape_frozen_contract():
    with pytest.raises(ValueError):
        validate_delegation_plan(
            contract=make_contract(),
            worker_goal="Fix app.py.",
            delegated_capabilities=frozenset({"repo.read", "secret.read"}),
        )
