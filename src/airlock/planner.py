"""Muse planner that proposes least-privilege worker delegation."""

from __future__ import annotations

import json

from airlock.contract import KNOWN_CAPABILITIES, TaskContract
from airlock.meta_client import DEFAULT_MODEL, client


PLAN_SCHEMA = {
    "type": "json_schema",
    "json_schema": {
        "name": "AgentAirlockDelegationPlan",
        "strict": True,
        "schema": {
            "type": "object",
            "properties": {
                "worker_goal": {"type": "string"},
                "delegated_capabilities": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": sorted(KNOWN_CAPABILITIES),
                    },
                },
                "rationale": {"type": "string"},
            },
            "required": [
                "worker_goal",
                "delegated_capabilities",
                "rationale",
            ],
            "additionalProperties": False,
        },
    },
}


def validate_delegation_plan(
    *,
    contract: TaskContract,
    worker_goal: str,
    delegated_capabilities: frozenset[str],
) -> None:
    if not worker_goal.strip():
        raise ValueError("Worker goal cannot be empty.")

    excessive = delegated_capabilities - contract.allowed_capabilities
    if excessive:
        raise ValueError(
            "Planner attempted to delegate authority outside the frozen contract: "
            + ", ".join(sorted(excessive))
        )


def plan_with_muse(
    contract: TaskContract,
    *,
    model: str = DEFAULT_MODEL,
) -> tuple[str, frozenset[str], str]:
    """Ask Muse for a worker task and minimal delegation inside the contract."""
    system = (
        "You are the planner inside Agent Airlock. The task contract is already "
        "frozen. Delegate the smallest capability set a code worker needs. You may "
        "only choose capabilities present in the frozen contract."
    )
    user = (
        f"Frozen goal: {contract.goal}\n"
        f"Allowed capabilities: {', '.join(sorted(contract.allowed_capabilities))}"
    )

    response = client().chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        response_format=PLAN_SCHEMA,
    )

    data = json.loads(response.choices[0].message.content)
    worker_goal = data["worker_goal"].strip()
    delegated = frozenset(data["delegated_capabilities"])
    validate_delegation_plan(
        contract=contract,
        worker_goal=worker_goal,
        delegated_capabilities=delegated,
    )
    return worker_goal, delegated, data["rationale"].strip()
