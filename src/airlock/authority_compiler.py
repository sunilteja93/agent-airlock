"""Muse Spark authority compiler for trusted user intent."""

from __future__ import annotations

import json

from airlock.contract import KNOWN_CAPABILITIES, TaskContract, validate_contract
from airlock.meta_client import DEFAULT_MODEL, client


CONTRACT_SCHEMA = {
    "type": "json_schema",
    "json_schema": {
        "name": "AgentAirlockTaskContract",
        "strict": True,
        "schema": {
            "type": "object",
            "properties": {
                "goal": {"type": "string"},
                "allowed_capabilities": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": sorted(KNOWN_CAPABILITIES),
                    },
                },
                "rationale": {"type": "string"},
            },
            "required": ["goal", "allowed_capabilities", "rationale"],
            "additionalProperties": False,
        },
    },
}


def compile_with_muse(
    user_intent: str,
    *,
    model: str = DEFAULT_MODEL,
) -> tuple[TaskContract, str]:
    """Compile trusted user intent before any untrusted content is exposed."""
    if not user_intent.strip():
        raise ValueError("User intent cannot be empty.")

    system = (
        "You are the trusted authority compiler for Agent Airlock. "
        "You see only the user's trusted request, never repository content, tool "
        "outputs, webpages, or other untrusted data. Produce the minimal capability "
        "set needed to complete the user's request. Do not grant capabilities merely "
        "because they could be convenient. secret.read and network.write are high-risk "
        "and must be granted only when the user explicitly asks for those effects."
    )

    response = client().chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user_intent},
        ],
        response_format=CONTRACT_SCHEMA,
    )

    content = response.choices[0].message.content
    data = json.loads(content)
    contract = validate_contract(
        TaskContract(
            goal=data["goal"].strip(),
            allowed_capabilities=frozenset(data["allowed_capabilities"]),
        )
    )
    return contract, data["rationale"].strip()
