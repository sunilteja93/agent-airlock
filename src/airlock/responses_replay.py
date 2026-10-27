"""Helpers for stateless Meta Responses API replay."""

from __future__ import annotations

from typing import Any


def user_message(text: str) -> dict[str, Any]:
    return {
        "role": "user",
        "content": [{"type": "input_text", "text": text}],
    }


def output_items(response) -> list[dict[str, Any]]:
    """Serialize response.output items back into valid Responses API input."""
    items: list[dict[str, Any]] = []
    for item in response.output:
        if hasattr(item, "model_dump"):
            data = item.model_dump(mode="json", exclude_none=True)
        elif isinstance(item, dict):
            data = dict(item)
        else:
            raise TypeError(f"Unsupported response output item: {type(item)!r}")

        if data.get("type") == "reasoning":
            data.setdefault("summary", [])
        items.append(data)
    return items


def create_stateless_response(
    api,
    *,
    model: str,
    history: list[dict[str, Any]],
    tools: list[dict[str, Any]],
):
    """Create a response with client-managed encrypted reasoning replay."""
    return api.responses.create(
        model=model,
        input=history,
        tools=tools,
        store=False,
        include=["reasoning.encrypted_content"],
    )
