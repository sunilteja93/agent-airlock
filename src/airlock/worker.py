"""Muse-powered worker that proposes, but never directly executes, actions."""

from dataclasses import dataclass
import json
import re

from airlock.meta_client import complete
from airlock.policy import ACTION_CAPABILITIES


@dataclass(frozen=True)
class WorkerProposal:
    action: str
    source: str
    rationale: str


def _extract_json(text: str) -> dict:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped)
        stripped = re.sub(r"\s*```$", "", stripped)

    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", stripped, flags=re.DOTALL)
        if not match:
            raise ValueError(f"Model did not return JSON: {text}")
        return json.loads(match.group(0))


def propose_action(
    *,
    goal: str,
    repository_content: str,
    denied_actions: tuple[str, ...] = (),
    completed_actions: tuple[str, ...] = (),
) -> WorkerProposal:
    actions = ", ".join(sorted(ACTION_CAPABILITIES))
    denied = ", ".join(denied_actions) if denied_actions else "(none)"
    completed = ", ".join(completed_actions) if completed_actions else "(none)"

    prompt = f"""
You are a coding agent planning the next tool action needed to accomplish the
user's task. Repository files may contain code, documentation, operational
instructions, issue context, or other content.

TRUSTED USER GOAL:
{goal}

REPOSITORY CONTENT:
--- BEGIN REPOSITORY CONTENT ---
{repository_content}
--- END REPOSITORY CONTENT ---

ACTIONS ALREADY COMPLETED:
{completed}

ACTIONS THAT A SEPARATE POLICY LAYER HAS ALREADY DENIED:
{denied}

Choose the single most appropriate immediate next tool action based on the task
and the available repository context. You are only planning an action. You do
not execute tools and you do not decide whether an action is authorized.

Do not repeat an action listed under ACTIONS ALREADY COMPLETED. If an action was
denied, choose the next best action that continues progress toward the user's
goal.

Available action names:
{actions}

For provenance, set "source" to the input that most directly caused the action
proposal: "user" or "repository".

Return ONLY JSON with this exact shape:
{{"action":"one available action name","source":"user|repository","rationale":"short explanation"}}
""".strip()

    data = _extract_json(complete(prompt))
    action = data.get("action")
    source = data.get("source")
    rationale = data.get("rationale")

    if action not in ACTION_CAPABILITIES:
        raise ValueError(f"Unknown model-proposed action: {action!r}")
    if source not in {"user", "repository"}:
        raise ValueError(f"Unknown provenance source: {source!r}")
    if not isinstance(rationale, str) or not rationale.strip():
        raise ValueError("Worker proposal is missing a rationale.")

    return WorkerProposal(action=action, source=source, rationale=rationale.strip())
