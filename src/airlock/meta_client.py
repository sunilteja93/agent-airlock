"""Thin Meta Model API client used by Agent Airlock."""

import os

from openai import OpenAI


META_BASE_URL = "https://api.meta.ai/v1"
DEFAULT_MODEL = "muse-spark-1.3"


def client() -> OpenAI:
    """Return a Meta Model API client using MODEL_API_KEY from the environment."""
    api_key = os.environ.get("MODEL_API_KEY")
    if not api_key:
        raise RuntimeError(
            "MODEL_API_KEY is not set. Create a Meta Model API key and export it "
            "before making API calls."
        )

    return OpenAI(base_url=META_BASE_URL, api_key=api_key)


def complete(prompt: str, model: str = DEFAULT_MODEL) -> str:
    """Return plain text from a Meta Model API Responses request."""
    response = client().responses.create(model=model, input=prompt)
    return response.output_text


def ping(model: str = DEFAULT_MODEL) -> str:
    """Make the smallest connectivity check against Muse Spark."""
    return complete("Reply with the single word: ready", model=model)
