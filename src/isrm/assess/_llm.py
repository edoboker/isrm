"""Shared OpenRouter LLM call helper."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from openai import OpenAI

from isrm.config import Settings

logger = logging.getLogger(__name__)

PROMPTS_DIR = Path(__file__).parent / "prompts"


def load_prompt(filename: str) -> str:
    """Load a prompt from the prompts directory."""
    return (PROMPTS_DIR / filename).read_text(encoding="utf-8")


def call_llm(system_prompt: str, user_content: str, settings: Settings) -> dict[str, Any]:
    """Call the OpenRouter API and return parsed JSON.

    Args:
        system_prompt: The system prompt string.
        user_content: The user message content.
        settings: Application settings.

    Returns:
        Parsed JSON dict from the model response.

    Raises:
        ValueError: If the response is empty or not valid JSON.
    """
    client = OpenAI(
        api_key=settings.openrouter_api_key,
        base_url="https://openrouter.ai/api/v1",
    )

    create_kwargs: dict[str, Any] = {
        "model": settings.openrouter_model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ],
        "response_format": {"type": "json_object"},
        "temperature": 0.1,
    }
    if settings.openrouter_max_tokens is not None:
        create_kwargs["max_tokens"] = settings.openrouter_max_tokens

    response = client.chat.completions.create(**create_kwargs)

    raw = response.choices[0].message.content
    if not raw:
        raise ValueError("LLM returned an empty response.")

    logger.debug("LLM raw response (%d bytes): %s", len(raw), raw[:300])

    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"LLM response is not valid JSON: {exc}") from exc
