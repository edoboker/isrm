"""Threat-history research agent using Pydantic AI + Tavily."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from openai import AsyncOpenAI
from pydantic_ai import Agent, RunContext
from pydantic_ai.models.openai import OpenAIModel
from pydantic_ai.providers.openai import OpenAIProvider
from tavily import TavilyClient

from isrm.config import Settings
from isrm.models import ThreatHistoryEvidence, ThreatHistorySource

logger = logging.getLogger(__name__)

_PROMPT_PATH = Path(__file__).parent.parent / "prompts" / "agent_threat_history.txt"
_SYSTEM_PROMPT = _PROMPT_PATH.read_text(encoding="utf-8")


@dataclass
class _SearchDeps:
    tavily: TavilyClient
    max_searches: int
    max_results: int
    search_depth: str
    queries: list[str] = field(default_factory=list)


def _build_agent(settings: Settings) -> Agent[_SearchDeps, ThreatHistoryEvidence]:
    model_name = settings.threat_history_model or settings.openrouter_model
    provider = OpenAIProvider(
        openai_client=AsyncOpenAI(
            api_key=settings.openrouter_api_key,
            base_url="https://openrouter.ai/api/v1",
        )
    )
    model = OpenAIModel(model_name, provider=provider)

    agent: Agent[_SearchDeps, ThreatHistoryEvidence] = Agent(
        model=model,
        output_type=ThreatHistoryEvidence,
        deps_type=_SearchDeps,
        system_prompt=_SYSTEM_PROMPT,
    )

    @agent.tool
    def web_search(ctx: RunContext[_SearchDeps], query: str) -> str:
        """Search the web for threat intelligence about a domain."""
        deps = ctx.deps
        if len(deps.queries) >= deps.max_searches:
            logger.debug("Search budget exhausted after %d queries", deps.max_searches)
            return "[Search budget exhausted. Synthesize findings from what you have so far.]"

        deps.queries.append(query)
        logger.debug("Searching [%d/%d]: %s", len(deps.queries), deps.max_searches, query)

        response = deps.tavily.search(
            query=query,
            max_results=deps.max_results,
            search_depth=deps.search_depth,
        )

        results = response.get("results", [])
        if not results:
            return "No results found."

        lines = []
        for r in results:
            title = r.get("title", "")
            url = r.get("url", "")
            content = r.get("content", "")
            lines.append(f"- [{title}]({url})\n  {content}")

        return "\n\n".join(lines)

    return agent


def run_agent(target: str, settings: Settings) -> ThreatHistoryEvidence:
    """Run the threat-history research agent for a URL or hostname.

    Args:
        target: Full URL (e.g. https://api.example.com/v1/create) or bare hostname.
        settings: Application settings.

    Returns:
        Structured ThreatHistoryEvidence.
    """
    agent = _build_agent(settings)
    deps = _SearchDeps(
        tavily=TavilyClient(api_key=settings.tavily_api_key),
        max_searches=settings.threat_history_max_searches,
        max_results=settings.threat_history_max_results_per_search,
        search_depth=settings.threat_history_search_depth,
    )

    result = agent.run_sync(
        f"Research the public threat history for: {target}",
        deps=deps,
    )

    evidence = result.output
    # Ensure searched_queries reflects actual tool calls even if agent omitted them
    if not evidence.searched_queries and deps.queries:
        evidence = evidence.model_copy(update={"searched_queries": deps.queries})

    logger.debug(
        "Agent finished: abuse_found=%s categories=%s queries=%d sources=%d",
        evidence.abuse_found,
        evidence.categories,
        len(evidence.searched_queries),
        len(evidence.sources),
    )
    return evidence
