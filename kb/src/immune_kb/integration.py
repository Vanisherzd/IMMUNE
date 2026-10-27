from __future__ import annotations

from pathlib import Path
from typing import Any

from .api import KnowledgeBase


def create_langchain_tool(database: str | Path | None = None) -> Any:
    """Create optional LangChain StructuredTool without making LangChain a package dependency."""
    try:
        from langchain_core.tools import StructuredTool
    except ImportError as exc:
        raise RuntimeError("Install project LangChain dependencies before creating tool") from exc

    kb = KnowledgeBase(database)

    def search_incident_knowledge(query: str, scenario: str | None = None, top_k: int = 5) -> str:
        """Search local historical cases and approved remediation runbooks. Read-only."""
        return kb.tool_search(query=query, scenario=scenario, top_k=top_k)

    return StructuredTool.from_function(
        func=search_incident_knowledge,
        name="search_incident_knowledge",
        description=(
            "Read-only local search for similar incident evidence and remediation plans. "
            "Use results as hypotheses; verify against current system before proposing a fix."
        ),
    )
