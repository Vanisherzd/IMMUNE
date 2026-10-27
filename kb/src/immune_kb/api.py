from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .corpus import infer_scenario
from .resources import default_database_path
from .store import search_database


def _flatten(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, dict):
        parts: list[str] = []
        for nested in value.values():
            parts.extend(_flatten(nested))
        return parts
    if isinstance(value, (list, tuple, set)):
        parts = []
        for nested in value:
            parts.extend(_flatten(nested))
        return parts
    return [str(value)]


class KnowledgeBase:
    """Small offline retrieval API. Safe default: read-only SQLite database."""

    def __init__(self, database: str | Path | None = None):
        self.database = Path(database) if database is not None else default_database_path()
        if not self.database.exists():
            raise FileNotFoundError(f"Knowledge database not found: {self.database}")

    def search(
        self,
        query: str,
        *,
        scenario: str | None = None,
        doc_type: str | None = None,
        top_k: int = 5,
    ) -> list[dict[str, Any]]:
        return search_database(
            self.database,
            query,
            scenario=scenario,
            doc_type=doc_type,
            limit=top_k,
        )

    def retrieve(
        self,
        incident: dict[str, Any],
        *,
        case_k: int = 4,
        solution_k: int = 4,
        minimum_solution_coverage: float = 0.34,
    ) -> dict[str, Any]:
        query = " ".join(_flatten(incident))
        scenario = incident.get("scenario") or infer_scenario(query)
        if scenario == "other":
            scenario_filter = None
        else:
            scenario_filter = scenario
        cases = self.search(query, scenario=scenario_filter, doc_type="case", top_k=case_k)
        solution_candidates = self.search(query, scenario=scenario_filter, doc_type="solution", top_k=solution_k)
        best_coverage = max((item["match_coverage"] for item in solution_candidates), default=0.0)
        has_match = bool(solution_candidates) and best_coverage >= minimum_solution_coverage
        return {
            "scenario": scenario,
            "query": query,
            "knowledge_match": {
                "status": "matched" if has_match else "insufficient",
                "best_solution_coverage": best_coverage,
                "minimum_solution_coverage": minimum_solution_coverage,
                "instruction": (
                    "Treat results as hypotheses and verify against current read-only evidence."
                    if has_match
                    else "Knowledge base has no strong solution match. Run read-only checks or escalate; do not repair."
                ),
            },
            "cases": cases,
            "solutions": solution_candidates if has_match else [],
            "weak_solution_candidates": [] if has_match else solution_candidates,
            "topologies": self.search(query, doc_type="topology", top_k=2),
            "policy": {
                "mode": "plan_only",
                "required_before_fix": [
                    "confirm root cause using current read-only evidence",
                    "state blast radius",
                    "provide rollback",
                    "obtain approval for W/D actions",
                ],
            },
        }

    def tool_search(self, query: str, scenario: str | None = None, top_k: int = 5) -> str:
        """LangChain/OpenShell-friendly JSON string tool result."""
        payload = self.retrieve(
            {"query": query, "scenario": scenario} if scenario else {"query": query},
            case_k=top_k,
            solution_k=top_k,
        )
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
