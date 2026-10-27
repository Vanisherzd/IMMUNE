from __future__ import annotations

import json
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Any


RAG_SCHEMA = "immune-rag/v1"


def _rag_document(row: sqlite3.Row) -> dict[str, Any]:
    tags = " ".join(str(row["tags"]).split())
    text = f"{row['title']}\n{row['content']}"
    return {
        "id": row["id"],
        "text": text,
        "metadata": {
            "schema": RAG_SCHEMA,
            "doc_type": row["doc_type"],
            "scenario": row["scenario"],
            "platform": row["platform"],
            "title": row["title"],
            "tags": tags,
            "source": row["source"],
            "split": row["split"],
            "risk_tier": row["risk_tier"],
        },
    }


def export_rag_corpus(database: str | Path, output: str | Path) -> dict[str, Any]:
    """Export portable RAG chunks without eval answers or host-specific paths."""

    database_path = Path(database)
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    rows = connection.execute(
        """
        SELECT id, doc_type, scenario, platform, title, content, tags, source,
               split, risk_tier
        FROM documents
        WHERE split IN ('train', 'knowledge')
        ORDER BY doc_type, id
        """
    ).fetchall()
    connection.close()

    by_type: Counter[str] = Counter()
    by_platform: Counter[str] = Counter()
    by_scenario: Counter[str] = Counter()
    with output_path.open("w", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            document = _rag_document(row)
            stream.write(json.dumps(document, ensure_ascii=False, separators=(",", ":")) + "\n")
            by_type[row["doc_type"]] += 1
            by_platform[row["platform"]] += 1
            by_scenario[row["scenario"]] += 1

    return {
        "schema": RAG_SCHEMA,
        "documents": len(rows),
        "by_type": dict(sorted(by_type.items())),
        "by_platform": dict(sorted(by_platform.items())),
        "by_scenario": dict(sorted(by_scenario.items())),
        "contains_eval_answers": False,
        "contains_absolute_host_paths": False,
        "output": output_path.name,
    }
