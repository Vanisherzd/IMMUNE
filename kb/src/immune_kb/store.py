from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterable
from pathlib import Path
from typing import Any


SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS documents (
    id TEXT PRIMARY KEY,
    doc_type TEXT NOT NULL,
    scenario TEXT NOT NULL,
    platform TEXT NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    tags TEXT NOT NULL,
    source TEXT NOT NULL,
    source_path TEXT,
    split TEXT NOT NULL,
    risk_tier INTEGER,
    metadata_json TEXT NOT NULL
);
CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts USING fts5(
    id UNINDEXED,
    title,
    content,
    tags,
    tokenize='unicode61 remove_diacritics 2'
);
CREATE INDEX IF NOT EXISTS idx_documents_type ON documents(doc_type);
CREATE INDEX IF NOT EXISTS idx_documents_scenario ON documents(scenario);
"""


QUERY_ALIASES = {
    "磁碟": "disk full node disk pressure no space filesystem inode",
    "硬碟": "disk full node disk pressure no space filesystem inode",
    "空間": "disk full no space filesystem",
    "當機": "crashloop pod failure container restart",
    "重啟": "crashloop pod restart",
    "記憶體": "memory OOMKilled memory limit",
    "解析": "DNS resolution no such host CoreDNS",
    "網域": "DNS resolution CoreDNS",
    "憑證": "certificate x509 TLS expired handshake",
    "服務失敗": "systemd service failed restart loop journalctl",
}

STOP_TERMS = {
    "and",
    "for",
    "from",
    "into",
    "kubernetes",
    "linux",
    "log",
    "platform",
    "pod",
    "service",
    "status",
    "the",
    "with",
}


def _solution_content(item: dict[str, Any]) -> str:
    checks = [
        f"CHECK [{step.get('level', 'R')}] {step.get('command', '')} :: {step.get('purpose', '')}"
        for step in item.get("checks", [])
    ]
    remediation = [
        f"FIX [{step.get('level', 'W')}] {step.get('action', '')} :: approval={step.get('approval_required', True)}"
        for step in item.get("remediation", [])
    ]
    return "\n".join(
        (
            f"Scenario: {item['scenario']}",
            "Symptoms: " + "; ".join(item.get("symptoms", [])),
            "Root causes: " + "; ".join(item.get("root_causes", [])),
            *checks,
            *remediation,
            "Rollback: " + "; ".join(item.get("rollback", [])),
            "Verify: " + "; ".join(item.get("verify", [])),
            "Safety: " + "; ".join(item.get("safety", [])),
        )
    )


def load_solutions(path: Path) -> list[dict[str, Any]]:
    items = json.loads(path.read_text(encoding="utf-8"))
    records = []
    for item in items:
        records.append(
            {
                "id": item["id"],
                "doc_type": "solution",
                "scenario": item["scenario"],
                "platform": item.get("platform", "kubernetes"),
                "title": item["title"],
                "content": _solution_content(item),
                "tags": item.get("tags", []),
                "source": item.get("source", "IMMUNE curated runbook"),
                "source_path": None,
                "split": "knowledge",
                "risk_tier": item.get("risk_tier"),
                "metadata": item,
            }
        )
    return records


def iter_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                yield json.loads(line)


def build_database(
    database: Path,
    case_train: Path,
    solutions: Path,
    topology: Path | None = None,
) -> dict[str, int]:
    database.parent.mkdir(parents=True, exist_ok=True)
    if database.exists():
        database.unlink()
    connection = sqlite3.connect(database)
    connection.executescript(SCHEMA)
    counts = {"case": 0, "solution": 0, "topology": 0}
    records = list(iter_jsonl(case_train)) + load_solutions(solutions)
    if topology is not None and topology.exists():
        records += list(iter_jsonl(topology))
    with connection:
        for record in records:
            tags = " ".join(record.get("tags") or [])
            connection.execute(
                """
                INSERT INTO documents(
                    id, doc_type, scenario, platform, title, content, tags, source,
                    source_path, split, risk_tier, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record["id"],
                    record["doc_type"],
                    record["scenario"],
                    record["platform"],
                    record["title"],
                    record["content"],
                    tags,
                    record["source"],
                    record.get("source_path"),
                    record["split"],
                    record.get("risk_tier"),
                    json.dumps(record.get("metadata") or {}, ensure_ascii=False, separators=(",", ":")),
                ),
            )
            connection.execute(
                "INSERT INTO documents_fts(id, title, content, tags) VALUES (?, ?, ?, ?)",
                (record["id"], record["title"], record["content"], tags),
            )
            counts[record["doc_type"]] = counts.get(record["doc_type"], 0) + 1
    connection.close()
    return counts


def _expand_query(query: str) -> str:
    expanded = query
    for needle, addition in QUERY_ALIASES.items():
        if needle in query:
            expanded += " " + addition
    return expanded


def _fts_query(query: str) -> str:
    tokens = re.findall(r"[A-Za-z0-9_.:/-]{2,}|[\u3400-\u9fff]{2,}", _expand_query(query))
    unique = list(dict.fromkeys(token.replace('"', "") for token in tokens if token.strip("-_/.:")))
    return " OR ".join(f'"{token}"' for token in unique[:40])


def query_terms(query: str) -> list[str]:
    tokens = re.findall(r"[A-Za-z0-9_.:/-]{2,}|[\u3400-\u9fff]{2,}", query.casefold())
    return list(
        dict.fromkeys(
            token.strip("-_/.:\"")
            for token in tokens
            if token.strip("-_/.:\"") and token.strip("-_/.:\"") not in STOP_TERMS
        )
    )[:40]


def _match_details(query: str, row: sqlite3.Row) -> tuple[list[str], float]:
    terms = query_terms(query)
    if not terms:
        return [], 0.0
    haystack = " ".join((row["title"], row["content"], row["tags"])).casefold()
    matched = [term for term in terms if term in haystack]
    return matched, round(len(matched) / len(terms), 3)


def search_database(
    database: Path,
    query: str,
    *,
    scenario: str | None = None,
    doc_type: str | None = None,
    limit: int = 5,
) -> list[dict[str, Any]]:
    match = _fts_query(query)
    if not match:
        return []
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    sql = """
        SELECT d.*, bm25(documents_fts, 0.0, 2.0, 1.0, 1.5) AS rank
        FROM documents_fts
        JOIN documents AS d ON d.id = documents_fts.id
        WHERE documents_fts MATCH ?
          AND (? IS NULL OR d.scenario = ?)
          AND (? IS NULL OR d.doc_type = ?)
        ORDER BY rank ASC
        LIMIT ?
    """
    rows = connection.execute(sql, (match, scenario, scenario, doc_type, doc_type, limit)).fetchall()
    connection.close()
    results = []
    for row in rows:
        matched_terms, match_coverage = _match_details(query, row)
        results.append(
            {
                "id": row["id"],
                "doc_type": row["doc_type"],
                "scenario": row["scenario"],
                "title": row["title"],
                "content": row["content"],
                "source": row["source"],
                "source_path": row["source_path"],
                "risk_tier": row["risk_tier"],
                "score": round(-float(row["rank"]), 6),
                "matched_terms": matched_terms,
                "match_coverage": match_coverage,
                "metadata": json.loads(row["metadata_json"]),
            }
        )
    return results


def database_stats(database: Path) -> dict[str, Any]:
    connection = sqlite3.connect(database)
    total = connection.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
    by_type = dict(connection.execute("SELECT doc_type, COUNT(*) FROM documents GROUP BY doc_type"))
    by_scenario = dict(connection.execute("SELECT scenario, COUNT(*) FROM documents GROUP BY scenario"))
    connection.close()
    return {"documents": total, "by_type": by_type, "by_scenario": by_scenario}
