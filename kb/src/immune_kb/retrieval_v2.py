"""Retrieval v2: the same knowledge pack, retrieved without the four defects measured on 2026-09-30.

v1 (store.search_database + api.KnowledgeBase.retrieve) and what v2 changes, each switchable for an ablation:

1. Coverage. v1 counts how many query terms appear as *substrings* of a document, unweighted, and calls a solution
   card `matched` at 0.34. A three-word query therefore matches on any two words, and the words that match are the
   ones every incident has ("pod", "error", "timeout"). v2 tokenises on word boundaries, drops generic incident words,
   weights every term by its IDF over the pack, and measures coverage from the card's side: how much of the card's
   own symptom signature shows up in the incident (`coverage="card"`), or v1's query-side fraction, IDF-weighted
   (`coverage="query"`).
2. Scenario filter. v1 infers a scenario from the query with substring rules and *hard-filters* on it, so any query
   containing "disk" can only ever see disk_full cases. v2 does not filter (`hard_filter=False`).
3. Scenario labels. v1's corpus maps RCAEval `disk`/`io` (I/O stress) to disk_full and `pod kill`/`pod failure` to
   crashloop. `scenario_v2` keeps disk_full for fill/no-space/inode faults and crashloop for restart loops and OOM,
   and moves the rest to other. Applied to the corpus at build time and to the ground truth by the evaluator.
4. Duplicates and label-only cases. 1,321 of 1,644 cases carry no symptom text (only the answer: fault, service,
   suite), and RCAEval has 591 cases with 192 distinct texts. v2 merges identical texts. Down-weighting the cases
   without evidence (`no_evidence_weight` < 1; 0 drops them) was measured on dev and lowers label@5 from 13 % to 7 %:
   those cases still carry the label and are reached through service names, so the default keeps them at full weight.

Ranking is a small in-process BM25 over the pack (1.7k documents, milliseconds), so tokenisation, stop words and
weights are the same for ranking and for coverage. Read-only: the v1 database is the input, a v2 JSONL is the output.
"""
from __future__ import annotations

import json
import math
import re
import sqlite3
import threading
from collections import Counter, defaultdict
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .store import STOP_TERMS

# Words that occur in almost every incident and every card: they say "something is wrong", not what.
GENERIC_TERMS = {
    "error", "errors", "err", "fail", "failed", "failure", "failures", "failing", "timeout", "timeouts", "timed",
    "request", "requests", "response", "service", "services", "pod", "pods", "container", "containers", "node",
    "nodes", "metric", "metrics", "log", "logs", "trace", "traces", "high", "low", "spike", "increase", "increased",
    "drop", "issue", "problem", "unknown", "app", "application", "info", "warn", "warning", "debug", "http", "https",
    "get", "post", "true", "false", "none", "null", "baseline", "window", "peak", "before", "after", "value", "time",
    "count", "total", "rate", "ratio", "usage", "using", "used", "default", "namespace", "name", "status", "this",
    "that", "not", "are", "was", "has", "have", "can", "will", "all", "any", "one", "per", "via", "while", "when",
    "fault", "symptom", "symptoms", "evidence", "key", "root", "cause", "system", "suite", "available", "telemetry",
    "injection", "boundary", "inject_time.txt", "txt", "json", "parquet", "kubernetes", "linux", "k8s",
}
STOP = {t.casefold() for t in STOP_TERMS} | GENERIC_TERMS

TOKEN_RE = re.compile(r"[a-z][a-z0-9_.:/-]*[a-z0-9]|[㐀-鿿]{2,}")
NOISE_RE = re.compile(r"^(?:[0-9a-f]{8,}|.*\d{4,}.*|[a-z]?\d+[a-z]?|.{41,})$")   # hashes, ids, timestamps, run-on blobs

FILL_TERMS = ("fill", "no space", "nospace", "file_write", "file write", "excessive_file", "inode", "disk full",
              "diskpressure", "disk pressure", "disk_full", "磁碟滿", "空間不足")
CRASH_TERMS = ("crashloop", "crash loop", "backoff", "oom", "memory_limit", "memory limit", "invalid command",
               "invalid-command", "restart loop", "restartloop", "podcrashloop")
DNS_TERMS = ("dns", "name resolution", "no such host", "resolver", "名稱解析", "網域解析")


def tokens(text: str) -> list[str]:
    """Word-boundary tokens plus the parts of compound names (pod_cpu_usage -> pod_cpu_usage, cpu; ts-route-service ->
    ts-route-service, route), minus stop words and noise. Order kept, duplicates kept (BM25 wants term counts)."""
    out = []
    for raw in TOKEN_RE.findall(str(text).casefold()):
        raw = raw.strip("-_.:/")
        parts = [raw] + [p for p in re.split(r"[_.:/-]+", raw) if p != raw]
        for p in parts:
            if len(p) >= 3 and p not in STOP and not NOISE_RE.match(p):
                out.append(p)
    return out


def scenario_v2(old: str, labels: list[str] | tuple[str, ...], title: str = "") -> str:
    """Corrected scenario: disk_full only for fill-type faults, crashloop only for restart loops and OOM."""
    text = " ".join([*map(str, labels or []), str(title)]).casefold()
    if old == "dns" or any(t in text for t in DNS_TERMS):
        return "dns"
    if old == "disk_full":
        return "disk_full" if any(t in text for t in FILL_TERMS) else "other"
    if old == "crashloop":
        return "crashloop" if any(t in text for t in CRASH_TERMS) else "other"
    return old


def has_evidence(content: str) -> bool:
    """A case document that says what was observed, not only what the answer was."""
    # Cloud-OpsBench's one-line "Symptom: Service Availability Disruption." is the same for most of its cases and
    # says nothing; its plural "Symptoms:" (AIOps) and the evidence/conclusion fields of the others do.
    return bool(re.search(r"^(Symptoms|Key evidence|Causal evidence|Conclusion|condition|description|effect):",
                          content, re.M | re.I))


# --- build ----------------------------------------------------------------------------------------------------------

def build_v2_corpus(database: str | Path, out: str | Path, observed: dict[str, str] | None = None) -> dict[str, Any]:
    """Read the v1 SQLite pack, write the v2 corpus as JSONL (one document per line, fields as in v1 plus `labels`,
    `has_evidence`, `scenario_v1`, `duplicates`). Cases are deduplicated on (source, content); the kept document
    carries the ids it absorbed and the union of their labels.

    `observed` (step 2): case id -> what the incident's own telemetry showed, extracted by `incident_query` from the
    case's raw data through the same compression as the evaluation inputs (train split only). A case with an observed
    text gets an `observed` field and counts as having evidence, and is deduplicated on its observed text too: two
    runs of the same fault on the same service are two incidents with different telemetry."""
    con = sqlite3.connect(database)
    con.row_factory = sqlite3.Row
    rows = con.execute("SELECT * FROM documents ORDER BY id").fetchall()
    con.close()
    train_labels = {}
    train = Path(database).parent / "cases_train.jsonl"
    if train.exists():
        for line in train.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rec = json.loads(line)
                train_labels[rec["id"]] = rec.get("labels") or []
    docs, by_text, stats = [], {}, Counter()
    for r in rows:
        meta = json.loads(r["metadata_json"] or "{}")
        labels = train_labels.get(r["id"]) or meta.get("labels") or []
        doc = {"id": r["id"], "doc_type": r["doc_type"], "scenario_v1": r["scenario"], "platform": r["platform"],
               "title": r["title"], "content": r["content"], "tags": r["tags"], "source": r["source"],
               "risk_tier": r["risk_tier"], "labels": labels, "metadata": meta, "duplicates": []}
        if r["doc_type"] == "case":
            doc["scenario"] = scenario_v2(r["scenario"], labels, r["title"])
            doc["has_evidence"] = has_evidence(r["content"])
            if observed and observed.get(r["id"]):
                doc["observed"] = observed[r["id"]]
                doc["has_evidence"] = True
                stats["observed"] += 1
            stats["relabelled"] += doc["scenario"] != r["scenario"]
            key = (r["source"], r["content"], doc.get("observed"))
            if key in by_text:
                kept = by_text[key]
                kept["duplicates"].append(r["id"])
                kept["labels"] = list(dict.fromkeys([*kept["labels"], *labels]))
                stats["merged"] += 1
                continue
            by_text[key] = doc
        else:
            doc["scenario"] = r["scenario"]
            doc["has_evidence"] = True
        docs.append(doc)
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        for d in docs:
            f.write(json.dumps(d, ensure_ascii=False) + "\n")
    stats.update(documents=len(docs), cases=sum(d["doc_type"] == "case" for d in docs),
                 cases_with_evidence=sum(d["doc_type"] == "case" and d["has_evidence"] for d in docs))
    return dict(stats)


# --- retrieve -------------------------------------------------------------------------------------------------------

# The configuration the agent uses, every value chosen on the dev split (README.md): cases by their own
# telemetry with a text fallback; a card only when one of its symptom phrases is in the query whole and specific
# (bar 8: the lowest with no wrong match on dev; "No space left on device" scores 16, "connection refused" 7).
AGENT_DEFAULTS = {"index": "observed", "coverage": "phrase", "phrase_bar": 8.0}

class KnowledgeBaseV2:
    """Drop-in for api.KnowledgeBase.retrieve on the v2 corpus. Defaults are the v2 behaviour; every change can be
    switched back for an ablation."""

    def __init__(self, corpus: str | Path, *, coverage: str = "card", hard_filter: bool = False,
                 no_evidence_weight: float = 1.0, minimum_solution_coverage: float = 0.34,
                 use_v2_scenarios: bool = True, k1: float = 1.2, b: float = 0.75, index: str = "original",
                 vote: int = 0, vote_k: int = 5, fallback: bool = True, phrase_bar: float | None = None,
                 extra_documents: list[dict[str, Any]] | None = None):
        """index: what a case is retrieved by -- "original" (its v1 text), "observed" (its own telemetry, step 2;
        falls back to the original text for a case without one), or "both". vote > 0 replaces the coverage rule for
        cards: `matched` when at least `vote` of the top `vote_k` cases share a target scenario, and the cards shown
        are that scenario's. Cards cannot be matched on vocabulary from telemetry (their words are not the
        telemetry's), but neighbouring incidents can say which card applies.

        fallback (observed index only): when fewer than top_k cases share a word with the query, the rest come from
        the original text. A telemetry query always has hits, so it is unaffected; a query typed in words
        ("No space left on device") would otherwise find no similar case at all.

        phrase_bar (coverage="phrase"): a card matches when one of its own symptom phrases occurs in full in the
        query (every non-generic word of it) and that phrase is specific enough: the sum of its words' IDF reaches
        the bar. "No space left on device" is specific; "connection refused" alone is not."""
        self.docs = [json.loads(l) for l in Path(corpus).read_text(encoding="utf-8").splitlines() if l.strip()]
        # Add curated repair knowledge without rebuilding the benchmark corpus or indexing evaluation answers.
        known_ids = {d["id"] for d in self.docs}
        for document in extra_documents or []:
            if document["id"] not in known_ids:
                self.docs.append(document)
                known_ids.add(document["id"])
        if not use_v2_scenarios:
            for d in self.docs:
                d["scenario"] = d.get("scenario_v1", d["scenario"])
        self.coverage, self.hard_filter = coverage, hard_filter
        self.no_evidence_weight, self.minimum = no_evidence_weight, minimum_solution_coverage
        self.k1, self.b, self.index, self.vote, self.vote_k = k1, b, index, vote, vote_k

        def text(d):
            original = " ".join((d["title"], d["title"], d["content"], d.get("tags") or ""))
            if d["doc_type"] != "case" or index == "original" or not d.get("observed"):
                return original
            return d["observed"] if index == "observed" else original + " " + d["observed"]
        self.tf = [Counter(tokens(text(d))) for d in self.docs]
        self.fallback = fallback and index == "observed"
        self.tf_alt = ([Counter(tokens(" ".join((d["title"], d["title"], d["content"], d.get("tags") or ""))))
                        for d in self.docs] if self.fallback else None)
        self.phrase_bar = phrase_bar
        self._local = threading.local()           # per-thread exclusion set, see excluding()
        self.len = [sum(c.values()) for c in self.tf]
        self.avglen = sum(self.len) / max(1, len(self.len))
        df = Counter(t for c in self.tf for t in c)
        n = len(self.docs)
        self.idf = defaultdict(lambda: math.log(n + 1), {t: math.log((n + 1) / (f + 0.5)) for t, f in df.items()})
        # A card's symptom signature: its title and Symptoms line, the words an incident would show.
        self.signature = {}
        for i, d in enumerate(self.docs):
            if d["doc_type"] == "solution":
                m = d.get("metadata") or {}
                sig = " ".join([d["title"], *m.get("symptoms", []), *m.get("tags", [])])
                self.signature[i] = set(tokens(sig))
        self.phrases = {i: [set(tokens(p)) for p in (d.get("metadata") or {}).get("symptoms", []) if tokens(p)]
                        for i, d in enumerate(self.docs) if d["doc_type"] == "solution"}

    @contextmanager
    def excluding(self, ids):
        """Hide these case ids (and documents that absorbed them as duplicates) from retrieval in this thread, for a
        leave-out evaluation: what retrieval knows about a fault when the index has never seen it on that service."""
        prev = getattr(self._local, "ids", frozenset())
        self._local.ids = frozenset(ids)
        try:
            yield self
        finally:
            self._local.ids = prev

    def _hidden(self, d: dict[str, Any]) -> bool:
        ids = getattr(self._local, "ids", None)
        return bool(ids) and (d["id"] in ids or any(x in ids for x in d.get("duplicates") or ()))

    def _bm25(self, q: Counter, i: int, tf_table=None) -> float:
        tf, s = (tf_table or self.tf)[i], 0.0
        for t, qn in q.items():
            f = tf.get(t)
            if f:
                s += self.idf[t] * f * (self.k1 + 1) / (f + self.k1 * (1 - self.b + self.b * self.len[i] / self.avglen))
        return s

    def _coverage(self, q: Counter, i: int) -> tuple[float, list[str]]:
        if self.coverage == "phrase":
            best, hit = 0.0, []
            for ph in self.phrases.get(i, []):
                if ph <= q.keys():
                    w = sum(self.idf[t] for t in ph)
                    if w > best:
                        best, hit = w, sorted(ph)
            return best, hit
        if self.coverage == "card":
            sig = self.signature.get(i) or set()
            hit = [t for t in sig if t in q]
            total = sum(self.idf[t] for t in sig)
            return (sum(self.idf[t] for t in hit) / total if total else 0.0), hit
        hit = [t for t in q if t in self.tf[i]]
        total = sum(self.idf[t] for t in q)
        return (sum(self.idf[t] for t in hit) / total if total else 0.0), hit

    def search(self, query: str, *, doc_type: str, top_k: int, scenario: str | None = None) -> list[dict[str, Any]]:
        q = Counter(tokens(query))
        if not q:
            return []
        scored = []
        for i, d in enumerate(self.docs):
            if d["doc_type"] != doc_type or (scenario and d["scenario"] != scenario) or self._hidden(d):
                continue
            s = self._bm25(q, i)
            if s <= 0:
                continue
            if doc_type == "case" and not d.get("has_evidence", True):
                if self.no_evidence_weight <= 0:
                    continue
                s *= self.no_evidence_weight
            scored.append((s, i))
        scored.sort(reverse=True)
        if doc_type == "case" and self.fallback and len(scored) < top_k:
            have = {i for _, i in scored}
            alt = sorted(((self._bm25(q, i, self.tf_alt), i) for i, d in enumerate(self.docs)
                          if i not in have and d["doc_type"] == "case" and not self._hidden(d)
                          and not (scenario and d["scenario"] != scenario)), reverse=True)
            scored += [(s, i) for s, i in alt if s > 0][:top_k - len(scored)]
        return [self._result(i, s, q) for s, i in scored[:top_k]]

    def _result(self, i: int, s: float, q: Counter) -> dict[str, Any]:
        d = self.docs[i]
        cov, hit = self._coverage(q, i)
        return {"id": d["id"], "doc_type": d["doc_type"], "scenario": d["scenario"], "title": d["title"],
                "content": d["content"], "source": d["source"], "risk_tier": d.get("risk_tier"),
                "labels": d.get("labels") or [], "score": round(s, 4), "matched_terms": hit,
                "match_coverage": round(cov, 3), "metadata": d.get("metadata") or {}}

    def _cards_for(self, query: str, scenario: str, k: int) -> list[dict[str, Any]]:
        """The cards of one scenario, best BM25 first; all of them, even those sharing no word with the query."""
        q = Counter(tokens(query))
        idx = [i for i, d in enumerate(self.docs) if d["doc_type"] == "solution" and d["scenario"] == scenario]
        return [self._result(i, s, q) for s, i in sorted(((self._bm25(q, i), i) for i in idx), reverse=True)[:k]]

    def retrieve(self, incident: dict[str, Any], *, case_k: int = 4, solution_k: int = 4,
                 minimum_solution_coverage: float | None = None) -> dict[str, Any]:
        from .api import _flatten
        from .corpus import infer_scenario
        query = " ".join(_flatten(incident))
        scenario = incident.get("scenario") or infer_scenario(query)
        filt = scenario if (self.hard_filter and scenario != "other") else None
        minimum = self.minimum if minimum_solution_coverage is None else minimum_solution_coverage
        if self.coverage == "phrase" and minimum_solution_coverage is None and self.phrase_bar is not None:
            minimum = self.phrase_bar
        cases = self.search(query, doc_type="case", top_k=case_k, scenario=filt)
        cands = self.search(query, doc_type="solution", top_k=solution_k, scenario=filt)
        # v1 takes the best coverage among the top-k by rank; keep that, but order the cards by coverage so the
        # first card shown is the one that cleared the bar.
        cands.sort(key=lambda c: -c["match_coverage"])
        best = cands[0]["match_coverage"] if cands else 0.0
        has_match = best >= minimum
        if self.vote:
            pool = cases if case_k >= self.vote_k else self.search(query, doc_type="case", top_k=self.vote_k, scenario=filt)
            votes = Counter(c["scenario"] for c in pool[:self.vote_k])
            top, n = votes.most_common(1)[0] if votes else (None, 0)
            has_match = top in ("disk_full", "crashloop", "dns") and n >= self.vote
            best = round(n / self.vote_k, 3) if has_match else 0.0
            if has_match:
                cands = self._cards_for(query, top, solution_k)
                for c in cands:
                    c["match_coverage"], c["vote"] = best, f"{n}/{self.vote_k} similar incidents were {top}"
        return {
            "scenario": scenario, "query": query,
            "knowledge_match": {"status": "matched" if has_match else "insufficient", "best_solution_coverage": best,
                                "minimum_solution_coverage": minimum,
                                "instruction": ("Treat results as hypotheses and verify against current read-only evidence."
                                                if has_match else "Knowledge base has no strong solution match. Run "
                                                "read-only checks or escalate; do not repair.")},
            "cases": cases, "solutions": cands if has_match else [], "weak_solution_candidates": [] if has_match else cands,
            "topologies": self.search(query, doc_type="topology", top_k=2),
            "policy": {"mode": "plan_only", "required_before_fix": [
                "confirm root cause using current read-only evidence", "state blast radius", "provide rollback",
                "obtain approval for W/D actions"]},
        }


# --- query from telemetry ---------------------------------------------------------------------------------------

SYMPTOM_RE = re.compile(r"\b(error|fail(ed|ure|ing)?|fatal|exception|refused|timeout|timed out|unavailable|oom(killed)?|"
                        r"killed|no space|restarting|crash(loop)?(backoff)?|back-?off|pressure|not found|no such|denied|"
                        r"unreachable|evict(ed|ion)?|5\d\d|unable|cannot|can't|deadline|reset|refus)\b", re.I)
# apm summaries: "apm pod frontend-0: error_ratio 0->2.779 (peak 10.34); rrt 1.2e+04->1.7e+06 ..."
CHANGE_RE = re.compile(r"([A-Za-z_][\w.-]*) ([0-9.e+-]+)->([0-9.e+-]+)")
# infra summaries: "pod_memory_working_set_bytes shippingservice-0: baseline 6795 -> window 3.16e+04, peak ..."
INFRA_RE = re.compile(r"^([A-Za-z_][\w.]*) (\S+): baseline ([0-9.e+-]+) -> window ([0-9.e+-]+)")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _ratio(a: str, b: str) -> float:
    try:
        x, y = float(a), float(b)
    except ValueError:
        return 0.0
    return abs(math.log((y + 1e-6) / (x + 1e-6)))


def incident_query(events: list[dict[str, Any]], *, max_metrics: int = 8, max_lines: int = 12,
                   entities: bool = True) -> str:
    """A deterministic query from compressed telemetry: the metrics that moved most (names, with their service) and
    the distinct symptom-looking log/event lines. No model call, so it is reproducible and free."""
    moved = []
    for e in events:
        msg = ANSI_RE.sub("", str(e.get("message") or ""))
        if e.get("kind") in ("metric", "metrics"):
            if msg.startswith("{"):
                try:
                    row = json.loads(msg)
                except ValueError:
                    continue
                if isinstance(row, dict) and "metric" in row:          # one-metric JSON rows (RCA100)
                    moved.append((0.1, f"{row.get('entity_name', '')} {row['metric']}"))
                continue                                             # wide rows: see _wide_moves
            infra = INFRA_RE.match(msg)
            if infra:
                name, entity, a, b = infra.groups()
                moved.append((_ratio(a, b), f"{entity} {name}"))
                continue
            for name, a, b in CHANGE_RE.findall(msg):
                moved.append((_ratio(a, b), f"{e.get('service') or ''} {name}"))
    moved += _wide_moves(events)
    moved.sort(key=lambda x: -x[0])
    if not entities:                                        # metric names only: "aiops-k8s-04 node_disk_..." -> "node_disk_..."
        moved = [(r, m.split()[-1]) for r, m in moved if m.split()]
    metric_part = list(dict.fromkeys(m for _, m in moved))[:max_metrics]
    lines = []
    for e in sorted(events, key=lambda e: -int(e.get("count") or 1)):
        if e.get("kind") in ("metric", "metrics", "boundary", "topology"):
            continue
        m = ANSI_RE.sub("", str(e.get("template") or e.get("message") or "")).replace("\n", " ")[:200]
        if SYMPTOM_RE.search(m) and m not in lines:
            lines.append(m)
        if len(lines) >= max_lines:
            break
    return " | ".join(metric_part + lines)


def _wide_moves(events: list[dict[str, Any]], top: int = 12) -> list[tuple[float, str]]:
    """Columns of wide per-timestamp metric rows (RCAEval) that moved most across the injection boundary."""
    rows, boundary = [], None
    for e in events:
        if e.get("kind") == "boundary":
            m = re.search(r"unix=(\d+)", str(e.get("message") or ""))
            boundary = float(m.group(1)) if m else boundary
        msg = str(e.get("message") or "")
        if e.get("kind") in ("metric", "metrics") and msg.startswith('{"time"'):
            try:
                d = json.loads(msg)
            except ValueError:
                continue
            if isinstance(d, dict) and isinstance(d.get("time"), (int, float)):
                rows.append(d)
    if len(rows) < 2:
        return []
    times = sorted(d["time"] for d in rows)
    split = boundary if boundary and times[0] < boundary <= times[-1] else times[len(times) // 2]
    cols = defaultdict(lambda: ([], []))
    for d in rows:
        side = 1 if d["time"] >= split else 0
        for k, v in d.items():
            if k != "time" and isinstance(v, (int, float)):
                cols[k][side].append(v)
    out = []
    for k, (b, a) in cols.items():
        if a and b:
            out.append((_ratio(str(sum(b) / len(b)), str(sum(a) / len(a))), k))
    out.sort(reverse=True)
    return out[:top]


# --- leave-out: which train cases are "the same incident again" -----------------------------------------------------

def case_services(metadata: dict[str, Any]) -> set[str]:
    """Service / pod / node names of a case, without pod hashes and replica ordinals (cart-64944cd445-8pbgx -> cart,
    cartservice-0 -> cartservice, app/adservice -> adservice)."""
    vals: list[Any] = []
    for k in ("service", "instance", "root_cause_service", "fault_object", "entities"):
        v = metadata.get(k)
        vals += v if isinstance(v, (list, tuple)) else [v]
    out = set()
    for v in vals:
        if not v:
            continue
        x = str(v).casefold().strip("[]'\" ").split("/")[-1]
        x = re.sub(r"-[0-9a-z]{6,10}-[0-9a-z]{5}$", "", x)
        x = re.sub(r"-\d+$", "", x)
        if len(x) >= 3:
            out.add(x)
    return out


def _norm_label(x: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(x).casefold())


def sibling_ids(target: dict[str, Any], train: list[dict[str, Any]]) -> set[str]:
    """Train cases that are the target's fault again on the same service: same source, a shared label, and an
    overlapping service name. When either side names no service, a shared label is enough (conservative: more is
    hidden, never less)."""
    labels = {_norm_label(x) for x in target.get("labels") or [] if x}
    services = case_services(target.get("metadata") or {})
    out = set()
    for c in train:
        if c.get("source") != target.get("source"):
            continue
        if not labels & {_norm_label(x) for x in c.get("labels") or [] if x}:
            continue
        other = case_services(c.get("metadata") or {})
        if not services or not other or any(a == b or a in b or b in a for a in services for b in other):
            out.add(c["id"])
    return out
