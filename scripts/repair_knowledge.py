"""Load hard-failure repair knowledge for RAG. Never reads evaluation inputs or answers; never executes calls."""
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
KNOWLEDGE = ROOT / "datasets" / "curated" / "hard_repairs" / "knowledge.json"


def documents():
    """The four curated procedures, in the existing BM25 solution-document schema."""
    cards = json.loads(KNOWLEDGE.read_text(encoding="utf-8"))
    out = []
    for card in cards:
        lines = [card["title"], "Symptoms: " + "; ".join(card["symptoms"]), card["diagnosis"]]
        lines += ["Evidence required: " + e for e in card["required_evidence"]]
        lines += [json.dumps(step, ensure_ascii=False) for step in card["tool_path"]]
        out.append({"id": card["id"], "doc_type": "solution", "scenario": "other", "scenario_v1": "other",
                    "platform": "docker", "title": card["title"], "content": "\n".join(lines),
                    "tags": " ".join(card["tags"]), "source": "curated hard-failure repair knowledge; not a live incident",
                    "risk_tier": 2, "labels": [], "metadata": card, "duplicates": [], "has_evidence": True})
    return out


def render(card, *, brief=False):
    """Keep conditional calls, verification and scope together; do not turn a retrieved plan into an executor."""
    lines = [f"\n--- retrieved hard-failure procedure: {card['id']} ---", card["title"],
             "Hypothesis only; confirm on this incident. " + card["diagnosis"],
             "REQUIRES: " + "; ".join(card["required_evidence"])]
    if brief:
        lines.append("CHECK: " + json.dumps(card["tool_path"][0], ensure_ascii=False))
        lines.append("For the conditional tool path, rollback and verification, call search_incident_knowledge "
                     "with the exact error and the container that emitted it.")
    else:
        lines.append("TOOL PATH (examples, not an automatically executed script):")
        lines += [json.dumps(step, ensure_ascii=False) for step in card["tool_path"]]
        lines.append("ROLLBACK: " + "; ".join(card["rollback"]))
        lines.append("VERIFY: " + "; ".join(card["verify"]))
        lines.append("ESCALATE: " + "; ".join(card["escalate"]))
        lines.append("Sources: " + " ".join(s["url"] for s in card["sources"]))
    lines.append("SCOPE: " + card["scope"])
    return "\n".join(lines)
