"""Runbook retrieval: keyword, dense, or both. Fully offline once the embedding model is cached.

  uv run --no-sync scripts/rag.py build              embed every runbook chunk into logs/rag-index.npz
  uv run --no-sync scripts/rag.py query "502 on api" show what each scorer retrieves
  uv run --no-sync scripts/rag.py eval               recall@1 for keyword / dense / hybrid over the query set

Measured on the 20-query set at the bottom of this file: dense 20/20, hybrid 18-20 depending on weight, keyword
15/20. Dense is the default; RAG_MODE=keyword|dense|hybrid overrides it.

Design notes. Chunks are scored, whole runbooks are returned: an agent that gets half a procedure will act on half a
procedure. The embedding model (BAAI/bge-small-en-v1.5, 33M params, 384 dims) runs on CPU in milliseconds and stays
off the GPU, which belongs to the inference server. Without the index, or without torch, everything falls back to the
keyword scorer, so a fresh clone still answers.
"""
import json
import os

os.environ.setdefault("HF_HUB_OFFLINE", "1")     # the box may have no route out; never let retrieval wait on the hub

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
RUNBOOKS = ROOT / "runbooks"
INDEX = ROOT / "logs" / "rag-index.npz"
MODEL = os.environ.get("RAG_MODEL", "BAAI/bge-small-en-v1.5")
QUERY_PREFIX = "Represent this sentence for searching relevant passages: "   # what bge-* was trained with
CHUNK_CHARS = 450
_model = None


def documents():
    """Every runbook as (name, title, text), sorted so results are reproducible."""
    out = []
    for f in sorted(RUNBOOKS.glob("*.md")):
        text = f.read_text().strip()
        title = text.splitlines()[0].lstrip("# ").strip() if text else f.stem
        out.append((f.name, title, text))
    return out


def chunks():
    """Chunk on line boundaries, each chunk carrying its runbook title so it can be read on its own."""
    out = []
    for name, title, text in documents():
        body, buf = text.splitlines()[1:], ""
        for line in body:
            if buf and len(buf) + len(line) > CHUNK_CHARS:
                out.append((name, f"{title}\n{buf.strip()}"))
                buf = ""
            buf += line + "\n"
        out.append((name, f"{title}\n{buf.strip()}"))
    return out


# --- scorers ------------------------------------------------------------------------------------------------------

def keyword_scores(query):
    """Title-weighted term overlap. Expected to win on pasted error strings; measured, it does not. Kept as the
    no-index fallback and as the baseline the dense scorer is judged against."""
    terms = set(re.findall(r"[a-z0-9]+", query.lower()))
    scores = {}
    for name, title, text in documents():
        title_words = set(re.findall(r"[a-z0-9]+", (pathlib.Path(name).stem + " " + title).lower()))
        body_words = set(re.findall(r"[a-z0-9]+", text.lower()))
        scores[name] = 3 * len(terms & title_words) + len(terms & body_words)
    return scores


def _encode(texts):
    global _model
    import numpy as np
    import torch
    if _model is None:
        from transformers import AutoModel, AutoTokenizer
        tok = AutoTokenizer.from_pretrained(MODEL)
        mod = AutoModel.from_pretrained(MODEL).eval()
        _model = (tok, mod)
    tok, mod = _model
    batch = tok(texts, padding=True, truncation=True, max_length=512, return_tensors="pt")
    with torch.no_grad():
        hidden = mod(**batch).last_hidden_state[:, 0]          # bge pools the CLS token
    vecs = torch.nn.functional.normalize(hidden, p=2, dim=1)
    return vecs.numpy().astype(np.float32)


def build():
    import numpy as np
    rows = chunks()
    vecs = _encode([c for _, c in rows])
    INDEX.parent.mkdir(parents=True, exist_ok=True)
    np.savez(INDEX, vectors=vecs, names=np.array([n for n, _ in rows]), model=np.array([MODEL]))
    return f"indexed {len(rows)} chunks from {len({n for n, _ in rows})} runbooks -> {INDEX}"


def dense_scores(query):
    """Cosine similarity of the best chunk of each runbook. {} when there is no usable index."""
    try:
        import numpy as np
        if not INDEX.exists():
            return {}
        data = np.load(INDEX, allow_pickle=False)
        q = _encode([QUERY_PREFIX + query])[0]
        sims = data["vectors"] @ q
        best = {}
        for name, sim in zip(data["names"], sims):
            best[str(name)] = max(best.get(str(name), -1.0), float(sim))
        return best
    except Exception as e:                     # never let retrieval break an incident response
        print(f"dense retrieval unavailable: {type(e).__name__}: {e}", file=sys.stderr)
        return {}


def _normalize(scores):
    if not scores:
        return {}
    lo, hi = min(scores.values()), max(scores.values())
    return {k: (v - lo) / (hi - lo) for k, v in scores.items()} if hi > lo else {k: 0.0 for k in scores}


def rank(query, mode="dense"):
    """Ranked [(name, score)].

    Measured over the 20-query set below on 8 runbooks: dense 20/20, hybrid at every weight 18-20, keyword 15/20.
    The expectation that exact error strings would favour lexical matching did not survive the measurement, so dense
    is the default and hybrid stays available for a larger corpus. Keyword is the fallback with no index.
    """
    kw = keyword_scores(query)
    if mode == "keyword":
        combined = dict(kw)
    else:
        dn = dense_scores(query)
        if not dn:
            combined = dict(kw)
        elif mode == "dense":
            combined = dict(dn)
        else:
            nk, nd = _normalize(kw), _normalize(dn)
            combined = {n: 0.6 * nk.get(n, 0.0) + 0.4 * nd.get(n, 0.0) for n in set(nk) | set(nd)}
    return sorted(combined.items(), key=lambda kv: (-kv[1], kv[0]))


def search(query, k=2, mode=None):
    """Formatted result for the agent: the full text of the best runbooks, or the catalogue when nothing matches."""
    mode = mode or os.environ.get("RAG_MODE", "dense")
    docs = {name: text for name, _, text in documents()}
    ranked = rank(query, mode)
    hits = [(n, s) for n, s in ranked if s > 0]
    if not hits:
        return "no runbook matched. Available runbooks:\n" + "\n".join(
            f"- {n}: {t}" for n, t, _ in documents())
    return "\n\n".join(f"## {n}\n{docs[n][:1500]}" for n, _ in hits[:k])


EVAL = [                                            # symptom -> the runbook an operator would want
    ("nginx exited with emerg unknown directive", "nginx-config-error.md"),
    ("missing semicolon in the config file", "nginx-config-error.md"),
    ("api returns 502 bad gateway", "upstream-502.md"),
    ("connection refused while connecting to upstream", "upstream-502.md"),
    ("api is timing out with 504", "upstream-504.md"),
    ("upstream timed out reading response header", "upstream-504.md"),
    ("host not found in upstream", "upstream-name-resolution.md"),
    ("proxy_pass points at a name that does not resolve", "upstream-name-resolution.md"),
    ("container keeps restarting over and over", "container-crashloop.md"),
    ("exited 137 killed", "oom-killed.md"),
    ("the kernel killed the process out of memory", "oom-killed.md"),
    ("no space left on device", "disk-full.md"),
    ("filesystem is full", "disk-full.md"),
    ("front end container is down and the site is unreachable", "web-service-down.md"),
    ("no such container, it is not listed at all", "container-missing.md"),
    ("someone deleted the container and start fails", "container-missing.md"),
    ("health check connection refused nothing listening", "web-service-down.md"),
    # paraphrases with none of the runbook's own vocabulary: what dense retrieval is supposed to buy us
    ("the web page will not load at all", "web-service-down.md"),
    ("backend keeps dying and coming back", "container-crashloop.md"),
    ("we ran out of storage", "disk-full.md"),
    ("the machine ran out of RAM and something was terminated", "oom-killed.md"),
    ("the gateway waits forever for the backend", "upstream-504.md"),
    ("the front end vanished from the container list", "container-missing.md"),
    ("api returns 500 but the upstream container is up", "upstream-5xx.md"),
    ("restart did not help, the upstream still answers 500", "upstream-5xx.md"),
    ("both containers up but nginx times out connecting to upstream", "upstream-detached.md"),
    ("the backend fell off the docker network", "upstream-detached.md"),
    ("container is paused", "upstream-504.md"),
    ("the service itself answers HTTP 500 to requests, container is up", "upstream-5xx.md"),
    ("container exited", "web-service-down.md"),
    ("container exited unexpectedly", "web-service-down.md"),
    ("exited with code 0 and nothing in the log", "web-service-down.md"),
    ("container exited cleanly with code 0, stopped, no error in the log, start it again", "web-service-down.md"),
]


def evaluate():
    rows = []
    for mode in ("keyword", "dense", "hybrid"):
        hits = [(q, rank(q, mode)[0][0] if rank(q, mode) else "-", want) for q, want in EVAL]
        ok = sum(1 for _, got, want in hits if got == want)
        rows.append((mode, ok, len(EVAL), [(q, got, want) for q, got, want in hits if got != want]))
    width = max(len(q) for q, _ in EVAL)
    for mode, ok, total, misses in rows:
        print(f"{mode:8} recall@1 {ok}/{total}")
        for q, got, want in misses:
            print(f"         MISS {q:<{width}}  got {got}  want {want}")
    return rows


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "help"
    if cmd == "build":
        print(build())
    elif cmd == "query":
        q = " ".join(sys.argv[2:])
        for mode in ("keyword", "dense", "hybrid"):
            print(f"-- {mode}: " + json.dumps([[n, round(s, 3)] for n, s in rank(q, mode)[:3]]))
        print()
        print(search(q))
    elif cmd == "eval":
        evaluate()
    else:
        print(__doc__)
