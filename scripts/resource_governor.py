#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///

# ─── How to run ───
# 1. Install uv: curl -LsSf https://astral.sh/uv/install.sh | sh
# 2. Run: uv run scripts/resource_governor.py [--mem GIB]
# 3. Or: python3 scripts/resource_governor.py [--mem GIB]
# ─────────────────

"""Decide specialist parallelism, reranker use, and community corpus size.
Never restrict the main agent or safety path; those always run.
scripts/community_knowledge.py consumes reranker_allowed and community_corpus.
"""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Mapping
from typing import Literal, TypedDict


class GovernorPlan(TypedDict):
    mode: Literal["full", "reduced", "minimal"]
    max_parallel_specialists: Literal[2, 1, 0]
    reranker_allowed: bool
    community_corpus: Literal["v2", "v1"]
    reason: str


def read_mem_available_gib(
    path: str | os.PathLike[str] = "/proc/meminfo",
) -> float | None:
    try:
        with open(path, encoding="utf-8") as stream:
            for line in stream:
                if line.startswith("MemAvailable:"):
                    return float(line.split()[1]) / (1024**2)
    except (OSError, IndexError, ValueError):
        return None
    return None


def plan(
    mem_available_gib: float | None,
    running_llm_instances: int = 1,
    env: Mapping[str, str] = os.environ,
) -> GovernorPlan:
    if mem_available_gib is None:
        return {"mode": "full", "max_parallel_specialists": 2,
                "reranker_allowed": True, "community_corpus": "v2",
                "reason": "memory unknown: not restricting"}

    full = float(env.get("GOV_FULL_GB", "20"))
    reduced = float(env.get("GOV_REDUCED_GB", "8"))
    extra = float(env.get("GOV_EXTRA_INSTANCE_GB", "25"))
    available = mem_available_gib - extra if running_llm_instances >= 2 else mem_available_gib
    if available >= full:
        return {"mode": "full", "max_parallel_specialists": 2,
                "reranker_allowed": True, "community_corpus": "v2",
                "reason": f"effective memory meets GOV_FULL_GB={full:g} GiB threshold."}
    if available >= reduced:
        return {"mode": "reduced", "max_parallel_specialists": 1,
                "reranker_allowed": True, "community_corpus": "v1",
                "reason": f"effective memory meets GOV_REDUCED_GB={reduced:g} GiB threshold."}
    return {"mode": "minimal", "max_parallel_specialists": 0,
            "reranker_allowed": False, "community_corpus": "v1",
            "reason": f"effective memory is below GOV_REDUCED_GB={reduced:g} GiB threshold."}


def main() -> None:
    parser = argparse.ArgumentParser(description="Plan optional agent resource use.")
    parser.add_argument("--mem", type=float, help="override available memory in GiB")
    args = parser.parse_args()
    memory = args.mem if args.mem is not None else read_mem_available_gib()
    print(json.dumps(plan(memory)))


if __name__ == "__main__":
    main()
