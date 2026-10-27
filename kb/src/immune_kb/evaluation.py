from __future__ import annotations

import csv
import json
import re
from collections import defaultdict
from pathlib import Path
from statistics import mean
from typing import Any

from .compression import compress_events
from .evidence import EvidenceUnavailable, load_evidence


DEFAULT_KEYWORDS = [
    "error",
    "failed",
    "failure",
    "fatal",
    "exception",
    "unavailable",
    "timeout",
    "restart",
    "pressure",
    "refused",
    "no such host",
    "oomkilled",
]


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    with Path(path).open("r", encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def prepare_evaluation(
    ground_truth: str | Path,
    datasets_root: str | Path,
    output_dir: str | Path,
    *,
    ratios: list[float],
    limit: int,
    scenario: str | None = None,
    source: str | None = None,
    max_events: int = 2000,
    keywords: list[str] | None = None,
) -> dict[str, Any]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    candidates = read_jsonl(ground_truth)
    if scenario:
        candidates = [item for item in candidates if item.get("scenario") == scenario]
    if source:
        candidates = [item for item in candidates if source.lower() in str(item.get("source", "")).lower()]
    streams = {
        ratio: (output / f"inputs_ratio_{str(ratio).replace('.', '_')}.jsonl").open(
            "w", encoding="utf-8", newline="\n"
        )
        for ratio in ratios
    }
    prepared = 0
    skipped: list[dict[str, str]] = []
    try:
        for truth in candidates:
            if prepared >= limit:
                break
            try:
                bundle = load_evidence(truth, datasets_root, max_events=max_events)
            except (EvidenceUnavailable, OSError, ValueError) as exc:
                skipped.append({"id": truth["id"], "reason": str(exc)})
                continue
            for ratio, stream in streams.items():
                compressed = compress_events(
                    bundle["events"],
                    target_ratio=ratio,
                    keywords=keywords or DEFAULT_KEYWORDS,
                    window_start=bundle.get("window", {}).get("start"),
                    window_end=bundle.get("window", {}).get("end"),
                )
                agent_input = {
                    "id": truth["id"],
                    "compression_ratio": ratio,
                    "telemetry": compressed["events"],
                    "compression_metrics": compressed["metrics"],
                }
                stream.write(json.dumps(agent_input, ensure_ascii=False, separators=(",", ":")) + "\n")
            prepared += 1
    finally:
        for stream in streams.values():
            stream.close()
    report = {
        "prepared_cases": prepared,
        "candidate_cases": len(candidates),
        "ratios": ratios,
        "scenario_filter": scenario,
        "source_filter": source,
        "keywords": keywords or DEFAULT_KEYWORDS,
        "skipped": skipped,
        "answer_fields_in_inputs": False,
    }
    (output / "prepare_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return report


def _normalize(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value).casefold())


def _label_correct(expected: list[str], predicted: Any) -> bool:
    predictions = predicted if isinstance(predicted, list) else [predicted]
    expected_norm = [_normalize(value) for value in expected if value]
    prediction_norm = [_normalize(value) for value in predictions if value]
    return any(
        wanted == got or (len(wanted) >= 6 and wanted in got)
        for wanted in expected_norm
        for got in prediction_norm
    )


def score_predictions(
    ground_truth: str | Path,
    predictions: str | Path,
    output_csv: str | Path,
) -> dict[str, Any]:
    truths = {item["id"]: item for item in read_jsonl(ground_truth)}
    rows: list[dict[str, Any]] = []
    unknown_ids: list[str] = []
    for prediction in read_jsonl(predictions):
        truth = truths.get(prediction.get("id"))
        if truth is None:
            unknown_ids.append(str(prediction.get("id")))
            continue
        ratio = float(prediction.get("compression_ratio", 1.0))
        rows.append(
            {
                "id": prediction["id"],
                "compression_ratio": ratio,
                "correct": _label_correct(
                    truth.get("labels") or [],
                    prediction.get("predicted_labels", prediction.get("predicted_label")),
                ),
                "scenario_correct": (
                    prediction.get("predicted_scenario") == truth.get("scenario")
                    if prediction.get("predicted_scenario") is not None
                    else None
                ),
                "input_tokens": float(prediction.get("input_tokens", 0) or 0),
                "latency_ms": float(prediction.get("latency_ms", 0) or 0),
                "energy_wh": float(prediction.get("energy_wh", 0) or 0),
            }
        )
    grouped: dict[float, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[row["compression_ratio"]].append(row)
    curve = []
    for ratio in sorted(grouped):
        values = grouped[ratio]
        scenario_values = [item["scenario_correct"] for item in values if item["scenario_correct"] is not None]
        curve.append(
            {
                "compression_ratio": ratio,
                "cases": len(values),
                "diagnostic_accuracy": round(mean(item["correct"] for item in values), 6),
                "scenario_accuracy": round(mean(scenario_values), 6) if scenario_values else None,
                "avg_input_tokens": round(mean(item["input_tokens"] for item in values), 3),
                "avg_latency_ms": round(mean(item["latency_ms"] for item in values), 3),
                "avg_energy_wh": round(mean(item["energy_wh"] for item in values), 6),
            }
        )
    output = Path(output_csv)
    output.parent.mkdir(parents=True, exist_ok=True)
    fields = (
        "compression_ratio",
        "cases",
        "diagnostic_accuracy",
        "scenario_accuracy",
        "avg_input_tokens",
        "avg_latency_ms",
        "avg_energy_wh",
    )
    with output.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(curve)
    selected = None
    if curve:
        best_accuracy = max(item["diagnostic_accuracy"] for item in curve)
        eligible = [item for item in curve if item["diagnostic_accuracy"] >= best_accuracy - 0.01]
        selected = min(eligible, key=lambda item: (item["avg_input_tokens"], -item["compression_ratio"]))
    report = {
        "prediction_rows": len(rows),
        "unknown_prediction_ids": unknown_ids,
        "curve": curve,
        "selected_working_point": selected,
        "selection_rule": "lowest average input tokens within 1 percentage point of best diagnostic accuracy",
    }
    output.with_suffix(".summary.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return report
