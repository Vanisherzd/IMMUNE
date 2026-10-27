from __future__ import annotations

import csv
import io
import json
import re
import tarfile
from datetime import datetime, timedelta, timezone
from statistics import mean
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any, BinaryIO


class EvidenceUnavailable(RuntimeError):
    pass


def _short(value: Any, limit: int = 4000) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        text = value
    else:
        text = json.dumps(value, ensure_ascii=False, default=str, separators=(",", ":"))
    return text if len(text) <= limit else text[:limit] + "…"


def _event(
    kind: str,
    message: Any,
    *,
    timestamp: Any = None,
    service: Any = None,
    source_file: str | None = None,
    fields: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "kind": kind,
        "timestamp": None if timestamp is None else str(timestamp),
        "service": None if service is None else str(service),
        "message": _short(message),
        "source_file": source_file,
        "fields": fields or {},
    }


def _timestamp(row: dict[str, Any]) -> Any:
    for key in (
        "timestamp",
        "@timestamp",
        "time",
        "ts",
        "datetime",
        "start_time",
        "event_time",
        "observed_time_unix_nano",
    ):
        if key in row and row[key] not in (None, ""):
            return row[key]
    return None


def _service(row: dict[str, Any]) -> Any:
    for key in ("service", "serviceName", "service_name", "container_name", "pod", "instance"):
        if key in row and row[key] not in (None, ""):
            return row[key]
    return None


def _row_message(row: dict[str, Any]) -> str:
    for key in ("message", "body", "log", "content", "description", "summary"):
        if key in row and row[key] not in (None, ""):
            return _short(row[key])
    useful = {key: value for key, value in row.items() if value not in (None, "")}
    return _short(useful)


def _parquet_events(
    source: Path | BinaryIO,
    *,
    kind: str,
    source_name: str,
    limit: int,
) -> Iterator[dict[str, Any]]:
    try:
        import pyarrow.parquet as parquet
    except ImportError as exc:
        raise EvidenceUnavailable("Parquet reader missing. Install: pip install 'immune-kb[telemetry]'") from exc
    parquet_file = parquet.ParquetFile(source)
    emitted = 0
    for batch in parquet_file.iter_batches(batch_size=min(256, max(limit, 1))):
        for row in batch.to_pylist():
            yield _event(
                kind,
                _row_message(row),
                timestamp=_timestamp(row),
                service=_service(row),
                source_file=source_name,
            )
            emitted += 1
            if emitted >= limit:
                return


def _json_events(path: Path, kind: str, limit: int) -> Iterator[dict[str, Any]]:
    item = json.loads(path.read_text(encoding="utf-8"))
    emitted = 0
    if kind == "log" and isinstance(item, dict):
        for service, values in item.items():
            for raw in values if isinstance(values, list) else [values]:
                parsed: Any = raw
                if isinstance(raw, str) and raw.lstrip().startswith(("{", "[")):
                    try:
                        parsed = json.loads(raw)
                    except json.JSONDecodeError:
                        parsed = raw
                if isinstance(parsed, dict):
                    yield _event(
                        kind,
                        parsed.get("message", parsed),
                        timestamp=parsed.get("time") or parsed.get("timestamp"),
                        service=service,
                        source_file=path.name,
                        fields={"level": parsed.get("level")},
                    )
                else:
                    yield _event(kind, parsed, service=service, source_file=path.name)
                emitted += 1
                if emitted >= limit:
                    return
        return
    if isinstance(item, dict):
        for key, value in item.items():
            if isinstance(value, str):
                for line in value.splitlines() or [value]:
                    yield _event(kind, line, service=key, source_file=path.name)
                    emitted += 1
                    if emitted >= limit:
                        return
            else:
                yield _event(kind, value, service=key, source_file=path.name)
                emitted += 1
                if emitted >= limit:
                    return
    elif isinstance(item, list):
        for value in item[:limit]:
            if isinstance(value, dict):
                yield _event(
                    kind,
                    _row_message(value),
                    timestamp=_timestamp(value),
                    service=_service(value),
                    source_file=path.name,
                )
            else:
                yield _event(kind, value, source_file=path.name)


def _delimited_events(path: Path, kind: str, limit: int) -> Iterator[dict[str, Any]]:
    if path.read_bytes()[:40].startswith(b"version https://git-lfs"):
        raise EvidenceUnavailable(f"Git LFS payload not downloaded: {path}")
    delimiter = "\t" if path.suffix.lower() == ".tsv" else ","
    with path.open("r", encoding="utf-8", errors="replace", newline="") as stream:
        reader = csv.DictReader(stream, delimiter=delimiter)
        for index, row in enumerate(reader):
            if index >= limit:
                return
            yield _event(
                kind,
                _row_message(row),
                timestamp=_timestamp(row),
                service=_service(row),
                source_file=path.name,
            )


def _load_cloud(record: dict[str, Any], root: Path, max_events: int) -> list[dict[str, Any]]:
    case_dir = (root / record["source_path"]).parent
    raw = case_dir / "raw_data"
    if not raw.exists():
        raise EvidenceUnavailable(f"Cloud-OpsBench raw_data missing: {raw}")
    events: list[dict[str, Any]] = []
    specs = (("logs.json", "log"), ("k8s_states.json", "k8s_state"), ("alert.json", "alert"))
    per_source = max(1, max_events // max(len(specs) + 1, 1))
    for filename, kind in specs:
        path = raw / filename
        if path.exists():
            events.extend(_json_events(path, kind, per_source))
    metrics = raw / "metrics.csv"
    if metrics.exists():
        events.extend(_delimited_events(metrics, "metric", per_source))
    return events[:max_events]


def _load_rca100(record: dict[str, Any], root: Path, max_events: int) -> list[dict[str, Any]]:
    task_id = record.get("metadata", {}).get("task_id")
    case_dir = root / "AgenticOpsEval" / "RCA100" / "cases" / str(task_id)
    if not case_dir.exists():
        raise EvidenceUnavailable(f"RCA100 case missing: {case_dir}")
    events: list[dict[str, Any]] = []
    files = [path for path in case_dir.iterdir() if path.suffix in {".json", ".parquet"}]
    per_source = max(1, max_events // max(len(files), 1))
    for path in sorted(files):
        if path.name == "topology.json":
            item = json.loads(path.read_text(encoding="utf-8"))
            entities = {entity.get("id"): entity.get("name") for entity in item.get("entities", [])}
            for edge in item.get("edges", [])[:per_source]:
                events.append(
                    _event(
                        "topology",
                        f"{entities.get(edge.get('src'), edge.get('src'))} {edge.get('relation')} "
                        f"{entities.get(edge.get('dst'), edge.get('dst'))}",
                        source_file=path.name,
                    )
                )
        elif path.suffix == ".json":
            events.extend(_json_events(path, "task", per_source))
        else:
            events.extend(_parquet_events(path, kind=path.stem, source_name=path.name, limit=per_source))
    return events[:max_events]


def _load_rcaeval(record: dict[str, Any], root: Path, max_events: int) -> list[dict[str, Any]]:
    case_dir = root / record["source_path"]
    if not case_dir.exists():
        raise EvidenceUnavailable(f"RCAEval case missing: {case_dir}")
    paths = sorted(case_dir.glob("*.parquet"))
    per_source = max(1, max_events // max(len(paths), 1))
    events: list[dict[str, Any]] = []
    for path in paths:
        events.extend(_parquet_events(path, kind=path.stem, source_name=path.name, limit=per_source))
    inject = case_dir / "inject_time.txt"
    if inject.exists():
        events.append(_event("boundary", f"fault injection boundary unix={inject.read_text().strip()}", source_file=inject.name))
    return events[:max_events]


def _load_itbench(record: dict[str, Any], root: Path, max_events: int) -> list[dict[str, Any]]:
    case_dir = (root / record["source_path"]).parent
    files = [
        path
        for path in case_dir.rglob("*")
        if path.is_file() and path.name != "ground_truth.yaml" and path.suffix.lower() in {".json", ".tsv"}
    ]
    if not files:
        raise EvidenceUnavailable(f"ITBench telemetry missing: {case_dir}")
    per_source = max(1, max_events // len(files))
    events: list[dict[str, Any]] = []
    for path in sorted(files):
        kind = "alert" if path.suffix.lower() == ".json" else path.stem
        try:
            if path.suffix.lower() == ".json":
                events.extend(_json_events(path, kind, per_source))
            else:
                events.extend(_delimited_events(path, kind, per_source))
        except EvidenceUnavailable:
            continue
        if len(events) >= max_events:
            break
    if not events:
        raise EvidenceUnavailable(f"ITBench selected payload is not downloaded: {case_dir}")
    return events[:max_events]


def _select_aiops_archive(record: dict[str, Any], root: Path) -> Path:
    """The daily archives run from 16:00Z to 15:59Z (a UTC+8 calendar day), so a window after 16:00Z lives in the
    archive named for the next date."""
    archive_root = root / "AgenticOpsEval" / "AIOps2025"
    start_dt = _iso(record.get("metadata", {}).get("start_time"))
    start = (start_dt + AIOPS_TZ_OFFSET).strftime("%Y-%m-%d") if start_dt else str(record.get("metadata", {}).get("start_time") or "")[:10]
    exact = archive_root / f"{start}.tar.gz"
    if exact.exists():
        return exact
    archives = sorted(archive_root.glob("*.tar.gz"))
    if not archives:
        raise EvidenceUnavailable("AIOps2025 archives missing")
    return min(archives, key=lambda path: abs(int(path.stem[:10].replace("-", "")) - int(start.replace("-", "") or 0)))


AIOPS_TZ_OFFSET = timedelta(hours=8)      # archive slices are named in UTC+8; ground-truth windows are UTC
AIOPS_MARGIN = timedelta(seconds=300)
AIOPS_BASELINE = timedelta(minutes=30)
AIOPS_INFRA_KPIS = (        # answer-agnostic: the same KPIs for every case, never the ground truth's key_metrics
    "pod_cpu_usage", "pod_memory_working_set_bytes", "pod_processes", "pod_fs_reads_bytes", "pod_fs_writes_bytes",
    "pod_network_receive_bytes", "pod_network_transmit_bytes", "node_cpu_usage_rate", "node_memory_usage_rate",
    "node_filesystem_usage_rate", "node_disk_written_bytes_total", "node_disk_read_bytes_total",
    "node_network_receive_bytes_total", "node_network_transmit_bytes_total", "node_sockstat_TCP_inuse",
)
AIOPS_APM_METRICS = ("error_ratio", "server_error_ratio", "client_error_ratio", "timeout", "rrt", "rrt_max", "request")
AIOPS_SYMPTOM_RE = re.compile(r"error|fail|exception|refused|timeout|timed out|killed|unavailable|panic|fatal|denied|"
                              r"no such|not found|unreachable|\b5\d\d\b", re.I)


def _iso(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _series_value(kpi: str, rows: list[tuple[str, float]]) -> float | None:
    """Mean of a gauge, or mean per-sample increase of a counter (cumulative *_total / *_bytes series)."""
    values = [v for _, v in sorted(rows) if isinstance(v, (int, float))]
    if not values:
        return None
    if re.search(r"_total$|_bytes$", kpi) and len(values) >= 2 and all(b >= a for a, b in zip(values, values[1:])):
        return (values[-1] - values[0]) / (len(values) - 1)
    return mean(values)


def _ratio_line(name: str, before: float | None, after: float | None, peak: float | None = None) -> tuple[float, str]:
    if before is None or after is None:
        return 0.0, ""
    ratio = (after + 1e-9) / (before + 1e-9)
    change = abs(ratio - 1.0) if before > 0 else (1.0 if after > 0 else 0.0)
    text = f"{name}: baseline {before:.4g} -> window {after:.4g}" + (f", peak {peak:.4g}" if peak is not None else "") + f" (x{ratio:.2f})"
    return change, text


def _load_aiops2025(record: dict[str, Any], root: Path, max_events: int) -> list[dict[str, Any]]:
    """Evidence for one AIOps2025 case: the logs inside its time window, and every APM and infra series of that day
    summarised as baseline (30 min before) versus window. One streaming pass over the day's archive.

    The archive's hourly slices are named in UTC+8 while the case windows are UTC, so the slice is chosen by the
    shifted hour; the first version of this loader read the twelve smallest slices of the day, which for a
    twenty-minute fault window meant logs from the wrong hours with no timestamps to filter on."""
    import pyarrow.compute as pc
    import pyarrow.parquet as parquet

    archive = _select_aiops_archive(record, root)
    metadata = record.get("metadata", {})
    start, end = _iso(metadata.get("start_time")), _iso(metadata.get("end_time"))
    if not start or not end:
        raise EvidenceUnavailable(f"AIOps2025 case without a time window: {record.get('id')}")
    lo, hi = start - AIOPS_MARGIN, end + AIOPS_MARGIN
    base_lo = lo - AIOPS_BASELINE
    hours = set()
    cursor = lo
    while cursor <= hi:
        hours.add((cursor + AIOPS_TZ_OFFSET).strftime("%Y-%m-%d_%H-00-00"))
        cursor += timedelta(hours=1)
    hours.add((hi + AIOPS_TZ_OFFSET).strftime("%Y-%m-%d_%H-00-00"))
    fmt = lambda t: t.strftime("%Y-%m-%dT%H:%M:%S") + "Z"        # the tables carry ISO Z strings; string order is time order
    log_rows: list[dict[str, Any]] = []
    apm_lines: list[tuple[float, str, str]] = []
    infra_lines: list[tuple[float, str, str]] = []

    def in_range(table, column, lo_s, hi_s):
        col = pc.cast(table[column], "string")
        return table.filter(pc.and_(pc.greater_equal(col, lo_s), pc.less_equal(col, hi_s)))

    with tarfile.open(archive, "r|gz") as tar:
        for member in tar:
            name = member.name
            if not member.isfile() or not name.endswith(".parquet") or "/._" in name or Path(name).name.startswith("._"):
                continue
            is_log = "log-parquet" in name and any(h in name for h in hours)
            is_apm = "/apm/" in name
            is_infra = ("/infra/infra_pod/" in name or "/infra/infra_node/" in name) and any(k in name for k in AIOPS_INFRA_KPIS)
            if not (is_log or is_apm or is_infra):
                continue
            extracted = tar.extractfile(member)
            if extracted is None:
                continue
            table = parquet.read_table(io.BytesIO(extracted.read()))
            if is_log:
                if "@timestamp" not in table.column_names:
                    continue
                window = in_range(table, "@timestamp", fmt(lo), fmt(hi) + "~")
                for row in window.select([c for c in ("@timestamp", "k8_pod", "k8_node_name", "message") if c in window.column_names]).to_pylist():
                    log_rows.append(row)
            elif is_apm:
                rows = in_range(table, "time", fmt(base_lo), fmt(hi) + "~").to_pylist()
                if not rows:
                    continue
                obj = f"{rows[0].get('object_type', 'apm')} {rows[0].get('object_id', Path(name).stem)}"
                before = [r for r in rows if str(r.get("time")) < fmt(lo)]
                during = [r for r in rows if str(r.get("time")) >= fmt(lo)]
                parts, score = [], 0.0
                for m in AIOPS_APM_METRICS:
                    b = [r[m] for r in before if isinstance(r.get(m), (int, float))]
                    d = [r[m] for r in during if isinstance(r.get(m), (int, float))]
                    if b and d:
                        change, _ = _ratio_line(m, mean(b), mean(d))
                        score = max(score, change if m != "request" else 0.0)
                        parts.append(f"{m} {mean(b):.4g}->{mean(d):.4g} (peak {max(d):.4g})")
                if parts:
                    apm_lines.append((score, obj, f"apm {obj}: " + "; ".join(parts)))
            else:
                kpi = next((k for k in AIOPS_INFRA_KPIS if k in name), Path(name).stem)
                if kpi not in table.column_names:
                    continue
                obj_col = "pod" if "infra_pod" in name else "kubernetes_node"
                rows = in_range(table, "time", fmt(base_lo), fmt(hi) + "~").select(["time", obj_col, kpi]).to_pylist()
                per_obj: dict[str, tuple[list, list]] = {}
                for r in rows:
                    obj = str(r.get(obj_col) or "?")
                    bucket = per_obj.setdefault(obj, ([], []))
                    (bucket[0] if str(r["time"]) < fmt(lo) else bucket[1]).append((str(r["time"]), r[kpi]))
                for obj, (b, d) in per_obj.items():
                    before, during = _series_value(kpi, b), _series_value(kpi, d)
                    peak = max((v for _, v in d if isinstance(v, (int, float))), default=None)
                    change, text = _ratio_line(f"{kpi} {obj}", before, during, peak)
                    if text:
                        infra_lines.append((change, obj, text))

    events: list[dict[str, Any]] = []
    stamp = start.isoformat().replace("+00:00", "Z")
    for change, obj, text in sorted(apm_lines, key=lambda x: -x[0]):
        events.append(_event("metric", text, timestamp=stamp, service=obj, source_file="apm", fields={"change": round(change, 3)}))
    for change, obj, text in sorted(infra_lines, key=lambda x: -x[0])[:80]:
        events.append(_event("metric", text, timestamp=stamp, service=obj, source_file="infra", fields={"change": round(change, 3)}))
    budget = max(200, max_events - len(events))
    symptomatic = [r for r in log_rows if AIOPS_SYMPTOM_RE.search(str(r.get("message", "")))]
    quiet = [r for r in log_rows if not AIOPS_SYMPTOM_RE.search(str(r.get("message", "")))]
    keep = symptomatic[: int(budget * 0.7)]
    step = max(1, len(quiet) // max(1, budget - len(keep)))
    keep += quiet[::step][: budget - len(keep)]
    keep.sort(key=lambda r: str(r.get("@timestamp")))
    for r in keep:
        service = str(r.get("k8_pod") or "")
        node = r.get("k8_node_name")
        events.append(_event("log", r.get("message"), timestamp=r.get("@timestamp"),
                             service=f"{service}@{node}" if node and service else (service or node),
                             source_file=f"{archive.name}:log", fields={}))
    if not log_rows and not apm_lines:
        raise EvidenceUnavailable(f"AIOps2025 archive {archive.name} has nothing inside {fmt(lo)}..{fmt(hi)}")
    return events[:max_events]

def load_evidence(record: dict[str, Any], datasets_root: str | Path, max_events: int = 2000) -> dict[str, Any]:
    root = Path(datasets_root).resolve()
    source = str(record.get("source", ""))
    if source == "Cloud-OpsBench":
        events = _load_cloud(record, root, max_events)
    elif source == "AgenticOpsEval/RCA100":
        events = _load_rca100(record, root, max_events)
    elif source == "RCAEval":
        events = _load_rcaeval(record, root, max_events)
    elif source == "ITBench-Lite/SRE":
        events = _load_itbench(record, root, max_events)
    elif source == "AgenticOpsEval/AIOps2025":
        events = _load_aiops2025(record, root, max_events)
    else:
        raise EvidenceUnavailable(f"Unsupported source: {source}")
    if not events:
        raise EvidenceUnavailable(f"No evidence loaded for {record.get('id')}")
    return {
        "id": record["id"],
        "source": source,
        "window": {
            "start": record.get("metadata", {}).get("start_time") or record.get("metadata", {}).get("time_start"),
            "end": record.get("metadata", {}).get("end_time") or record.get("metadata", {}).get("time_end"),
        },
        "events": events,
    }


def find_eval_truth(path: str | Path, eval_id: str) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                item = json.loads(line)
                if item.get("id") == eval_id:
                    return item
    raise KeyError(f"Unknown eval id: {eval_id}")
