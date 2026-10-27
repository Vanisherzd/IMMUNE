from __future__ import annotations

import hashlib
import json
import re
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from typing import Any


NOISE_PATTERNS = (
    re.compile(r"\b(?:GET|HEAD)\s+/(?:healthz|readyz|livez|metrics)\b.*\b200\b", re.I),
    re.compile(r"\bhealth(?:y| check)?\b.*\b(?:ok|pass|success)\b", re.I),
    re.compile(r"\bheartbeat\b", re.I),
    re.compile(r"\bstats enabled, but temporarily unavailable\b", re.I),
    re.compile(r"\btracing enabled but temporarily unavailable\b", re.I),
)

UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
HEX_RE = re.compile(r"\b[0-9a-f]{16,}\b", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ISO_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ][0-9:.+-]+Z?\b")
POD_SUFFIX_RE = re.compile(r"\b([a-z0-9-]+)-[a-f0-9]{8,10}-[a-z0-9]{5}\b", re.I)


def _parse_time(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    try:
        number = float(text)
        if number > 1e17:
            number /= 1e9
        elif number > 1e14:
            number /= 1e6
        elif number > 1e11:
            number /= 1e3
        return datetime.fromtimestamp(number, tz=timezone.utc)
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def template_message(message: str) -> str:
    text = ISO_RE.sub("<TIME>", message)
    text = UUID_RE.sub("<UUID>", text)
    text = HEX_RE.sub("<HEX>", text)
    text = IP_RE.sub("<IP>", text)
    text = POD_SUFFIX_RE.sub(r"\1-<POD>", text)
    return " ".join(text.split())


def _encoded_size(events: list[dict[str, Any]]) -> int:
    return len(json.dumps(events, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def _in_window(event: dict[str, Any], start: datetime | None, end: datetime | None, margin: timedelta) -> bool:
    if start is None and end is None:
        return True
    current = _parse_time(event.get("timestamp"))
    if current is None:
        return True
    if start is not None:
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        if current < start - margin:
            return False
    if end is not None:
        if end.tzinfo is None:
            end = end.replace(tzinfo=timezone.utc)
        if current > end + margin:
            return False
    return True


def compress_events(
    events: list[dict[str, Any]],
    *,
    target_ratio: float = 4.0,
    keywords: list[str] | None = None,
    window_start: Any = None,
    window_end: Any = None,
    margin_seconds: int = 300,
) -> dict[str, Any]:
    """Rules -> time window -> dedup -> keyword anchoring -> byte budget."""
    original = list(events)
    original_bytes = _encoded_size(original)
    if target_ratio <= 1.0:
        return {
            "events": original,
            "metrics": {
                "target_ratio": 1.0,
                "actual_ratio": 1.0,
                "original_events": len(original),
                "compressed_events": len(original),
                "original_bytes": original_bytes,
                "compressed_bytes": original_bytes,
                "estimated_input_tokens": max(1, original_bytes // 4),
                "noise_removed": 0,
                "duplicates_collapsed": 0,
            },
        }

    keyword_values = [value.lower() for value in (keywords or []) if value.strip()]
    start = _parse_time(window_start)
    end = _parse_time(window_end)
    margin = timedelta(seconds=max(0, margin_seconds))

    filtered: list[dict[str, Any]] = []
    noise_removed = 0
    for event in original:
        message = str(event.get("message", ""))
        anchored = any(keyword in message.lower() for keyword in keyword_values)
        noisy = any(pattern.search(message) for pattern in NOISE_PATTERNS)
        if noisy and not anchored:
            noise_removed += 1
            continue
        if not _in_window(event, start, end, margin):
            continue
        filtered.append(event)

    groups: OrderedDict[str, dict[str, Any]] = OrderedDict()
    for event in filtered:
        template = template_message(str(event.get("message", "")))
        signature = hashlib.sha256(
            f"{event.get('kind')}|{event.get('service')}|{template}".encode("utf-8")
        ).hexdigest()
        if signature not in groups:
            current = dict(event)
            current["template"] = template
            current["count"] = 1
            current["first_timestamp"] = event.get("timestamp")
            current["last_timestamp"] = event.get("timestamp")
            groups[signature] = current
        else:
            groups[signature]["count"] += 1
            groups[signature]["last_timestamp"] = event.get("timestamp")

    deduplicated = list(groups.values())
    duplicates_collapsed = max(0, len(filtered) - len(deduplicated))

    def score(item: dict[str, Any]) -> tuple[int, int, int]:
        message = str(item.get("message", "")).lower()
        anchor_hits = sum(keyword in message for keyword in keyword_values)
        severity = int(any(word in message for word in ("error", "fail", "fatal", "exception", "oom", "pressure", "timeout")))
        return (anchor_hits, severity, int(item.get("count", 1)))

    ranked = sorted(enumerate(deduplicated), key=lambda pair: (score(pair[1]), -pair[0]), reverse=True)
    budget = max(512, int(original_bytes / max(target_ratio, 1.0)))
    selected: list[tuple[int, dict[str, Any]]] = []
    used = 2
    for index, event in ranked:
        event_bytes = len(json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) + 1
        if selected and used + event_bytes > budget:
            continue
        selected.append((index, event))
        used += event_bytes
        if used >= budget:
            break
    selected.sort(key=lambda pair: pair[0])
    compressed = [event for _, event in selected]
    compressed_bytes = _encoded_size(compressed)
    actual_ratio = round(original_bytes / max(compressed_bytes, 1), 3)
    return {
        "events": compressed,
        "metrics": {
            "target_ratio": target_ratio,
            "actual_ratio": actual_ratio,
            "original_events": len(original),
            "compressed_events": len(compressed),
            "original_bytes": original_bytes,
            "compressed_bytes": compressed_bytes,
            "estimated_input_tokens": max(1, compressed_bytes // 4),
            "noise_removed": noise_removed,
            "duplicates_collapsed": duplicates_collapsed,
        },
    }
