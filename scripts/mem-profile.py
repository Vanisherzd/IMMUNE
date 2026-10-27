#!/usr/bin/env python3
import argparse
import json
import pathlib
import statistics

MEMORY_FIELDS = ("MemTotal", "MemAvailable", "MemFree", "Cached", "Shmem")


def load(path, since=None, until=None):
    rows = []
    try:
        with path.open() as stream:
            for line in stream:
                try:
                    row = json.loads(line)
                    ts = float(row["ts"])
                except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                    continue
                if (since is None or ts >= since) and (until is None or ts <= until):
                    rows.append(row)
    except OSError as error:
        raise SystemExit(f"cannot read {path}: {error}") from error
    return sorted(rows, key=lambda row: float(row["ts"]))


def series(rows):
    values = {}
    for row in rows:
        for field in MEMORY_FIELDS:
            if field in row:
                values.setdefault(field, []).append(float(row[field]))
        for group in ("containers", "services"):
            for name, value in row.get(group, {}).items():
                values.setdefault(f"{group}.{name}", []).append(float(value))
    return values


def report(rows):
    if not rows:
        return "No samples in window."
    values = series(rows)
    ordered = [field for field in MEMORY_FIELDS if field in values]
    ordered += sorted(field for field in values if field not in MEMORY_FIELDS)
    lines = [
        "| Field | Minimum (GiB) | Median (GiB) | Peak (GiB) |",
        "|---|---:|---:|---:|",
    ]
    for field in ordered:
        points = values[field]
        lines.append(
            f"| {field} | {min(points):.3f} | {statistics.median(points):.3f} | {max(points):.3f} |"
        )
    headroom = min(values["MemAvailable"])
    lines += ["", f"Headroom (minimum MemAvailable): **{headroom:.3f} GiB**", "",
              "| Container | Start (GiB) | Peak (GiB) | Peak - start (GiB) |",
              "|---|---:|---:|---:|"]
    for field in sorted(name for name in values if name.startswith("containers.")):
        points = values[field]
        lines.append(f"| {field.removeprefix('containers.')} | {points[0]:.3f} | "
                     f"{max(points):.3f} | {max(points) - points[0]:.3f} |")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Summarise memory-profiler JSONL as Markdown.")
    parser.add_argument("path", nargs="?", type=pathlib.Path,
                        default=pathlib.Path("logs/mem-profile.jsonl"))
    parser.add_argument("--since", type=float)
    parser.add_argument("--until", type=float)
    args = parser.parse_args()
    print(report(load(args.path, args.since, args.until)))


if __name__ == "__main__":
    main()
