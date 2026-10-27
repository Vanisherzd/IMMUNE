import datetime
import json
import os
import pathlib
import re
import socket
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
MEMORY_FILE = ROOT / "logs" / "incident-memory.jsonl"
MUTATING = {"docker_start", "docker_restart", "write_config", "recreate_stack", "network_repair", "cleanup_disk",
            "clear_scratch_volume", "restore_config", "kill_process"}
ERROR = re.compile(r"emerg|error|fatal|fail|refus|denied|timed out|timeout|cannot|could not|no such|not found|"
                   r"exit(ed)?|restarting|paused|oom|killed|no space|\b50[0-9]\b", re.I)
BLOCKED = ("refused:", "denied:", "review-rejected:", "approval-rejected:", "DRY-RUN")
_cache_key = None
_cache_index = None


def _path():
    return pathlib.Path(os.environ.get("INCIDENT_MEMORY_FILE", MEMORY_FILE))


def _short(text, limit):
    return re.sub(r"\s+", " ", str(text)).strip()[:limit]


def memory_from_archive(archive):
    rows = archive.get("ops_api", [])
    alert = _short(archive.get("alert", ""), 200)
    symptoms = [alert] if alert else []
    containers = []
    actions = []
    diagnostics = []
    for row in rows:
        tool = str(row.get("tool", ""))
        args = row.get("args") if isinstance(row.get("args"), dict) else {}
        name = args.get("name")
        if isinstance(name, str) and name not in containers:
            containers.append(name)
        result = str(row.get("result", ""))
        blocked = bool(row.get("is_error")) or result.startswith(BLOCKED)
        if tool in MUTATING:
            if not blocked:
                actions.append({"tool": tool, "args": args})
        elif tool and tool not in diagnostics:
            diagnostics.append(tool)
        if tool == "docker_logs":
            line = next((_short(line, 200) for line in result.splitlines() if ERROR.search(line)), "")
            if line and line not in symptoms:
                symptoms.append(line)
    report = str(archive.get("agent_output", "")).strip()
    starts = list(re.finditer(r"root cause", report, re.I))
    root_cause = _short(report[starts[-1].start():] if starts else report[-400:], 400)
    reviews = archive.get("reviews", [])
    rejected = sum(str(row.get("verdict", "")).upper() == "REJECT" for row in reviews)
    denied = sum(str(row.get("result", "")).startswith(("refused:", "denied:", "approval-rejected:")) for row in rows)
    return {"id": archive.get("id"), "ts": archive.get("ts"), "symptoms": symptoms,
            "containers": containers, "actions": actions, "diagnostics": diagnostics,
            "final_health": archive.get("final_health"), "seconds": archive.get("seconds"),
            "root_cause": root_cause,
            "verification": {"health": "200/200", "reviewer_rejections": rejected, "policy_denials": denied},
            "trust": "local_verified", "platform": socket.gethostname()}


def record(incident):
    if os.environ.get("INCIDENT_MEMORY", "1") == "0":
        return False
    health = incident.get("final_health")
    if not isinstance(health, dict) or len(health) != 2 or any(value != 200 for value in health.values()):
        return False
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(incident, ensure_ascii=False) + "\n")
    return True


def _index():
    global _cache_key, _cache_index
    path = _path()
    try:
        stat = path.stat()
    except OSError:
        return None
    key = (path, stat.st_mtime_ns, stat.st_size)
    if key != _cache_key:
        from community_knowledge import CommunityIndex
        docs = []
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            record["index_text"] = " ".join([*record.get("symptoms", []), *record.get("containers", []), str(record.get("root_cause", ""))])
            docs.append(record)
        _cache_key, _cache_index = key, CommunityIndex(docs)
    return _cache_index


def record_drill(case, log_path, alert, seconds, report_path=None):
    """A drill that ended with both URLs healthy is a verified recovery of this stack, the same as a stage incident the
    watchdog records: the ops-api rows of that drill (tool-layer rows excluded), the agent's report for the cause.
    The drill prompt is not passed as a symptom: it is the same text for every drill and would make every record
    share words with every query. DRILL_MEMORY=0 in nemoclaw-drill.sh keeps drills out of the memory."""
    rows = []
    for line in pathlib.Path(log_path).read_text(errors="replace").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if row.get("from") != "tool-layer":
            rows.append(row)
    report = pathlib.Path(report_path).read_text(errors="replace") if report_path and pathlib.Path(report_path).exists() else ""
    now = time.time()
    memory = memory_from_archive({"id": f"drill-{case}-{int(now)}", "ts": now - float(seconds), "seconds": round(float(seconds), 1),
                                  "alert": "", "final_health": {"front": 200, "api": 200}, "ops_api": rows, "reviews": [],
                                  "agent_output": report})
    memory["source"] = "drill"
    memory["case"] = case
    return record(memory)


def recall(query, k=2, min_shared=1):
    """Verified recoveries whose symptoms share at least min_shared terms with the query. The pull path keeps 1; the
    push next to the runbook asks for 3, so a different fault that merely mentions nginx twice is not offered."""
    if os.environ.get("INCIDENT_MEMORY", "1") == "0":
        return []
    index = _index()
    if index is None:
        return []
    out = []
    for _, _, incident in index.search(query, k=k, min_shared=min_shared):
        date = datetime.datetime.fromtimestamp(float(incident["ts"])).date().isoformat()
        actions = "; ".join(f"{action['tool']} {json.dumps(action['args'], ensure_ascii=False, sort_keys=True)}"
                            for action in incident.get("actions", [])) or "no state-changing action recorded"
        out.append(f"this stack recovered from the same symptom on {date} in {incident['seconds']} s: {actions}; "
                   f"cause: {incident.get('root_cause', '')}; verified {incident['verification']['health']}")
    return out


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="incident memory: record a verified drill recovery")
    sub = ap.add_subparsers(dest="cmd", required=True)
    rd = sub.add_parser("record-drill")
    rd.add_argument("--case", required=True)
    rd.add_argument("--log", required=True)
    rd.add_argument("--alert", default="")
    rd.add_argument("--seconds", type=float, required=True)
    rd.add_argument("--report", default=None)
    a = ap.parse_args()
    ok = record_drill(a.case, a.log, a.alert, a.seconds, a.report)
    print(f"incident memory: {'recorded' if ok else 'not recorded'} {a.case}")
