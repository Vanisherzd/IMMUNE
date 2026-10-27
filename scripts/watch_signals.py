import json
import re
import subprocess
import time
from typing import Final, Literal, TypedDict

CONTAINERS: Final = ("edge-victim", "edge-victim-app")
DISK_WARN_PCT: Final = 90
INODE_WARN_PCT: Final = 90
OPEN_PCT: Final = 98
LOG_ERROR: Final = re.compile(
    r"\[(?:emerg|crit|alert)\]|upstream timed out|connect\(\) failed|no live upstreams|"
    r"Permission denied|No space left on device|Too many open files",
    re.IGNORECASE,
)


Severity = Literal["warn", "open"]


class Finding(TypedDict):
    signal: str
    severity: Severity
    detail: str


class Snapshot(TypedDict):
    docker_ps: str
    logs: dict[str, str]
    disk: str
    events: str
    sampled_at: float


def _finding(signal: str, severity: Severity, detail: str) -> Finding:
    return {"signal": signal, "severity": severity, "detail": detail.strip()[:200]}


def _counts(text: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for line in text.splitlines():
        match = re.search(r"(?:RestartCount|restarts?)[=:\s]+(\d+)", line, re.IGNORECASE)
        if match and line.split():
            counts[line.split()[0].lstrip("/")] = int(match.group(1))
    return counts


def container_state(docker_ps_text: str, previous_text: str = "") -> list[Finding]:
    findings: list[Finding] = []
    previous = _counts(previous_text)
    current = _counts(docker_ps_text)
    up: set[str] = set()
    for line in docker_ps_text.splitlines():
        words = line.split()
        if not words:
            continue
        name = words[0].lstrip("/")
        if name not in CONTAINERS:
            continue
        if re.search(r"\bUp\b", line, re.IGNORECASE):
            up.add(name)
        states = [state for state in ("Restarting", "Exited", "Paused") if state.lower() in line.lower()]
        findings.extend(_finding("container_state", "open", line) for _ in states[:1])
        if re.search(r"OOMKilled[=:\s]+(?:yes|true)", line, re.IGNORECASE):
            findings.append(_finding("container_oom", "open", line))
    for name, count in current.items():
        if name in up and count > previous.get(name, count):
            findings.append(_finding("container_restart", "warn",
                                     f"{name} restart count {previous[name]} -> {count} while Up"))
    return findings


def log_errors(container: str, log_tail_text: str) -> list[Finding]:
    return [_finding("log_error", "warn", f"{container}: {line}")
            for line in log_tail_text.splitlines() if LOG_ERROR.search(line)]


def disk(disk_text_or_dict: str | dict[str, str]) -> list[Finding]:
    sections = disk_text_or_dict.items() if isinstance(disk_text_or_dict, dict) else (("space", disk_text_or_dict),)
    findings: list[Finding] = []
    for initial_kind, text in sections:
        kind = "inodes" if "inode" in initial_kind.lower() else "space"
        for line in text.splitlines():
            lowered = line.lower()
            if "iuse%" in lowered or lowered.rstrip(":") == "inodes":
                kind = "inodes"
            elif "use%" in lowered or lowered.rstrip(":") == "space":
                kind = "space"
            match = re.search(r"(\d+)%", line)
            if not match or line.lower().startswith("filesystem"):
                continue
            used = int(match.group(1))
            threshold = INODE_WARN_PCT if kind == "inodes" else DISK_WARN_PCT
            if used >= threshold:
                severity = "open" if used >= OPEN_PCT else "warn"
                findings.append(_finding(f"disk_{kind}", severity, line))
    return findings


def docker_events(lines: str) -> list[Finding]:
    findings: list[Finding] = []
    for line in lines.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        action = str(row.get("Action") or row.get("status") or "").lower()
        actor = row.get("Actor") or {}
        name = str((actor.get("Attributes") or {}).get("name") or row.get("id") or "")
        if name in CONTAINERS and action in {"die", "oom", "kill", "pause", "destroy"}:
            findings.append(_finding("docker_event", "open", f"{name}: {action}"))
    return findings


def append_signals(alert: str, findings: list[Finding]) -> str:
    if not findings:
        return alert
    lines = [f"- [{item['severity']}] {item['signal']}: {item['detail']}" for item in findings]
    return f"{alert}\n\nSignals:\n" + "\n".join(lines)


def _run(command: list[str], include_stderr: bool = False) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=5)
        return result.stdout + (result.stderr if include_stderr else "")
    except (OSError, subprocess.SubprocessError):
        return ""


def collect(since: float | None = None) -> Snapshot:
    now = time.time()
    status = _run(["docker", "ps", "-a", "--format", "{{.Names}}\t{{.Status}}\t{{.RunningFor}}"])
    inspect = _run(["docker", "inspect", "--format",
                    "{{.Name}}\tOOMKilled={{.State.OOMKilled}}\tRestartCount={{.RestartCount}}", *CONTAINERS])
    logs = {name: _run(["docker", "logs", "--tail", "20", name], True) for name in CONTAINERS}
    mount = _run(["docker", "volume", "inspect", "-f", "{{.Mountpoint}}", "edge-cache"]).strip()
    paths = ["/"] + ([mount] if mount else [])
    disk_text = "space:\n" + _run(["df", "-h", *paths]) + "inodes:\n" + _run(["df", "-i", *paths])
    events = _run(["docker", "events", "--since", str(now if since is None else since), "--until", str(now),
                   "--format", "{{json .}}"])
    return {"docker_ps": status + inspect, "logs": logs, "disk": disk_text, "events": events, "sampled_at": now}
