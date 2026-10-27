"""Watchdog: rule-based patrol of the victim's health URLs; on two failures in a row it opens an incident and wakes the
NemoClaw agent with a fixed alert, so nobody on stage types a prompt. No model runs while all is green.

  .venv/bin/python scripts/watchdog.py              # patrol every 5 s, dispatch the agent on an incident
  .venv/bin/python scripts/watchdog.py --dry-run    # patrol and log incidents, never wake the agent
  env: WATCH_URLS (comma list, default the two 127.0.0.1:8880 health URLs), WATCH_INTERVAL (5), WATCH_FAILS (2),
       WATCH_LOGS (log directory, default logs/), WATCH_TRIAGE=1 (put scripts/triage.py's first look under the alert),
       WATCH_SIGNALS=1 (sample Docker/log/disk signals every SIGNALS_EVERY polls, default 3), INCIDENT_TIMEOUT (900 s)

One incident at a time: the lock holds until both URLs are 200 twice in a row. If the agent finishes and the stack is
still down, the incident stays open as `agent-done-unhealthy` (a human takes over) and no second agent is woken.
While scripts/nemoclaw-drill.sh or scripts/test-guardrails.py runs (both inject their own faults and wake their own
agent) the watchdog only records what it sees and dispatches nothing.

Log: logs/incidents.jsonl (one row per event, `ts` in epoch seconds); each incident's ops-API calls, reviews and agent
output are copied to logs/runs/<time>-incident/ when it closes, the same layout as scripts/run-archive.sh.
"""
import json
import os
import pathlib
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
LOGS = pathlib.Path(os.environ.get("WATCH_LOGS", ROOT / "logs"))   # override only to test the watchdog itself
INCIDENTS = LOGS / "incidents.jsonl"
PIDFILE = LOGS / "watchdog.pid"
URLS = [u.strip() for u in os.environ.get(
    "WATCH_URLS", "http://127.0.0.1:8880/,http://127.0.0.1:8880/api/").split(",") if u.strip()]
INTERVAL = float(os.environ.get("WATCH_INTERVAL", "5"))
FAILS = int(os.environ.get("WATCH_FAILS", "2"))
TIMEOUT = float(os.environ.get("INCIDENT_TIMEOUT", "900"))
SIGNALS = os.environ.get("WATCH_SIGNALS") == "1"
SIGNALS_EVERY = max(1, int(os.environ.get("SIGNALS_EVERY", "3"))) if SIGNALS else 3
if SIGNALS:
    import watch_signals
# after its incident closes the agent may finish its report; past this it is stopped. Lightning kept acting for 5+ min
# after a fix (memory notes, a clear_scratch_volume the rules refused), holding the host lock the next agent needs
GRACE = float(os.environ.get("AGENT_GRACE", "60"))
ALERT = ("Alert: the web stack is degraded. Diagnose it and repair it with your ops tools, then verify both health "
         "URLs return 200. Finish with exactly three lines and nothing else, each under 40 words: "
         "Root cause: ... / Actions: ... / Final health: ...")   # same words as nemoclaw-drill.sh; the report turn was 3.9 s median


def status(url):
    """HTTP status, or 0 when nothing answers (same convention as faults.http); a 200 whose body is not the deployed
    page counts as 0 too (HEALTH_CONTENT=0 restores the status-only probe)."""
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            if r.status == 200 and os.environ.get("HEALTH_CONTENT") != "0":
                try:
                    import faults
                    expect = faults.EXPECT_BODY.get(urllib.parse.urlsplit(url).path or "/", "")
                    if expect and expect not in r.read(4096).decode("utf-8", "replace"):
                        return 0
                except Exception:
                    pass
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def probe():
    s = {u: status(u) for u in URLS}
    return s, all(c == 200 for c in s.values())


def event(**row):
    with INCIDENTS.open("a") as f:
        f.write(json.dumps(dict(ts=round(time.time(), 3), **row)) + "\n")


def lines(p):
    try:
        with open(p, errors="replace") as f:
            return sum(1 for _ in f)
    except OSError:
        return 0


def drill_running():
    r = subprocess.run(["pgrep", "-f", "nemoclaw-drill[.]sh|test-guardrails[.]py"], capture_output=True, text=True)
    return bool(r.stdout.strip())


def dispatch(iid, alert=ALERT):
    if os.environ.get("WATCH_TRIAGE") == "1":
        tri = subprocess.run([sys.executable, str(ROOT / "scripts" / "triage.py")], capture_output=True, text=True,
                             timeout=300, cwd=ROOT).stdout
        alert = f"{alert}\n\n{tri}"
    out = LOGS / "incidents" / f"{iid}.txt"
    out.parent.mkdir(exist_ok=True)
    env = dict(os.environ, PATH=f"{pathlib.Path.home()}/.npm-global/bin:{pathlib.Path.home()}/.local/bin:{os.environ.get('PATH', '')}")
    cmd = ["nemoclaw", "edge-agent", "agent", "--agent", "main", "--session-id", f"incident-{iid}", "-m", alert]
    # own process group: stopping it must also end the openshell exec it spawns
    return (subprocess.Popen(cmd, stdout=out.open("w"), stderr=subprocess.STDOUT, env=env, cwd=ROOT,
                            start_new_session=True), out, alert)


def stop_agent(p):
    for sig, wait in ((signal.SIGTERM, 15), (signal.SIGKILL, 5)):
        try:
            os.killpg(p.pid, sig)
        except ProcessLookupError:
            pass
        try:
            p.wait(wait)
            return
        except subprocess.TimeoutExpired:
            continue


def archive(inc, s_end, outcome):
    """Copy what this incident wrote, cut at the line counts taken when it opened."""
    d = LOGS / "runs" / f"{time.strftime('%Y%m%d-%H%M%S', time.localtime(inc['t0']))}-incident"
    d.mkdir(parents=True, exist_ok=True)
    for name, start in inc["marks"].items():
        src = LOGS / name
        if src.exists():
            with open(src, errors="replace") as f:
                rows = f.readlines()
            # ops-api.log is truncated by every drill; a shorter file than the mark means it restarted at 0
            (d / name).write_text("".join(rows[start if len(rows) >= start else 0:]))
    if inc.get("out") and pathlib.Path(inc["out"]).exists():
        (d / "agent.txt").write_text(pathlib.Path(inc["out"]).read_text(errors="replace"))
    t1 = time.time()
    meta = dict(case="incident", id=inc["id"], start=inc["t0"], end=t1,
                seconds=round(t1 - inc["t0"], 1), verify="PASS" if outcome == "resolved" else "FAIL",
                outcome=outcome, first_status=inc["status"], last_status=s_end)
    (d / "meta.json").write_text(json.dumps(meta, indent=1) + "\n")
    if outcome == "resolved":
        try:
            import incident_memory
            ops = [json.loads(line) for line in (d / "ops-api.log").read_text(errors="replace").splitlines()] if (d / "ops-api.log").exists() else []
            reviews = [json.loads(line) for line in (d / "reviews.jsonl").read_text(errors="replace").splitlines()] if (d / "reviews.jsonl").exists() else []
            report = (d / "agent.txt").read_text(errors="replace") if (d / "agent.txt").exists() else ""
            memory = incident_memory.memory_from_archive({"id": meta["id"], "ts": meta["start"],
                "seconds": meta["seconds"], "alert": inc.get("alert", ALERT), "final_health": meta["last_status"],
                "ops_api": ops, "reviews": reviews, "agent_output": report})
            incident_memory.record(memory)
        except Exception:
            pass
    return d


def stop(*_):
    raise KeyboardInterrupt        # kill / systemd stop: close the open incident and drop the pid file


def main():
    dry = "--dry-run" in sys.argv
    signal.signal(signal.SIGTERM, stop)
    LOGS.mkdir(exist_ok=True)
    PIDFILE.write_text(str(os.getpid()))
    print(f"watchdog: {URLS} every {INTERVAL}s, open after {FAILS} failures{' (dry run)' if dry else ''}", flush=True)
    bad = good = 0
    inc = None
    polls = 0
    signal_last = None
    signal_previous = ""
    signal_findings = []
    seen_signals = set()
    # agents still running after their incident closed, with the time it closed: reaped every loop (a zombie keeps the
    # NemoClaw host lock "owned" and every later agent fails to start) and stopped after GRACE
    lingering = []
    try:
        while True:
            for q, t_close in lingering:
                if q.poll() is None and time.time() - t_close > GRACE:
                    stop_agent(q)
                    event(event="agent-stopped-after-close", pid=q.pid, grace=GRACE)
            lingering = [(q, t) for q, t in lingering if q.poll() is None]
            s, ok = probe()
            bad, good = (0, good + 1) if ok else (bad + 1, 0)
            polls += 1
            if SIGNALS and polls % SIGNALS_EVERY == 0:
                snapshot = watch_signals.collect(signal_last)
                signal_last = snapshot["sampled_at"]
                findings = watch_signals.container_state(snapshot["docker_ps"], signal_previous)
                signal_previous = snapshot["docker_ps"]
                for container, log_text in snapshot["logs"].items():
                    findings.extend(watch_signals.log_errors(container, log_text))
                findings.extend(watch_signals.disk(snapshot["disk"]))
                findings.extend(watch_signals.docker_events(snapshot["events"]))
                for finding in findings:
                    key = (finding["signal"], finding["severity"], finding["detail"])
                    if key not in seen_signals:
                        seen_signals.add(key)
                        signal_findings.append(finding)
                        event(event="signal", signal=finding["signal"], severity=finding["severity"],
                              detail=finding["detail"])
                if inc is None and any(finding["severity"] == "open" for finding in findings):
                    bad += 1
                    good = 0
            if inc is None and bad >= FAILS:
                iid = time.strftime("%Y%m%d-%H%M%S")
                alert = watch_signals.append_signals(ALERT, signal_findings) if SIGNALS else ALERT
                inc = dict(id=iid, t0=time.time(), status=s, proc=None, out=None, alert=alert,
                           marks={n: lines(LOGS / n) for n in ("ops-api.log", "reviews.jsonl", "oai-shim.log")})
                if dry or drill_running():
                    why = "dry-run" if dry else "drill in progress"
                    event(event="open", id=iid, status=s, dispatched=False, why=why)
                    print(f"{time.strftime('%T')} incident {iid} {s} (not dispatched: {why})", flush=True)
                else:
                    for q, _ in lingering:       # its incident is closed; it only holds the host lock now
                        stop_agent(q)
                    if lingering:
                        event(event="previous-agent-stopped", id=iid, count=len(lingering))
                        lingering = []
                    if SIGNALS:
                        inc["proc"], out, inc["alert"] = dispatch(iid, alert)
                    else:
                        inc["proc"], out, inc["alert"] = dispatch(iid)
                    inc["out"] = str(out)
                    event(event="open", id=iid, status=s, dispatched=True)
                    print(f"{time.strftime('%T')} incident {iid} {s} -> agent woken", flush=True)
            elif inc is not None:
                p = inc["proc"]
                if p is not None and p.poll() is not None and not inc.get("agent_done"):
                    inc["agent_done"] = True
                    event(event="agent-done", id=inc["id"], rc=p.returncode, status=s)
                if good >= 2:
                    event(event="close", id=inc["id"], outcome="resolved", seconds=round(time.time() - inc["t0"], 1))
                    d = archive(inc, s, "resolved")
                    print(f"{time.strftime('%T')} incident {inc['id']} resolved -> {d}", flush=True)
                    if p is not None and p.poll() is None:
                        lingering.append((p, time.time()))
                    inc = None
                    signal_findings = []
                    seen_signals.clear()
                elif inc.get("agent_done") and not inc.get("flagged"):
                    inc["flagged"] = True       # the agent gave up or claimed a fix that did not hold: hand to a human
                    event(event="agent-done-unhealthy", id=inc["id"], status=s)
                    print(f"{time.strftime('%T')} incident {inc['id']} agent finished, still {s}: human needed", flush=True)
                elif time.time() - inc["t0"] > TIMEOUT and not inc.get("timed_out"):
                    inc["timed_out"] = True
                    if p is not None and p.poll() is None:
                        stop_agent(p)
                    event(event="timeout", id=inc["id"], status=s)
            time.sleep(INTERVAL)
    except KeyboardInterrupt:
        pass
    finally:
        # agents this watchdog started would outlive it as orphans and hold the host lock
        for q in [q for q, _ in lingering] + ([inc["proc"]] if inc is not None and inc.get("proc") else []):
            if q.poll() is None:
                stop_agent(q)
        if inc is not None:
            event(event="close", id=inc["id"], outcome="watchdog-stopped")
        PIDFILE.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
