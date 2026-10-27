"""Self-healing decision loop: observe -> retrieve runbooks -> decide (tool calls) -> act -> verify.

  uv run --no-sync scripts/agent.py [--case NAME] [--dry-run] [--max-steps 8]
  env: VLLM_URL (default http://127.0.0.1:8000), SERVED_NAME (edge-agent), AGENT_THINK=0 to disable thinking

Scope is deliberately small: two sandbox containers (see scripts/faults.py). Every action goes through a whitelist;
remediation tools become no-ops with --dry-run. Each step is appended to logs/agent/<timestamp>.jsonl.
"""
import argparse
import concurrent.futures
import json
import os
import pathlib
import glob
import ipaddress
import re
import shlex
import socket
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request

from openai import OpenAI
from ops_safety import diagnostic_argv, restore_config_file

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONF_DIR = (ROOT / "victim" / "conf.d").resolve()
RUNBOOKS = ROOT / "runbooks"
NAMES = {"edge-victim", "edge-victim-app"}
HEALTH = {"front": "http://127.0.0.1:8880/", "api": "http://127.0.0.1:8880/api/"}
# VM_VICTIM=1: the victim is a real guest (scripts/vm-victim.sh) reached only over ssh; health URLs and the tool list
# switch to it (scripts/vm_victim.py). The container tools stay out of the list so the model is not offered a second,
# healthy stack to look at.
VM_VICTIM = os.environ.get("VM_VICTIM", "0") == "1"
if VM_VICTIM:
    import vm_victim
    HEALTH = dict(vm_victim.HEALTH)
EVIDENCE_BUNDLE_TIMEOUT = 8
# Community references ride along with the runbook (COMMUNITY_PUSH=0 turns it off): pulling them was left to the model
# and measured at one search_incident_knowledge call in a night of 70 drills, so the tool layer pushes them, the way it
# pushes the runbook, for symptoms no runbook owns. Capped so a slow reranker or judge cannot stall an evidence read.
COMMUNITY_PUSH = os.environ.get("COMMUNITY_PUSH", "1") != "0"
COMMUNITY_PUSH_TIMEOUT = float(os.environ.get("COMMUNITY_PUSH_TIMEOUT", "4"))
_KB_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=2)
_SYMPTOM_PREFIX = re.compile(r"^the service itself answers HTTP .*? container is up\.\s*")
# nginx's error-line preamble ("2026/10/22 07:40:12 [error] 29#29: *503 ") and its trailing fields: the connection
# serial and pid look like HTTP statuses to the ownership gate, and the fields are noise to retrieval
_NGINX_PREAMBLE = re.compile(r"\d{4}/\d\d/\d\d \d\d:\d\d:\d\d \[\w+\] \d+#\d+: (?:\*\d+ )?")
_NGINX_FIELDS = re.compile(r", (?:client|server|request|upstream|host|referrer): [^,]*")
EVIDENCE_BUNDLE_LIMIT = 6000
UNIT_RE = re.compile(r"^[A-Za-z0-9@._:-]{1,64}$")          # systemd unit / journal identifier

# --- retrieval discipline ----------------------------------------------------------------------------------------
# Telling a model to read the runbook first does not make it read the runbook first: across seven drills it skipped
# retrieval whenever it believed it already knew the answer, and one bad-config run wandered for six minutes because
# of it. So the rule lives in the tool layer. Evidence tools push the matching runbook into the answer, and an action
# refuses once until a runbook has been seen for this incident. An incident ends when health comes back green.
MUTATING = {"repair_image_file", "write_container_file", "vm_service", "vm_write_config", "vm_restore_config",
            "docker_start", "docker_restart", "write_config", "recreate_stack", "network_repair", "cleanup_disk",
            "clear_scratch_volume", "restore_config",
            "kill_process"}
LEVEL_RE = re.compile(r"\[(emerg|alert|crit|error)\]")


def _shape(line):
    """A log line with its digits dropped: the shape a flood repeats."""
    return re.sub(r"\d+", "#", line.strip())


SYMPTOM_RE = re.compile(r"emerg|error|fatal|fail|refus|denied|timed out|timeout|cannot|could not|no such|"
                        r"not found|exit(ed)? \(?\d|restarting|paused|oom|killed|no space|\b50[0-9]\b", re.I)
_incident = {"runbook_seen": False, "refusals": 0, "trace": [], "injected": []}
DESTRUCTIVE = {"kill_process", "cleanup_disk", "clear_scratch_volume"}          # plus recreate_stack with replace=true; see reviewed()


def reviewed(name, args):
    """Second-agent approval for an irreversible action. Returns None to proceed, or the refusal text."""
    import reviewer
    import tier                                            # an irreversible action is the hard judgement: Tier-2
    tier.set_tier(2, f"review of {name}")
    ok, reason = reviewer.review(name, args, _incident["trace"], _incident["runbook_seen"])
    if ok:
        import approval                                    # third key, a human (APPROVAL=off by default: passes)
        approved, text = approval.request(name, args, reason)
        return None if approved else text
    # Every refusal names who refused and the next call. "the change reviewer did not approve" once read as a request
    # for a human: the agent answered "/approve" and the drill ended (2026-10-14).
    return (f"review-rejected: refused by the automatic change reviewer (no human approval exists: do not ask for one or send /approve). "
            f"Reason: {reason}\nNext: make the call the reason names, then call {name} again; if there is none, choose "
            "a less invasive action, or stop and escalate in your final report.")


# 4xx too (2026-10-18): an upstream answering 429 or 403 to every request logged only access lines, so the query was
# empty and neither a runbook nor a card was attached.
ACCESS_ERR_RE = re.compile(r'"(?:GET|POST|HEAD) [^"]*" ([45]\d\d) ')


def layer_note(name):
    """Whose logs these are, and which files of that container's own filesystem differ from its known-good state.
    Both containers have /etc/nginx/conf.d/default.conf; an error in the upstream's was fixed in the front end's file,
    which took the front end down too (upstream-config-crash, blind batch 4)."""
    import faults
    head = (f"[logs of {name}: every path below is inside {name}'s own filesystem"
            + (", not the host file read_config shows" if name != faults.FRONT else
               "; its /etc/nginx/conf.d/default.conf is the host file read_config shows") + "]\n")
    try:
        changes = faults.layer_changes(name)
    except (OSError, subprocess.SubprocessError):
        changes = []
    if changes:
        head += (f"[files of {name} changed since its known-good state (a restart keeps them, recreate_stack "
                 f"replace=true restores them): " + "; ".join(f"{p} {w}" for p, w in changes[:6]) + "]\n")
    return head


def symptom_query(text):
    """The lines that look like a complaint, or None when the output carries no symptom worth matching on.

    An nginx access-log line (`"GET / HTTP/1.0" 500 177 "-" "curl"`) is a symptom, but as embedding input it is mostly
    noise: quotes, sizes, user agents. Say what it means instead, in the words the runbook uses.
    """
    lines = [l.strip() for l in (text or "").splitlines() if SYMPTOM_RE.search(l) or ACCESS_ERR_RE.search(l)]
    if not lines:
        return None
    codes = sorted({m.group(1) for l in lines for m in [ACCESS_ERR_RE.search(l)] if m})
    plain = [l for l in lines if not ACCESS_ERR_RE.search(l)]
    # One line per shape (digits dropped), newest kept: twenty workers dying at start give the master eighty lines of
    # "exited with fatal code 2" and the one [emerg] that names the cause is sixty lines up. Lines that carry a cause
    # level ([emerg]/[alert]/[crit]/[error]) come first, then the newest of the rest.
    distinct, shapes = [], set()
    for l in reversed(plain):
        if _shape(l) not in shapes:
            shapes.add(_shape(l))
            distinct.append(l)
    distinct.reverse()
    levelled = [l for l in distinct if LEVEL_RE.search(l)]
    picked = (levelled[-3:] + [l for l in distinct if not LEVEL_RE.search(l)][-1:]) if levelled else distinct[-4:]
    query = " ".join(picked)[:400]
    if codes:
        import http
        named = " ".join(f"{c} {http.HTTPStatus(int(c)).phrase}" if int(c) in http.HTTPStatus._value2member_map_ else c
                         for c in codes)
        query = f"the service itself answers HTTP {named} to requests, container is up. " + query
    return query.strip() or None


def with_health(result):
    """Append the health check to an action's result. The agent that fixed the stack and kept digging for five
    minutes had not run check_health after acting; now the answer arrives with the action."""
    health = {k: http_status(u) for k, u in HEALTH.items()}
    import tier                                            # TIER_MODE=off by default: both calls are no-ops
    if all(v == 200 for v in health.values()):
        _incident.update(runbook_seen=False, refusals=0, trace=[], injected=[], community_seen=set(), community_pending={})
        snapshot_known_good()
        tier.set_tier(1, "health green after an action")
        return f"{result}\nhealth now: {json.dumps(health)} -> both URLs healthy. The incident is resolved: report root cause, actions, final health and stop."
    state = vm_victim.state() if VM_VICTIM else docker_ps()
    hint = ""
    for line in state.splitlines():
        if "Exited" in line or "MISSING" in line or "Restarting" in line:
            hint = f" {line.split(chr(9))[0]} is {line.split(chr(9))[1][:40]}: that is the next thing to fix."
    tier.set_tier(2, "an action left the stack failing")
    adaptive = ("\nstill failing after an action: parallel_diagnosis gathers the service, platform and knowledge "
                "views at once." if result and os.environ.get("AGENT_MODE") == "adaptive" else "")
    return f"{result}\nhealth now: {json.dumps(health)} -> still failing.{hint}\ncontainers now:\n{state}{adaptive}"


# A container state is a fact with a known procedure; it does not need a similarity search that can land on the
# runbook with the loudest "Exited" in it (it did: a clean stop retrieved container-crashloop). Log text, which is
# free-form, still goes through retrieval.
STATE_RUNBOOKS = (("MISSING", "container-missing.md"), ("Restarting", "container-crashloop.md"),
                  ("Paused", "upstream-504.md"), ("Exited (137)", "oom-killed.md"), ("Exited (0)", "web-service-down.md"))


def attach_named(result, name):
    body = {n: t for n, _, t in __import__("rag").documents()}.get(name)
    if not body:
        return result
    _incident["runbook_seen"] = True
    # a container state is a short line ("edge-victim-app  Exited (0)"): two shared terms with a recorded recovery is a match
    return f"{result}\n\n--- matching runbook, read it before you act ---\n## {name}\n{body[:1500]}" + memory_note(result[:300], min_shared=2)


def attach_runbook(result, query, *, container=None):
    """Push the matching procedure into an evidence answer, so the agent cannot act without having seen it.

    Only on a query with a real symptom in it: cosine similarity is positive for anything, so attaching on every
    read would staple an irrelevant procedure to healthy output and teach the agent to ignore the section.
    """
    import rag
    if not query:
        return result
    ranked = rag.rank(query)
    if not ranked or ranked[0][1] <= 0:
        return result
    name = ranked[0][0]
    body = {n: t for n, _, t in rag.documents()}[name]
    _incident["runbook_seen"] = True
    # Keep the existing runbook ranking, but preserve log ownership for the repair-knowledge lookup.
    knowledge_query = f"{container} {query}" if container else query
    return (f"{result}\n\n--- matching runbook, read it before you act ---\n## {name}\n{body[:1500]}" + knowledge_note(knowledge_query)
            + memory_note(query) + community_push(query))


def memory_note(query, min_shared=3):
    """This stack's own verified recovery for the same symptom (scripts/incident_memory.py), pushed with the runbook the
    way the runbook itself is pushed. Only a close match (three shared terms for a log line, two for a container-state
    line, which has fewer words), one line, never raising, logged as a tool-layer row. It is a record of what worked
    here last time, not a licence: the cause has to match again before the action is repeated."""
    if os.environ.get("INCIDENT_MEMORY", "1") == "0" or not query:
        return ""
    t0 = time.time()
    try:
        import incident_memory
        hits = incident_memory.recall(query, k=1, min_shared=min_shared)
    except Exception:
        return ""
    _oplog("memory_push", {"query": query[:120]}, f"{len(hits)} hit", t0)
    if not hits:
        return ""
    return ("\n\n--- this stack's own verified recovery for this symptom (incident memory: confirm the cause still matches "
            "before repeating it) ---\n" + hits[0][:600])


def earlier_errors(name, shown, window=300, k=4):
    """Cause-level lines ([emerg]/[alert]/[crit]/[error]) from a wider window of this container's log, since its last
    start, that the shown tail does not already contain, one per shape. front-rlimit-nofile (2026-10-22): the worker
    logs one [emerg] "(24: Too many open files)" and the master then logs four lines per worker; with twenty workers
    the tail the agent asked for was all master chatter, and so was the retrieval query. Since the last start only:
    the log keeps every earlier incident's lines, and those are not evidence here."""
    try:
        since = sh(f"docker inspect -f '{{{{.State.StartedAt}}}}' {name}").strip()
        if not since or since.startswith("("):
            return []
        wide = sh(f"docker logs --since {since} --tail {window} {name} 2>&1", limit=60000)
    except Exception:
        return []
    seen = {_shape(l) for l in shown.splitlines()}
    out = []
    for l in wide.splitlines():
        if LEVEL_RE.search(l) and _shape(l) not in seen:
            seen.add(_shape(l))
            out.append(l.strip()[:300])
    return out[-k:]


IMAGE_FILE_PREFIXES = ("/etc/nginx/", "/usr/share/nginx/html/")
PRISTINE_DIR = ROOT / "victim" / "known-good" / "image"


def _trace_arg(t, key):
    """One argument of a trace entry; the trace keeps args as the JSON text the reviewer greps."""
    a = t.get("args")
    if isinstance(a, str):
        try:
            a = json.loads(a)
        except ValueError:
            return None
    return a.get(key) if isinstance(a, dict) else None


def repairable_path(name, path):
    """A file of the nginx image the in-place repair may restore: under /etc/nginx/ or the html root, a plain path (no
    '..'), and on the front end not the mounted conf.d (a host file, write_config's business)."""
    if not path.startswith(IMAGE_FILE_PREFIXES) or ".." in path or path.endswith("/"):
        return False
    if name == "edge-victim" and path.startswith("/etc/nginx/conf.d/"):
        return False
    return True


def pristine_copy(path):
    """The image's own copy of a file, extracted once from a throwaway container of the same image and cached."""
    import faults
    dst = PRISTINE_DIR / path.lstrip("/")
    if dst.exists():
        return dst
    dst.parent.mkdir(parents=True, exist_ok=True)
    cid = sh("docker create nginx:latest").strip().splitlines()[-1]
    try:
        r = subprocess.run(["docker", "cp", f"{cid}:{path}", str(dst)], capture_output=True, text=True, timeout=60)
    finally:
        sh(f"docker rm -f {cid}")
    if r.returncode or not dst.exists():
        raise FileNotFoundError(f"the image has no {path}: {(r.stderr or r.stdout).strip()[:160]}")
    return dst


def write_container_file(name, path, content):
    """The corrected file goes in over the container's copy; nginx -t inside decides; a rejected file is put back
    (the previous content is kept in victim/known-good/container-previous/); then reload, or start a stopped one."""
    import tempfile
    prev_dir = ROOT / "victim" / "known-good" / "container-previous" / name
    prev_dir.mkdir(parents=True, exist_ok=True)
    prev = prev_dir / path.strip("/").replace("/", "__")
    subprocess.run(["docker", "cp", f"{name}:{path}", str(prev)], capture_output=True, text=True, timeout=60)   # may not exist: fine
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".conf") as f:
        f.write(content if content.endswith("\n") else content + "\n")
        tmp = f.name
    try:
        r = subprocess.run(["docker", "cp", tmp, f"{name}:{path}"], capture_output=True, text=True, timeout=60)
    finally:
        os.unlink(tmp)
    if r.returncode:
        return f"error: docker cp failed: {(r.stderr or r.stdout).strip()[:200]}"
    running = sh(f"docker inspect -f '{{{{.State.Running}}}}' {name}").strip() == "true"
    if not running:
        sh(f"docker start {name}")
        settle()
        return f"wrote {path} in {name} and started the container"
    test = sh(f"docker exec {name} nginx -t 2>&1")
    if "syntax is ok" not in test and "test is successful" not in test:
        if prev.exists():
            subprocess.run(["docker", "cp", str(prev), f"{name}:{path}"], capture_output=True, text=True, timeout=60)
        return f"rejected by nginx -t inside {name}, previous file put back: {test.strip()[-300:]}"
    sh(f"docker exec {name} nginx -s reload")
    settle()
    note = ""
    if path.endswith("/conf.d/default.conf") and "root " not in content:
        # a stub that answers text (return 200 "ok") passes nginx -t and fails the deployed-page check: say so now
        note = (" NOTE: this config has no `root` directive, so it does not serve the deployed page; the image's own "
                f"config comes back with repair_image_file {{\"name\": \"{name}\", \"path\": \"{path}\"}}.")
    return f"wrote {path} in {name}; nginx -t ok; reloaded (previous content kept).{note}"


def repair_image_file(name, path):
    """docker cp the pristine file over the container's copy (mode comes with it, so a chmod 000 is undone too), then
    nginx -t and reload inside; a container that is not running gets the file and a start."""
    try:
        src = pristine_copy(path)
    except Exception as e:
        return f"error: {e}"
    r = subprocess.run(["docker", "cp", str(src), f"{name}:{path}"], capture_output=True, text=True, timeout=60)
    if r.returncode:
        return f"error: docker cp failed: {(r.stderr or r.stdout).strip()[:200]}"
    running = sh(f"docker inspect -f '{{{{.State.Running}}}}' {name}").strip() == "true"
    if not running:
        sh(f"docker start {name}")
        settle()
        return f"restored {path} in {name} from the image and started the container"
    test = sh(f"docker exec {name} nginx -t 2>&1")
    if "syntax is ok" not in test and "test is successful" not in test:
        return f"restored {path} in {name} from the image, but nginx -t still fails: {test.strip()[-300:]}. Another file of its layer is still wrong: docker_logs / docker_exec cat it."
    sh(f"docker exec {name} nginx -s reload")
    settle()
    return f"restored {path} in {name} from the image; nginx -t ok; reloaded"


def _oplog(tool, args, result, t0):
    """A line in logs/ops-api.log in the server's own format, so drill logs show what the tool layer did on its own."""
    try:
        with (ROOT / "logs" / "ops-api.log").open("a") as f:
            f.write(json.dumps({"ts": time.strftime("%H:%M:%S"), "from": "tool-layer", "tool": tool, "args": args,
                                "ms": int((time.time() - t0) * 1000), "result": result}, ensure_ascii=False) + "\n")
    except Exception:
        pass


def community_push(query):
    """Community references (README.md) pushed next to the runbook. Only for a symptom no runbook owns
    (community_knowledge.owned_symptom: the access-log status prefix is dropped first, a 502 is the runbook's), once per
    symptom per incident, within COMMUNITY_PUSH_TIMEOUT seconds, never raising. The judge gate inside references() keeps
    only what the local model accepts as on-topic, so a covered-by-nothing symptom usually comes back empty."""
    if not COMMUNITY_PUSH or not query:
        return ""
    try:
        import community_knowledge
    except Exception:
        return ""
    # Ownership is decided line by line: a log tail mixes an earlier incident's "Connection refused" (the runbook's)
    # with this one's "too big header" (nobody's), and the joined text would count as owned. One line per shape.
    raw = _SYMPTOM_PREFIX.sub("", query)
    parts = [p for p in re.split(r"(?=\d{4}/\d\d/\d\d \d\d:\d\d:\d\d \[)", raw) if p.strip()]
    unowned, shapes = [], set()
    for p in parts:
        line = _NGINX_FIELDS.sub("", _NGINX_PREAMBLE.sub("", p)).strip()
        shape = re.sub(r"[\d\W]+", " ", line.lower()).strip()
        if not shape or shape in shapes or community_knowledge.owned_symptom(line):
            continue
        shapes.add(shape)
        unowned.append(line)
    if not unowned:
        return ""
    core = " ".join(unowned[-2:])[:300]
    key = re.sub(r"[\d\W]+", " ", core.lower()).strip()[:160]
    seen = _incident.setdefault("community_seen", set())
    pending = _incident.setdefault("community_pending", {})
    if key in seen:
        return ""
    t0 = time.time()
    try:
        fut = pending.get(key)
        if fut is None:
            fut = pending[key] = _KB_POOL.submit(community_knowledge.references, core, 2, community_knowledge.owned_symptom)
        refs = fut.result(timeout=COMMUNITY_PUSH_TIMEOUT)
    except concurrent.futures.TimeoutError:                # still running: the next read of the same symptom collects it
        _oplog("community_push", {"query": core[:120]}, "pending (timeout)", t0)
        return ""
    except Exception as e:                                 # the push is an extra on an evidence read; it must never break it
        refs, note = "", f"skipped ({type(e).__name__})"
    else:
        note = f"{refs.count(chr(10) + '- ')} references"
    seen.add(key)
    pending.pop(key, None)
    _oplog("community_push", {"query": core[:120]}, note, t0)
    return refs


# --- host layer -------------------------------------------------------------------------------------------------
# What this agent may touch outside the two containers. The rule behind the list: only things this project created.
# Deliberately absent, and why:
#   docker.service / containerd  - the inference server runs as `docker run --rm`, so bouncing the daemon deletes the
#                                  model this agent thinks with. A stopped daemon is unrecoverable from in here by
#                                  construction; report it and escalate.
#   any system unit              - sudo on this host needs a password, and no password belongs in this repo.
#   images and volumes           - shared with the rest of the lab; the agent reports pressure, a human decides.
# logs/agent/*.jsonl is the incident audit trail and is deliberately not cleanable: an ops agent does not delete
# the record of what it did.
# An allowlist of service output that can be regenerated, not "logs/*.log": a pattern over a directory also catches
# whatever is written there later, and it did twice (drill logs on 2026-10-14 01:37, the first A/B's logs at 12:29).
CLEANUP_GLOBS = (str(ROOT / "logs" / "*.out"), str(ROOT / "logs" / "trt-serve.log"), "/tmp/edge-agent-*")
CLEANUP_MIN_AGE_S = 600        # never delete a file something is probably still writing
# Evidence is not a log to rotate. On 2026-10-14 an inode-exhaustion drill ran cleanup_disk (the host's / really is at
# 94 %, so it looked justified) and deleted every earlier drills-*.log, the raw record behind README.md.
EVIDENCE_GLOBS = (str(ROOT / "logs" / "drills-*.log"), str(ROOT / "logs" / "ab-*.log"), str(ROOT / "logs" / "oai-shim.log"),
                  str(ROOT / "logs" / "ops-api.log"), str(ROOT / "logs" / "reviews.jsonl"))   # belt and braces


def cleanup_candidates(now=None):
    """(path, size) of the files cleanup_disk would delete, and how many it skips because a process holds them."""
    now = now or time.time()
    keep = {os.path.realpath(f) for pattern in EVIDENCE_GLOBS for f in glob.glob(pattern)}
    open_files, victims, skipped = held_open(), [], 0
    for pattern in CLEANUP_GLOBS:
        for f in glob.glob(pattern):
            if not os.path.isfile(f) or now - os.path.getmtime(f) <= CLEANUP_MIN_AGE_S or os.path.realpath(f) in keep:
                continue
            if os.path.realpath(f) in open_files:   # a live service still writes here; unlinking it loses the log
                skipped += 1
                continue
            victims.append((f, os.path.getsize(f)))
    return victims, skipped
PROTECTED_CMD = re.compile(r"sshd?\b|systemd|dockerd|containerd|trtllm|tensorrt|openclaw|openshell|nemoclaw|"
                           r"ops_api|oai_shim|uv run|/init\b", re.I)


def docker_ps():
    """State of this stack's containers, naming the ones that are absent.

    `docker ps -a` simply omits a container that was removed, so its absence is invisible next to a healthy sibling.
    An agent then re-reads the same output looking for the difference. Say it outright instead.
    """
    listed = dict(line.split("\t", 1) for line in
                  sh("docker ps -a --filter name=edge-victim --format '{{.Names}}\t{{.Status}}'").splitlines()
                  if "\t" in line)
    # A container's own memory limit and the kernel's OOM verdict are not in `docker ps`; without them an
    # "Exited (137)" upstream read as host memory pressure, and both models went 0/3 on it (2026-10-17).
    extra = {}
    present = [n for n in sorted(NAMES) if n in listed]
    if present:
        for line in sh("docker inspect -f '{{.Name}}\t{{.HostConfig.Memory}}\t{{.State.OOMKilled}}' "
                       + " ".join(present)).splitlines():
            parts = line.strip().lstrip("/").split("\t")
            if len(parts) == 3:
                name, mem, oom = parts
                notes = []
                if mem.isdigit() and int(mem) > 0:
                    notes.append(f"memory limit {int(mem) / 2**20:.0f} MiB")
                if oom == "true":
                    notes.append("OOMKilled: yes (the kernel killed it at its memory limit)")
                if notes:
                    extra[name] = " | " + " | ".join(notes)
    return "\n".join(f"{n}\t{listed.get(n, 'MISSING (no such container: it was removed, not stopped)')}{extra.get(n, '')}"
                      for n in sorted(NAMES))


# Last known-good config: recorded at deploy (faults.reset/setup) and whenever both health URLs are 200, outside the
# directory nginx reads. write_config keeps the file it replaces. Without one, an emptied config left the agent
# guessing a server block from nothing (config-empty, 0/3 for both models on 2026-10-17).
KNOWN_GOOD_DIR = ROOT / "victim" / "known-good"
KNOWN_GOOD = KNOWN_GOOD_DIR / "default.conf"
PREVIOUS = KNOWN_GOOD_DIR / "previous.conf"


def snapshot_known_good():
    try:
        cur = (CONF_DIR / "default.conf").read_text()
        if cur.strip() and "proxy_pass" in cur:
            KNOWN_GOOD_DIR.mkdir(parents=True, exist_ok=True)
            KNOWN_GOOD.write_text(cur)
        import faults
        faults.record_layers()      # what each container's own filesystem looks like while healthy
    except (OSError, subprocess.SubprocessError):
        pass


def held_open():
    """Realpaths this user's processes currently have open. Deleting one frees no space until the writer exits, and
    the service keeps logging into a file nobody can read again."""
    out = set()
    for fd in glob.glob("/proc/[0-9]*/fd/*"):
        try:
            out.add(os.path.realpath(fd))
        except OSError:
            pass
    return out


def local_target(host):
    """Loopback and RFC1918 only: these tools run on the host for anyone who can reach the ops API, so they must not
    become a probe into the rest of the network (or a cloud metadata endpoint)."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return f"cannot resolve {host!r}"
    for *_, addr in infos:
        ip = ipaddress.ip_address(addr[0])
        if not (ip.is_loopback or ip.is_private) or ip.is_link_local:
            return f"denied: {host} resolves to {ip}, outside loopback and the private ranges"
    return None
BASE = os.environ.get("VLLM_URL", "http://127.0.0.1:8000")
MODEL = os.environ.get("SERVED_NAME", "edge-agent")
THINK = os.environ.get("AGENT_THINK", "1") == "1"

SYSTEM = f"""You are an autonomous IT operations agent keeping a small web stack healthy.
Environment: docker container `edge-victim` (nginx front-end, health URLs {HEALTH['front']} and {HEALTH['api']}) and
`edge-victim-app` (upstream behind /api/). The nginx config lives on the host at victim/conf.d/default.conf.
Host-level read-only diagnostics are also available (disk_usage, service_status, journal_tail, port_check, http_check,
top_processes) for faults that are not inside the containers.
Rules: gather evidence first (health, container states, logs, config test), consult runbooks, then apply the least
invasive fix, then verify with check_health. Never touch anything outside these two containers and that config
directory. Call `finish` once both health URLs return 200 or when you cannot fix it (status=escalate)."""

TOOLS = [
    {"name": "check_health", "description": "HTTP status of the front-end and /api/ health URLs", "parameters": {"type": "object", "properties": {}}},
    {"name": "evidence_bundle", "description": "One call that gathers the first look in parallel: health of both URLs, container states, the last log lines of both containers (with the matching runbook), the site config, the 8880 port and disk usage. Use it as the first move of an incident or right after an action instead of five separate calls; it never changes anything.", "parameters": {"type": "object", "properties": {"containers": {"type": "array", "items": {"type": "string"}, "default": ["edge-victim", "edge-victim-app"]}, "tail": {"type": "integer", "default": 30}}}},
    {"name": "docker_ps", "description": "State of the two containers (docker ps -a), with any memory limit and whether the kernel OOM-killed them", "parameters": {"type": "object", "properties": {}}},
    {"name": "docker_logs", "description": "Last lines of a container's logs", "parameters": {"type": "object", "properties": {"name": {"type": "string"}, "tail": {"type": "integer", "default": 40}}, "required": ["name"]}},
    {"name": "docker_exec", "description": "Run one diagnostic inside a container, without a shell (nginx -t/-T, cat, ls, ps, df, du, tail without follow, head, grep, id, env with no arguments). curl is GET/HEAD only to localhost, stack containers or private IP literals; no writes, uploads, custom config or redirects", "parameters": {"type": "object", "properties": {"name": {"type": "string"}, "cmd": {"type": "string"}}, "required": ["name", "cmd"]}},
    {"name": "docker_start", "description": "Start a stopped container", "parameters": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}},
    {"name": "docker_restart", "description": "Restart a container (needed after a config change)", "parameters": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}},
    {"name": "read_config", "description": "Read the front end's (edge-victim's) nginx site config, a host file mounted at /etc/nginx/conf.d/default.conf. edge-victim-app has its own file at that path inside its container: docker_exec cat", "parameters": {"type": "object", "properties": {}}},
    {"name": "write_config", "description": "Replace the nginx config with the given full content. The file lives on the host and is mounted read-only into edge-victim, so this tool is the only way to change it (the container's own 'read-only file system' warning is expected). docker_restart edge-victim afterwards to apply", "parameters": {"type": "object", "properties": {"content": {"type": "string"}}, "required": ["content"]}},
    {"name": "restore_config", "description": "Put back the last known-good nginx config (saved when both health URLs returned 200), or with source=previous the file the last write replaced; then docker_restart edge-victim to apply", "parameters": {"type": "object", "properties": {"source": {"type": "string", "enum": ["known-good", "previous"], "default": "known-good"}}}},
    {"name": "search_runbooks", "description": "Search the IT runbooks for a symptom in your own words or with the exact error text (502 upstream, nginx emerg config, disk full, exit 137, crash loop); returns the best matching procedures, or the catalogue if nothing matches", "parameters": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}},
    {"name": "search_incident_knowledge", "description": "Offline knowledge base: historical incidents from four public AIOps benchmarks, Linux/Kubernetes remediation cards (disk full, inode exhaustion, systemd restart loop, OOM, DNS resolver, TLS expiry, port not listening, CrashLoopBackOff), this stack's own past fixes, and, when no card matches, community references (Server Fault / Unix & Linux accepted answers) for symptoms outside this stack: hardware, power/UPS, network, NTP, Proxmox/Ceph, Kubernetes. Use it for a symptom no runbook covers. Answers 'matched' with checks and fixes to verify on this host, or 'insufficient', which means gather more evidence or escalate; never repair from a weak candidate", "parameters": {"type": "object", "properties": {"query": {"type": "string", "description": "symptom or exact error text"}, "scenario": {"type": "string", "enum": ["disk_full", "crashloop", "dns"]}}, "required": ["query"]}},
    {"name": "disk_usage", "description": "Disk usage: this stack's scratch volume, the host filesystems, and docker; use for disk-full symptoms", "parameters": {"type": "object", "properties": {"inodes": {"type": "boolean", "default": False, "description": "also report inode usage per filesystem (df -i)"}}}},
    {"name": "service_status", "description": "Whether a host systemd unit is active, plus its last status line (read-only)", "parameters": {"type": "object", "properties": {"unit": {"type": "string"}}, "required": ["unit"]}},
    {"name": "journal_tail", "description": "Last lines of a host systemd unit's journal", "parameters": {"type": "object", "properties": {"unit": {"type": "string"}, "lines": {"type": "integer", "default": 30}}, "required": ["unit"]}},
    {"name": "port_check", "description": "Whether a TCP port accepts connections", "parameters": {"type": "object", "properties": {"host": {"type": "string", "default": "127.0.0.1"}, "port": {"type": "integer"}}, "required": ["port"]}},
    {"name": "http_check", "description": "GET an http(s) URL on this host or the private network and return the status code and the first bytes of the body", "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}},
    {"name": "top_processes", "description": "Top host processes by CPU with memory usage", "parameters": {"type": "object", "properties": {}}},
    {"name": "write_container_file", "description": "Fix a file inside a container in place: write the complete corrected file (e.g. the upstream's /etc/nginx/conf.d/default.conf after you read it with docker_exec cat and found the wrong directive), nginx -t decides, a rejected file is put back, then nginx reloads. The container is kept. Same whitelist as repair_image_file", "parameters": {"type": "object", "properties": {"name": {"type": "string"}, "path": {"type": "string"}, "content": {"type": "string"}}, "required": ["name", "path", "content"]}},
    {"name": "repair_image_file", "description": "Put back one file of a container's image in place (the pristine copy from the image, same mode) and reload nginx there, without rebuilding the container: the upstream's own config (/etc/nginx/conf.d/default.conf), its nginx.conf, its pages under /usr/share/nginx/html/. For a file the container changed, deleted or chmodded inside its own layer; the front end's site config is a host file (write_config / restore_config instead)", "parameters": {"type": "object", "properties": {"name": {"type": "string"}, "path": {"type": "string"}}, "required": ["name", "path"]}},
    {"name": "recreate_stack", "description": "Recreate a container of this stack from its definition: one that no longer exists at all, or with replace=true one whose own state is corrupt and survives a restart AND cannot be repaired in place (repair_image_file first for a changed image file; replace is for resource limits, a read-only root, a container that will not start). Start/restart first if it merely exited", "parameters": {"type": "object", "properties": {"name": {"type": "string"}, "replace": {"type": "boolean", "default": False}}}},
    {"name": "network_repair", "description": "Make sure the stack network exists and both containers are attached to it; use when the front end cannot resolve or reach the upstream", "parameters": {"type": "object", "properties": {}}},
    {"name": "cleanup_disk", "description": "Free space by deleting this project's own old service output (*.out, the inference server's startup log); never images, volumes, records, or anyone else's data", "parameters": {"type": "object", "properties": {}}},
    {"name": "clear_scratch_volume", "description": "Delete every file in this stack's scratch volume edge-cache (mounted as /var/cache/nginx in edge-victim: nginx's temp files). Its contents are disposable; nginx recreates its temp directories when it starts", "parameters": {"type": "object", "properties": {}}},
    {"name": "kill_process", "description": "Terminate a runaway host process by pid; only processes owned by this user and not part of the platform itself", "parameters": {"type": "object", "properties": {"pid": {"type": "integer"}, "force": {"type": "boolean", "default": False}}, "required": ["pid"]}},
    {"name": "finish", "description": "End the run with a verdict", "parameters": {"type": "object", "properties": {"status": {"type": "string", "enum": ["resolved", "unresolved", "escalate"]}, "root_cause": {"type": "string"}, "actions": {"type": "string"}}, "required": ["status", "root_cause", "actions"]}},
]

VM_TOOLS = [
    {"name": "vm_exec", "description": "Read-only diagnostic command on the victim host over ssh: ps, ss, cat, ls, df, du, tail, head, grep, nginx -t, systemctl status|is-active <unit>, journalctl -u <unit> -n N. One command, no shell operators, nothing that changes state", "parameters": {"type": "object", "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]}},
    {"name": "vm_logs", "description": "The victim host's nginx journal and error-log tail (attaches the matching runbook); the first look at a degraded web service there", "parameters": {"type": "object", "properties": {"lines": {"type": "integer", "default": 40}}}},
    {"name": "vm_service", "description": "systemctl start|restart|reload|unmask of an allowed unit (nginx) on the victim host; the health check follows", "parameters": {"type": "object", "properties": {"unit": {"type": "string", "default": "nginx"}, "action": {"type": "string", "enum": ["start", "restart", "reload", "unmask"]}}, "required": ["action"]}},
    {"name": "vm_write_config", "description": "Replace the victim host's nginx site config (/etc/nginx/sites-available/default) with the full file given; nginx -t decides, a rejected file is put back; then reload", "parameters": {"type": "object", "properties": {"content": {"type": "string"}}, "required": ["content"]}},
    {"name": "vm_restore_config", "description": "Put back the victim host's known-good nginx site config and reload", "parameters": {"type": "object", "properties": {}}},
]
if VM_VICTIM:
    _KEEP = {"check_health", "search_runbooks", "search_incident_knowledge", "port_check", "http_check", "finish"}
    TOOLS = [t for t in TOOLS if t["name"] in _KEEP] + VM_TOOLS


def vm_argv(cmd):
    """The read-only allow-list of docker_exec (ops_safety.diagnostic_argv) plus systemd's own read-only verbs."""
    try:
        return diagnostic_argv(cmd)
    except ValueError as error:
        argv = shlex.split(cmd) if isinstance(cmd, str) else []
        if argv[:1] == ["systemctl"] and len(argv) >= 2 and argv[1] in ("status", "is-active", "is-failed", "is-enabled", "list-units", "show") \
                and not any(a.startswith("-") and a not in ("--no-pager", "-l", "--all") for a in argv[2:]):
            return argv + ([] if "--no-pager" in argv or argv[1] != "status" else ["--no-pager"])
        if argv[:1] == ["journalctl"] and "-f" not in argv and "--follow" not in argv and all(not a.startswith("--since") or True for a in argv):
            return argv + ([] if "--no-pager" in argv else ["--no-pager"])
        raise error


def vm_tool(name, args, dry_run):
    """The vm_* tools: the same shape as the container tools (gate, health after an action, runbook pushed with the
    log), over ssh to the guest. Nothing here runs on the IMMUNE host itself."""
    if name == "vm_exec":
        try:
            argv = vm_argv(str(args.get("cmd", "")))
        except ValueError as error:
            return f"denied: {error}"
        return vm_victim.run(argv)
    if name == "vm_logs":
        n = max(1, min(int(args.get("lines", 40)), 200))
        out = ("[journal of nginx on victim-vm]\n" + vm_victim.run(["journalctl", "-u", "nginx", "-n", str(n), "--no-pager"])
               + "\n\n[/var/log/nginx/error.log tail]\n" + vm_victim.run(["sudo", "-n", "tail", "-n", str(n), "/var/log/nginx/error.log"]))
        query = symptom_query(out)
        if not query:
            return out + "\n\nno error line in these logs; " + vm_victim.state() + ". vm_exec systemctl status nginx says why a unit is not running."
        return attach_runbook(out, query, container="victim-vm")
    if name == "vm_service":
        unit, action = str(args.get("unit") or "nginx"), str(args.get("action") or "")
        if unit not in vm_victim.UNITS:
            return f"denied: unit {unit!r} is outside the allowed set {list(vm_victim.UNITS)}"
        if action not in ("start", "restart", "reload", "unmask"):
            return "denied: action must be start, restart, reload or unmask"
        if dry_run:
            return f"DRY-RUN: would systemctl {action} {unit} on victim-vm"
        out = vm_victim.run(["sudo", "-n", "systemctl", action, unit], timeout=40)
        return with_health(f"systemctl {action} {unit}: {out or 'ok'}; {vm_victim.state()}")
    if name == "vm_write_config":
        content = args.get("content")
        if not isinstance(content, str) or not content.strip():
            return "error: vm_write_config needs args.content (the full site file)"
        if dry_run:
            return "DRY-RUN: would install the site config on victim-vm"
        return with_health(vm_victim.write_config(content))
    if name == "vm_restore_config":
        if dry_run:
            return "DRY-RUN: would restore the known-good site config on victim-vm"
        return with_health(vm_victim.restore_config())
    return f"error: unknown vm tool {name}"

if os.environ.get("AGENT_MODE") == "adaptive":
    TOOLS.append({"name": "parallel_diagnosis", "description": "Gather service, platform and offline knowledge diagnoses concurrently through read-only tools; it never changes anything.", "parameters": {"type": "object", "properties": {"focus": {"type": "string", "description": "optional symptom or exact error line to investigate"}}}})


def sh(cmd, timeout=30, limit=4000):
    r = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, timeout=timeout)
    out = (r.stdout + r.stderr).strip()
    if not out:
        return f"(exit {r.returncode}, no output)"
    # Keep the tail, not the head. A crash-looping nginx printed ten lines of entrypoint chatter per restart on
    # stdout and its one [emerg] on stderr; head truncation dropped the only line that mattered, three drills in a row.
    return out if len(out) <= limit else "...(earlier output cut)\n" + out[-limit:]


def collapse(text):
    """Fold lines that repeat into one line with a count, keeping first-seen order. A restart loop turns 100 lines of
    the same entrypoint chatter into a dozen, and the error that recurs every cycle becomes the loudest line."""
    seen, order = {}, []
    for line in text.splitlines():
        key = line.strip()
        if key in seen:
            seen[key] += 1
        else:
            seen[key] = 1
            order.append(line)
    return "\n".join(f"{l}   (x{seen[l.strip()]})" if seen[l.strip()] > 1 else l for l in order)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def settle(max_s=2.0, step=0.25):
    """After an action, wait only as long as the stack needs: poll both health URLs until both answer 200 or max_s
    passes. A fixed sleep(2) cost 2 s on every start/restart/recreate (measured 2026-10-22: docker_start 3.1 s,
    docker_restart 2.4-3.3 s wall, most of it the sleep); nginx answers in well under a second once it is up."""
    end = time.time() + max_s
    while time.time() < end:
        if all(http_status(u) == 200 for u in HEALTH.values()):
            return
        time.sleep(step)


HEALTH_TIMEOUT = float(os.environ.get("HEALTH_TIMEOUT", "3"))   # was 5: a hung dependency made every probe wait the full budget


PROC_TABLE = ("for p in /proc/[0-9]*; do pid=${p#/proc/}; st=$(awk '{print $3}' $p/stat 2>/dev/null); "
              "cmd=$(tr '\\0' ' ' < $p/cmdline 2>/dev/null | cut -c1-70); [ -n \"$cmd\" ] && echo \"$pid $st $cmd\"; done")


def hosts_oddities(text):
    """Lines of a container's /etc/hosts that Docker did not write: loopback, IPv6 boilerplate and the container's own
    id line are defaults; anything else pins a name to an address by hand, which is how a stale entry breaks name
    resolution while every log stays clean (front-hosts-poisoned took one drill nine minutes to see, 2026-10-22)."""
    odd = []
    for line in str(text).splitlines():
        parts = line.split()
        if not parts or parts[0].startswith("#"):
            continue
        ip, names = parts[0], parts[1:]
        if ip in ("127.0.0.1", "::1") or ip.startswith(("fe00::", "ff00::", "ff02::")):
            continue
        if len(names) == 1 and re.fullmatch(r"[0-9a-f]{12}", names[0]):
            continue                                    # the container's own id, written by Docker
        odd.append(line.strip())
    return odd


def expected_body(url):
    """The marker a healthy answer at this URL contains (scripts/faults.py EXPECT_BODY), or "" when the stack definition
    is unavailable, in which case the probe stays status-only."""
    try:
        path = urllib.parse.urlsplit(url).path or "/"
        if VM_VICTIM:
            return vm_victim.EXPECT_BODY.get(path, "")
        import faults
        return faults.EXPECT_BODY.get(path, "")
    except Exception:
        return ""


def http_status(url):
    """The status the URL answers with. A redirect is reported, not followed: following a 301 to a name the host
    cannot resolve read "unreachable", and the agent went repairing the network (upstream-redirect, 2026-10-19)."""
    try:
        with urllib.request.build_opener(_NoRedirect).open(url, timeout=HEALTH_TIMEOUT) as r:
            if r.status == 200 and os.environ.get("HEALTH_CONTENT") != "0":
                # a 200 with the wrong page is a failure the status alone hides (upstream-wrong-content, 2026-10-22)
                expect = expected_body(url)
                if expect:
                    body = r.read(4096).decode("utf-8", "replace")
                    if expect not in body:
                        head = " ".join(body.split())[:60]
                        return (f"200 but not the deployed page (body starts {head!r}; expected it to contain {expect!r}). "
                                "Do not invent page content: a container's own page or config goes back from the image with "
                                "repair_image_file (e.g. edge-victim-app /etc/nginx/conf.d/default.conf serves the deployed page); "
                                "the front end's site config is restore_config.")
            return r.status
    except urllib.error.HTTPError as e:
        if 300 <= e.code < 400:
            return f"{e.code} redirect to {e.headers.get('Location', '?')}"
        return e.code
    except Exception as e:
        # A timeout and a refusal are different faults: nothing answering within the budget is a hung process, a
        # paused container or a dependency that never replies; a refusal is nothing listening. The dependency-timeout
        # drills spent 220-295 s mostly in 5 s probes that all ended the same way (2026-10-22).
        reason = getattr(e, "reason", e)
        if isinstance(e, TimeoutError) or isinstance(reason, TimeoutError) or "timed out" in str(e).lower():
            return f"timed out after {HEALTH_TIMEOUT:g} s (nothing answered: a hung or paused process, or a dependency that never replies; not a refused connection)"
        return f"unreachable ({type(e).__name__})"


def search_runbooks(query):
    """Retrieval lives in scripts/rag.py: hybrid keyword + dense, with its own fallback when the index is absent."""
    import rag
    return rag.search(query) + knowledge_note(query) + memory_note(query) + community_push(query)


KB_DB = ROOT / "kb" / "artifacts" / "immune_kb.sqlite"
# v3 (2026-10-13, README.md): cases indexed by their own incident's telemetry, word-boundary IDF
# scoring, no substring `matched`. On the held-out benchmark it turned retrieval from harmful (50 answers broken, 16
# fixed) to helpful (16 broken, 53 fixed). KB_RETRIEVAL=v1 restores the pack as shipped.
KB_V3 = ROOT / "kb" / "artifacts" / "corpus_v3.jsonl"
# v4 (2026-10-18, scripts/kb-cards.py): v3 plus repair cards written for this stack's tools per public fault family,
# and the fixes this stack's drills verified. KB_RETRIEVAL=v4 selects it; v3 stays the default until a drill A/B says.
KB_V4 = ROOT / "kb" / "artifacts" / "corpus_v4.jsonl"
_kb = None


def kb_version():
    v = os.environ.get("KB_RETRIEVAL", "v3")
    return v if v in ("v1", "v3", "v4") else "v3"


def knowledge_base():
    """The pack, opened once: v3 unless KB_RETRIEVAL=v1 or v4."""
    global _kb
    if _kb is None:
        sys.path.insert(0, str(ROOT / "kb" / "src"))
        corpus = {"v3": KB_V3, "v4": KB_V4}.get(kb_version())
        if corpus and corpus.exists():
            from immune_kb.retrieval_v2 import AGENT_DEFAULTS, KnowledgeBaseV2
            try:
                from repair_knowledge import documents
                extra = documents() if os.environ.get("OPS_HARD_REPAIR_KNOWLEDGE", "1") != "0" else []
            except (OSError, ValueError, KeyError) as error:
                print(f"extra repair knowledge unavailable: {error}", file=sys.stderr)
                extra = []
            _kb = KnowledgeBaseV2(corpus, extra_documents=extra, **AGENT_DEFAULTS)
        else:
            from immune_kb import KnowledgeBase
            _kb = KnowledgeBase(KB_DB)
    return _kb


def knowledge_note(query):
    """A knowledge card pushed next to a runbook, only when the pack is confident (v3: one of the card's own symptom
    phrases is in the query whole and specific). Pulling it was left to the model and never happened: the skill said
    to ask the pack when runbook search returns the catalogue, and dense search never does ("printer toner low"
    returns disk-full.md), so in every drill the pack went unread. A score floor to detect "no runbook covers this"
    was measured and does not separate (covered 0.66-0.88, uncovered up to 0.73), so the card rides along instead.
    Measured on 24 uncovered symptoms: 6 cards pushed, 5 right, 14 correct silences, 4 missed; on 38 covered ones 3
    cards, each consistent with the runbook. Never counts as a runbook: the gate is unchanged."""
    try:
        kb = knowledge_base()
        if type(kb).__name__ != "KnowledgeBaseV2" or not query:
            return ""                                      # v1's `matched` was wrong 20 times in 21; push nothing
        # v4: six candidates, or a stack card outranked on BM25 by a generic one never reaches the phrase test
        b = kb.retrieve({"query": query}, case_k=0, solution_k=6 if kb_version() == "v4" else 3)
    except Exception:                                      # the note is an extra; it must never break the tool
        return ""
    if b["knowledge_match"]["status"] != "matched" or not b["solutions"]:
        return ""
    s = b["solutions"][0]
    m = s.get("metadata") or {}
    if m.get("kind") == "hard_failure_repair":
        from repair_knowledge import render
        return render(m, brief=True)
    if m.get("platform") == "docker":
        return stack_card_note(s, m)
    lines = [f"\n\n--- knowledge card (from other systems' incidents: a hypothesis to confirm here, not this stack's "
             f"procedure) ---\n{s['id']}: {m.get('title', s.get('title', ''))} [matched on: {' '.join(s.get('matched_terms') or [])}]"]
    lines += [f"CHECK {c.get('command', '')} :: {c.get('purpose', '')}" for c in m.get("checks", [])[:3]]
    lines += [f"FIX {f.get('action', '')}" for f in m.get("remediation", [])[:2]]
    lines.append("If the runbook above does not fit what you see, test the card's CHECK lines with your read-only tools.")
    return "\n".join(lines)[:1200]


def stack_card_note(s, m):
    """A v4 repair card: written for this stack's tools, so its CHECK and FIX lines are calls the agent can make; still
    a hypothesis until the CHECK lines confirm it, and never a substitute for the runbook."""
    lines = [f"\n\n--- repair card (a public fault family mapped to this stack's tools: confirm with its CHECK lines "
             f"before any FIX) ---\n{s['id']}: {m.get('title', '')} [matched on: {' '.join(s.get('matched_terms') or [])}]"]
    lines += [f"CHECK {c['command']} :: {c['purpose']}" for c in m.get("checks", [])[:3]]
    lines += [f"FIX {f['action']}" + (" (destructive: only once the CHECKs confirm it)" if f.get("approval_required") else "")
              for f in m.get("remediation", [])[:2]]
    lines += [f"ESCALATE if {x}" for x in m.get("escalate", [])[:1]]
    lines += [f"verified on this stack: {x}" for x in m.get("proven_here", [])[:2]]
    return "\n".join(lines)[:1600]


def search_incident_knowledge(query, scenario=None):
    """A teammate's offline knowledge pack (kb/): historical cases from four public AIOps benchmarks plus curated
    Linux/Kubernetes remediation cards in SQLite FTS5, stdlib only. Its verdict is kept (`matched` = a card covers
    the symptom, `insufficient` = nothing does, so no repair may be derived from the weak candidates) but its size
    is not: the raw bundle is 14-24 KB of JSON and the model has a 32k window, so only the lines the agent can act
    on come back. It never counts as having read this stack's runbook; the gate still wants search_runbooks."""
    memory = ""
    if os.environ.get("INCIDENT_MEMORY", "1") != "0":
        try:
            import incident_memory
            recoveries = incident_memory.recall(query)
            if recoveries:
                memory = "## this stack's own verified recoveries\n" + "\n\n".join(recoveries) + "\n\n"
        except Exception:
            pass
    try:
        kb = knowledge_base()
        incident = {"query": query, "scenario": scenario} if scenario in ("disk_full", "crashloop", "dns") else {"query": query}
        bundle = kb.retrieve(incident, case_k=3, solution_k=3)
    except Exception as e:
        return memory + f"knowledge base unavailable ({type(e).__name__}: {str(e)[:100]}); use search_runbooks"
    km = bundle["knowledge_match"]
    best = bundle["solutions"][0] if bundle["solutions"] else {}
    if km["status"] == "matched" and (best.get("metadata") or {}).get("kind") == "hard_failure_repair":
        from repair_knowledge import render
        # Return the complete best procedure, rather than cutting off its conditions and verification at 2.5 KB.
        return memory + render(best["metadata"])
    lines = [f"knowledge base ({bundle['scenario']}): {km['status']}, best card coverage {km['best_solution_coverage']:.2f}"]
    for s in bundle["solutions"][:2]:            # two cards: the third is mostly noise on a 33-term query
        m = s.get("metadata") or {}
        lines.append(f"\n## {s['id']}: {m.get('title', s.get('title', ''))} [{m.get('platform', '?')}, risk {s.get('risk_tier')}, coverage {s['match_coverage']:.2f}]")
        if m.get("symptoms"):
            lines.append("symptoms: " + "; ".join(m["symptoms"][:2]))
        for c in m.get("checks", [])[:3]:
            lines.append(f"CHECK [{c.get('level', 'R')}] {c.get('command', '')} :: {c.get('purpose', '')}")
        for f in m.get("remediation", [])[:2]:
            lines.append(f"FIX [{f.get('level', 'W')}] {f.get('action', '')}")
        if m.get("verify"):
            lines.append("verify: " + str(m["verify"][0]))
    if km["status"] != "matched":
        weak = ", ".join(f"{s['id']} ({s['match_coverage']:.2f})" for s in bundle["weak_solution_candidates"][:3]) or "none"
        lines.append(f"no remediation card covers this symptom; weak candidates ({weak}) are not a basis for repair. "
                     "Use search_runbooks for this stack's own procedures, gather more read-only evidence, or escalate.")
        # Community reference layer (README.md): Server Fault / Unix & Linux accepted answers for
        # symptoms outside this stack, a separate index that no card or runbook ranking shares. Excerpts with links,
        # labelled as unverified here; the tool contracts and the reviewer are unchanged. KB_COMMUNITY=0 turns it off.
        try:
            import community_knowledge
            refs = community_knowledge.references(query)
            if refs:
                lines.append(refs)
        except Exception:
            pass
    # v4 cases name the repair card of their fault type, and this stack's own past fixes say what fixed them
    titles = list(dict.fromkeys(str(c.get("title", ""))[:(110 if c["id"].startswith("stack-") else 60)]
                                + (f" (card: {c['metadata']['repair_card']})" if (c.get("metadata") or {}).get("repair_card")
                                   and not c["id"].startswith("stack-") else "") for c in bundle["cases"][:3]))
    if titles:
        lines.append("\nsimilar historical cases: " + "; ".join(titles))
    lines.append("These are hypotheses from other systems' incidents: confirm against this host's evidence before acting.")
    out = "\n".join(lines)
    pack = out if len(out) <= 2500 else out[:2500] + "\n...(cut)"
    return memory + pack


def trace_summary(name, result):
    """What the incident trace (the reviewer's evidence) keeps of a result. A blind first-300-characters cut kept nginx's
    startup notices and dropped the one [emerg] line at the end of a log, and the reviewer then judged an inode
    exhaustion "a connectivity issue": logs keep their end (without the attached runbook), other results their head
    and, when long, their tail, where the appended health check is."""
    # other hosts' text is not evidence from this incident: drop the block, keep what follows it (a bundle's next
    # section, the health line)
    text = re.sub(r"\ncommunity references.*?(?=\n\n|\nhealth now:|$)", "", str(result), flags=re.S)
    if name == "docker_logs":
        # the read-only note appended to front-end logs pushed the [emerg] line out of the kept tail, and the rebuild
        # rule, which reads the trace, never saw the missing image file it was waiting for (front-mime-missing, 0/6)
        body = text.split("\n\n--- matching runbook")[0].split("\n\nnote: the entrypoint")[0]
        text = body if len(body) <= 300 else "… " + body[-300:]
    elif name == "search_incident_knowledge":
        # community excerpts are other hosts' text, not evidence from this incident: keep them out of what the reviewer reads
        text = text.split("\ncommunity references")[0]
        if len(text) > 450:
            text = text[:300] + " … " + text[-150:]
    elif len(text) > 450:
        text = text[:300] + " … " + text[-150:]
    return text[:460].replace("\n", " ")


def run_tool(name, args, dry_run):
    """Dispatch one tool call and record it in the incident trace (the reviewer's evidence). With GUARDRAILS=1 the
    NeMo Guardrails rails (scripts/guard.py) sit on both sides: a state-changing call that does what text injected
    into the monitored system's output asked for is refused, and that output is screened before the agent reads it."""
    import guard
    refusal = guard.check_action(name, args if isinstance(args, dict) else {}, _incident) if name in MUTATING else None
    result = refusal or guard.screen(name, _run_tool(name, args, dry_run), _incident)
    try:
        shown = {k: (v if len(str(v)) < 80 else str(v)[:77] + "...") for k, v in (args or {}).items()} if isinstance(args, dict) else str(args)[:80]
        _incident["trace"].append(dict(tool=name, args=json.dumps(shown, ensure_ascii=False), result=trace_summary(name, result)))
        del _incident["trace"][:-30]
    except Exception:
        pass
    return result


def evidence_bundle(args, dry_run):
    containers = args.get("containers", ["edge-victim", "edge-victim-app"])
    tail = args.get("tail", 30)
    calls = ([
        ("check_health", {}),
        ("docker_ps", {}),
    ] + [("docker_logs", {"name": container, "tail": tail}) for container in containers] + [
        ("read_config", {}),
        ("port_check", {"port": 8880}),
        ("disk_usage", {}),
    ])
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=6)
    futures = [pool.submit(_run_tool, tool, dict(tool_args), dry_run) for tool, tool_args in calls]
    try:
        done, pending = concurrent.futures.wait(futures, timeout=EVIDENCE_BUNDLE_TIMEOUT)
        results = []
        for (tool, _), future in zip(calls, futures):
            if future in pending:
                future.cancel()
                results.append(f"(evidence_bundle: {tool} failed: timeout after {EVIDENCE_BUNDLE_TIMEOUT:g}s)")
                continue
            try:
                results.append(str(future.result()))
            except Exception as error:  # noqa: BROAD_EXCEPT_OK - one failed diagnostic must not hide the others
                results.append(f"(evidence_bundle: {tool} failed: {type(error).__name__}: {error})")
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    suffix = with_health("")
    suffix = suffix[1:] if suffix.startswith("\n") else suffix
    sections = [f"## {tool} {json.dumps(tool_args, ensure_ascii=False, sort_keys=True)}\n{result}"
                for (tool, tool_args), result in zip(calls, results)]
    budget = max(0, EVIDENCE_BUNDLE_LIMIT - len(suffix) - 1)
    body = "\n\n".join(sections)
    if len(body) > budget:
        log_indexes = [i for i, (tool, _) in enumerate(calls) if tool == "docker_logs"]
        fixed = len(body) - sum(len(results[i]) for i in log_indexes)
        quota = max(0, budget - fixed) // max(1, len(log_indexes))
        marker = "...(earlier evidence cut)\n"
        for i in log_indexes:
            result = results[i]
            if len(result) <= quota:
                continue
            keep = max(0, quota - len(marker))
            trimmed = marker + result[-keep:] if keep else marker[:quota]
            tool, tool_args = calls[i]
            sections[i] = f"## {tool} {json.dumps(tool_args, ensure_ascii=False, sort_keys=True)}\n{trimmed}"
        body = "\n\n".join(sections)
    return (body[:budget] + "\n" + suffix)[:EVIDENCE_BUNDLE_LIMIT]


def parallel_diagnosis(args, dry_run):
    import specialists
    module = sys.modules.get(__name__) or argparse.Namespace(**globals())
    return specialists.parallel_diagnosis(module, args, dry_run)


def _run_tool(name, args, dry_run):
    if isinstance(args, str):            # some clients send arguments as a JSON string
        try:
            args = json.loads(args or "{}")
        except json.JSONDecodeError:
            return f"bad arguments (not JSON): {args[:200]}"
    args = args or {}
    if "name" in args and args["name"] is None:
        args.pop("name")
    for alias in ("container", "container_name", "service"):   # small models / meta-tool layers rename things
        if alias in args and "name" not in args:
            args["name"] = args.pop(alias)
    c = args.get("content")
    if isinstance(c, str) and "\n" not in c and "\\n" in c:   # double-escaped JSON: literal backslash-n, no real newlines
        args["content"] = c.replace("\\n", "\n").replace("\\t", "\t").replace('\\"', '"')
    if name in ("docker_logs", "docker_exec", "docker_start", "docker_restart") and "name" not in args:
        return f"error: {name} needs args.name (one of {sorted(NAMES)})"
    if name == "docker_exec" and "cmd" not in args:
        return "error: docker_exec needs args.cmd"
    if name == "write_config" and "content" not in args:
        return "error: write_config needs args.content (the full file)"
    if name in ("search_runbooks", "search_incident_knowledge") and "query" not in args:
        return f"error: {name} needs args.query"
    for alias in ("service", "unit_name", "systemd_unit"):         # small models rename this one too
        if alias in args and "unit" not in args:
            args["unit"] = args.pop(alias)
    if name in ("service_status", "journal_tail") and "unit" not in args:
        return f"error: {name} needs args.unit (a systemd unit name, e.g. docker)"
    if name == "port_check" and "port" not in args:
        return "error: port_check needs args.port"
    if name == "http_check" and "url" not in args:
        return "error: http_check needs args.url"
    if name == "kill_process" and "pid" not in args:
        return "error: kill_process needs args.pid (from top_processes)"

    if name in MUTATING and os.environ.get("HEALTHY_GUARD", "1") == "1":
        # Every fault case takes a health URL off 200, so both at 200 means there is nothing to repair. On the prototype device
        # (2026-10-21) Lightning kept acting after a fix: OpenClaw resumed a finished session, wrote a broken
        # default.conf and took the front end down 30 s after the board had turned green.
        health = {k: http_status(u) for k, u in HEALTH.items()}
        if all(v == 200 for v in health.values()):
            return (f"refused: (automatic rule) the stack is healthy right now ({json.dumps(health)}); there is "
                    f"nothing to repair and {name} could only make it worse. The incident is over: call no more "
                    "tools and end with your final report (root cause, actions taken, final health).")

    if name in MUTATING and not _incident["runbook_seen"]:
        # The agent is about to act without having read any evidence, so we do not know the symptom either and
        # cannot pick the procedure for it. Send it back for the symptom. Bounded, so a stubborn model cannot
        # deadlock: after two refusals the action goes through and the log shows it did.
        _incident["refusals"] += 1
        if _incident["refusals"] >= 2:
            import tier
            tier.set_tier(2, "guards refused twice in this incident")
        if _incident["refusals"] <= 2:
            import rag
            catalogue = "\n".join(f"- {n}: {t}" for n, t, _ in rag.documents())
            return (f"refused: (automatic rule) no runbook consulted yet for this incident, so {name} is premature. "
                    'Next: call docker_logs {"name": "<the failing container>"} (it attaches the matching runbook), or '
                    'search_runbooks {"query": "<the error text>"}; then call ' + name + " again. Runbooks available:\n"
                    + catalogue)

    def guard(n):
        if n not in NAMES:
            return f"denied: container {n!r} is outside the allowed set {sorted(NAMES)}. Next: the same call with one of those names."
    if name == "check_health":
        health = {k: http_status(u) for k, u in HEALTH.items()}
        if all(v == 200 for v in health.values()):
            _incident.update(runbook_seen=False, refusals=0, trace=[], injected=[], community_seen=set(), community_pending={})   # incident over; the next one starts clean
            snapshot_known_good()
            import tier
            tier.set_tier(1, "health green")
        return json.dumps(health)
    if name == "evidence_bundle":
        return evidence_bundle(args, dry_run)
    if name == "parallel_diagnosis":
        return parallel_diagnosis(args, dry_run)
    if name.startswith("vm_"):
        if not VM_VICTIM:
            return "denied: the VM victim is not enabled on this host (VM_VICTIM=1)"
        return vm_tool(name, args, dry_run)
    if name == "docker_ps":
        out = docker_ps()
        for marker, runbook in STATE_RUNBOOKS:
            if marker in out:
                return attach_named(out, runbook)
        return out
    if name == "docker_logs":
        denied = guard(args["name"])
        if denied:
            return denied
        out = collapse(sh(f"docker logs --tail {int(args.get('tail', 40))} {args['name']} 2>&1", limit=6000))
        earlier = earlier_errors(args["name"], out)
        if earlier:
            out += "\n\nearlier distinct error lines since this container last started (not in the tail above):\n" + "\n".join(earlier)
        if re.search(r"exited with fatal code|Too many open files|worker_connections are not enough", out):
            # front-rlimit-nofile 0/5 (2026-10-22): the agent rewrote the site config five times; the limit lives in the
            # image's nginx.conf, which only repair_image_file / write_container_file reach
            out += (f"\n\nnote: workers dying at start are a limit in the image's /etc/nginx/nginx.conf (worker_rlimit_nofile, "
                    f"worker_connections), not the site config: docker_exec cat /etc/nginx/nginx.conf, then "
                    f'repair_image_file {{"name": "{args["name"]}", "path": "/etc/nginx/nginx.conf"}}.')
        out = layer_note(args["name"]) + out
        if "read-only file system" in out:
            out += ("\n\nnote: the entrypoint's 'can not modify /etc/nginx/conf.d/default.conf (read-only file "
                    "system?)' is expected and harmless. That file is a host file mounted read-only into the "
                    "container; write_config changes it on the host, then docker_restart applies it.")
        query = symptom_query(out)
        if not query:
            state = next((l for l in docker_ps().splitlines() if l.startswith(args["name"] + "\t")), "")
            for marker, runbook in STATE_RUNBOOKS:
                if marker in state:
                    # nothing wrong in the log and the process is gone: say so, or the agent goes looking for an
                    # error that does not exist while the gate keeps refusing the start it should have done.
                    out += f"\n\nno error in this log; the container is {state.split(chr(9))[1][:30]}."
                    return attach_named(out, runbook)
        return attach_runbook(out, query, container=args["name"])
    if name == "docker_exec":
        denied = guard(args["name"])
        if denied:
            return denied
        try:
            command = diagnostic_argv(args["cmd"])
        except ValueError as error:
            return (f"denied: {error}. Next: use one read-only diagnostic, e.g. "
                    '{"name": "edge-victim-app", "cmd": "df -h /"}. '
                    "Use action tools for changes; curl only supports GET/HEAD without file output or redirects.")
        # 8 s, not the default 30: `cat /var/log/nginx/error.log` blocks forever in the nginx image (the file is a link
        # to the container's stderr) and once cost a drill 30 s of silence that read like model thinking (2026-10-22).
        try:
            out = sh(["docker", "exec", args["name"], *command], timeout=8)
            if command[0] == "ps" and "executable file not found" in out:
                # the nginx image ships no ps; the agent that could not see its workers in state T (SIGSTOP) curled for
                # three minutes and gave up (upstream-sigstop, 2026-10-22). The table comes from /proc instead: a fixed
                # command of the tool's own, never model text.
                out = sh(["docker", "exec", args["name"], "sh", "-c", PROC_TABLE], timeout=8)
                out = ("[ps is not in this image; process table from /proc: PID STATE COMMAND, state T = stopped/traced "
                       "(a SIGSTOP), D = uninterruptible wait, Z = zombie]\n" + out)
            if command[0] == "curl":
                # a curl to a stack name that hangs is a name-resolution question before it is a connectivity one: show
                # what the name resolves to inside this container right away (front-hosts-poisoned spent 3.5 min curling
                # before a restart happened to re-render /etc/hosts, 2026-10-22)
                m = re.search(r"https?://(edge-victim(?:-app)?)(?=[:/]|$)", " ".join(command))
                if m and re.search(r"timed out|Connection timed out|\(28\)|Failed to connect|Could not resolve|no output", out, re.I):
                    name = m.group(1)
                    resolved = sh(["docker", "exec", args["name"], "getent", "hosts", name], timeout=5).strip()
                    odd = hosts_oddities(sh(["docker", "exec", args["name"], "cat", "/etc/hosts"], timeout=5))
                    out += (f"\n[inside {args['name']}, {name} resolves to: {resolved or '(nothing)'}"
                            + (f"; /etc/hosts carries hand-written entries: {'; '.join(odd)}" if odd else "")
                            + ". Docker's embedded DNS gives a stack container its current address; a hosts entry or a broken "
                            "resolver overrides it. A restart re-renders /etc/hosts and resolv.conf.]")
            if command[:2] == ["cat", "/etc/hosts"]:
                odd = hosts_oddities(out)
                out += ("\n[hosts entries beyond Docker's defaults: " + "; ".join(odd) + ". An entry that names a stack container pins "
                        "its address by hand; if it is wrong or stale, name resolution fails while every log stays clean. A restart "
                        "re-renders /etc/hosts.]" if odd else "\n[only Docker's default hosts entries]")
            return out
        except subprocess.TimeoutExpired:
            return (f"(no output in 8 s: {' '.join(command)} is still waiting for data, stopped). In this image "
                    "/var/log/nginx/access.log and error.log are links to the container's stdout/stderr, so reading them "
                    "never ends; the log is what docker_logs returns. Next: call docker_logs on this container.")
    if name in ("docker_start", "docker_restart"):
        d = guard(args["name"])
        if d:
            return d
        if args["name"] == "edge-victim":
            import faults
            app_nets = sh(f"docker inspect edge-victim-app --format '{{{{json .NetworkSettings.Networks}}}}'")
            if faults.NET not in app_nets:
                return (f"denied: edge-victim-app is not on the {faults.NET} network right now, so nginx would fail to "
                        "resolve it at startup and exit. Run network_repair first, then start/restart edge-victim.")
            app_running = sh("docker inspect -f '{{.State.Running}}' edge-victim-app").strip() == "true"
            if not app_running and http_status(HEALTH["front"]) == 200:
                # it serves / now; restarted, nginx resolves edge-victim-app at start, fails and exits (two runs made
                # worse this way in blind batch 4)
                return ("denied: edge-victim is serving / right now and edge-victim-app is not running; restarted, "
                        "edge-victim would fail to resolve edge-victim-app at startup and go down too. The fault is in "
                        'edge-victim-app: docker_logs {"name": "edge-victim-app"} and fix it first.')
        if dry_run:
            return f"DRY-RUN: would run docker {name.split('_')[1]} {args['name']}"
        out = sh(f"docker {name.split('_')[1]} -t 5 {args['name']}" if name == "docker_restart" else f"docker start {args['name']}")
        settle()
        return with_health(out + "\n" + docker_ps())
    if name == "read_config":
        cur = (CONF_DIR / "default.conf").read_text()
        out = cur if cur.strip() else "(the file is empty: nginx starts with no server block and listens nowhere)"
        if KNOWN_GOOD.exists() and KNOWN_GOOD.read_text() != cur:
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(KNOWN_GOOD.stat().st_mtime))
            out += (f"\n\n--- note: a known-good copy of this file (saved {when}, while both health URLs returned 200) "
                    "differs from it. restore_config puts it back; then docker_restart edge-victim.")
        return out
    if name == "write_config":
        content = args["content"]
        if len(content) > 20000 or "proxy_pass" not in content or "/board/" not in content:
            return ("denied: config must stay under 20 KB and keep the /api/ proxy_pass and the /board/ location. "
                    "Next: read_config, keep those lines, and write_config the complete corrected file.")
        if dry_run:
            return "DRY-RUN: would write default.conf"
        KNOWN_GOOD_DIR.mkdir(parents=True, exist_ok=True)
        PREVIOUS.write_text((CONF_DIR / "default.conf").read_text())
        (CONF_DIR / "default.conf").write_text(content)
        return "written, but not applied: nginx only reads it on start. Call docker_restart {\"name\": \"edge-victim\"} now."
    if name == "restore_config":
        source = args.get("source", "known-good")
        if source not in ("known-good", "previous"):
            return "error: restore_config source must be known-good or previous"
        src = KNOWN_GOOD if source == "known-good" else PREVIOUS
        if not src.exists():
            return (f"error: no {args.get('source', 'known-good')} copy exists. Next: read_config, then write_config the "
                    "complete corrected file.")
        if dry_run:
            return f"DRY-RUN: would restore {src.name}"
        KNOWN_GOOD_DIR.mkdir(parents=True, exist_ok=True)
        restore_config_file(CONF_DIR / "default.conf", src, PREVIOUS)
        return (f"restored {src.name} into default.conf (the replaced file is kept as previous.conf), not applied yet: "
                'nginx reads it on start. Next: docker_restart {"name": "edge-victim"}.')
    if name == "search_runbooks":
        _incident["runbook_seen"] = True
        return search_runbooks(args["query"])
    if name == "search_incident_knowledge":
        return search_incident_knowledge(str(args["query"]), args.get("scenario"))
    if name == "disk_usage":
        # The scratch volume comes first: the incident trace keeps 300 characters of a result, and the reviewer's
        # precondition for clearing it is read from there.
        import faults
        # OPS_INODES=on-request (the knowledge A/B, README.md): inode figures only when asked for, so
        # whether the agent thinks of inodes is part of what is measured. Default: always shown.
        inodes = os.environ.get("OPS_INODES", "always") != "on-request" or bool(args.get("inodes"))
        vol = sh(f"docker exec {faults.CACHE} sh -c 'df -h /cache | tail -1; df -i /cache | tail -1'")
        lines = vol.strip().splitlines()
        if len(lines) == 2 and len(lines[1].split()) >= 5:
            scratch = f"scratch volume edge-cache (/var/cache/nginx in edge-victim): space {lines[0].split()[4]}"
            scratch += f", inodes {lines[1].split()[4]}" if inodes else ""
        else:
            scratch = f"scratch volume edge-cache: unreadable ({vol.strip()[:120]})"
        return (scratch + "\n\nhost, space:\n" + sh("df -h -x tmpfs -x devtmpfs -x efivarfs | head -12")
                + ("\nhost, inodes:\n" + sh("df -i -x tmpfs -x devtmpfs -x efivarfs | head -12") if inodes else "")
                + "\n" + sh("docker system df"))
    if name in ("service_status", "journal_tail"):
        unit = str(args["unit"]).strip()
        if not UNIT_RE.match(unit):
            return f"denied: {unit!r} is not a plain unit name"
        if name == "service_status":
            return sh(f"systemctl is-active {unit}; systemctl status {unit} --no-pager -n 0 | head -6")
        return sh(f"journalctl -u {unit} -n {max(1, min(int(args.get('lines', 30)), 200))} --no-pager")
    if name == "port_check":
        host, port = str(args.get("host") or "127.0.0.1"), int(args["port"])
        denied = local_target(host)
        if denied:
            return denied
        try:
            with socket.create_connection((host, port), timeout=3):
                return f"{host}:{port} open"
        except Exception as e:
            return f"{host}:{port} closed ({type(e).__name__})"
    if name == "http_check":
        url = str(args["url"])
        if not url.startswith(("http://", "https://")):
            return "denied: url must be http(s)"
        denied = local_target(urllib.parse.urlsplit(url).hostname or "")
        if denied:
            return denied
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                return f"{r.status}\n{r.read(600).decode(errors='replace')}"
        except urllib.error.HTTPError as e:
            return f"{e.code}\n{e.read(600).decode(errors='replace')}"
        except Exception as e:
            return f"unreachable ({type(e).__name__})"
    if name == "top_processes":
        return sh("ps -eo pid,comm,pcpu,pmem,rss --sort=-pcpu | head -16")
    if name == "recreate_stack":
        import faults                                   # one definition of the containers, shared with the harness
        targets = [args["name"]] if args.get("name") else sorted(faults.SPECS)
        for t in targets:
            if t not in faults.SPECS:
                return f"denied: {t!r} is not part of this stack"
        if args.get("replace") and not args.get("name"):
            return ("denied: replace=true needs an explicit name; it destroys that container and builds it again. "
                    'Next: recreate_stack {"name": "edge-victim-app", "replace": true}.')
        if args.get("replace") and args.get("name") == "edge-victim":
            # The site config is a host file a rebuild keeps; a file of the image (nginx.conf includes mime.types) is
            # restored by one. Denying every rebuild of the front end left front-mime-missing unfixable (0/6, 2026-10-18).
            import reviewer
            if not (reviewer.front_image_file(_incident["trace"]) or reviewer.front_layer_changes()):
                return ("denied: edge-victim's site config is a host file mounted into the container; rebuilding the "
                        "container keeps the same file and the same fault. Fix the file with write_config or "
                        "restore_config, then docker_restart edge-victim. (A rebuild is allowed only when a file of its "
                        "image, outside /etc/nginx/conf.d, is missing or changed: docker_logs edge-victim lists them.)")
        if dry_run:
            return f"DRY-RUN: would recreate {targets}" + (" (replacing)" if args.get("replace") else "")
        if args.get("replace"):
            # Known precondition, checked in code: a rebuild is never a first move. The runbook says restart first,
            # and the reviewer once approved a premature rebuild because "the runbook was consulted".
            # A start of an exited container is the same evidence as a restart: it ran again and still failed. Only
            # docker_restart counted, and an agent that had read "OOMKilled: yes", started the container and seen it
            # killed again was still refused the rebuild (2026-10-17).
            import reviewer
            if not reviewer.restarted(_incident["trace"], args["name"]):
                return (f"denied: recreate_stack replace=true on {args['name']} before it was started or restarted in this "
                        f'incident. Next: docker_restart {{"name": "{args["name"]}"}}; if it still fails, call '
                        f'recreate_stack {{"name": "{args["name"]}", "replace": true}} again.')
            # Replacing a container is the heavy hand: when what changed in its layer is a file the image has, that
            # file is put back in place first (repair_image_file); the rebuild is for what a file repair cannot undo.
            repairable = [p for p, _ in faults.layer_changes(args["name"]) if repairable_path(args["name"], p)]
            tried = {_trace_arg(t, "path") for t in _incident["trace"] if t["tool"] in ("repair_image_file", "write_container_file")
                     and reviewer.named(t, args["name"]) and not t["result"].startswith(("refused:", "denied:", "error:", "DRY-RUN"))}
            untried = [p for p in repairable if p not in tried]
            if untried and os.environ.get("REPAIR_FIRST", "1") == "1":
                return (f"denied: {args['name']}'s own layer changed these image files: {', '.join(untried[:4])}. Fix them in place "
                        f"first, that keeps the container: read the file (docker_exec cat {untried[0]}), correct the wrong line and "
                        f"write_container_file {{\"name\": \"{args['name']}\", \"path\": \"{untried[0]}\", \"content\": \"<the whole corrected file>\"}}; "
                        f"a destroyed or deleted file goes back from the image with repair_image_file. Replace the container only if the "
                        "service is still failing after that.")
            refusal = reviewed(name, {"name": args["name"], "replace": True})
            if refusal:
                return refusal
        if args.get("replace"):
            sh(f"docker rm -f {args['name']}")       # stateless by definition (SPECS); the site config is a host file
        out = [faults.ensure(t) for t in targets]
        settle()
        return with_health("\n".join(out) + "\n" + docker_ps())
    if name == "write_container_file":
        denied = guard(args["name"])
        if denied:
            return denied
        path, content = str(args.get("path") or ""), args.get("content")
        if not repairable_path(args["name"], path):
            return (f"denied: {path!r} is not a file this tool writes on {args['name']}. Allowed: files under /etc/nginx/ (not the "
                    "front end's mounted conf.d: write_config) and /usr/share/nginx/html/.")
        if not isinstance(content, str) or not content.strip():
            return "error: write_container_file needs args.content (the complete corrected file)"
        if dry_run:
            return f"DRY-RUN: would write {path} in {args['name']} and reload nginx"
        return with_health(write_container_file(args["name"], path, content))
    if name == "repair_image_file":
        import faults
        denied = guard(args["name"])
        if denied:
            return denied
        path = str(args.get("path") or "")
        if not repairable_path(args["name"], path):
            return (f"denied: {path!r} is not a file this tool restores on {args['name']}. Allowed: files of the image under "
                    "/etc/nginx/ (not the front end's mounted conf.d: that is write_config / restore_config) and /usr/share/nginx/html/.")
        if dry_run:
            return f"DRY-RUN: would restore {path} in {args['name']} from the image and reload nginx"
        return with_health(repair_image_file(args["name"], path))
    if name == "network_repair":
        import faults
        if dry_run:
            return "DRY-RUN: would attach both containers to the stack network"
        sh(f"docker network create {faults.NET} 2>/dev/null")
        out = []
        for c in sorted(NAMES):
            joined = faults.NET in sh(f"docker inspect {c} --format '{{{{json .NetworkSettings.Networks}}}}'")
            out.append(f"{c}: already on {faults.NET}" if joined
                       else f"{c}: " + (sh(f"docker network connect {faults.NET} {c}") or f"attached to {faults.NET}"))
        time.sleep(1)
        return with_health("\n".join(out))
    if name == "cleanup_disk":
        victims, skipped = cleanup_candidates()
        freed = sum(n for _, n in victims)
        if dry_run:
            return f"DRY-RUN: would delete {len(victims)} project log file(s), {freed / 1e6:.1f} MB"
        refusal = reviewed(name, {"files": len(victims), "mb": round(freed / 1e6, 1)})
        if refusal:
            return refusal
        for f, _ in victims:
            try:
                os.remove(f)
            except OSError as e:
                return f"stopped after an error on {f}: {e}"
        usage = shutil.disk_usage("/")
        return (f"deleted {len(victims)} project log file(s), freed {freed / 1e6:.1f} MB "
                f"(skipped {skipped} still held open by a running service); "
                f"/ is now {100 * usage.used / usage.total:.0f}% full with {usage.free / 1e9:.0f} GB free. "
                "Images and volumes were not touched: report disk pressure instead of deleting shared data.")
    if name == "clear_scratch_volume":
        import faults
        if dry_run:
            return "DRY-RUN: would delete every file in the scratch volume edge-cache"
        refusal = reviewed(name, {})
        if refusal:
            return refusal
        out = sh(f"docker exec {faults.CACHE} sh -c 'n=$(find /cache -mindepth 1 | wc -l); "
                 f"find /cache -mindepth 1 -delete; echo deleted $n entries; df -i /cache | tail -1'")
        return with_health(out.strip() + "\nThe front end creates its temp directories when it starts; start it if it is down.")
    if name == "kill_process":
        pid = int(args["pid"])
        if pid in (os.getpid(), os.getppid(), 1):
            return "denied: that pid is this agent or init. Next: top_processes, and pick the runaway pid it lists."
        info = sh(f"ps -o uid=,args= -p {pid}").strip()
        if not info or "exit " in info:
            return f"no such process: {pid}"
        uid, cmd = info.split(None, 1)
        if int(uid) != os.getuid():
            return f"denied: pid {pid} belongs to uid {uid}, not this agent. Next: report it in your final report; it is not yours to kill."
        if PROTECTED_CMD.search(cmd):
            return f"denied: pid {pid} is part of the platform ({cmd[:120]}). Next: report it; the platform is not killed from here."
        if dry_run:
            return f"DRY-RUN: would signal {pid} ({cmd[:80]})"
        refusal = reviewed(name, {"pid": pid, "cmd": cmd[:80], "force": bool(args.get("force"))})
        if refusal:
            return refusal
        sig = "-9" if args.get("force") else "-15"
        sh(f"kill {sig} {pid}")
        for _ in range(6):                       # SIGTERM is a request; give the process a moment to honour it
            time.sleep(0.5)
            if not sh(f"ps -p {pid} -o pid=").strip():
                return f"signalled {pid} with {sig} ({cmd[:80]}); gone"
        return (f"signalled {pid} with {sig} ({cmd[:80]}); still running after 3s"
                + ("" if args.get("force") else " — call again with force=true to send SIGKILL"))
    return f"unknown tool {name}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", default="")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--max-steps", type=int, default=8)
    a = ap.parse_args()
    client = OpenAI(base_url=f"{BASE}/v1", api_key="none", timeout=300)
    log_dir = ROOT / "logs" / "agent"
    log_dir.mkdir(parents=True, exist_ok=True)
    log = (log_dir / f"{time.strftime('%Y%m%d-%H%M%S')}-{a.case or 'adhoc'}.jsonl").open("w")
    trace = lambda **kw: (log.write(json.dumps(kw, ensure_ascii=False) + "\n"), log.flush())

    observation = json.dumps({"health": {k: http_status(u) for k, u in HEALTH.items()},
                              "containers": sh("docker ps -a --filter name=edge-victim --format '{{.Names}}\t{{.Status}}'")})
    messages = [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": f"Alert: health check degraded. Initial observation: {observation}\nDiagnose and repair."}]
    trace(step=0, observation=observation)
    tools = [{"type": "function", "function": t} for t in TOOLS]
    verdict = None
    for step in range(1, a.max_steps + 1):
        t0 = time.time()
        r = client.chat.completions.create(model=MODEL, messages=messages, tools=tools, tool_choice="auto",
                                           temperature=0, max_tokens=1500,
                                           extra_body={"chat_template_kwargs": {"enable_thinking": THINK}})
        m = r.choices[0].message
        extra = m.model_extra or {}
        reasoning = (getattr(m, "reasoning_content", None) or extra.get("reasoning_content")
                     or getattr(m, "reasoning", None) or extra.get("reasoning"))
        calls = m.tool_calls or []
        messages.append({"role": "assistant", "content": m.content or "", "tool_calls": [c.model_dump() for c in calls]} if calls
                        else {"role": "assistant", "content": m.content or ""})
        if not calls:
            trace(step=step, latency=round(time.time() - t0, 1), reasoning=(reasoning or "")[:2000], text=m.content)
            messages.append({"role": "user", "content": "Use a tool, or call finish."})
            continue
        for c in calls:
            try:
                args = json.loads(c.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            if c.function.name == "finish":
                verdict = args
                trace(step=step, latency=round(time.time() - t0, 1), reasoning=(reasoning or "")[:2000], finish=args)
                break
            result = run_tool(c.function.name, args, a.dry_run)
            trace(step=step, latency=round(time.time() - t0, 1), reasoning=(reasoning or "")[:2000],
                  tool=c.function.name, args=args, result=result[:2000])
            print(f"[{step}] {c.function.name}({json.dumps(args)[:120]}) -> {result[:160]!r}")
            messages.append({"role": "tool", "tool_call_id": c.id, "content": result})
        if verdict:
            break
    final = {k: http_status(u) for k, u in HEALTH.items()}
    trace(step="final", health=final, verdict=verdict)
    print("verdict:", json.dumps(verdict, ensure_ascii=False))
    print("final health:", final)
    return 0 if all(v == 200 for v in final.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
