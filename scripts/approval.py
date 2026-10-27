"""Human approval gate: the third key, after the code key and the change reviewer approve an irreversible action.
Order: program precondition -> reviewer APPROVE -> human. The human answers on the dashboard (scripts/dashboard.py).

  APPROVAL=off      (default) every call passes: wiring this in changes nothing until it is switched on
  APPROVAL=manual   the stage: wait for the dashboard's decision, up to APPROVAL_TIMEOUT seconds (180); no answer = reject
  APPROVAL=auto     overnight runs: approve at once, recorded as "benchmark auto-approval"

  .venv/bin/python scripts/approval.py request recreate_stack '{"name": "edge-victim-app", "replace": true}'   # try it
  .venv/bin/python scripts/approval.py decide <id> approve|reject                                             # no dashboard

Files (the dashboard reads and writes the same ones): logs/approvals/pending.json {"id", "action", "args", "reason",
"ts", "channel"}; logs/approvals/<id>.decision.json {"id", "decision", "ts", "by"}; every outcome appended to
logs/approvals.jsonl. Fail closed: a timeout or an unreadable decision is a rejection, and the text returned to the
agent tells it to escalate, not to ask again.
"""
import json
import os
import pathlib
import sys
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parent.parent
DIR = ROOT / "logs" / "approvals"
LOG = ROOT / "logs" / "approvals.jsonl"


def mode():
    m = os.environ.get("APPROVAL", "off")
    return m if m in ("off", "manual", "auto") else "off"


def channel():
    """Where the request is shown. Only the dashboard exists; do not stage a switch to a channel that is not there."""
    return os.environ.get("APPROVAL_CHANNEL", "local dashboard")


def record(**row):
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a") as f:
        f.write(json.dumps(dict(ts=round(time.time(), 3), **row), ensure_ascii=False) + "\n")


def request(action, args, reason=""):
    """(approved, text). text is empty when approved, else what the agent should read as the tool result."""
    m = mode()
    if m == "off":
        return True, ""
    rid = uuid.uuid4().hex[:8]
    if m == "auto":
        record(id=rid, action=action, args=args, decision="approve", by="benchmark auto-approval", mode=m)
        return True, ""
    DIR.mkdir(parents=True, exist_ok=True)
    pending = dict(id=rid, action=action, args=args, reason=reason, ts=time.time(), channel=channel())
    tmp = DIR / f".pending-{rid}"
    tmp.write_text(json.dumps(pending, ensure_ascii=False))
    tmp.replace(DIR / "pending.json")                  # atomic: the dashboard never reads half a request
    record(id=rid, action=action, args=args, event="requested", channel=pending["channel"], mode=m)
    timeout = float(os.environ.get("APPROVAL_TIMEOUT", "180"))
    decision_file = DIR / f"{rid}.decision.json"
    t0 = time.time()
    decision, by = "reject", "timeout"
    while time.time() - t0 < timeout:
        if decision_file.exists():
            try:
                d = json.loads(decision_file.read_text())
                decision, by = (d.get("decision") if d.get("decision") in ("approve", "reject") else "reject"), d.get("by", "?")
            except ValueError:
                decision, by = "reject", "unreadable decision"
            break
        time.sleep(1)
    try:
        cur = json.loads((DIR / "pending.json").read_text())
        if cur.get("id") == rid:
            (DIR / "pending.json").unlink()
    except (OSError, ValueError):
        pass
    waited = round(time.time() - t0, 1)
    record(id=rid, action=action, args=args, decision=decision, by=by, waited_s=waited, mode=m)
    if decision == "approve":
        return True, ""
    why = f"no human answered within {int(timeout)} s" if by == "timeout" else "the on-call human rejected it"
    return False, (f"approval-rejected: {action} {json.dumps(args)} was not approved ({why}). Do not retry it or ask "
                   "again; stop and escalate in your final report with the evidence you have.")


def main():
    if len(sys.argv) >= 3 and sys.argv[1] == "request":
        ok, text = request(sys.argv[2], json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}, "manual test")
        print("APPROVED" if ok else text)
    elif len(sys.argv) == 4 and sys.argv[1] == "decide":
        DIR.mkdir(parents=True, exist_ok=True)
        (DIR / f"{sys.argv[2]}.decision.json").write_text(json.dumps(dict(id=sys.argv[2], decision=sys.argv[3], ts=time.time(), by="cli")))
        print("written")
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
