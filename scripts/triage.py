"""First look at an incident, taken by the system before the agent is woken: what an on-call human would have on
screen when the page arrives. Prints a block to put under the alert.

  .venv/bin/python scripts/triage.py        # calls the ops API (OPS_URL, default http://127.0.0.1:8790)

Every drill opened with the same two or three calls (check_health, docker_ps, docker_logs of the failing
container), each a full model turn of about ten seconds. Through the ops API, so the calls land in the incident's
trace: the reviewer sees them, and docker_logs attaches the matching runbook as it does for the agent.
"""
import json
import os
import urllib.request

OPS = os.environ.get("OPS_URL", "http://127.0.0.1:8790").rstrip("/")
CALLS = [("check_health", {}), ("docker_ps", {}),
         ("docker_logs", {"name": "edge-victim", "tail": 30}), ("docker_logs", {"name": "edge-victim-app", "tail": 30})]


def call(name, args):
    req = urllib.request.Request(f"{OPS}/call", data=json.dumps({"name": name, "args": args}).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return str(json.loads(r.read()).get("result", ""))
    except Exception as e:
        return f"(triage call failed: {type(e).__name__})"


def main():
    parts = []
    for name, args in CALLS:
        out = call(name, args)
        parts.append(f"### {name} {json.dumps(args) if args else ''}\n{out[:2500]}")
    print("Triage already taken by the monitoring system (these calls ran a moment ago; repeat one only to see a "
          "change):\n\n" + "\n\n".join(parts))


if __name__ == "__main__":
    main()
