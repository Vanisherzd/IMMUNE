"""Tier controller: which model serves the agent's next turn, and the power mode that goes with it. The signals are
objective, not the model's self-rated confidence: escalate to Tier-2 when an action left the stack still failing,
when an irreversible action is about to be reviewed, or when the guards refused twice in one incident; drop back to
Tier-1 when health is green again.

  TIER_MODE=off       (default) nothing changes: set_tier() is a no-op and upstream() returns UPSTREAM
  TIER_MODE=adaptive  the stage: Tier-1 by default, Tier-2 on the signals above
  TIER_MODE=always2   the A/B baseline: Tier-2 throughout
  env: UPSTREAM_T1 (Tier-1 server, e.g. http://127.0.0.1:8010), UPSTREAM_T2 (default UPSTREAM or :8000),
       TIER_NVPMODEL=1 with NVP_T1 / NVP_T2 (nvpmodel mode ids from `nvpmodel -q --verbose` on the device)

  .venv/bin/python scripts/tier.py status
  .venv/bin/python scripts/tier.py set 2 "manual test"

State: logs/tier-state.json {"tier", "mode", "reason", "ts", "nvpmodel"}; each change appended to logs/tier.jsonl.
The shim reads the state on every request (see README.md for the two-line hook); the reviewer stays
on Tier-2 because review is the hard judgement.
"""
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
STATE = ROOT / "logs" / "tier-state.json"
LOG = ROOT / "logs" / "tier.jsonl"


def mode():
    m = os.environ.get("TIER_MODE", "off")
    return m if m in ("off", "adaptive", "always2") else "off"


def current():
    try:
        return json.loads(STATE.read_text())
    except (OSError, ValueError):
        return {"tier": 2 if mode() == "always2" else 1, "mode": mode(), "reason": "default", "ts": 0}


def nvpmodel(tier):
    if os.environ.get("TIER_NVPMODEL") != "1" or not shutil.which("nvpmodel"):
        return None
    m = os.environ.get("NVP_T2" if tier == 2 else "NVP_T1")
    if m is None:
        return None
    r = subprocess.run(["sudo", "-n", "nvpmodel", "-m", str(m)], capture_output=True, text=True, timeout=30)
    return dict(mode=m, rc=r.returncode, out=(r.stdout + r.stderr).strip()[-200:])


def set_tier(tier, reason):
    """Move to `tier` (1 or 2) unless already there; returns the state. No-op when TIER_MODE is off; pinned to 2
    when it is always2."""
    m = mode()
    if m == "off":
        return current()
    if m == "always2":
        tier = 2
    cur = current()
    if cur.get("tier") == tier and cur.get("mode") == m:
        return cur
    t0 = time.time()
    nv = nvpmodel(tier)
    st = dict(tier=tier, mode=m, reason=reason, ts=round(time.time(), 3), nvpmodel=nv,
              switch_ms=round((time.time() - t0) * 1000))
    STATE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE.with_suffix(".tmp")
    tmp.write_text(json.dumps(st))
    tmp.replace(STATE)
    with LOG.open("a") as f:
        f.write(json.dumps(dict(st, frm=cur.get("tier"))) + "\n")
    return st


def upstream(default):
    """The server for the next agent turn: the shim calls this per request."""
    m = mode()
    if m == "off":
        return default
    t2 = os.environ.get("UPSTREAM_T2", default)
    if m == "always2":
        return t2
    t1 = os.environ.get("UPSTREAM_T1")
    return t1 if (current().get("tier") == 1 and t1) else t2


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "status":
        print(json.dumps(dict(current(), env_mode=mode())))
    elif len(sys.argv) > 2 and sys.argv[1] == "set":
        print(json.dumps(set_tier(int(sys.argv[2]), " ".join(sys.argv[3:]) or "cli")))
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
