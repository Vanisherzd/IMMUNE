"""Power logger and energy integrator. Embedded GPU boards: tegrastats rails; elsewhere: nvidia-smi GPU power. The
number is the module's rails (or the GPU alone), not the wall: say so on every slide that shows it.

  .venv/bin/python scripts/power.py log                  # append {"ts", "mw", "src", "rails"} to logs/power.jsonl
  .venv/bin/python scripts/power.py energy <t0> <t1>     # Wh between two epoch times
  .venv/bin/python scripts/power.py incidents            # Wh, average and peak W per closed incident (logs/incidents.jsonl)
  env: POWER_INTERVAL_MS (500), POWER_LOG (logs/power.jsonl), POWER_SRC (auto|tegrastats|nvidia-smi),
       POWER_TOTAL_RAIL (the rail that is the module input; default VDD_IN, then VIN, then VIN_*, else the sum)

tegrastats prints rails as `NAME 1234mW/1200mW` (current/average); rail names differ between boards, so the
pattern takes any name and the total rail can be named at the stage.
"""
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
LOG = pathlib.Path(os.environ.get("POWER_LOG", ROOT / "logs" / "power.jsonl"))
INTERVAL = int(os.environ.get("POWER_INTERVAL_MS", "500"))
RAIL_RE = re.compile(r"([A-Za-z0-9_]+) (\d+)mW/(\d+)mW")


def total(rails):
    want = os.environ.get("POWER_TOTAL_RAIL")
    if want and want in rails:
        return rails[want]
    # The module input: VDD_IN on some boards, VIN on others (2026-10-21: the prototype device's rails are VDD_GPU, VDD_CPU_SOC_MSS,
    # VIN_SYS_5V0 and VIN; VIN_SYS_5V0 is one 5 V branch, not the total, so exact names win over the VIN_ prefix).
    for exact in ("VDD_IN", "VIN"):
        if exact in rails:
            return rails[exact]
    for name in rails:
        if name.startswith("VIN"):
            return rails[name]
    return sum(rails.values())


def write(f, row):
    f.write(json.dumps(row) + "\n")
    f.flush()


def log_tegrastats(f):
    p = subprocess.Popen(["tegrastats", "--interval", str(INTERVAL)], stdout=subprocess.PIPE, text=True)
    for line in p.stdout:
        rails = {n: int(cur) for n, cur, _avg in RAIL_RE.findall(line)}
        if rails:
            write(f, dict(ts=round(time.time(), 3), mw=total(rails), src="tegrastats", rails=rails))


def log_nvidia_smi(f):
    while True:
        r = subprocess.run(["nvidia-smi", "--query-gpu=power.draw", "--format=csv,noheader,nounits"],
                           capture_output=True, text=True)
        vals = []
        for v in r.stdout.split():
            try:
                vals.append(float(v))
            except ValueError:
                pass
        if vals:
            write(f, dict(ts=round(time.time(), 3), mw=round(sum(vals) * 1000), src="nvidia-smi",
                          rails={f"GPU{i}": round(v * 1000) for i, v in enumerate(vals)}))
        time.sleep(INTERVAL / 1000)


def rows(path=LOG):
    try:
        with open(path) as f:
            for line in f:
                try:
                    d = json.loads(line)
                    yield float(d["ts"]), float(d["mw"])
                except (ValueError, KeyError, TypeError):
                    pass
    except OSError:
        return


def energy(t0, t1, path=LOG):
    """Trapezoid over the samples inside [t0, t1]: (Wh, average W, peak W, samples)."""
    pts = [(t, mw) for t, mw in rows(path) if t0 <= t <= t1]
    if len(pts) < 2:
        return None
    wh = sum((b[0] - a[0]) * (a[1] + b[1]) / 2 for a, b in zip(pts, pts[1:])) / 1000 / 3600
    return dict(wh=round(wh, 5), avg_w=round(wh * 3600 / (pts[-1][0] - pts[0][0]), 2),
                peak_w=round(max(mw for _, mw in pts) / 1000, 2), samples=len(pts))


def incidents():
    opened = {}
    for line in open(ROOT / "logs" / "incidents.jsonl"):
        e = json.loads(line)
        if e.get("event") == "open":
            opened[e["id"]] = e["ts"]
        elif e.get("event") == "close" and e.get("id") in opened:
            print(json.dumps(dict(id=e["id"], outcome=e.get("outcome"), seconds=round(e["ts"] - opened[e["id"]], 1),
                                  **(energy(opened[e["id"]], e["ts"]) or {"wh": None}))))


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "help"
    if cmd == "log":
        src = os.environ.get("POWER_SRC", "auto")
        if src == "auto":
            src = "tegrastats" if shutil.which("tegrastats") else "nvidia-smi"
        LOG.parent.mkdir(parents=True, exist_ok=True)
        with LOG.open("a") as f:
            try:
                (log_tegrastats if src == "tegrastats" else log_nvidia_smi)(f)
            except KeyboardInterrupt:
                pass
    elif cmd == "energy":
        print(json.dumps(energy(float(sys.argv[2]), float(sys.argv[3]))))
    elif cmd == "incidents":
        incidents()
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
