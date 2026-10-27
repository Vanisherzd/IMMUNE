"""VM victim (scripts/vm-victim.sh boots it): ssh plumbing, health, and faults for a real Ubuntu guest running nginx.

VM_VICTIM=1 in scripts/agent.py points the health URLs at this host and swaps the container tools for the vm_* tools;
the agent reaches the guest only over ssh as user "ops" (sudo inside the guest, nothing on the IMMUNE host itself).

  .venv/bin/python scripts/vm_victim.py setup             api page + known-good copy of the site config (once per guest)
  .venv/bin/python scripts/vm_victim.py verify            exit 0 when / and /api/ answer 200 with the expected bodies
  .venv/bin/python scripts/vm_victim.py inject <case>     vm-nginx-stopped | vm-bad-config | vm-unit-masked | vm-config-deleted
  .venv/bin/python scripts/vm_victim.py reset             undo every injection
"""
import os
import shlex
import subprocess
import sys
import urllib.error
import urllib.request

HOST = os.environ.get("VM_HOST", "127.0.0.1")
SSH_PORT = os.environ.get("VM_SSH_PORT", "2222")
HTTP_PORT = os.environ.get("VM_HTTP_PORT", "8881")
KEY = os.path.expanduser(os.environ.get("VM_KEY", "~/.ssh/id_ed25519"))
KNOWN_HOSTS = os.path.expanduser(os.environ.get("VM_KNOWN_HOSTS", "~/vm-victim/known_hosts"))
USER = "ops"
BASE = f"http://{HOST}:{HTTP_PORT}"
HEALTH = {"front": f"{BASE}/", "api": f"{BASE}/api/"}
EXPECT_BODY = {"/": "victim-vm ok", "/api/": "Welcome to nginx"}
UNITS = ("nginx",)
SITE = "/etc/nginx/sites-available/default"
KNOWN_GOOD = "/etc/nginx/sites-available/default.known-good"
CASES = {
    "vm-nginx-stopped":  dict(cause=r"stopped|inactive|not running|start", fix_tools={"vm_service"}),
    "vm-bad-config":     dict(cause=r"config|emerg|unknown directive|bogus|syntax|sites-available", fix_tools={"vm_restore_config", "vm_write_config"}),
    "vm-unit-masked":    dict(cause=r"mask|unit|systemd|cannot start|refused", fix_tools={"vm_service"}),
    "vm-config-deleted": dict(cause=r"deleted|missing|no such file|config|sites-available|restore", fix_tools={"vm_restore_config", "vm_write_config"}),
}


def ssh_argv():
    return ["ssh", "-p", SSH_PORT, "-i", KEY, "-o", "StrictHostKeyChecking=no", "-o", f"UserKnownHostsFile={KNOWN_HOSTS}",
            "-o", "ConnectTimeout=5", "-o", "BatchMode=yes", "-o", "LogLevel=ERROR", f"{USER}@{HOST}"]


def run(argv, timeout=20):
    """One command on the guest, argv quoted so nothing is interpreted by the guest's shell (the agent's path)."""
    try:
        r = subprocess.run(ssh_argv() + ["--"] + [shlex.quote(a) for a in argv], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return f"(timeout after {timeout}s: {' '.join(argv[:3])})"
    out = (r.stdout + r.stderr).strip()
    return (out if r.returncode == 0 else f"(exit {r.returncode}) {out}")[:4000]


def shell(cmd, timeout=30, stdin=None):
    """A shell line on the guest: the harness and the config tools only, never a string from the agent."""
    r = subprocess.run(ssh_argv() + [cmd], capture_output=True, text=True, timeout=timeout, input=stdin)
    return r.returncode, (r.stdout + r.stderr).strip()


def probe(path, timeout=5):
    try:
        with urllib.request.urlopen(f"{BASE}{path}", timeout=timeout) as r:
            body = r.read(4096).decode("utf-8", "replace")
            return r.status, (EXPECT_BODY.get(path, "") in body)
    except urllib.error.HTTPError as e:
        return e.code, False
    except Exception:
        return 0, False


def verify():
    front, api = probe("/"), probe("/api/")
    ok = front == (200, True) and api == (200, True)
    print(f"verify: / {front[0]} /api/ {api[0]} -> {'PASS' if ok else 'FAIL'}" + ("" if ok else " (status or content)"))
    return ok


def state():
    return "victim-vm nginx: " + run(["systemctl", "is-active", "nginx"])


def setup():
    rc, out = shell("sudo -n mkdir -p /var/www/html/api && echo 'Welcome to nginx (victim-vm api)' | sudo -n tee /var/www/html/api/index.html >/dev/null "
                    "&& echo 'victim-vm ok' | sudo -n tee /var/www/html/index.html >/dev/null "
                    f"&& sudo -n cp -n {SITE} {KNOWN_GOOD}; sudo -n systemctl enable --now nginx >/dev/null 2>&1; echo setup-done")
    print(out)
    return verify()


def write_config(content):
    """Install a full site file; nginx -t decides; a rejected file is put back at once."""
    rc, out = shell(f"cat > /tmp/ops-site.conf && sudo -n cp {SITE} {SITE}.previous 2>/dev/null; sudo -n cp /tmp/ops-site.conf {SITE} && "
                    f"if sudo -n nginx -t 2>&1; then (sudo -n systemctl reload nginx || sudo -n systemctl restart nginx) && echo applied; "
                    f"else sudo -n cp {SITE}.previous {SITE}; echo 'rejected by nginx -t: previous file put back'; fi", stdin=content)
    return out[-1500:]


def restore_config():
    rc, out = shell(f"sudo -n cp {KNOWN_GOOD} {SITE} && sudo -n nginx -t 2>&1 && (sudo -n systemctl reload nginx || sudo -n systemctl restart nginx) && echo 'known-good site config restored'")
    return out[-1500:]


def inject(case):
    if case == "vm-nginx-stopped":
        shell("sudo -n systemctl stop nginx")
    elif case == "vm-bad-config":
        shell(f"echo 'server {{ listen 8089; bogus_directive on; }}' | sudo -n tee -a {SITE} >/dev/null; sudo -n systemctl restart nginx")
    elif case == "vm-unit-masked":
        shell("sudo -n systemctl stop nginx; sudo -n systemctl mask nginx")
    elif case == "vm-config-deleted":
        shell(f"sudo -n rm -f {SITE}; sudo -n systemctl restart nginx")
    else:
        raise SystemExit(f"unknown case {case!r}; one of {sorted(CASES)}")
    front, api = probe("/"), probe("/api/")
    print(f"injected {case}: / {front[0]} /api/ {api[0]}")


def reset():
    shell(f"sudo -n systemctl unmask nginx >/dev/null 2>&1; [ -f {KNOWN_GOOD} ] && sudo -n cp {KNOWN_GOOD} {SITE}; "
          "sudo -n systemctl restart nginx >/dev/null 2>&1; sudo -n chmod 755 /var/www/html")
    return verify()


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "verify"
    if cmd == "setup":
        sys.exit(0 if setup() else 1)
    if cmd == "verify":
        sys.exit(0 if verify() else 1)
    if cmd == "inject":
        inject(sys.argv[2])
    elif cmd == "reset":
        sys.exit(0 if reset() else 1)
    else:
        raise SystemExit(__doc__)
