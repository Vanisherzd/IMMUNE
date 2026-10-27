---
name: ops
description: Diagnose and repair the local web stack (edge-victim nginx front end + edge-victim-app upstream) with the ops tools. Use for any alert about the web stack, a 502/504, an unreachable health URL, a container that is down or restarting, disk or memory pressure on the host.
---
# ops — diagnose and repair the web stack

You are the only responder. There is no internet and no human to ask, so decide and act with the tools below.

## The stack
- `edge-victim` — nginx front end. `http://127.0.0.1:8880/` must return 200 and `http://127.0.0.1:8880/api/` must
  return 200 (it proxies to the upstream).
- `edge-victim-app` — the upstream behind `/api/`.
- The nginx config is a host file. Read it with `ops__read_config`, replace the whole file with `ops__write_config`,
  then `ops__docker_restart` the front end. A write alone changes nothing.

## Tools
Look first, and never guess a state you can read:

| Tool | Arguments | Use it for |
| --- | --- | --- |
| `ops__check_health` | – | the two health URLs; this is the definition of healthy |
| `ops__docker_ps` | – | container state and exit code, any memory limit, and whether the kernel OOM-killed it |
| `ops__docker_logs` | `name`, `tail` | why a container exited |
| `ops__docker_exec` | `name`, `cmd` | one diagnostic inside a container (`nginx -t/-T`, `cat`, `ls`, `df`, `du`, `ps`, `grep`, `head`, `tail` without follow). No shell. `curl` is GET/HEAD only to localhost, stack containers, or private IP literals; no uploads, file output, custom config, or redirects. `env` takes no arguments. |
| `ops__read_config` | – | the current nginx config |
| `ops__search_runbooks` | `query` | the written procedure for a symptom; an unmatched query returns the catalogue |
| `ops__search_incident_knowledge` | `query`, `scenario` | historical incidents and Linux/Kubernetes remediation cards for a symptom no runbook covers (disk, inode, systemd, OOM, DNS, TLS, ports, CrashLoopBackOff); hypotheses to verify here, never a licence to act |
| `ops__disk_usage` | – | host filesystems and docker disk usage |
| `ops__service_status` | `unit` | whether a host systemd unit is active |
| `ops__journal_tail` | `unit`, `lines` | host journal, including OOM kills |
| `ops__port_check` | `port`, `host` | whether something is listening |
| `ops__http_check` | `url` | status code and body of a local or private-network URL |
| `ops__top_processes` | – | what is eating CPU and memory |

Actions, least invasive first:

| Tool | Arguments | Use it for |
| --- | --- | --- |
| `ops__docker_start` | `name` | a container that is Exited |
| `ops__docker_restart` | `name` | after a config change, or a container that is up but wedged |
| `ops__write_config` | `content` | the complete corrected nginx config, then restart the front end |
| `ops__restore_config` | `source` | put back the last known-good nginx config (`read_config` says when one differs), then restart the front end |
| `ops__self_heal` | – | runs this whole loop on the host in one call; use it only if you are stuck |

## Procedure
1. `ops__check_health` — know the actual symptom before theorising.
2. `ops__docker_ps` — which container, and how did it exit.
3. `ops__docker_logs` on that container — read the real error, not the first plausible one.
4. `ops__search_runbooks` with words from that error (`ops__docker_logs` attaches the nearest runbook by itself). The
   runbook is this stack's procedure. When the knowledge pack recognises the symptom, a **knowledge card** is attached
   too: a hypothesis from other systems' incidents. If the runbook's steps do not fit what you see, test the card's
   CHECK lines with your read-only tools before acting. `ops__search_incident_knowledge` asks the pack directly;
   `insufficient` means gather more evidence or escalate, not repair from a weak candidate.
5. Apply the smallest action that addresses the cause. A container that exited on a config error will exit again if
   you only restart it.
6. `ops__check_health` again. Both URLs must be 200. If they are not, go back to step 3 with what you learned.

## Boundaries and when to stop
- Touch only those two containers and that one config file. Everything else on this host belongs to someone else.
- Never delete an image, a volume, or another container.
- If the same action fails twice, stop repeating it and look for a different cause.
- Once the evidence names the fault, act on it. Re-reading the same config or re-arguing a conclusion you already
  reached spends the turn without changing anything; the tools, not more thought, are what tell you if you are right.
- If you cannot reach 200/200, stop and report: the symptom, what you ruled out, the exit code and the last log lines.
  An honest escalation is a valid outcome; a silent loop is not.

Finish every incident with three lines: root cause, actions taken, final health.

## If the tools are missing
Your shell has no docker and no systemctl. If the `ops__*` tools are not offered in a turn, the same tools are
reachable as a shell fallback: `/sandbox/bin/ops tools` and `/sandbox/bin/ops call <tool> '<json>'`.
