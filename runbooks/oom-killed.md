# Container killed (exit 137, out of memory)
Symptoms: `ops__docker_ps` shows `Exited (137)`; `ops__journal_tail {"unit": "docker", "lines": 60}` or the kernel
journal mentions `Out of memory: Killed process` / `oom-kill`. This host has unified CPU+GPU memory and no swap, so a
large model load or a compile job can push everything else out.
First tell the two kinds apart in `ops__docker_ps`: a container that shows `memory limit N MiB | OOMKilled: yes` hit
its own limit, not the host's memory. That limit is too low for the service; restarting cannot raise it. Steps for that
case: 1) `ops__docker_restart` it once to confirm it dies again. 2) `ops__recreate_stack {"name": "<container>",
"replace": true}`: the stack's definition sets no memory limit. 3) `ops__check_health`.
Host memory pressure (no limit shown):
Steps: 1) `ops__disk_usage` and `ops__top_processes` to see what is holding memory right now.
2) If a heavy process (model server, compiler, backup) is running, the container died as collateral: start it again
with `ops__docker_start` and verify.
3) If it is killed again within a minute, the host is genuinely short of memory. Do not keep restarting it.
4) Report which process holds the memory; freeing it is a host-level decision outside this agent's scope.
