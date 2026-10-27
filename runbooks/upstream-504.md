# 504 upstream timeout: paused, stopped workers, PID limit, network
For /200 and /api/504, collect check_health, docker_ps and backend docker_logs before changing frontend.
Exited backend: start it once and read the new startup error (syntax, OOM or Cannot fork). Paused: the native docker_restart tool unpauses before restart.
Up backend: docker_exec {"name":"edge-victim-app","cmd":"curl -sS -m 3 -I http://127.0.0.1/"}. If direct backend is 200, check its network attachment and frontend target; network_repair only fixes measured disconnection.
If direct backend hangs, read /proc/1/task/1/children, then a listed child's /proc/<pid>/status. State T for nginx workers supports SIGSTOP; one backend restart restores its process tree.
Cannot fork: read cgroup pids.max/current/events when possible. Exec failure alone is not proof. Restart once; confirmed PID-limit corruption that persists may require reviewer-approved backend replacement from its stateless definition.
If workers run normally, inspect logs/resource pressure and escalate rather than inventing a network cause. Do not keep restarting or rewrite a healthy frontend. Verify both URLs 200 after every repair.
