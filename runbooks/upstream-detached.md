# Upstream unreachable although both containers are Up (network detached)
Symptoms: `/` 200, `/api/` 504. `ops__docker_ps` shows both containers Up, neither log shows a crash; the front end's
log says `upstream timed out (110: Connection timed out) while connecting to upstream`. The upstream is running but
fell off the docker network: detached or disconnected from the stack network `edge-net`, so nginx's connection never
arrives. Nothing crashed, nothing is misconfigured; the two containers just cannot see each other any more.
Steps: 1) `ops__docker_logs {"name": "edge-victim"}` and look for `timed out ... while connecting to upstream`.
2) `ops__docker_logs {"name": "edge-victim-app"}`: no errors, no recent requests — it is not being reached.
3) `ops__network_repair`: makes sure the network exists and both containers are attached to it.
4) If `/api/` still fails, `ops__docker_restart {"name": "edge-victim"}` so nginx re-resolves the upstream.
5) `ops__check_health`: both URLs 200.
