# nginx cannot resolve the upstream name
Symptoms: `edge-victim` exits or returns 502, and its logs contain `host not found in upstream "<name>"` or
`could not be resolved`. The two containers share the docker network `edge-net` and reach each other by container
name, so a typo in the config or a renamed container breaks resolution.
Decide first: if the name in the config is the real container name and `edge-victim-app` is Up, this is not a
config problem — the upstream has left the stack network and the name cannot resolve because of that. Run
`ops__network_repair`, then restart the front end (runbook: upstream-detached). Never restart the front end
while the upstream is off the network: nginx refuses to start when an upstream name does not resolve.
Steps: 1) `ops__docker_logs {"name": "edge-victim", "tail": 30}` and note the exact name nginx could not resolve.
2) `ops__docker_ps` for the real container names (`edge-victim`, `edge-victim-app`).
3) `ops__read_config` and compare the `proxy_pass` host against the real name.
4) `ops__write_config` with the corrected name, keeping the rest of the file, then
`ops__docker_restart {"name": "edge-victim"}`.
5) Verify both health URLs return 200.
