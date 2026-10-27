# 502 Bad Gateway on /api/
Symptoms: the front-end answers 200 on `/` but `/api/` returns 502. nginx logs show `connect() failed (111: Connection
refused) while connecting to upstream` or `no live upstreams` or `could not be resolved`.
Steps: 1) Confirm with `check_health`. 2) `docker ps -a`: the
upstream container `edge-victim-app` is Exited or missing. 3) `docker start edge-victim-app`. 4) Re-check `/api/`.
Do not restart the front-end for an upstream failure; fix the upstream.
