# nginx worker processes die right after start (fatal code 2, Too many open files), container stays Up
Symptoms: `/` and `/api/` time out or are refused while `ops__docker_ps` shows `edge-victim` Up. `ops__docker_logs {"name": "edge-victim"}`
repeats `worker process N exited with fatal code 2 and cannot be respawned`; the first lines of the log (or the
"earlier distinct error lines" the tool appends) show the worker's own cause, typically
`[emerg] epoll_create() failed (24: Too many open files)` or `socket() failed (24: Too many open files)`.
Cause: a limit in the image's main config `/etc/nginx/nginx.conf` (`worker_rlimit_nofile` set far too low,
`worker_connections` too low) or a process limit on the container. The site config in conf.d is not involved:
write_config / restore_config will not help and `nginx -t` passes.
Steps: 1) `ops__docker_exec {"name": "edge-victim", "cmd": "cat /etc/nginx/nginx.conf"}` and look for `worker_rlimit_nofile` /
`worker_connections` lines that are not the image's defaults (`worker_connections 1024;`, no `worker_rlimit_nofile`).
2) Put the image's nginx.conf back in place, which keeps the container:
`ops__repair_image_file {"name": "edge-victim", "path": "/etc/nginx/nginx.conf"}`; or write the corrected file with
`ops__write_container_file`. 3) `ops__docker_restart {"name": "edge-victim"}` if workers do not come back after the reload.
4) Only if the service still fails: `ops__recreate_stack {"name": "edge-victim", "replace": true}`.
5) `ops__check_health`: both URLs 200.
