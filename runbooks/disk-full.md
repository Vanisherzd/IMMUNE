# Disk full (No space left on device)
Symptoms: writes fail, containers exit, logs contain `No space left on device`, `ops__disk_usage` shows a filesystem
near 100 %. On this host the docker image and container layers are the usual cause, and the kubelet is not there to
garbage-collect them any more.
Steps: 1) `ops__disk_usage` for the filesystem percentage and the docker image/container/build-cache breakdown.
2) `ops__docker_exec {"name": "edge-victim", "cmd": "du -sh /var/cache/nginx /tmp"}` for space used inside the
container.
3) Remove temporary files only, never configuration, data, or images someone else may be using. Deleting a docker
image on this host is not this agent's decision: report it instead.
4) Restart whatever exited because of the full disk, then verify the health URLs.
