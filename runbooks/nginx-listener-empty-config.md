# Frontend Up but unreachable with empty mounted site / no server block
If both health URLs fail while containers are Up, run docker_ps, read_config and frontend nginx -T before changing anything. A successful nginx -t checks syntax, not whether an HTTP listener or useful server block exists.
If the FRONTEND mounted default.conf is empty or lacks the approved server/listen block, restore_config {"source":"known-good"}, then docker_restart {"name":"edge-victim"}, then check_health.
If no trusted snapshot exists, write the full approved frontend config; do not invent routes. Recreating frontend keeps the broken bind mount and does not repair an empty site.
If the site is valid, inspect Paused state, worker_connections and frontend logs instead. Backend failures while / still returns 200 are a different branch. Verify both URLs 200 and stable. Restore previous only if it was known healthy.
