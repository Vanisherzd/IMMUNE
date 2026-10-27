# Container does not exist any more (removed, not stopped)
Symptoms: `ops__docker_ps` lists the other container but not this one, or marks it `MISSING (no such container)`.
Health URLs are unreachable. `ops__docker_start` and `ops__docker_restart` both fail with `No such container`: there
is nothing to start, because the container was deleted rather than stopped.
Steps: 1) `ops__docker_ps` and read which names are present. An absent name is the whole diagnosis; do not keep
re-running it or go looking at the container that is still healthy.
2) `ops__recreate_stack {"name": "<the missing container>"}` recreates it from this stack's own definition, on the
right network, with the config mounted.
3) `ops__check_health`. Both URLs should return 200.
4) If the recreated container exits again, it is no longer this case: read its logs and treat it as a config error or
a crash loop.
