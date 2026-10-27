# Frontend missing image-owned mime.types
Symptoms: nginx [emerg] open() /etc/nginx/mime.types failed; frontend exited. Missing mime.types is not a MIME response mismatch.
Read docker_logs {"name":"edge-victim","tail":50} and docker_ps. read_config/restore_config only handle the mounted conf.d site, not mime.types.
Start/restart edge-victim once, then read fresh logs and check_health. If the same image-owned file is still missing and health fails, recreate_stack {"name":"edge-victim","replace":true} may pass the existing reviewer. It restores the approved image layer; it does not fix a bad bind mount.
Never exec a stopped container or write via read-only docker_exec. Operator alternative: copy the exact same-image known-good mime.types, then start and verify nginx -t and both health URLs. Preserve needed state before replacement.
In-place repair first: a page or image file the container deleted, emptied or chmodded is put back from the image with `ops__repair_image_file {"name": "<container>", "path": "<file>"}` (the html pages, nginx.conf, mime.types, snippets); rebuild the container only if the service still fails after that.
