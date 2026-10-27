# Backend 403 Forbidden / missing index / 404 content
Symptoms: / is 200, /api/ is 403 or 404. First determine backend content vs frontend route.
1) check_health; docker_logs {"name":"edge-victim-app","tail":60}.
2) docker_exec {"name":"edge-victim-app","cmd":"curl -sS -m 3 -I http://127.0.0.1/"}; this tests backend /, not /api/ (frontend strips /api/).
3) docker_exec {"name":"edge-victim-app","cmd":"ls -l /usr/share/nginx/html/index.html"}. Directory index forbidden + missing index differs from Permission denied + mode 000.
4) Confirm backend root/index with its own default.conf. read_config is frontend-only; do not invent /api/ content or rewrite a healthy frontend.
5) For confirmed damaged image-owned content: docker_restart {"name":"edge-victim-app"} once, then check_health. If same failure persists, reviewer may permit recreate_stack {"name":"edge-victim-app","replace":true} for this stateless baseline.
6) Both URLs must be 200 and stable. A missing route in the frontend instead requires its approved config recovery. Preserve state first; production persistent content requires operator restoration, not blind replacement.
In-place repair first: a page or image file the container deleted, emptied or chmodded is put back from the image with `ops__repair_image_file {"name": "<container>", "path": "<file>"}` (the html pages, nginx.conf, mime.types, snippets); rebuild the container only if the service still fails after that.
