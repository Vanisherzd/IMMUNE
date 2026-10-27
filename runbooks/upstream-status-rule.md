# Backend returns 301 redirect loop or 429 Too Many Requests
An HTTP response is not a network outage. 301 Location loops, 429, or an explicit backend return rule need evidence.
docker_exec {"name":"edge-victim-app","cmd":"curl -sS -m 3 -I http://127.0.0.1/"}; do not follow redirects.
docker_exec {"name":"edge-victim-app","cmd":"cat /etc/nginx/conf.d/default.conf"}; frontend read_config cannot inspect this backend file.
An unconditional injected return 301/429 in this disposable backend survives restart. Restart backend once and check_health; if the confirmed same own-layer rule remains and /api/ is not 200, put the backend's config back from the image in place: repair_image_file {"name":"edge-victim-app","path":"/etc/nginx/conf.d/default.conf"}; only if it still fails may the reviewer allow recreate_stack {"name":"edge-victim-app","replace":true}.
Do not rebuild for legitimate redirects or traffic limits; 429 alone proves neither overload nor a broken config. Use the approved backend config; never rewrite healthy frontend routes or disable limits globally. Verify both URLs 200 without loops, then repeat.
