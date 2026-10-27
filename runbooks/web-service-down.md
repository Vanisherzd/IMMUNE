# Web service down (connection refused / no response)
Symptoms: health check on the front-end URL fails with connection refused or timeout; `docker ps` shows the
`edge-victim` container `Exited (0)`: it stopped cleanly, the container exited with code 0, and its log ends in
`worker process exited with code 0` notices with no error line at all. Nothing is broken inside; it was stopped.
Exit code 1 with an `[emerg]` line is the config-error case instead, and exit 137 is the OOM case.
Steps: 1) `docker ps -a` to confirm the container state. 2) `docker logs edge-victim --tail 50` for the exit reason.
3) If it exited without a config error, start it again (`docker start edge-victim`). 4) Re-check the health URL.
