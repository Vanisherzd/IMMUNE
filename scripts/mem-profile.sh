#!/usr/bin/env bash
set -u
cd "$(dirname "$0")/.." || exit 1

LOG=logs/mem-profile.jsonl
PID_FILE=logs/mem-profile.pid
SERVICES="oai-shim guard-api ops-api power watchdog dashboard"

to_gib() {
  awk -v value="$1" 'BEGIN {
    number = value; gsub(/[[:alpha:]]/, "", number)
    unit = value; gsub(/[0-9.]/, "", unit)
    scale["B"] = 1073741824; scale["kB"] = 1048576; scale["KiB"] = 1048576
    scale["MB"] = 1073.741824; scale["MiB"] = 1024
    scale["GB"] = 1.073741824; scale["GiB"] = 1
    scale["TB"] = 0.001073741824; scale["TiB"] = 0.0009765625
    if (unit in scale) printf "%.6f", number / scale[unit]
  }'
}

sample() {
  local memory containers services name usage gib pid pidfile rss
  while :; do
    memory=$(awk '
      /^(MemTotal|MemAvailable|MemFree|Cached|Shmem):/ { value[$1] = $2 / 1048576 }
      END {
        printf "\"MemTotal\":%.6f,\"MemAvailable\":%.6f,\"MemFree\":%.6f,", \
               value["MemTotal:"], value["MemAvailable:"], value["MemFree:"]
        printf "\"Cached\":%.6f,\"Shmem\":%.6f", value["Cached:"], value["Shmem:"]
      }' /proc/meminfo) || { sleep 1; continue; }

    containers=""
    if command -v docker >/dev/null 2>&1; then
      while read -r name usage _; do
        case "$name" in
          vllm-*|openshell-*)
            gib=$(to_gib "$usage")
            [ -n "$gib" ] || continue
            [ -z "$containers" ] || containers+=,
            containers+="\"$name\":$gib"
            ;;
        esac
      done < <(docker stats --no-stream --format '{{.Name}} {{.MemUsage}}' 2>/dev/null || true)
    fi

    services=""
    for name in $SERVICES; do
      pidfile="logs/$name.pid"
      [ -f "$pidfile" ] || continue
      pid=$(cat "$pidfile" 2>/dev/null) || continue
      case "$pid" in *[!0-9]*|'') continue ;; esac
      rss=$(awk '/^VmRSS:/ { printf "%.6f", $2 / 1048576 }' "/proc/$pid/status" 2>/dev/null)
      [ -n "$rss" ] || continue
      [ -z "$services" ] || services+=,
      services+="\"$name\":$rss"
    done

    printf '{"ts":%s,%s,"containers":{%s},"services":{%s}}\n' \
      "$(date +%s)" "$memory" "$containers" "$services" >> "$LOG"
    sleep 1
  done
}

start() {
  local pid
  mkdir -p logs
  if [ -f "$PID_FILE" ]; then
    pid=$(cat "$PID_FILE" 2>/dev/null || true)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      echo "memory profiler already running (pid $pid)"
      return
    fi
    rm -f "$PID_FILE"
  fi
  setsid nohup "$0" _sample >> logs/mem-profile.out 2>&1 < /dev/null &
  echo "$!" > "$PID_FILE"
  echo "started memory profiler (pid $!, $LOG)"
}

stop() {
  local pid
  if [ -f "$PID_FILE" ]; then
    pid=$(cat "$PID_FILE" 2>/dev/null || true)
    [ -z "$pid" ] || kill "$pid" 2>/dev/null || true
    rm -f "$PID_FILE"
    echo "stopped memory profiler"
  else
    echo "memory profiler is not running"
  fi
}

case "${1:-}" in
  start) start ;;
  stop) stop ;;
  report)
    shift
    path=$LOG
    if [ "$#" -gt 0 ] && [ "${1#-}" = "$1" ]; then path=$1; shift; fi
    exec python3 scripts/mem-profile.py "$path" "$@"
    ;;
  _sample) trap 'rm -f "$PID_FILE"' EXIT; trap 'exit 0' INT TERM; sample ;;
  *) echo "usage: $0 {start|stop|report [jsonl] [--since epoch] [--until epoch]}" >&2; exit 2 ;;
esac
