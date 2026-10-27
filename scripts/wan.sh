#!/usr/bin/env bash
# The stage's "cut the WAN" switch (L1: ISP down, LAN fine). Rejects traffic to every non-private address in OUTPUT and
# FORWARD, so the monitoring segment, the venue LAN, tailscale (100.64/10) and the dashboard keep working; counts what
# the sandbox tried to send out while the WAN was down.
#   scripts/wan.sh down --yes     # cut (needs sudo iptables; --yes because on a shared host it cuts everyone)
#   scripts/wan.sh up             # restore
#   scripts/wan.sh status         # "online" | "offline sandbox_blocked=<n> other_blocked=<n>"
# SANDBOX_NET is the sandbox bridge, read from the openshell-docker network (for example 172.24.0.0/16 or 172.19.0.0/16);
# 172.24.0.0/16 if that network is missing. Only it is counted apart, so the OS's NTP or apt does not move the
# counter the audience sees. sudoers needs only iptables and ip6tables for this script.
CHAIN=IMMUNE_WAN
SANDBOX_NET="${SANDBOX_NET:-$(docker network inspect openshell-docker --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null | awk '{print $1}')}"
SANDBOX_NET="${SANDBOX_NET:-172.24.0.0/16}"
PRIV4="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 127.0.0.0/8 169.254.0.0/16 100.64.0.0/10 224.0.0.0/4 255.255.255.255/32"
PRIV6="::1/128 fe80::/10 fc00::/7 ff00::/8"
IPT="sudo -n iptables"; IP6T="sudo -n ip6tables"

installed() { $IPT -S "$CHAIN" >/dev/null 2>&1; }

down() {
  installed && { echo "already offline"; return 0; }
  $IPT -N "$CHAIN" || { echo "cannot run iptables (sudo -n): nothing changed" >&2; exit 1; }
  for n in $PRIV4; do $IPT -A "$CHAIN" -d "$n" -j RETURN; done
  $IPT -A "$CHAIN" -s "$SANDBOX_NET" -m comment --comment sandbox -j REJECT
  $IPT -A "$CHAIN" -m comment --comment other -j REJECT
  $IPT -I OUTPUT 1 -j "$CHAIN"; $IPT -I FORWARD 1 -j "$CHAIN"
  if $IP6T -N "$CHAIN" 2>/dev/null; then      # no IPv6 bypass of the cut
    for n in $PRIV6; do $IP6T -A "$CHAIN" -d "$n" -j RETURN; done
    $IP6T -A "$CHAIN" -j REJECT
    $IP6T -I OUTPUT 1 -j "$CHAIN"; $IP6T -I FORWARD 1 -j "$CHAIN"
  fi
  echo "offline (non-private egress rejected; sandbox counted as $SANDBOX_NET)"
}

up() {
  for T in "$IPT" "$IP6T"; do
    while $T -D OUTPUT -j "$CHAIN" 2>/dev/null; do :; done
    while $T -D FORWARD -j "$CHAIN" 2>/dev/null; do :; done
    $T -F "$CHAIN" 2>/dev/null; $T -X "$CHAIN" 2>/dev/null
  done
  installed && { echo "could not remove $CHAIN" >&2; exit 1; }
  echo "online"
}

status() {
  if ! $IPT -S >/dev/null 2>&1; then echo "unknown (no passwordless sudo for iptables)"; return 1; fi
  if ! installed; then echo "online"; return 0; fi
  # packet counters of the two REJECT rules, matched by their comments
  local rows sb ot
  rows=$($IPT -L "$CHAIN" -v -x -n 2>/dev/null)
  sb=$(echo "$rows" | awk '/\/\* sandbox \*\//{print $1}'); ot=$(echo "$rows" | awk '/\/\* other \*\//{print $1}')
  echo "offline sandbox_blocked=${sb:-0} other_blocked=${ot:-0}"
}

case "$1" in
  down) [ "$2" = "--yes" ] || { echo "refusing without --yes: this cuts internet for every user of $(hostname)" >&2; exit 2; }; down ;;
  up) up ;;
  status) status ;;
  *) sed -n '2,10p' "$0"; exit 2 ;;
esac
