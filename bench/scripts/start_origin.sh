#!/usr/bin/env bash
# Start (or stop) the local Caddy origin. Exports the cert/key/root the Caddyfile
# reads. Usage:
#   start_origin.sh start   -> launches caddy in the background, writes server/caddy.pid
#   start_origin.sh stop    -> stops it
#   start_origin.sh run     -> runs in the foreground (Ctrl-C to stop)
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
srv="$here/server"; cfg="$here/config"
# shellcheck source=/dev/null
. "$cfg/origin.env"
export CADDY_CERT="$cfg/leaf.pem" CADDY_KEY="$cfg/leaf.key" CADDY_ROOT="$srv/payloads"
export CADDY_PORT="$ORIGIN_PORT"
bin="$srv/caddy"; conf="$cfg/server.caddyfile"; pidf="$srv/caddy.pid"; logf="$srv/caddy.log"

case "${1:-run}" in
  start)
    [ -x "$bin" ] || { echo "caddy missing; run fetch_caddy.sh" >&2; exit 1; }
    "$bin" start --config "$conf" --adapter caddyfile --pidfile "$pidf" 2>"$logf"
    echo "[origin] started (pid $(cat "$pidf" 2>/dev/null)) — log: $logf" ;;
  stop)
    # admin is off in the Caddyfile, so `caddy stop` (admin API) can't work —
    # kill the backgrounded process by its pidfile, plus a belt-and-suspenders
    # sweep of any caddy started from THIS config.
    [ -f "$pidf" ] && kill "$(cat "$pidf")" 2>/dev/null || true
    # Belt-and-suspenders: kill any caddy launched from THIS Caddyfile (matches
    # the config path in its argv; our own shell argv never contains it). Catches
    # leftover instances whose pidfile was lost.
    pkill -f "$conf" 2>/dev/null || true
    rm -f "$pidf"; sleep 0.3; echo "[origin] stopped" ;;
  run)
    exec "$bin" run --config "$conf" --adapter caddyfile ;;
  *) echo "usage: $0 {start|stop|run}" >&2; exit 2 ;;
esac
