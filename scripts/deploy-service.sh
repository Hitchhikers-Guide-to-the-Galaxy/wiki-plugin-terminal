#!/bin/sh
# deploy-service.sh — put this plugin's pty service into the local Farm API
# and restart it. The Farm API (uvicorn main:app on 127.0.0.1:4244, launched
# by ~/bin/wiki-start) imports a COPY of service/terminal_service.py from its
# own folder; this is the one way that copy is refreshed, so it cannot drift.
#
#   scripts/deploy-service.sh            # copy, keep the local ssh-host list, restart
#   scripts/deploy-service.sh --no-restart
set -e
HERE=$(cd "$(dirname "$0")/.." && pwd)
API_DIR="${WIKI_FARM_API_DIR:-$HOME/Music/Guides/Private/localhost/assets/api-test}"
SRC="$HERE/service/terminal_service.py"
DST="$API_DIR/terminal_service.py"
[ -f "$DST" ] || { echo "no deployed copy at $DST" >&2; exit 1; }
cp "$DST" "$DST.bak-$(date +%Y%m%d-%H%M%S)"
# The deployed copy carries the machine's own ssh-host allowlist in its default;
# carry that one line across rather than publishing tailnet names in the package.
LOCAL_HOSTS=$(python3 - "$DST" <<'PY'
import re, sys
s = open(sys.argv[1]).read()
m = re.search(r'"WIKI_TERMINAL_SSH_HOSTS",\s*"([^"]+)"', s)
print(m.group(1) if m else "")
PY
)
cp "$SRC" "$DST"
if [ -n "$LOCAL_HOSTS" ]; then
  python3 - "$DST" "$LOCAL_HOSTS" <<'PY'
import re, sys
p, hosts = sys.argv[1], sys.argv[2]
s = open(p).read()
s2 = re.sub(r'("WIKI_TERMINAL_SSH_HOSTS",\s*)"[^"]+"', lambda m: m.group(1) + '"' + hosts + '"', s, count=1)
open(p, "w").write(s2)
PY
fi
python3 -m py_compile "$DST"
# Chrome's Private Network Access preflight header, answered by the Farm API's
# own app: one line in main.py, added once.
MAIN="$API_DIR/main.py"
if [ -f "$MAIN" ] && ! grep -q "private_network_headers" "$MAIN"; then
  printf '\n# Terminal plugin: answer the private-network preflight (Terminal Trust Plan)\nfrom terminal_service import private_network_headers as _terminal_pna\napp.middleware("http")(_terminal_pna)\n' >> "$MAIN"
fi
echo "deployed $DST (ssh hosts: ${LOCAL_HOSTS:-package default})"
[ "$1" = "--no-restart" ] && exit 0
PORT=4244
pkill -f "uvicorn main:app.*--port $PORT" 2>/dev/null || true
sleep 1
UV="$(command -v uvicorn || true)"; [ -z "$UV" ] && UV="$HOME/.pyenv/shims/uvicorn"
LOG="$HOME/Library/Logs/wiki-farm-api.log"
echo "=== deploy-service $(date '+%Y-%m-%d %H:%M:%S') — restarting Farm API on $PORT ===" >> "$LOG"
( cd "$API_DIR" && exec /usr/bin/nohup "$UV" main:app --port "$PORT" >> "$LOG" 2>&1 ) &
for i in 1 2 3 4 5 6 7 8 9 10; do
  sleep 1
  if curl -s -m 2 "http://127.0.0.1:$PORT/terminal/health" >/dev/null; then echo "Farm API back on $PORT"; exit 0; fi
done
echo "Farm API did not answer on $PORT — see $LOG" >&2; exit 1
