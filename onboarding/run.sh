#!/usr/bin/env bash
# Onboarding: fresh SamiGPT on ports 18081 and 18082, then walk the setup wizard.
# Does not restart or reconfigure the service already listening on 8081/8082.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

COMPOSE=(docker compose -p samigpt-onboarding -f onboarding/docker-compose.yml)
UI_PORT=18081
MCP_PORT=18082

python3 - << 'PY'
import re
import sys
text = open("onboarding/docker-compose.yml", encoding="utf-8").read()
for match in re.finditer(r'^\s*-\s*"?(\d+):', text, re.M):
    host = int(match.group(1))
    if host in (8081, 8082):
        sys.exit(f"Refusing to publish host port {host}")
PY

if ! command -v docker >/dev/null 2>&1; then
    echo "docker is required" >&2
    exit 1
fi

port_busy() {
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -ltn | awk '{print $4}' | grep -Eq "(^|:)${port}$"
        return $?
    fi
    python3 - "$port" << 'PY'
import socket, sys
port = int(sys.argv[1])
sock = socket.socket()
try:
    sock.bind(("0.0.0.0", port))
except OSError:
    sys.exit(0)
finally:
    sock.close()
sys.exit(1)
PY
}

"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true

if port_busy "$UI_PORT" || port_busy "$MCP_PORT"; then
    echo "Port ${UI_PORT} or ${MCP_PORT} is already in use. Onboarding will not start." >&2
    exit 1
fi

"${COMPOSE[@]}" up -d --build

ready=0
for _ in $(seq 1 90); do
    if curl -skf "https://127.0.0.1:${UI_PORT}/api/setup/status" >/dev/null; then
        ready=1
        break
    fi
    sleep 2
done
if [[ "$ready" != 1 ]]; then
    echo "Onboarding did not become ready on port ${UI_PORT}." >&2
    "${COMPOSE[@]}" logs --tail 80 || true
    exit 1
fi

set +e
python3 onboarding/test_wizard.py \
    --base-url "https://127.0.0.1:${UI_PORT}" \
    --golden "${ROOT}/config.json" \
    --example "${ROOT}/config.json.example"
code=$?
set -e

if [[ "$code" -eq 0 ]]; then
    "${COMPOSE[@]}" down -v --remove-orphans
    echo "Onboarding wizard matched the golden config."
else
    echo "Onboarding left running at https://127.0.0.1:${UI_PORT}/setup" >&2
    exit "$code"
fi
