#!/usr/bin/env bash
# Kills any process listening on the ports used by the dev/prod stacks
# (SAML IdP :3000, backend :3001, Vite dev server :5173).
set -e

PORTS=(3000 3001 5173)

for port in "${PORTS[@]}"; do
    pids=$(lsof -ti tcp:"$port" 2>/dev/null || true)
    if [ -n "$pids" ]; then
        echo "Killing process(es) on port $port: $pids"
        kill -9 $pids 2>/dev/null || true
    else
        echo "Port $port is free."
    fi
done
