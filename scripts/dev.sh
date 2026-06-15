#!/usr/bin/env bash
# Starts the backend (dev mode, :3001) and the Vite dev server (:5173) together.
set -e
cd "$(dirname "$0")/.."

cleanup() {
    echo ""
    echo "Stopping dev servers..."
    kill $(jobs -p) 2>/dev/null
}
trap cleanup EXIT INT TERM

echo "Starting backend (dev mode) on http://localhost:3001 ..."
npm run sp &

echo "Starting Vite dev server on http://localhost:5173 ..."
npm --prefix src/web run dev &

wait
