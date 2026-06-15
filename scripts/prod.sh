#!/usr/bin/env bash
# Builds the frontend and starts the backend (production mode, :3001, serving
# the built SPA + requiring real SAML login) alongside the SAML IdP (:3000).
set -e
cd "$(dirname "$0")/.."

echo "Building frontend..."
npm --prefix src/web run build

cleanup() {
    echo ""
    echo "Stopping servers..."
    kill $(jobs -p) 2>/dev/null
}
trap cleanup EXIT INT TERM

echo "Starting backend (production mode) on http://localhost:3001 ..."
NODE_ENV=production npm run sp &

echo "Starting SAML IdP on http://localhost:3000 ..."
npm run idp &

wait
