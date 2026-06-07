#!/usr/bin/env bash
#
# Build and start the Lab Manager application via docker-compose.
#
# Usage:
#   ./start.sh              # Build and start in background
#   ./start.sh --logs       # Build, start, and tail logs
#   ./start.sh --foreground # Build and run in foreground
#   ./start.sh --stop       # Stop the running container
#   ./start.sh --restart    # Rebuild and restart
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Pick docker compose v2 (plugin) if available, fall back to docker-compose v1.
if docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE=(docker-compose)
else
    echo "Error: neither 'docker compose' nor 'docker-compose' is installed." >&2
    exit 1
fi

# Ensure instance directory exists so the bind mount doesn't get created as root.
mkdir -p instance

# Generate a LAB_MANAGER_SECRET_KEY on first run and persist it to .env so restarts
# keep existing sessions valid. SECRET_KEY is optional (the app generates a
# random key if unset), but setting one is recommended beyond local development.
if [[ ! -f .env ]]; then
    if command -v openssl >/dev/null 2>&1; then
        SECRET_KEY="$(openssl rand -hex 32)"
        printf 'LAB_MANAGER_SECRET_KEY=%s\n' "$SECRET_KEY" > .env
        chmod 600 .env
        echo "Created .env with a generated LAB_MANAGER_SECRET_KEY."
    else
        echo "Warning: openssl not found; skipping LAB_MANAGER_SECRET_KEY generation." >&2
    fi
fi

case "${1:-}" in
    --stop)
        echo "Stopping lab-manager..."
        "${COMPOSE[@]}" down
        ;;
    --restart)
        echo "Rebuilding and restarting lab-manager..."
        "${COMPOSE[@]}" down
        "${COMPOSE[@]}" up -d --build
        "${COMPOSE[@]}" ps
        ;;
    --foreground)
        echo "Building and starting lab-manager in foreground..."
        "${COMPOSE[@]}" up --build
        ;;
    --logs)
        echo "Building and starting lab-manager, then tailing logs..."
        "${COMPOSE[@]}" up -d --build
        "${COMPOSE[@]}" ps
        "${COMPOSE[@]}" logs -f
        ;;
    "" )
        echo "Building and starting lab-manager..."
        "${COMPOSE[@]}" up -d --build
        "${COMPOSE[@]}" ps
        echo
        echo "Lab Manager started. Tail logs with: ${COMPOSE[*]} logs -f"
        ;;
    -h|--help)
        sed -n '2,12p' "$0"
        ;;
    *)
        echo "Unknown option: $1" >&2
        echo "Run '$0 --help' for usage." >&2
        exit 1
        ;;
esac
