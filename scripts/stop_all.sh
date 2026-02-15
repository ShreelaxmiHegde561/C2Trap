#!/bin/bash
# Stop all C2Trap services

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║              C2Trap - Stopping All Services               ║"
echo "╚═══════════════════════════════════════════════════════════╝"

cd "$(dirname "$0")/.."

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null; then
    COMPOSE_CMD="docker compose"
else
    COMPOSE_CMD="docker-compose"
fi

echo "[*] Stopping Docker containers..."
$COMPOSE_CMD down

echo ""
echo "[*] Services stopped."
