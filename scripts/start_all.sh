#!/bin/bash
# Start all C2Trap services

cd "$(dirname "$0")/.."

# Print Banner
python3 scripts/common_banner.py

# Force use of Docker socket
export DOCKER_HOST=unix:///var/run/docker.sock

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null; then
    if ! command -v docker &> /dev/null; then
        echo "Error: Docker not installed"
        exit 1
    fi
    # Use docker compose instead of docker-compose
    COMPOSE_CMD="docker compose"
else
    COMPOSE_CMD="docker-compose"
fi

# Create log directory
mkdir -p logs

# Start services
echo "[*] Starting Docker containers..."
$COMPOSE_CMD up -d

# Wait for services to start
echo "[*] Waiting for services to start..."
sleep 5

# Check status
echo ""
echo "[*] Service Status:"
$COMPOSE_CMD ps

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                    Services Started!                      ║"
echo "╠═══════════════════════════════════════════════════════════╣"
echo "║  Dashboard:    http://localhost:8000                      ║"
echo "║  HTTP Decoy:   http://localhost:8888                      ║"
echo "║  DNS Decoy:    localhost:53                               ║"
echo "║  FTP Decoy:    localhost:21                               ║"
echo "║  SMTP Decoy:   localhost:25                               ║"
echo "╠═══════════════════════════════════════════════════════════╣"
echo "║  To test: python3 scripts/test_c2.py                      ║"
echo "║  Logs:    tail -f logs/analysis_queue.jsonl               ║"
echo "╚═══════════════════════════════════════════════════════════╝"
