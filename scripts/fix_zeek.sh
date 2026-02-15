#!/bin/bash
# Rebuild Zeek components to apply fixes
# Use this if Zeek events are missing from the dashboard

# Force use of Docker socket (fix for Podman/Docker conflict)
export DOCKER_HOST=unix:///var/run/docker.sock

echo "[*] Stopping C2Trap services..."
docker-compose down

echo "[*] Removing old Zeek containers and images to force rebuild..."
docker rm -f c2trap-zeek c2trap-zeek-parser 2>/dev/null
docker rmi c2-zeek c2-zeek_parser 2>/dev/null

echo "[*] Rebuilding Zeek services..."
docker-compose build --no-cache zeek zeek_parser

echo "[*] Starting all services..."
./scripts/start_all.sh

echo "[*] Waiting for services to initialize (10s)..."
sleep 10

echo "[*] Checking Zeek logs..."
if [ -f "logs/zeek/startup.log" ]; then
    echo "   > Startup log found."
    tail -n 5 logs/zeek/startup.log
else
    echo "   > WARNING: Startup log NOT found yet."
fi

echo "[*] Done! Check the dashboard 'Zeek' tab."
echo "    If it's still empty, generate some traffic by running: python3 scripts/test_c2.py"
