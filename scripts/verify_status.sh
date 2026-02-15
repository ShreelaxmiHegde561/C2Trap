#!/bin/bash
# Verify C2Trap Status and Troubleshooting

echo "=== C2Trap System Verification ==="
echo "Date: $(date)"

echo -e "\n[1] Checking Docker Containers..."
if command -v docker &> /dev/null; then
    docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "zeek|c2trap"
else
    echo "Docker command not found!"
fi

echo -e "\n[2] Checking Zeek Logs Directory..."
LOG_DIR="./logs/zeek"
if [ -d "$LOG_DIR" ]; then
    echo "Directory exists: $LOG_DIR"
    ls -la "$LOG_DIR"
else
    echo "Directory NOT found: $LOG_DIR"
fi

echo -e "\n[3] Checking Zeek Startup Log..."
STARTUP_LOG="$LOG_DIR/startup.log"
if [ -f "$STARTUP_LOG" ]; then
    echo "Found startup log. Last 20 lines:"
    echo "----------------------------------------"
    tail -n 20 "$STARTUP_LOG"
    echo "----------------------------------------"
else
    echo "Startup log not found. Zeek container might have failed before running start script."
fi

echo -e "\n[4] Checking Zeek Data Logs..."
for log in conn.log dns.log http.log ssl.log notice.log; do
    if [ -f "$LOG_DIR/$log" ]; then
        echo "Found $log - Size: $(du -h "$LOG_DIR/$log" | cut -f1)"
    else
        echo "Missing $log"
    fi
done

echo -e "\n[5] Network Interface Check..."
echo "If Zeek logs are missing, it might be listening on the wrong interface."
echo "Check startup.log above for 'Selected Interface'."

echo -e "\n=== Verification Complete ==="
echo "If issues persist:"
echo "1. Run './scripts/stop_all.sh'"
echo "2. Run 'docker-compose build zeek' to apply changes"
echo "3. Run './scripts/start_all.sh'"
