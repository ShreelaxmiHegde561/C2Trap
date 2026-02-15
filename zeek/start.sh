#!/bin/bash
# Zeek startup script for C2Trap - Simplified for debugging
# Captures network traffic on loopback for localhost testing

LOG_DIR="/usr/local/zeek/logs"

# Ensure log directory exists with proper permissions
mkdir -p "$LOG_DIR"
chmod 777 "$LOG_DIR"

# Redirect all output to startup log
exec > >(tee -a "$LOG_DIR/startup.log") 2>&1

echo "[C2Trap Zeek] ============================================"
echo "[C2Trap Zeek] Starting at $(date)"
echo "[C2Trap Zeek] ============================================"

# Show Zeek version
zeek --version

# Clean old logs
find "$LOG_DIR" -name "*.log" ! -name "startup.log" -delete 2>/dev/null || true

# Change to log directory
cd "$LOG_DIR"

echo "[C2Trap Zeek] Starting Zeek on loopback interface..."
echo "[C2Trap Zeek] Logs will be written to: $LOG_DIR"

# Run Zeek with minimal config - just load JSON logs policy
# -C: Ignore checksums
# -i lo: Capture loopback traffic (for localhost testing)
exec zeek -C -i lo local policy/tuning/json-logs 2>&1
