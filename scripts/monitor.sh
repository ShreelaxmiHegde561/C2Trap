#!/bin/bash
# C2Trap Security Monitor

# Ensure execution from project root
cd "$(dirname "$0")/.." || exit

# Print Banner
python3 scripts/common_banner.py
export NO_BANNER=1

# Create logs if missing
mkdir -p logs/falco
touch logs/falco/events.json
touch logs/analysis_queue.jsonl

PYTHON_SCRIPT="scripts/monitor_formatter.py"

echo "Initializing C2Trap Security Monitor..."
# Use unbuffered python output
tail -f -n 0 logs/falco/events.json logs/analysis_queue.jsonl 2>/dev/null | python3 -u "$PYTHON_SCRIPT"
