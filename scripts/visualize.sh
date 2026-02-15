#!/bin/bash
# C2Trap Traffic Rerouting Visualizer

# Ensure execution from project root
cd "$(dirname "$0")/.." || exit

# Print Banner
python3 scripts/common_banner.py
export NO_BANNER=1

PYTHON_SCRIPT="scripts/visualize_trap.py"

echo "Launching Rerouting Visualizer..."
echo "Watch for green \"REDIRECTED\" messages..."
echo ""

python3 -u "$PYTHON_SCRIPT"
