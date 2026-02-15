#!/bin/bash
# C2Trap Attack Launcher

# Ensure execution from project root
cd "$(dirname "$0")/.." || exit

# Print Banner
python3 scripts/common_banner.py
export NO_BANNER=1

echo ""
echo "Select Attack Intensity:"
echo "1. Low (Stealth Mode)"
echo "2. High (Active Engagement)"
echo "3. Insane (Stress Test)"
echo ""
read -p "Enter choice [1-3]: " choice

case $choice in
    1) intensity="low";;
    2) intensity="high";;
    3) intensity="insane";;
    *) intensity="medium";;
esac

echo ""
echo "[*] Launching attack sequence..."
# Ensure execution from project root
cd "$(dirname "$0")/.." || exit
python3 scripts/random_traffic.py --intensity $intensity --duration 300
