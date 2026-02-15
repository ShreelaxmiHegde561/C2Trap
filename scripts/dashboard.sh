#!/bin/bash
# C2Trap Dashboard Launcher

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Ensure execution from project root
cd "$(dirname "$0")/.." || exit

# Print Banner
python3 scripts/common_banner.py

echo -e "${BLUE}[+] Starting C2Trap Dashboard...${NC}"

# Check if running in Docker or Manual mode
if sudo docker ps -a | grep -q c2trap-dashboard; then
    echo -e "${BLUE}[*] Attempting to start Dashboard via Docker...${NC}"
    
    # Ensure all auxiliary services are running
    # We need: decoys (http/dns/ftp/smtp), zeek (ids), zeek_parser (log conversion), and analysis (detection)
    echo -e "${BLUE}[*] Starting auxiliary services...${NC}"
    
    for container in c2trap-http c2trap-dns c2trap-ftp c2trap-smtp c2trap-zeek c2trap-zeek-parser c2trap-analysis; do
        if sudo docker start $container 2>/dev/null; then
            echo -e "${GREEN}  ✓ $container${NC}"
        else
            echo -e "${YELLOW}  ⚠ $container (not found or already running)${NC}"
        fi
    done

    if sudo docker start c2trap-dashboard 2>/dev/null; then
        echo -e "${GREEN}[✔] Dashboard container started.${NC}"
        echo -e "\n${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║           DASHBOARD READY                                 ║${NC}"
        echo -e "${GREEN}╠═══════════════════════════════════════════════════════════╣${NC}"
        echo -e "${GREEN}║  🌐 URL: http://localhost:8000                           ║${NC}"
        echo -e "${GREEN}║  🔄 Auto-Refresh: Every 5 seconds                        ║${NC}"
        echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}\n"
    else
        echo -e "${RED}[!] Docker start failed for dashboard. Falling back to local execution...${NC}"
        echo -e "${BLUE}[*] Starting Dashboard locally (requires sudo)...${NC}"
        
        # Set environment variables for local execution
        export LOG_PATH="/home/shree/c2/logs/analysis_queue.jsonl"
        export FALCO_LOG_PATH="/home/shree/c2/logs/falco/events.json"
        
        # Try to ensure services are running again just in case
        sudo docker start c2trap-http c2trap-dns c2trap-ftp c2trap-smtp c2trap-zeek c2trap-zeek-parser c2trap-analysis 2>/dev/null
        
        echo -e "\n${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║           DASHBOARD STARTING (Local Mode)                 ║${NC}"
        echo -e "${GREEN}╠═══════════════════════════════════════════════════════════╣${NC}"
        echo -e "${GREEN}║  🌐 URL: http://localhost:8000                           ║${NC}"
        echo -e "${GREEN}║  🔄 Auto-Refresh: Every 5 seconds                        ║${NC}"
        echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}\n"
        
        cd dashboard/backend && sudo -E python3 -m uvicorn main:app --host 0.0.0.0 --port 8000
    fi
else
    echo -e "${BLUE}[*] Docker container for dashboard not found. Starting locally...${NC}"
    
    # Set environment variables for local execution
    export LOG_PATH="/home/shree/c2/logs/analysis_queue.jsonl"
    export FALCO_LOG_PATH="/home/shree/c2/logs/falco/events.json"
    
    # Ensure services are running
    echo -e "${BLUE}[*] Starting auxiliary services...${NC}"
    
    for container in c2trap-http c2trap-dns c2trap-ftp c2trap-smtp c2trap-zeek c2trap-zeek-parser c2trap-analysis; do
        if sudo docker start $container 2>/dev/null; then
            echo -e "${GREEN}  ✓ $container${NC}"
        else
            echo -e "${YELLOW}  ⚠ $container (not found or already running)${NC}"
        fi
    done
    
    echo -e "\n${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║           DASHBOARD STARTING (Local Mode)                 ║${NC}"
    echo -e "${GREEN}╠═══════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║  🌐 URL: http://localhost:8000                           ║${NC}"
    echo -e "${GREEN}║  🔄 Auto-Refresh: Every 5 seconds                        ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}\n"
    
    cd dashboard/backend && sudo -E python3 -m uvicorn main:app --host 0.0.0.0 --port 8000
fi

