#!/bin/bash
#
# C2Trap Demo Script
# ==================
#
# Run a full demonstration of C2Trap's capabilities:
# - Start the demo malware simulator
# - Show traffic interception in real-time
# - Trigger sandbox analysis
# - Display results on dashboard
#
# Usage:
#   ./run_demo.sh [--quick | --full]
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
cat << 'EOF'
   ██████╗██████╗ ████████╗██████╗  █████╗ ██████╗ 
  ██╔════╝╚════██╗╚══██╔══╝██╔══██╗██╔══██╗██╔══██╗
  ██║      █████╔╝   ██║   ██████╔╝███████║██████╔╝
  ██║     ██╔═══╝    ██║   ██╔══██╗██╔══██║██╔═══╝ 
  ╚██████╗███████╗   ██║   ██║  ██║██║  ██║██║     
   ╚═════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     
                                                   
     C O M M A N D  &  C O N T R O L  T R A P
         D E M O N S T R A T I O N
EOF
echo -e "${NC}"

# Parse arguments
MODE="full"
C2_DOMAIN="c2.evil.com"
BEACON_INTERVAL=15
DROP_FILES=true

while [[ $# -gt 0 ]]; do
    case $1 in
        --quick)
            MODE="quick"
            BEACON_INTERVAL=5
            shift
            ;;
        --full)
            MODE="full"
            shift
            ;;
        --no-files)
            DROP_FILES=false
            shift
            ;;
        --c2)
            C2_DOMAIN="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --quick         Quick demo (5s beacon interval)"
            echo "  --full          Full demo with all features (default)"
            echo "  --no-files      Skip file dropping"
            echo "  --c2 DOMAIN     Use custom C2 domain"
            echo "  -h, --help      Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  Demo Mode: ${YELLOW}$MODE${NC}"
echo -e "${BLUE}  C2 Domain: ${YELLOW}$C2_DOMAIN${NC}"
echo -e "${BLUE}  Interval:  ${YELLOW}${BEACON_INTERVAL}s${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Check if C2Trap is running
echo -e "${YELLOW}[1/5] Checking C2Trap status...${NC}"

if sudo docker ps | grep -q "c2trap-dashboard"; then
    echo -e "  ${GREEN}✓${NC} Dashboard container running"
else
    echo -e "  ${RED}✗${NC} Dashboard not running. Starting C2Trap..."
    cd "$PROJECT_DIR"
    ./C2Trap &
    sleep 10
fi

if sudo docker ps | grep -q "c2trap-analysis"; then
    echo -e "  ${GREEN}✓${NC} Analysis engine running"
else
    echo -e "  ${YELLOW}!${NC} Analysis engine may not be running"
fi

if sudo docker ps | grep -q "http-decoy"; then
    echo -e "  ${GREEN}✓${NC} HTTP decoy running"
else
    echo -e "  ${YELLOW}!${NC} HTTP decoy may not be running"
fi

echo ""
echo -e "${YELLOW}[2/5] Opening Dashboard...${NC}"
echo -e "  ${CYAN}→${NC} Dashboard: http://localhost:8000"
echo ""

# Try to open browser (works on many Linux systems)
if command -v xdg-open &> /dev/null; then
    xdg-open "http://localhost:8000" 2>/dev/null &
elif command -v open &> /dev/null; then
    open "http://localhost:8000" 2>/dev/null &
fi

sleep 2

echo -e "${YELLOW}[3/5] Running System Reconnaissance...${NC}"
echo ""

# Run recon only first
python3 "$SCRIPT_DIR/demo_malware.py" --recon-only 2>/dev/null | head -30
echo "  ..."
echo ""

echo -e "${YELLOW}[4/5] Starting Malware Simulation...${NC}"
echo ""
echo -e "  ${RED}⚠${NC}  This is a SAFE simulation - no malicious code is executed"
echo -e "  ${CYAN}→${NC}  C2 Domain: $C2_DOMAIN"
echo -e "  ${CYAN}→${NC}  Beacon Interval: ${BEACON_INTERVAL}s"
echo ""

# Prepare command
# Prepare command
DEMO_CMD="python3 $SCRIPT_DIR/demo_malware.py --mode full --c2 $C2_DOMAIN --target-ip 127.0.0.1 --interval $BEACON_INTERVAL"
if [ "$DROP_FILES" = false ]; then
    DEMO_CMD="$DEMO_CMD --no-drop"
fi

echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${PURPLE}  MALWARE SIMULATION OUTPUT${NC}"
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Run the demo (will run until Ctrl+C)
$DEMO_CMD

echo ""
echo -e "${YELLOW}[5/5] Demo Complete${NC}"
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Check the C2Trap Dashboard to see captured events:${NC}"
echo -e "${GREEN}  ${CYAN}http://localhost:8000${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "  What you should see:"
echo -e "  ${CYAN}•${NC} DNS spoofing events (domain redirected to fake C2)"
echo -e "  ${CYAN}•${NC} HTTP beacon captures (POST requests intercepted)"
echo -e "  ${CYAN}•${NC} Beacon detection alerts (periodic connection pattern)"
echo -e "  ${CYAN}•${NC} Sandbox analysis results (dropped files analyzed)"
echo -e "  ${CYAN}•${NC} MITRE ATT&CK technique mappings"
echo ""
