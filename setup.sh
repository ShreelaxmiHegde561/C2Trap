#!/bin/bash
# C2Trap Setup Script for Kali Linux

set -e

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║              C2Trap Setup Script v1.0                     ║"
echo "║         Command & Control Detection System                ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[+]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[-]${NC} $1"; }

# Check if running as root for certain operations
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_warn "Some features require root. Run with sudo for full functionality."
    fi
}

# Install system dependencies
install_deps() {
    log_info "Updating package lists..."
    sudo apt-get update -qq

    log_info "Installing system dependencies..."
    sudo apt-get install -y -qq \
        python3 \
        python3-pip \
        python3-venv \
        docker.io \
        docker-compose \
        tcpdump \
        tshark \
        libpcap-dev \
        libssl-dev \
        libffi-dev \
        build-essential
}

# Setup Python virtual environment
setup_venv() {
    log_info "Creating Python virtual environment..."
    python3 -m venv venv
    source venv/bin/activate

    log_info "Installing Python dependencies..."
    pip install --upgrade pip -q
    pip install -r requirements.txt -q
}

# Setup Docker
setup_docker() {
    log_info "Configuring Docker..."
    sudo systemctl enable docker
    sudo systemctl start docker
    sudo usermod -aG docker $USER
    log_warn "You may need to log out and back in for Docker group changes"
}

# Initialize directories
init_dirs() {
    log_info "Initializing log and data directories..."
    mkdir -p logs/{decoys,analysis,sandbox,alerts}
    mkdir -p data/ioc_cache
    touch logs/analysis_queue.jsonl
    touch logs/sandbox_queue.jsonl
    chmod 755 logs data
}

# Create default config files
create_configs() {
    log_info "Creating default configuration files..."
    
    # Decoys config
    cat > config/decoys.yaml << 'EOF'
http:
  port: 8080
  ssl_port: 8443
  endpoints:
    - /api/beacon
    - /check
    - /update
    - /gate
    - /panel
    - /c2

dns:
  port: 53
  default_ip: "127.0.0.1"
  log_all: true

ftp:
  port: 21
  passive_ports: "30000-30009"
  accept_all_creds: true

smtp:
  port: 25
  accept_all: true
EOF

    # Network config
    cat > config/network.yaml << 'EOF'
capture:
  interface: eth0
  promiscuous: true
  filter: "tcp or udp"

rerouting:
  enabled: false
  dns_spoof: []
  
analysis:
  beacon_threshold: 5
  beacon_variance: 0.1
EOF

    # VirusTotal config (placeholder)
    if [ ! -f config/virustotal.env ]; then
        cat > config/virustotal.env << 'EOF'
# Get your API key from https://www.virustotal.com/gui/join-us
VT_API_KEY=your_api_key_here
EOF
        log_warn "Remember to set your VirusTotal API key in config/virustotal.env"
    fi
}

# Build Docker images
build_images() {
    log_info "Building Docker images..."
    docker-compose build --quiet
}

# Main
main() {
    check_root
    install_deps
    setup_venv
    setup_docker
    init_dirs
    create_configs
    
    echo ""
    log_info "Setup complete!"
    echo ""
    echo "Next steps:"
    echo "  1. Set your VirusTotal API key: nano config/virustotal.env"
    echo "  2. Build containers: docker-compose build"
    echo "  3. Start services: docker-compose up -d"
    echo "  4. Access dashboard: http://localhost:8000"
    echo "  5. Run demo: python3 scripts/test_c2.py"
    echo ""
}

main "$@"
