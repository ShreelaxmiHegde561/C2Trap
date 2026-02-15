# C2Trap - Command & Control Detection System

[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-required-blue.svg)](https://www.docker.com/)

## 🎯 Overview

**C2Trap** is an advanced Command & Control (C2) detection system designed to detect, analyze, and visualize malicious C2 communications. It combines honeypot technology, traffic analysis, and threat intelligence to provide a comprehensive view of C2 activity.

### Key Features

- **Multi-Protocol Decoys**: HTTP, DNS, FTP, and SMTP honeypots
- **Traffic Analysis**: Beacon detection, JA3 TLS fingerprinting
- **Threat Intelligence**: VirusTotal integration for IOC enrichment
- **MITRE ATT&CK Mapping**: Automatic technique detection
- **Kill Chain Tracking**: Attack progression visualization
- **Real-time Dashboard**: Web-based SOC interface

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     C2TRAP SYSTEM                       │
├─────────────────────────────────────────────────────────┤
│  [Decoy Services]  →  [Analysis Engine]  →  [Dashboard] │
│   HTTP/DNS/FTP        Beacon Detection     Real-time    │
│   SMTP Honeypots      JA3 Fingerprint      Alerts       │
│                       MITRE Mapping        MITRE Matrix │
└─────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Docker & Docker Compose
- Python 3.11+
- Kali Linux (recommended)

### Installation

```bash
# Clone or navigate to the project
cd ~/c2

# Start all services
./scripts/start_all.sh

# Open dashboard
firefox http://localhost:8000
```

### Testing

```bash
# Run the C2 simulator
python3 scripts/test_c2.py

# Or test specific protocols
python3 scripts/test_c2.py --http-only
python3 scripts/test_c2.py --dns-only
```

## 📊 Dashboard

Access the SOC Dashboard at **http://localhost:8000**

| View | Description |
|------|-------------|
| Overview | Summary stats, recent alerts, kill chain |
| Events | Real-time event feed with filtering |
| Alerts | Alert management by severity |
| MITRE ATT&CK | Technique heatmap and detections |
| Kill Chain | Attack progression timeline |
| IOCs | Indicators of Compromise database |

## 🔌 Services

| Service | Port | Description |
|---------|------|-------------|
| Dashboard | 8000 | Web UI and API |
| HTTP Decoy | 8888 | HTTP honeypot |
| HTTPS Decoy | 8443 | HTTPS honeypot |
| DNS Decoy | 53 | DNS server |
| FTP Decoy | 21 | FTP honeypot |
| SMTP Decoy | 25 | SMTP honeypot |

## 📁 Project Structure

```
~/c2/
├── config/              # Configuration files
├── decoys/              # Honeypot services
│   ├── http/            # HTTP/HTTPS decoy
│   ├── dns/             # DNS server
│   ├── ftp/             # FTP honeypot
│   └── smtp/            # SMTP honeypot
├── analysis/            # Traffic analysis
│   ├── traffic/         # Packet capture, beacon detection
│   ├── ja3/             # TLS fingerprinting
│   └── rerouting/       # DNS spoofing, fake C2
├── intelligence/        # Threat intel
│   ├── virustotal/      # VT API client
│   └── mitre/           # MITRE mapper
├── sandbox/             # Malware sandbox
├── falco/               # Kernel monitoring
├── dashboard/           # Web dashboard
│   ├── backend/         # FastAPI
│   └── frontend/        # HTML/CSS/JS
├── scripts/             # Utility scripts
└── logs/                # Event logs
```

## 🔧 Configuration

### VirusTotal API

Edit `config/virustotal.env`:
```
VT_API_KEY=your_api_key_here
```

### Decoy Settings

Edit `config/decoys.yaml` to customize honeypot behavior.

## 📝 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/stats` | GET | Dashboard statistics |
| `/api/events` | GET | Event log |
| `/api/alerts` | GET | Alerts list |
| `/api/iocs` | GET | IOC database |
| `/api/mitre` | GET | MITRE mappings |
| `/api/killchain` | GET | Kill chain status |

## 🛡️ MITRE Techniques Detected

- **T1071**: Application Layer Protocol
- **T1071.001**: Web Protocols
- **T1071.004**: DNS
- **T1573**: Encrypted Channel
- **T1105**: Ingress Tool Transfer
- **T1059**: Command Interpreter
- **T1041**: Exfiltration Over C2

## 📜 License

MIT License - See [LICENSE](LICENSE) for details.

## 👤 Author

Final Year Cybersecurity Project

---

**C2Trap** - Catch the Command & Control 🎯
