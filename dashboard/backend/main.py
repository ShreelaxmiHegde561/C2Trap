"""
C2Trap SOC Dashboard Backend
FastAPI application providing APIs for the dashboard
"""

import os
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, HTTPException, Query, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('dashboard')

# Paths
BASE_DIR = Path(__file__).parent.parent
import sys
sys.path.append(str(BASE_DIR))
sys.path.append(str(Path(__file__).parent))

# Add detection module paths
for _det_path in ['/app/detection', str(BASE_DIR / 'detection'), str(BASE_DIR.parent / 'analysis' / 'detection')]:
    if os.path.isdir(_det_path) and _det_path not in sys.path:
        sys.path.insert(0, _det_path)

# Import detection modules
try:
    from dga_detector import DGADetector
    _dga = DGADetector()
    logger.info('DGA Detector loaded in dashboard')
except Exception:
    _dga = None
    logger.warning('DGA Detector not available')

try:
    from dns_tunnel_detector import DNSTunnelDetector
    _tunnel = DNSTunnelDetector()
    logger.info('DNS Tunnel Detector loaded in dashboard')
except Exception:
    _tunnel = None
    logger.warning('DNS Tunnel Detector not available')

try:
    from tls_anomaly_detector import TLSAnomalyDetector
    _tls = TLSAnomalyDetector()
    logger.info('TLS Anomaly Detector loaded in dashboard')
except Exception:
    _tls = None
    logger.warning('TLS Anomaly Detector not available')

LOG_PATH = os.environ.get('LOG_PATH', '/app/logs/analysis_queue.jsonl')
FALCO_LOG_PATH = os.environ.get('FALCO_LOG_PATH', '/app/logs/falco/events.json')
DATA_PATH = os.environ.get('DATA_PATH', '/app/data')

app = FastAPI(
    title="C2Trap Dashboard",
    description="Command & Control Detection System Dashboard",
    version="1.0.0"
)

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================
# Data Models
# =============================================

class Event(BaseModel):
    timestamp: str
    source: str
    event_type: str
    data: Dict[str, Any]


class Alert(BaseModel):
    id: str
    severity: str
    title: str
    description: str
    timestamp: str
    source_ip: Optional[str] = None
    mitre_technique: Optional[str] = None


class EnrichmentRequest(BaseModel):
    value: str
    type: str


class IOC(BaseModel):
    type: str
    value: str
    first_seen: str
    last_seen: str
    hit_count: int
    is_malicious: bool
    virus_total: Optional[Dict[str, Any]] = None
    threat_score: Optional[int] = 0


# =============================================
# Event Storage (in-memory with file backing)
# =============================================

class EventStore:
    def __init__(self, log_path: str = LOG_PATH):
        self.log_path = log_path
        self.events: List[dict] = []
        self.alerts: List[dict] = []
        self.iocs: Dict[str, dict] = {}
        self.mitre_detections: Dict[str, int] = {}
        self.falco_events: List[dict] = []
        self.last_offset = 0
        self._initial_load = True   # Skip heavy detection during bulk load
        self.sync()
        self._initial_load = False  # Enable detection for new events
        logger.info(f'EventStore initialized: {len(self.events)} events, {len(self.alerts)} alerts')
        self._load_falco_events()
    
    def sync(self):
        """Synchronize with log file (incremental, fast startup)"""
        try:
            if not os.path.exists(self.log_path):
                return
            
            file_size = os.path.getsize(self.log_path)
            
            if self._initial_load and self.last_offset == 0:
                # FAST STARTUP: Only load the last ~5000 events
                # Seek backwards from end of file to find recent events
                MAX_INITIAL = 5000
                with open(self.log_path, 'r') as f:
                    # Read all lines but only keep the tail
                    all_lines = f.readlines()
                    recent_lines = all_lines[-MAX_INITIAL:] if len(all_lines) > MAX_INITIAL else all_lines
                    self.last_offset = f.tell()  # Set offset to END of file
                
                new_lines = 0
                for line in recent_lines:
                    try:
                        line = line.strip()
                        if not line:
                            continue
                        event = json.loads(line)
                        self._process_event(event)
                        new_lines += 1
                    except:
                        continue
                
                logger.info(f"Fast-loaded {new_lines} recent events (skipped {len(all_lines) - len(recent_lines)} older events)")
            else:
                # INCREMENTAL: Process only new events since last sync
                with open(self.log_path, 'r') as f:
                    f.seek(self.last_offset)
                    
                    new_lines = 0
                    for line in f:
                        try:
                            line = line.strip()
                            if not line:
                                continue
                            event = json.loads(line)
                            self._process_event(event)
                            new_lines += 1
                        except:
                            continue
                    
                    self.last_offset = f.tell()
                    if new_lines > 0:
                        logger.info(f"Synchronized {new_lines} new events")
        except Exception as e:
            logger.error(f"Sync failed: {e}")
    
    def _process_event(self, event: dict):
        """Process and categorize an event"""
        self.events.append(event)
        
        data = event.get('data', {})
        event_type = event.get('event_type', '')
        
        # Extract IOCs
        if 'remote_ip' in data:
            self._add_ioc('ip', data['remote_ip'], event)
        if 'domain' in data:
            self._add_ioc('domain', data['domain'], event)
        if 'query_name' in data:
            self._add_ioc('domain', data['query_name'], event)
        
        # Extract File Hashes
        if 'sample_hash' in data:
            self._add_ioc('hash', data['sample_hash'], event)
        if 'sha256' in data:
            self._add_ioc('hash', data['sha256'], event)
        
        # Track MITRE techniques
        if 'mitre_technique' in data and data['mitre_technique']:
            tech = data['mitre_technique']
            self.mitre_detections[tech] = self.mitre_detections.get(tech, 0) + 1
        
        # === Inline Detection: Run DGA/DNS Tunnel/TLS analysis ===
        # Only run on NEW events (not during initial bulk load to avoid startup hang)
        if not self._initial_load:
            self._run_inline_detection(event)
        
        # Generate alerts for important events
        if self._is_alertable(event):
            self._create_alert(event)
    
    def _add_ioc(self, ioc_type: str, value: str, event: dict):
        """Add or update IOC"""
        key = f"{ioc_type}:{value}"
        ts = event.get('timestamp', datetime.utcnow().isoformat())
        
        if key not in self.iocs:
            self.iocs[key] = {
                'type': ioc_type,
                'value': value,
                'first_seen': ts,
                'last_seen': ts,
                'hit_count': 0,
                'is_malicious': False,
                'threat_score': 0,
                'virus_total': None,
                'events': []
            }
        
        self.iocs[key]['last_seen'] = ts
        self.iocs[key]['hit_count'] += 1
        
        # Check for malicious indicators and auto-populate threat scores
        data = event.get('data', {})
        is_suspicious = data.get('suspicious') or data.get('is_malicious') or data.get('is_known_malware')
        
        if is_suspicious:
            self.iocs[key]['is_malicious'] = True
            
            # Auto-generate mock VT data for demo (without real API)
            import random
            if self.iocs[key]['threat_score'] == 0:
                # Calculate threat score based on indicators
                base_score = 50
                if 'c2' in value.lower() or 'evil' in value.lower() or 'malware' in value.lower():
                    base_score = 85
                if 'beacon' in value.lower() or 'trojan' in value.lower() or 'backdoor' in value.lower():
                    base_score = 90
                if data.get('is_known_malware'):
                    base_score = 95
                
                # Add some variation
                threat_score = min(100, base_score + random.randint(0, 10))
                self.iocs[key]['threat_score'] = threat_score
                
                # Create mock VT result for display
                self.iocs[key]['virus_total'] = {
                    'malicious': random.randint(5, 20) if threat_score > 70 else random.randint(1, 5),
                    'suspicious': random.randint(2, 8),
                    'harmless': random.randint(50, 70),
                    'is_malicious': True,
                    'threat_score': threat_score,
                    'source': 'auto-detection'
                }

    
    def _run_inline_detection(self, event: dict):
        """Run DGA/DNS Tunnel/TLS detection on incoming events"""
        # Skip if event source is already a detector to avoid loops/dups
        if event.get('source') in ['dga_detector', 'dns_tunnel_detector', 'tls_anomaly_detector']:
            return

        data = event.get('data', {})
        event_type = event.get('event_type', '')
        source = event.get('source', '')
        
        # Get domain from various event fields
        domain = data.get('domain') or data.get('query_name') or data.get('qname', '')
        
        # Also extract domain from HTTP host header if available
        if not domain and 'headers' in data:
            domain = data.get('headers', {}).get('Host', '')
            if ':' in domain:
                domain = domain.split(':')[0]
        
        # DGA Detection on any event with a domain
        if _dga and domain and len(domain) > 3:
            try:
                score, is_dga, details = _dga.analyze(domain)
                if is_dga:
                    dga_event = {
                        'timestamp': event.get('timestamp', datetime.utcnow().isoformat()),
                        'source': 'dga_detector',
                        'event_type': 'dga_domain_detected',
                        'data': {
                            'domain': domain,
                            'dga_score': round(score, 3),
                            'entropy': round(details.get('entropy', 0), 2),
                            'suspicious': True,
                            'mitre_technique': 'T1568.002',
                            'original_source': source,
                            'original_event': event_type
                        }
                    }
                    self.events.append(dga_event)
                    self._create_alert(dga_event)
            except Exception as e:
                logger.debug(f'DGA check failed: {e}')
        
        # DNS Tunneling Detection on DNS queries
        if _tunnel and domain and (source == 'dns_decoy' or 'dns' in event_type):
            try:
                score, is_tunnel, details = _tunnel.analyze_query(domain)
                if is_tunnel:
                    tunnel_event = {
                        'timestamp': event.get('timestamp', datetime.utcnow().isoformat()),
                        'source': 'dns_tunnel_detector',
                        'event_type': 'dns_tunneling_detected',
                        'data': {
                            'domain': domain,
                            'tunnel_score': round(score, 3),
                            'encoding': details.get('encoding', 'unknown'),
                            'entropy': round(details.get('entropy', 0), 2),
                            'suspicious': True,
                            'mitre_technique': 'T1071.004',
                            'original_source': source
                        }
                    }
                    self.events.append(tunnel_event)
                    self._create_alert(tunnel_event)
            except Exception as e:
                logger.debug(f'DNS tunnel check failed: {e}')
        
        # TLS Anomaly Detection on TLS/HTTPS events
        if _tls and (data.get('tls_detected') or data.get('ja3_hash') or 'ssl' in event_type or 'tls' in event_type):
            try:
                conn_info = {
                    'dst_ip': data.get('dst_ip', data.get('remote_ip', '')),
                    'dst_port': data.get('dst_port', 443),
                    'ja3_hash': data.get('ja3_hash', ''),
                    'server_name': data.get('server_name', domain),
                    'cert_subject': data.get('cert_subject', ''),
                    'cert_issuer': data.get('cert_issuer', ''),
                    'cert_not_before': data.get('cert_not_before', ''),
                    'cert_not_after': data.get('cert_not_after', ''),
                }
                score, is_suspicious, details = _tls.analyze_connection(conn_info)
                if is_suspicious:
                    tls_event = {
                        'timestamp': event.get('timestamp', datetime.utcnow().isoformat()),
                        'source': 'tls_anomaly_detector',
                        'event_type': 'tls_anomaly_detected',
                        'data': {
                            'dst_ip': conn_info['dst_ip'],
                            'ja3_hash': conn_info['ja3_hash'],
                            'tls_score': round(score, 3),
                            'anomalies': details.get('alerts', []),
                            'suspicious': True,
                            'mitre_technique': 'T1573',
                            'original_source': source
                        }
                    }
                    self.events.append(tls_event)
                    self._create_alert(tls_event)
            except Exception as e:
                logger.debug(f'TLS check failed: {e}')

    def _is_alertable(self, event: dict) -> bool:
        """Check if event should generate an alert"""
        alertable_types = [
            'beacon_detected', 'malware_detected', 'malicious_ip_detected',
            'malicious_domain_detected', 'cobalt_strike_beacon', 'c2_direct',
            'data_exfil_attempt', 'ja3_fingerprint',
            'dga_domain_detected', 'dns_tunneling_detected', 'tls_anomaly_detected',
            'c2_beacon', 'c2_task_request'
        ]
        event_type = event.get('event_type', '')
        source = event.get('source', '')
        data = event.get('data', {})

        # Alert on decoy/trap hits ONLY if they are significant
        # This prevents 1:1 event/alert ratio for raw connection logs
        if 'decoy' in source or 'trap' in source or 'sinkhole' in source:
            # If it's a specific detection event (e.g. cmd_injection), always alert
            if event_type not in ['http_connection', 'http_request', 'dns_query', 'ftp_connection']:
                return True
            # For raw connections, only alert if flagged as suspicious/malicious
            is_suspicious = data.get('suspicious') or data.get('is_malicious') or data.get('is_known_malware')
            if is_suspicious:
                 return True
            # Debug: Log what was skipped
            # logger.info(f"Skipping alert for raw decoy event: {event_type}")
            return False

        # Don't alert on raw events unless they have high severity flags
        if event_type in ['dns_query', 'http_request', 'http_connection', 'tls_handshake']:
             return data.get('is_malicious') or data.get('is_known_malware')

        return (
            event_type in alertable_types or
            data.get('suspicious') or
            data.get('is_malicious') or
            data.get('is_known_malware')
        )
    
    def _create_alert(self, event: dict):
        """Create an alert from event"""
        data = event.get('data', {})
        
        # Determine severity
        event_type = event.get('event_type', '')
        
        # Critical for confirmed high-confidence detections
        if (data.get('is_known_malware') or 
            'malware' in event_type or 
            event_type in ['dns_tunneling_detected', 'dga_domain_detected', 'cobalt_strike_beacon']):
            severity = 'critical'
        elif data.get('is_malicious') or event_type in ['tls_anomaly_detected', 'c2_beacon']:
            severity = 'high'
        elif data.get('suspicious'):
            severity = 'medium'
        else:
            severity = 'low'
        
        alert = {
            'id': f"alert-{len(self.alerts)+1}",
            'severity': severity,
            'title': event.get('event_type', 'Unknown Event').replace('_', ' ').title(),
            'description': self._format_alert_description(event),
            'timestamp': event.get('timestamp', datetime.utcnow().isoformat()),
            'source_ip': data.get('remote_ip') or data.get('src_ip') or data.get('client_ip'),
            'mitre_technique': data.get('mitre_technique'),
            'event_type': event.get('event_type'),
            'raw_data': data
        }
        
        self.alerts.append(alert)
    
    def _format_alert_description(self, event: dict) -> str:
        """Format alert description"""
        data = event.get('data', {})
        parts = []
        
        # Check for rerouting/decoy
        source = event.get('source', '')
        if 'decoy' in source or 'sinkhole' in source or 'trap' in source:
             parts.append("🛑 Rerouted to Decoy")

        if 'remote_ip' in data:
            parts.append(f"Source: {data['remote_ip']}")
        if 'path' in data:
            parts.append(f"Path: {data['path']}")
        if 'domain' in data or 'query_name' in data:
            parts.append(f"Domain: {data.get('domain') or data.get('query_name')}")
        if 'malware' in data:
            parts.append(f"Malware: {data['malware']}")
        
        return ' | '.join(parts) if parts else 'Suspicious activity detected'
    
    def add_event(self, event: dict):
        """Add a new event"""
        self._process_event(event)
    
    def get_events(self, limit: int = 100, event_type: Optional[str] = None) -> List[dict]:
        """Get recent events"""
        events = self.events
        if event_type:
            events = [e for e in events if e.get('event_type') == event_type]
        return events[-limit:][::-1]  # Most recent first
    
    def get_alerts(self, limit: int = 50, severity: Optional[str] = None) -> List[dict]:
        """Get alerts"""
        alerts = self.alerts
        if severity:
            alerts = [a for a in alerts if a['severity'] == severity]
        return alerts[-limit:][::-1]
    
    def get_iocs(self, ioc_type: Optional[str] = None, malicious_only: bool = False) -> List[dict]:
        """Get IOCs"""
        iocs = list(self.iocs.values())
        if ioc_type:
            iocs = [i for i in iocs if i['type'] == ioc_type]
        if malicious_only:
            iocs = [i for i in iocs if i['is_malicious']]
        return sorted(iocs, key=lambda x: x['hit_count'], reverse=True)
    
    def get_mitre_stats(self) -> Dict[str, int]:
        """Get MITRE technique detection counts"""
        return self.mitre_detections
    
    def get_statistics(self) -> dict:
        """Get overall statistics"""
        zeek_events = [e for e in self.events if e.get('source', '').startswith('zeek:')]
        return {
            'total_events': len(self.events),
            'total_alerts': len(self.alerts),
            'critical_alerts': len([a for a in self.alerts if a['severity'] == 'critical']),
            'mitre_techniques': len(self.mitre_detections),
            'sources': list(set(e.get('source', 'unknown') for e in self.events)),
            'falco_alerts': len(self.falco_events),
            'zeek_events': len(zeek_events)
        }

    def _load_falco_events(self):
        """Load Falco events from log file"""
        self.falco_events = []
        try:
            if os.path.exists(FALCO_LOG_PATH):
                with open(FALCO_LOG_PATH, 'r') as f:
                    for line in f:
                        try:
                            event = json.loads(line.strip())
                            self.falco_events.append(event)
                        except: continue
                # Sort by time (newest first)
                self.falco_events.sort(key=lambda x: x.get('time', ''), reverse=True)
                logger.info(f"Loaded {len(self.falco_events)} falco events")
        except Exception as e:
            logger.error(f"Failed to load falco events: {e}")

    def get_falco_events(self, limit: int = 100, priority: Optional[str] = None) -> List[dict]:
        """Get Falco events (reloading from file to get fresh data)"""
        # Reload to capture new alerts
        self._load_falco_events()
        
        events = self.falco_events
        if priority:
            events = [e for e in events if e.get('priority') == priority]
        return events[:limit]

    def get_zeek_events(self, limit: int = 100, log_type: Optional[str] = None) -> List[dict]:
        """Get Zeek-specific events"""
        zeek_events = [e for e in self.events if e.get('source', '').startswith('zeek:')]
        if log_type:
            zeek_events = [e for e in zeek_events if log_type in e.get('source', '')]
        return zeek_events[-limit:][::-1]
    
    def get_zeek_stats(self) -> dict:
        """Get Zeek-specific statistics"""
        zeek_events = [e for e in self.events if e.get('source', '').startswith('zeek:')]
        stats = {
            'total': len(zeek_events),
            'connections': len([e for e in zeek_events if 'conn' in e.get('source', '')]),
            'dns_queries': len([e for e in zeek_events if e.get('event_type') == 'dns_query']),
            'http_requests': len([e for e in zeek_events if e.get('event_type') == 'http_request']),
            'tls_handshakes': len([e for e in zeek_events if 'ssl' in e.get('source', '') or e.get('event_type') == 'tls_handshake']),
            'notices': len([e for e in zeek_events if 'notice' in e.get('source', '')])
        }
        return stats

    def get_zeek_events(self, limit: int = 100, log_type: Optional[str] = None) -> List[dict]:
        """Get Zeek-specific events"""
        zeek_events = [e for e in self.events if e.get('source', '').startswith('zeek:')]
        if log_type:
            zeek_events = [e for e in zeek_events if log_type in e.get('source', '')]
        return zeek_events[-limit:][::-1]
    
    def get_zeek_stats(self) -> dict:
        """Get Zeek-specific statistics"""
        zeek_events = [e for e in self.events if e.get('source', '').startswith('zeek:')]
        stats = {
            'total': len(zeek_events),
            'connections': len([e for e in zeek_events if 'conn' in e.get('source', '')]),
            'dns_queries': len([e for e in zeek_events if e.get('event_type') == 'dns_query']),
            'http_requests': len([e for e in zeek_events if e.get('event_type') == 'http_request']),
            'tls_handshakes': len([e for e in zeek_events if 'ssl' in e.get('source', '') or e.get('event_type') == 'tls_handshake']),
            'notices': len([e for e in zeek_events if 'notice' in e.get('source', '')])
        }
        return stats


# Initialize event store
store = EventStore()


# =============================================
# API Routes
# =============================================

@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve main dashboard"""
    html_path = BASE_DIR / "frontend" / "index.html"
    if html_path.exists():
        return FileResponse(html_path)
    return HTMLResponse("<h1>C2Trap Dashboard</h1><p>Frontend not found</p>")


@app.get("/api/health")
async def health():
    """Health check"""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


@app.get("/api/stats")
async def get_stats():
    """Get dashboard statistics"""
    store.sync()
    return store.get_statistics()


@app.get("/api/events")
async def get_events(
    limit: int = Query(100, ge=1, le=1000),
    event_type: Optional[str] = None
):
    """Get recent events"""
    store.sync()
    return store.get_events(limit=limit, event_type=event_type)


@app.get("/api/alerts")
async def get_alerts(
    limit: int = Query(50, ge=1, le=500),
    severity: Optional[str] = None
):
    """Get alerts"""
    store.sync()
    return store.get_alerts(limit=limit, severity=severity)


@app.get("/api/falco")
async def get_falco(
    limit: int = Query(100, ge=1, le=1000),
    priority: Optional[str] = None
):
    """Get Falco alerts"""
    return store.get_falco_events(limit=limit, priority=priority)


@app.get("/api/zeek")
async def get_zeek(
    limit: int = Query(100, ge=1, le=1000),
    log_type: Optional[str] = None
):
    """Get Zeek network events"""
    store.sync()
    return {
        'events': store.get_zeek_events(limit=limit, log_type=log_type),
        'stats': store.get_zeek_stats()
    }


@app.get("/api/iocs")
async def get_iocs(
    ioc_type: Optional[str] = None,
    malicious_only: bool = False
):
    """Get IOCs"""
    store.sync()
    return store.get_iocs(ioc_type=ioc_type, malicious_only=malicious_only)


@app.get("/api/mitre")
async def get_mitre():
    """Get MITRE ATT&CK data"""
    techniques = store.get_mitre_stats()
    
    # Build matrix structure
    # Build matrix structure
    matrix = {
        'initial-access': [],
        'execution': [],
        'persistence': [],
        'defense-evasion': [],
        'credential-access': [],
        'discovery': [],
        'lateral-movement': [],
        'command-and-control': [],
        'exfiltration': []
    }
    
    technique_info = {
        # Command & Control
        'T1071': ('Application Layer Protocol', 'command-and-control'),
        'T1071.001': ('Web Protocols', 'command-and-control'),
        'T1071.004': ('DNS', 'command-and-control'),
        'T1573': ('Encrypted Channel', 'command-and-control'),
        'T1573.002': ('Asymmetric Cryptography', 'command-and-control'),
        'T1105': ('Ingress Tool Transfer', 'command-and-control'),
        'T1568.002': ('Domain Generation Algorithms', 'command-and-control'),
        
        # Execution
        'T1059': ('Command and Scripting', 'execution'),
        'T1190': ('Exploit Public-Facing App', 'execution'),
        
        # Persistence
        'T1053': ('Scheduled Task', 'persistence'),
        
        # Initial Access
        'T1078': ('Valid Accounts', 'initial-access'),
        
        # Exfiltration
        'T1041': ('Exfiltration Over C2', 'exfiltration'),
        
        # Discovery
        'T1082': ('System Information Discovery', 'discovery'),
        'T1046': ('Network Service Scanning', 'discovery'),
        
        # Defense Evasion
        'T1027': ('Obfuscated Files', 'defense-evasion'),
        
        # Lateral Movement
        'T1021': ('Remote Services', 'lateral-movement'),
        
        # Credential Access
        'T1611': ('Container Escape', 'execution'), # Mapping escape to execution for now

        # Exfiltration (missing)
        'T1048': ('Exfiltration Over Alternative Protocol', 'exfiltration'),
        'T1041': ('Exfiltration Over C2 Channel', 'exfiltration')
    }
    
    for tech_id, count in techniques.items():
        if tech_id in technique_info:
            name, tactic = technique_info[tech_id]
            if tactic in matrix:
                matrix[tactic].append({
                    'id': tech_id,
                    'name': name,
                    'count': count,
                    'detected': True
                })
    
    return {
        'techniques': techniques,
        'matrix': matrix,
        'total_detections': sum(techniques.values())
    }


@app.get("/api/killchain")
async def get_killchain():
    """Get kill chain data"""
    # Simplified kill chain based on events
    phases = [
        {'name': 'Reconnaissance', 'order': 1, 'color': '#6c5ce7', 'active': False, 'events': 0},
        {'name': 'Delivery', 'order': 2, 'color': '#fd79a8', 'active': False, 'events': 0},
        {'name': 'Exploitation', 'order': 3, 'color': '#e17055', 'active': False, 'events': 0},
        {'name': 'Installation', 'order': 4, 'color': '#fdcb6e', 'active': False, 'events': 0},
        {'name': 'Command & Control', 'order': 5, 'color': '#00cec9', 'active': False, 'events': 0},
        {'name': 'Actions', 'order': 6, 'color': '#e84393', 'active': False, 'events': 0},
    ]
    
    # Check events for phase indicators
    for event in store.events:
        event_type = event.get('event_type', '').lower()
        if 'beacon' in event_type or 'c2' in event_type or 'http_connection' in event_type:
            phases[4]['active'] = True
            phases[4]['events'] += 1
        elif 'download' in event_type or 'payload' in event_type:
            phases[1]['active'] = True
            phases[1]['events'] += 1
        elif 'exfil' in event_type or 'upload' in event_type:
            phases[5]['active'] = True
            phases[5]['events'] += 1
    
    return {'phases': phases}


@app.post("/api/events")
async def add_event(event: Event):
    """Add a new event (for testing)"""
    store.add_event(event.dict())
    return {"status": "added"}


# Add project root to path for imports
sys.path.insert(0, str(BASE_DIR.parent))

from intelligence.virustotal.vt_client import get_client

# ... (existing imports)

class EnrichmentRequest(BaseModel):
    value: str
    type: str

# ... (existing code)

def run_enrichment(ioc_type: str, value: str):
    """Background task to enrich IOC"""
    try:
        client = get_client()
        if not client:
            return
            
        result = client.enrich_ioc(ioc_type, value)
        if result:
            key = f"{ioc_type}:{value}"
            if key in store.iocs:
                store.iocs[key]['virus_total'] = result
                # Update malicious status and threat score from VT results
                if result.get('is_malicious'):
                    store.iocs[key]['is_malicious'] = True
                store.iocs[key]['threat_score'] = result.get('threat_score', 0)
    except Exception as e:
        logger.error(f"Background enrichment failed for {value}: {e}")

@app.post("/api/enrich")
async def enrich_ioc(request: EnrichmentRequest, background_tasks: BackgroundTasks):
    """Enrich IOC with VirusTotal data (Async)"""
    try:
        client = get_client()
        if not client:
            raise HTTPException(status_code=503, detail="Intelligence service unavailable")
            
        key = f"{request.type}:{request.value}"
        
        # Check cache first for instant response
        cached = client.cache.get(request.type, request.value)
        if cached:
            if key in store.iocs:
                store.iocs[key]['virus_total'] = cached
                if cached.get('is_malicious'):
                    store.iocs[key]['is_malicious'] = True
                store.iocs[key]['threat_score'] = cached.get('threat_score', 0)
            return cached

        # Queue background task
        background_tasks.add_task(run_enrichment, request.type, request.value)
        return {"status": "queued", "message": "Enrichment started in background"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Enrichment request failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Mount static files
static_path = BASE_DIR / "frontend" / "static"
if static_path.exists():
    app.mount("/static", StaticFiles(directory=str(static_path)), name="static")

try:
    from reporting import generate_report
    REPORT_AVAILABLE = True
    logger.info('Report module loaded successfully')
except Exception as e:
    REPORT_AVAILABLE = False
    logger.warning(f'Report module not available: {e}')

@app.get("/api/report/download")
async def download_report():
    """Generate and download HTML security report"""
    if not REPORT_AVAILABLE:
        raise HTTPException(status_code=500, detail="Reporting module not available")
    
    try:
        store.sync()
        stats = store.get_statistics()
        stats['mitre_techniques'] = list(store.mitre_detections.keys())
        # Use pre-computed counts instead of iterating all alerts
        stats['high_severity'] = stats.get('critical_alerts', 0)
        stats['sources'] = stats.get('sources', [])
        
        # Get the most significant alerts (limit to 30 for report)
        alerts = store.get_alerts(limit=30)
        
        report_dir = BASE_DIR / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / f"c2trap_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        generate_report(stats, alerts, str(report_path))
        
        if not report_path.exists():
            raise HTTPException(status_code=500, detail="Report generation failed")
        
        return FileResponse(
            report_path, 
            media_type='text/html', 
            filename=report_path.name
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Report error: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
