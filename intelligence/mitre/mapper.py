"""
C2Trap MITRE ATT&CK Mapper
Map detected behaviors to MITRE techniques
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from pathlib import Path

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('mitre_mapper')

LOG_PATH = os.environ.get('LOG_PATH', '/app/logs/analysis_queue.jsonl')
MITRE_CONFIG = os.environ.get('MITRE_CONFIG', '/app/config/mitre_mappings.json')


def log_event(event_type: str, data: dict) -> None:
    """Write event to analysis queue"""
    event = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'source': 'mitre_mapper',
        'event_type': event_type,
        'data': data
    }
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, 'a') as f:
            f.write(json.dumps(event) + '\n')
    except Exception as e:
        logger.error(f"Failed to write log: {e}")


@dataclass
class TechniqueDetection:
    """A detected MITRE technique"""
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float
    evidence: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class MITREMapper:
    """Map events to MITRE ATT&CK techniques"""
    
    # Built-in technique definitions
    TECHNIQUES = {
        'T1071': {
            'name': 'Application Layer Protocol',
            'tactic': 'command-and-control',
            'indicators': ['http_beacon', 'https_connection', 'dns_query', 'c2_connection']
        },
        'T1071.001': {
            'name': 'Web Protocols',
            'tactic': 'command-and-control',
            'indicators': ['http_beacon', 'https_post', 'web_c2']
        },
        'T1071.004': {
            'name': 'DNS',
            'tactic': 'command-and-control',
            'indicators': ['dns_c2', 'dns_tunnel', 'suspicious_dns']
        },
        'T1573': {
            'name': 'Encrypted Channel',
            'tactic': 'command-and-control',
            'indicators': ['tls_connection', 'encrypted_c2', 'ssl_beacon']
        },
        'T1573.002': {
            'name': 'Asymmetric Cryptography',
            'tactic': 'command-and-control',
            'indicators': ['tls_handshake', 'ssl_certificate', 'rsa_key_exchange']
        },
        'T1105': {
            'name': 'Ingress Tool Transfer',
            'tactic': 'command-and-control',
            'indicators': ['file_download', 'payload_fetch', 'tool_transfer']
        },
        'T1041': {
            'name': 'Exfiltration Over C2 Channel',
            'tactic': 'exfiltration',
            'indicators': ['data_upload', 'file_exfil', 'c2_exfil']
        },
        'T1059': {
            'name': 'Command and Scripting Interpreter',
            'tactic': 'execution',
            'indicators': ['shell_command', 'script_execution', 'cmd_run']
        },
        'T1059.001': {
            'name': 'PowerShell',
            'tactic': 'execution',
            'indicators': ['powershell', 'ps1_execution', 'encoded_command']
        },
        'T1059.003': {
            'name': 'Windows Command Shell',
            'tactic': 'execution',
            'indicators': ['cmd.exe', 'batch_file', 'command_prompt']
        },
        'T1053': {
            'name': 'Scheduled Task/Job',
            'tactic': 'persistence',
            'indicators': ['task_scheduler', 'cron_job', 'at_command']
        },
        'T1082': {
            'name': 'System Information Discovery',
            'tactic': 'discovery',
            'indicators': ['sysinfo', 'hostname_query', 'os_version']
        },
        'T1083': {
            'name': 'File and Directory Discovery',
            'tactic': 'discovery',
            'indicators': ['dir_listing', 'file_search', 'path_enum']
        },
        'T1057': {
            'name': 'Process Discovery',
            'tactic': 'discovery',
            'indicators': ['process_list', 'task_list', 'ps_command']
        },
        'T1027': {
            'name': 'Obfuscated Files or Information',
            'tactic': 'defense-evasion',
            'indicators': ['base64_encoded', 'packed_binary', 'encrypted_payload']
        },
        'T1140': {
            'name': 'Deobfuscate/Decode Files or Information',
            'tactic': 'defense-evasion',
            'indicators': ['base64_decode', 'xor_decode', 'payload_unpack']
        }
    }
    
    TACTICS = {
        'initial-access': {'order': 1, 'color': '#e74c3c'},
        'execution': {'order': 2, 'color': '#e67e22'},
        'persistence': {'order': 3, 'color': '#f1c40f'},
        'privilege-escalation': {'order': 4, 'color': '#2ecc71'},
        'defense-evasion': {'order': 5, 'color': '#1abc9c'},
        'credential-access': {'order': 6, 'color': '#3498db'},
        'discovery': {'order': 7, 'color': '#9b59b6'},
        'lateral-movement': {'order': 8, 'color': '#34495e'},
        'collection': {'order': 9, 'color': '#e91e63'},
        'command-and-control': {'order': 10, 'color': '#ff5722'},
        'exfiltration': {'order': 11, 'color': '#795548'},
        'impact': {'order': 12, 'color': '#607d8b'}
    }
    
    def __init__(self):
        self.detections: List[TechniqueDetection] = []
        self.detected_techniques: Set[str] = set()
        self._load_config()
    
    def _load_config(self):
        """Load additional technique mappings from config"""
        try:
            if os.path.exists(MITRE_CONFIG):
                with open(MITRE_CONFIG, 'r') as f:
                    config = json.load(f)
                    self.TECHNIQUES.update(config.get('techniques', {}))
        except Exception as e:
            logger.debug(f"Could not load MITRE config: {e}")
    
    def map_event(self, event_type: str, event_data: dict) -> List[TechniqueDetection]:
        """Map an event to MITRE techniques"""
        detections = []
        
        # Check explicit technique in event
        if 'mitre_technique' in event_data:
            tech_id = event_data['mitre_technique']
            if tech_id in self.TECHNIQUES:
                det = self._create_detection(tech_id, event_data, confidence=0.9)
                detections.append(det)
        
        # Map by event type patterns
        type_mappings = {
            'http_connection': ['T1071.001'],
            'https_connection': ['T1071.001', 'T1573'],
            'dns_query': ['T1071.004'],
            'c2_beacon': ['T1071'],
            'c2_interaction': ['T1071'],
            'beacon_detected': ['T1071'],
            'ftp_upload': ['T1041'],
            'ftp_download': ['T1105'],
            'file_download': ['T1105'],
            'file_upload': ['T1041'],
            'ja3_fingerprint': ['T1573.002'],
            'malware_detected': ['T1071'],
            'shell_execution': ['T1059'],
            'process_spawn': ['T1059'],
        }
        
        for pattern, techniques in type_mappings.items():
            if pattern in event_type.lower():
                for tech_id in techniques:
                    if tech_id in self.TECHNIQUES:
                        det = self._create_detection(tech_id, event_data, confidence=0.7)
                        detections.append(det)
        
        # Log detections
        for det in detections:
            self._record_detection(det)
        
        return detections
    
    def _create_detection(self, technique_id: str, event_data: dict, 
                          confidence: float = 0.5) -> TechniqueDetection:
        """Create a technique detection"""
        tech = self.TECHNIQUES.get(technique_id, {})
        
        evidence = []
        if 'remote_ip' in event_data:
            evidence.append(f"IP: {event_data['remote_ip']}")
        if 'path' in event_data:
            evidence.append(f"Path: {event_data['path']}")
        if 'domain' in event_data:
            evidence.append(f"Domain: {event_data['domain']}")
        
        return TechniqueDetection(
            technique_id=technique_id,
            technique_name=tech.get('name', 'Unknown'),
            tactic=tech.get('tactic', 'unknown'),
            confidence=confidence,
            evidence=evidence
        )
    
    def _record_detection(self, detection: TechniqueDetection):
        """Record a detection"""
        self.detections.append(detection)
        self.detected_techniques.add(detection.technique_id)
        
        log_event('technique_detected', {
            'technique_id': detection.technique_id,
            'technique_name': detection.technique_name,
            'tactic': detection.tactic,
            'confidence': detection.confidence,
            'evidence': detection.evidence
        })
        
        logger.info(f"[MITRE] Detected {detection.technique_id}: {detection.technique_name}")
    
    def get_detected_techniques(self) -> List[dict]:
        """Get all detected techniques"""
        return [
            {
                'technique_id': d.technique_id,
                'technique_name': d.technique_name,
                'tactic': d.tactic,
                'confidence': d.confidence,
                'evidence': d.evidence,
                'timestamp': d.timestamp
            }
            for d in self.detections
        ]
    
    def get_tactic_coverage(self) -> Dict[str, dict]:
        """Get coverage by tactic"""
        coverage = {}
        for tactic, info in self.TACTICS.items():
            techniques = [d for d in self.detections if d.tactic == tactic]
            coverage[tactic] = {
                'count': len(techniques),
                'techniques': list(set(d.technique_id for d in techniques)),
                'color': info['color'],
                'order': info['order']
            }
        return coverage
    
    def get_technique_matrix(self) -> Dict[str, List[dict]]:
        """Get technique matrix grouped by tactic"""
        matrix = {}
        for tactic in self.TACTICS:
            matrix[tactic] = []
        
        for tech_id, tech in self.TECHNIQUES.items():
            tactic = tech.get('tactic', 'unknown')
            if tactic in matrix:
                matrix[tactic].append({
                    'id': tech_id,
                    'name': tech['name'],
                    'detected': tech_id in self.detected_techniques
                })
        
        return matrix
    
    def get_statistics(self) -> dict:
        """Get mapping statistics"""
        return {
            'total_detections': len(self.detections),
            'unique_techniques': len(self.detected_techniques),
            'tactics_covered': len(set(d.tactic for d in self.detections)),
            'techniques': list(self.detected_techniques)
        }


# Singleton instance
_mapper = None

def get_mapper() -> MITREMapper:
    global _mapper
    if _mapper is None:
        _mapper = MITREMapper()
    return _mapper


if __name__ == '__main__':
    mapper = MITREMapper()
    
    # Test mapping
    test_events = [
        ('http_connection', {'remote_ip': '10.0.0.1', 'path': '/api/beacon'}),
        ('dns_query', {'domain': 'c2.malware.com', 'mitre_technique': 'T1071.004'}),
        ('beacon_detected', {'src_ip': '192.168.1.100', 'interval': 60}),
    ]
    
    for event_type, event_data in test_events:
        detections = mapper.map_event(event_type, event_data)
        print(f"Event: {event_type} -> {[d.technique_id for d in detections]}")
    
    print(f"\nStatistics: {mapper.get_statistics()}")
