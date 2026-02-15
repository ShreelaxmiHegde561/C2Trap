"""
C2Trap Kill Chain Tracker
Track attack progression through Cyber Kill Chain phases
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, field

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('killchain')

LOG_PATH = os.environ.get('LOG_PATH', '/app/logs/analysis_queue.jsonl')


def log_event(event_type: str, data: dict) -> None:
    """Write event to analysis queue"""
    event = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'source': 'killchain',
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
class KillChainPhase:
    """A phase in the kill chain"""
    name: str
    order: int
    description: str
    color: str
    events: List[dict] = field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    active: bool = False


class KillChainTracker:
    """Track attack progression through kill chain phases"""
    
    # Lockheed Martin Cyber Kill Chain phases
    PHASES = {
        'reconnaissance': {
            'order': 1,
            'description': 'Research, identification, and selection of targets',
            'color': '#6c5ce7',
            'mitre_tactics': [],
            'indicators': ['scan', 'probe', 'enum']
        },
        'weaponization': {
            'order': 2,
            'description': 'Creating malware/exploit payload',
            'color': '#a29bfe',
            'mitre_tactics': [],
            'indicators': ['payload', 'exploit', 'malware']
        },
        'delivery': {
            'order': 3,
            'description': 'Transmission of weapon to target',
            'color': '#fd79a8',
            'mitre_tactics': ['initial-access'],
            'indicators': ['phish', 'download', 'dropper']
        },
        'exploitation': {
            'order': 4,
            'description': 'Exploitation of vulnerability to gain access',
            'color': '#e17055',
            'mitre_tactics': ['execution'],
            'indicators': ['exploit', 'shell', 'execute']
        },
        'installation': {
            'order': 5,
            'description': 'Installation of backdoor/implant',
            'color': '#fdcb6e',
            'mitre_tactics': ['persistence'],
            'indicators': ['install', 'persist', 'backdoor']
        },
        'command_control': {
            'order': 6,
            'description': 'C2 channel established',
            'color': '#00cec9',
            'mitre_tactics': ['command-and-control'],
            'indicators': ['beacon', 'c2', 'callback', 'heartbeat']
        },
        'actions_on_objectives': {
            'order': 7,
            'description': 'Achieving original goals',
            'color': '#e84393',
            'mitre_tactics': ['exfiltration', 'impact'],
            'indicators': ['exfil', 'encrypt', 'destroy', 'steal']
        }
    }
    
    def __init__(self, attack_id: Optional[str] = None):
        self.attack_id = attack_id or datetime.utcnow().strftime('%Y%m%d%H%M%S')
        self.phases: Dict[str, KillChainPhase] = {}
        self._init_phases()
        self.start_time = datetime.utcnow().isoformat()
    
    def _init_phases(self):
        """Initialize kill chain phases"""
        for name, info in self.PHASES.items():
            self.phases[name] = KillChainPhase(
                name=name,
                order=info['order'],
                description=info['description'],
                color=info['color']
            )
    
    def record_event(self, event_type: str, event_data: dict,
                     phase: Optional[str] = None) -> Optional[str]:
        """Record an event and determine its kill chain phase"""
        # Auto-detect phase if not specified
        if not phase:
            phase = self._detect_phase(event_type, event_data)
        
        if not phase or phase not in self.phases:
            return None
        
        now = datetime.utcnow().isoformat()
        
        phase_obj = self.phases[phase]
        phase_obj.events.append({
            'event_type': event_type,
            'data': event_data,
            'timestamp': now
        })
        
        if not phase_obj.first_seen:
            phase_obj.first_seen = now
            phase_obj.active = True
            
            log_event('killchain_phase_started', {
                'attack_id': self.attack_id,
                'phase': phase,
                'phase_order': phase_obj.order,
                'event_type': event_type
            })
            
            logger.warning(f"[KILLCHAIN] Phase activated: {phase}")
        
        phase_obj.last_seen = now
        
        return phase
    
    def _detect_phase(self, event_type: str, event_data: dict) -> Optional[str]:
        """Auto-detect kill chain phase from event"""
        event_lower = event_type.lower()
        
        # Check for explicit MITRE tactic
        if 'tactic' in event_data:
            tactic = event_data['tactic']
            for phase_name, phase_info in self.PHASES.items():
                if tactic in phase_info['mitre_tactics']:
                    return phase_name
        
        # Check indicators
        for phase_name, phase_info in self.PHASES.items():
            for indicator in phase_info['indicators']:
                if indicator in event_lower:
                    return phase_name
        
        # Default mappings for common events
        event_phase_map = {
            'c2_beacon': 'command_control',
            'c2_interaction': 'command_control',
            'beacon_detected': 'command_control',
            'http_connection': 'command_control',
            'dns_query': 'command_control',
            'file_upload': 'actions_on_objectives',
            'data_exfil': 'actions_on_objectives',
            'file_download': 'delivery',
            'payload_request': 'delivery',
            'shell_execution': 'exploitation',
            'process_spawn': 'exploitation',
            'task_creation': 'installation',
            'persistence_detected': 'installation',
        }
        
        for pattern, phase in event_phase_map.items():
            if pattern in event_lower:
                return phase
        
        return None
    
    def get_active_phases(self) -> List[dict]:
        """Get all active phases"""
        return [
            {
                'name': p.name,
                'order': p.order,
                'description': p.description,
                'color': p.color,
                'event_count': len(p.events),
                'first_seen': p.first_seen,
                'last_seen': p.last_seen
            }
            for p in sorted(self.phases.values(), key=lambda x: x.order)
            if p.active
        ]
    
    def get_timeline(self) -> List[dict]:
        """Get chronological timeline of phase activations"""
        timeline = []
        for phase in self.phases.values():
            if phase.active and phase.first_seen:
                timeline.append({
                    'phase': phase.name,
                    'order': phase.order,
                    'color': phase.color,
                    'timestamp': phase.first_seen,
                    'event_count': len(phase.events)
                })
        
        return sorted(timeline, key=lambda x: x['timestamp'])
    
    def get_phase_details(self, phase_name: str) -> Optional[dict]:
        """Get detailed info about a specific phase"""
        if phase_name not in self.phases:
            return None
        
        phase = self.phases[phase_name]
        return {
            'name': phase.name,
            'order': phase.order,
            'description': phase.description,
            'color': phase.color,
            'active': phase.active,
            'first_seen': phase.first_seen,
            'last_seen': phase.last_seen,
            'events': phase.events[-10:]  # Last 10 events
        }
    
    def get_progression(self) -> dict:
        """Get attack progression summary"""
        active_phases = [p for p in self.phases.values() if p.active]
        max_phase = max((p.order for p in active_phases), default=0)
        
        return {
            'attack_id': self.attack_id,
            'start_time': self.start_time,
            'phases_activated': len(active_phases),
            'total_phases': len(self.PHASES),
            'max_phase_reached': max_phase,
            'total_events': sum(len(p.events) for p in self.phases.values()),
            'active_phase_names': [p.name for p in active_phases]
        }
    
    def get_full_chain(self) -> List[dict]:
        """Get full kill chain with status"""
        return [
            {
                'name': p.name,
                'order': p.order,
                'description': p.description,
                'color': p.color,
                'active': p.active,
                'event_count': len(p.events) if p.active else 0
            }
            for p in sorted(self.phases.values(), key=lambda x: x.order)
        ]


# Global tracker instance
_tracker = None

def get_tracker() -> KillChainTracker:
    global _tracker
    if _tracker is None:
        _tracker = KillChainTracker()
    return _tracker


if __name__ == '__main__':
    tracker = KillChainTracker()
    
    # Simulate attack progression
    events = [
        ('beacon_detected', {'src_ip': '192.168.1.100'}),
        ('c2_beacon', {'path': '/api/beacon'}),
        ('file_download', {'filename': 'payload.exe'}),
        ('shell_execution', {'command': 'whoami'}),
        ('data_exfil', {'size': 1024}),
    ]
    
    for event_type, event_data in events:
        phase = tracker.record_event(event_type, event_data)
        print(f"Event: {event_type} -> Phase: {phase}")
    
    print(f"\nProgression: {tracker.get_progression()}")
    print(f"\nTimeline: {tracker.get_timeline()}")
