#!/usr/bin/env python3
"""
C2Trap Baseline Learner
=======================

ML-lite baseline learning to reduce false positives.
Learns normal traffic patterns and scores anomalies.

Features:
- Connection frequency profiling
- Domain access pattern learning
- Time-based activity baselines
- Adaptive threshold calculation
- Whitelist/allowlist generation
"""

import os
import json
import time
import math
import logging
import pickle
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Tuple
from collections import defaultdict, Counter
from dataclasses import dataclass, field, asdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('baseline_learner')

LOG_PATH = os.environ.get('LOG_PATH', '/app/logs/analysis_queue.jsonl')
BASELINE_PATH = os.environ.get('BASELINE_PATH', '/app/data/baseline.pkl')


def log_event(event_type: str, data: dict) -> None:
    """Write event to analysis queue"""
    event = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'source': 'baseline_learner',
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
class ConnectionProfile:
    """Profile for an IP/domain connection pattern"""
    target: str
    first_seen: float
    last_seen: float
    connection_count: int = 0
    total_bytes: int = 0
    ports_used: Set[int] = field(default_factory=set)
    hours_active: Set[int] = field(default_factory=set)  # Hours of day (0-23)
    avg_interval: float = 0.0
    intervals: List[float] = field(default_factory=list)


@dataclass 
class DomainProfile:
    """Profile for a domain's access patterns"""
    domain: str
    first_seen: float
    access_count: int = 0
    unique_sources: Set[str] = field(default_factory=set)
    is_whitelisted: bool = False
    whitelist_reason: str = ""


class BaselineLearner:
    """
    Learn normal traffic patterns to reduce false positives
    
    Operating Modes:
    1. Learning Mode (first 24h): Observe and build baseline
    2. Detection Mode: Score new traffic against baseline
    
    Features:
    - IP connection frequency profiling
    - Domain popularity tracking
    - Time-of-day activity patterns
    - Auto-whitelisting of common destinations
    """
    
    # Known legitimate services to auto-whitelist
    KNOWN_LEGITIMATE = {
        'google.com', 'googleapis.com', 'gstatic.com',
        'microsoft.com', 'windows.com', 'azure.com',
        'amazon.com', 'amazonaws.com', 'cloudfront.net',
        'github.com', 'githubusercontent.com',
        'cloudflare.com', 'cloudflare-dns.com',
        'ubuntu.com', 'debian.org', 'redhat.com',
        'docker.io', 'docker.com',
        'npmjs.org', 'pypi.org'
    }
    
    # Auto-whitelist threshold (connections per hour)
    WHITELIST_THRESHOLD = 50
    
    # Learning period (24 hours)
    LEARNING_PERIOD_HOURS = 24
    
    def __init__(self, learning_mode: bool = True):
        """
        Initialize baseline learner
        
        Args:
            learning_mode: Start in learning mode (default True)
        """
        self.learning_mode = learning_mode
        self.start_time = time.time()
        
        # Connection profiles by destination IP
        self.ip_profiles: Dict[str, ConnectionProfile] = {}
        
        # Domain profiles
        self.domain_profiles: Dict[str, DomainProfile] = {}
        
        # Whitelisted destinations
        self.whitelist: Set[str] = set(self.KNOWN_LEGITIMATE)
        
        # Time-based patterns (hour -> connection count)
        self.hourly_patterns: Dict[int, int] = defaultdict(int)
        
        # Statistics
        self.total_connections = 0
        self.anomalies_detected = 0
        self.false_positive_reductions = 0
        
        # Load existing baseline if available
        self._load_baseline()
        
        logger.info(f"Baseline Learner initialized (learning_mode: {learning_mode})")
    
    def learn(self, connection: Dict) -> None:
        """
        Learn from observed connection
        
        Args:
            connection: Dict with src_ip, dst_ip, dst_port, domain, size, timestamp
        """
        self.total_connections += 1
        
        # Extract fields
        dst_ip = connection.get('dst_ip', '')
        domain = connection.get('domain', '')
        port = connection.get('dst_port', 0)
        size = connection.get('size', 0)
        timestamp = connection.get('timestamp', time.time())
        src_ip = connection.get('src_ip', '')
        
        hour = datetime.fromtimestamp(timestamp).hour
        
        # Update hourly patterns
        self.hourly_patterns[hour] += 1
        
        # Update IP profile
        if dst_ip:
            self._update_ip_profile(dst_ip, port, size, timestamp, hour)
        
        # Update domain profile
        if domain:
            self._update_domain_profile(domain, src_ip, timestamp)
        
        # Auto-whitelist check (only in learning mode)
        if self.learning_mode:
            self._check_auto_whitelist(domain, dst_ip)
    
    def _update_ip_profile(self, ip: str, port: int, size: int, 
                           timestamp: float, hour: int) -> None:
        """Update IP connection profile"""
        if ip not in self.ip_profiles:
            self.ip_profiles[ip] = ConnectionProfile(
                target=ip,
                first_seen=timestamp,
                last_seen=timestamp
            )
        
        profile = self.ip_profiles[ip]
        profile.connection_count += 1
        profile.total_bytes += size
        profile.ports_used.add(port)
        profile.hours_active.add(hour)
        
        # Calculate interval
        if profile.last_seen != timestamp:
            interval = timestamp - profile.last_seen
            profile.intervals.append(interval)
            profile.intervals = profile.intervals[-100:]  # Keep last 100
            profile.avg_interval = sum(profile.intervals) / len(profile.intervals)
        
        profile.last_seen = timestamp
    
    def _update_domain_profile(self, domain: str, src_ip: str, timestamp: float) -> None:
        """Update domain access profile"""
        # Normalize domain
        domain = domain.lower().rstrip('.')
        
        if domain not in self.domain_profiles:
            self.domain_profiles[domain] = DomainProfile(
                domain=domain,
                first_seen=timestamp
            )
        
        profile = self.domain_profiles[domain]
        profile.access_count += 1
        profile.unique_sources.add(src_ip)
    
    def _check_auto_whitelist(self, domain: str, ip: str) -> None:
        """Check if destination should be auto-whitelisted"""
        if domain:
            domain = domain.lower().rstrip('.')
            
            # Check if it's a subdomain of known legitimate
            for known in self.KNOWN_LEGITIMATE:
                if domain.endswith(known) or domain == known:
                    self.whitelist.add(domain)
                    return
            
            # Check frequency threshold
            if domain in self.domain_profiles:
                profile = self.domain_profiles[domain]
                if profile.access_count >= self.WHITELIST_THRESHOLD:
                    profile.is_whitelisted = True
                    profile.whitelist_reason = f"High access count ({profile.access_count})"
                    self.whitelist.add(domain)
                    logger.info(f"Auto-whitelisted: {domain} (count: {profile.access_count})")
    
    def get_anomaly_score(self, connection: Dict) -> Tuple[float, List[str]]:
        """
        Score how anomalous a connection is
        
        Args:
            connection: Connection to score
            
        Returns:
            Tuple of (anomaly_score 0-100, list of reasons)
        """
        if self.learning_mode:
            return 0.0, ["In learning mode"]
        
        score = 0.0
        reasons = []
        
        dst_ip = connection.get('dst_ip', '')
        domain = connection.get('domain', '')
        port = connection.get('dst_port', 0)
        timestamp = connection.get('timestamp', time.time())
        hour = datetime.fromtimestamp(timestamp).hour
        
        # Check whitelist first
        if self._is_whitelisted(domain, dst_ip):
            self.false_positive_reductions += 1
            return 0.0, ["Whitelisted destination"]
        
        # 1. New destination penalty
        if dst_ip and dst_ip not in self.ip_profiles:
            score += 20
            reasons.append("New destination IP")
        
        if domain and domain.lower() not in self.domain_profiles:
            score += 15
            reasons.append("New domain")
        
        # 2. Unusual port
        if dst_ip in self.ip_profiles:
            profile = self.ip_profiles[dst_ip]
            if port and port not in profile.ports_used:
                score += 10
                reasons.append(f"Unusual port: {port}")
        
        # 3. Unusual time
        avg_hourly = sum(self.hourly_patterns.values()) / 24 if self.hourly_patterns else 0
        if avg_hourly > 0:
            current_hour_count = self.hourly_patterns.get(hour, 0)
            if current_hour_count < avg_hourly * 0.2:  # Less than 20% of average
                score += 15
                reasons.append(f"Unusual time of day (hour {hour})")
        
        # 4. Connection pattern anomaly
        if dst_ip in self.ip_profiles:
            profile = self.ip_profiles[dst_ip]
            
            # Check if connection pattern changed
            if profile.avg_interval > 0:
                expected_next = profile.last_seen + profile.avg_interval
                deviation = abs(timestamp - expected_next) / profile.avg_interval
                if deviation > 3:  # More than 3x expected interval deviation
                    score += 10
                    reasons.append("Unusual connection pattern")
        
        # 5. Low domain popularity
        if domain in self.domain_profiles:
            profile = self.domain_profiles[domain]
            if profile.access_count < 5 and len(profile.unique_sources) == 1:
                score += 15
                reasons.append("Low popularity domain (single source)")
        
        # Normalize to 0-100
        score = min(score, 100)
        
        if score > 50:
            self.anomalies_detected += 1
            log_event('baseline_anomaly', {
                'dst_ip': dst_ip,
                'domain': domain,
                'score': score,
                'reasons': reasons
            })
        
        return score, reasons
    
    def _is_whitelisted(self, domain: str, ip: str) -> bool:
        """Check if destination is whitelisted"""
        if domain:
            domain = domain.lower().rstrip('.')
            
            # Direct match
            if domain in self.whitelist:
                return True
            
            # Subdomain match
            for wl in self.whitelist:
                if domain.endswith('.' + wl):
                    return True
        
        # IP whitelist (could add in future)
        return False
    
    def is_learning_complete(self) -> bool:
        """Check if learning period is complete"""
        elapsed_hours = (time.time() - self.start_time) / 3600
        return elapsed_hours >= self.LEARNING_PERIOD_HOURS
    
    def switch_to_detection_mode(self) -> None:
        """Switch from learning to detection mode"""
        self.learning_mode = False
        self._save_baseline()
        
        log_event('baseline_learning_complete', {
            'total_connections': self.total_connections,
            'ip_profiles': len(self.ip_profiles),
            'domain_profiles': len(self.domain_profiles),
            'whitelist_size': len(self.whitelist)
        })
        
        logger.info("Switched to detection mode")
        logger.info(f"  Learned {len(self.ip_profiles)} IP profiles")
        logger.info(f"  Learned {len(self.domain_profiles)} domain profiles")
        logger.info(f"  Whitelist size: {len(self.whitelist)}")
    
    def add_to_whitelist(self, destination: str, reason: str = "Manual") -> None:
        """Manually add destination to whitelist"""
        destination = destination.lower().rstrip('.')
        self.whitelist.add(destination)
        
        if destination in self.domain_profiles:
            self.domain_profiles[destination].is_whitelisted = True
            self.domain_profiles[destination].whitelist_reason = reason
        
        logger.info(f"Added to whitelist: {destination} ({reason})")
    
    def get_adaptive_threshold(self) -> float:
        """
        Calculate adaptive detection threshold based on baseline
        
        Returns:
            Recommended threshold for beacon detection
        """
        if not self.ip_profiles:
            return 50.0  # Default
        
        # Calculate average activity level
        avg_connections = sum(p.connection_count for p in self.ip_profiles.values()) / len(self.ip_profiles)
        
        # More active networks need higher thresholds
        if avg_connections > 1000:
            return 60.0
        elif avg_connections > 100:
            return 50.0
        else:
            return 40.0
    
    def get_statistics(self) -> Dict:
        """Get baseline statistics"""
        return {
            'mode': 'learning' if self.learning_mode else 'detection',
            'total_connections': self.total_connections,
            'ip_profiles_count': len(self.ip_profiles),
            'domain_profiles_count': len(self.domain_profiles),
            'whitelist_size': len(self.whitelist),
            'anomalies_detected': self.anomalies_detected,
            'false_positive_reductions': self.false_positive_reductions,
            'learning_progress': min(1.0, (time.time() - self.start_time) / (self.LEARNING_PERIOD_HOURS * 3600)),
            'top_domains': self._get_top_domains(10),
            'hourly_distribution': dict(self.hourly_patterns)
        }
    
    def _get_top_domains(self, n: int) -> List[Dict]:
        """Get top N most accessed domains"""
        sorted_domains = sorted(
            self.domain_profiles.values(),
            key=lambda x: x.access_count,
            reverse=True
        )
        return [
            {
                'domain': d.domain,
                'count': d.access_count,
                'whitelisted': d.is_whitelisted
            }
            for d in sorted_domains[:n]
        ]
    
    def _save_baseline(self) -> None:
        """Save baseline to disk"""
        try:
            os.makedirs(os.path.dirname(BASELINE_PATH), exist_ok=True)
            
            # Convert sets to lists for serialization
            data = {
                'start_time': self.start_time,
                'learning_mode': self.learning_mode,
                'whitelist': list(self.whitelist),
                'hourly_patterns': dict(self.hourly_patterns),
                'total_connections': self.total_connections,
                # Simplified profiles (skip complex objects)
                'ip_count': len(self.ip_profiles),
                'domain_count': len(self.domain_profiles)
            }
            
            with open(BASELINE_PATH, 'wb') as f:
                pickle.dump(data, f)
            
            logger.info(f"Baseline saved to {BASELINE_PATH}")
            
        except Exception as e:
            logger.error(f"Failed to save baseline: {e}")
    
    def _load_baseline(self) -> None:
        """Load baseline from disk"""
        if not os.path.exists(BASELINE_PATH):
            return
        
        try:
            with open(BASELINE_PATH, 'rb') as f:
                data = pickle.load(f)
            
            self.whitelist = set(data.get('whitelist', []))
            self.whitelist.update(self.KNOWN_LEGITIMATE)
            self.hourly_patterns = defaultdict(int, data.get('hourly_patterns', {}))
            self.total_connections = data.get('total_connections', 0)
            
            # If previously in detection mode and baseline exists
            if not data.get('learning_mode', True):
                self.learning_mode = False
            
            logger.info(f"Baseline loaded from {BASELINE_PATH}")
            
        except Exception as e:
            logger.error(f"Failed to load baseline: {e}")


# Singleton
_learner = None

def get_learner() -> BaselineLearner:
    global _learner
    if _learner is None:
        _learner = BaselineLearner()
    return _learner


if __name__ == '__main__':
    import random
    
    # Demo
    learner = BaselineLearner(learning_mode=True)
    
    # Simulate learning phase
    print("Simulating learning phase...")
    
    domains = ['google.com', 'github.com', 'api.internal.com', 'cdn.cloudflare.net']
    
    for i in range(100):
        learner.learn({
            'src_ip': '192.168.1.100',
            'dst_ip': f'10.0.0.{random.randint(1, 10)}',
            'domain': random.choice(domains),
            'dst_port': random.choice([80, 443, 8080]),
            'size': random.randint(100, 5000),
            'timestamp': time.time() - random.randint(0, 86400)
        })
    
    print(f"\nStatistics: {json.dumps(learner.get_statistics(), indent=2)}")
    
    # Switch to detection
    learner.switch_to_detection_mode()
    
    # Test anomaly detection
    print("\nTesting anomaly detection...")
    
    # Normal traffic
    score, reasons = learner.get_anomaly_score({
        'dst_ip': '10.0.0.1',
        'domain': 'google.com',
        'dst_port': 443,
        'timestamp': time.time()
    })
    print(f"Normal traffic: score={score}, reasons={reasons}")
    
    # Anomalous traffic
    score, reasons = learner.get_anomaly_score({
        'dst_ip': '185.143.223.1',
        'domain': 'evil.xyz',
        'dst_port': 4444,
        'timestamp': time.time()
    })
    print(f"Anomalous traffic: score={score}, reasons={reasons}")
