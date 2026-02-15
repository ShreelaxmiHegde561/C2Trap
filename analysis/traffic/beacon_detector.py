"""
C2Trap Beacon Detection
Identify periodic C2 beaconing patterns in network traffic
"""

import os
import sys
import json
import logging
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Set
from collections import defaultdict
from dataclasses import dataclass, field

# Add project root to path for imports
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import enhanced detection modules
try:
    from ml.baseline_learner import BaselineLearner, get_learner
    ENHANCED_DETECTION = True
except ImportError:
    ENHANCED_DETECTION = False

# Import Smart Whitelist (False Positive Reduction)
try:
    from intelligence.whitelist import whitelist as smart_whitelist
    WHITELIST_AVAILABLE = True
except ImportError:
    WHITELIST_AVAILABLE = False

# Import Active Defense (Auto-Blocking)
try:
    from response.active_defense import active_defense
    ACTIVE_DEFENSE_AVAILABLE = True
except ImportError:
    ACTIVE_DEFENSE_AVAILABLE = False

# Import Wazuh SIEM Integration
try:
    from intelligence.wazuh_integration import wazuh
    WAZUH_AVAILABLE = True
except ImportError:
    WAZUH_AVAILABLE = False

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('beacon_detector')

LOG_PATH = os.environ.get('LOG_PATH', '/app/logs/analysis_queue.jsonl')


def log_event(event_type: str, data: dict) -> None:
    """Write event to analysis queue"""
    event = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'source': 'beacon_detector',
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
    """Profile for a specific connection"""
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    timestamps: List[float] = field(default_factory=list)
    intervals: List[float] = field(default_factory=list)
    byte_sizes: List[int] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    beacon_score: float = 0.0
    is_beacon: bool = False
    is_whitelisted: bool = False
    whitelist_reason: str = ""


class BeaconDetector:
    """
    Detect C2 beaconing patterns using statistical analysis and ML
    
    Enhanced Features:
    - Adaptive thresholding based on baseline learner
    - Time-series variance analysis
    - Alert suppression for known legitimate traffic
    - Payload size consistency check
    - Long-duration connection analysis
    """
    
    # Trusted services that often exhibit beacon-like behavior
    TRUSTED_DESTINATIONS = {
        '8.8.8.8', '8.8.4.4', '1.1.1.1',  # DNS
        '169.254.169.254',  # Cloud metadata
        '127.0.0.1', '::1',  # Localhost
    }
    
    def __init__(self, 
                 min_connections: int = 5,
                 max_jitter_percent: float = 25.0,  # Increased tolerance
                 min_duration_seconds: int = 60,    # Decreased for faster detection
                 baseline_learner: Optional[BaselineLearner] = None):
        """
        Initialize beacon detector
        
        Args:
            min_connections: Minimum connections to analyze
            max_jitter_percent: Maximum allowed jitter percentage
            min_duration_seconds: Minimum duration to consider for beaconing
            baseline_learner: Optional ML learner for adaptive thresholds
        """
        self.min_connections = min_connections
        self.max_jitter_percent = max_jitter_percent
        self.min_duration = timedelta(seconds=min_duration_seconds)
        self.baseline_learner = baseline_learner or (get_learner() if ENHANCED_DETECTION else None)
        
        # Connection profiles: key -> ConnectionProfile
        self.profiles: Dict[str, ConnectionProfile] = {}
        
        # Detected beacons
        self.detected_beacons: List[dict] = []
        
        # Alert cache to prevent flooding
        self.alert_cache: Set[str] = set()
    
    def _get_connection_key(self, src_ip: str, dst_ip: str, 
                            dst_port: int, protocol: str) -> str:
        """Generate unique connection identifier"""
        return f"{protocol}:{src_ip}->{dst_ip}:{dst_port}"
    
    def add_connection(self, src_ip: str, dst_ip: str, dst_port: int,
                       protocol: str, timestamp: float, size: int = 0,
                       domain: str = None):
        """
        Add a connection event for analysis
        """
        # Skip local traffic optimization
        if src_ip == '127.0.0.1' and dst_ip == '127.0.0.1':
            return
            
        key = self._get_connection_key(src_ip, dst_ip, dst_port, protocol)
        
        if key not in self.profiles:
            # Check hardcoded whitelist
            is_whitelisted = (dst_ip in self.TRUSTED_DESTINATIONS)
            reason = "Hardcoded trusted IP" if is_whitelisted else ""
            
            # Check SmartWhitelist (False Positive Reduction)
            if not is_whitelisted and WHITELIST_AVAILABLE:
                if smart_whitelist.is_safe_ip(dst_ip):
                    is_whitelisted = True
                    reason = f"SmartWhitelist: Safe IP range"
                    logger.info(f"[WHITELIST] Skipping safe IP: {dst_ip}")
                elif domain and smart_whitelist.is_safe_domain(domain):
                    is_whitelisted = True
                    reason = f"SmartWhitelist: Safe domain {domain}"
                    logger.info(f"[WHITELIST] Skipping safe domain: {domain}")
            
            self.profiles[key] = ConnectionProfile(
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                first_seen=datetime.fromtimestamp(timestamp),
                is_whitelisted=is_whitelisted,
                whitelist_reason=reason
            )
        
        profile = self.profiles[key]
        
        # Don't analyze whitelisted connections further to save resources
        if profile.is_whitelisted:
            return
            
        profile.timestamps.append(timestamp)
        profile.byte_sizes.append(size)
        profile.last_seen = datetime.fromtimestamp(timestamp)
        
        # Calculate interval if we have previous timestamp
        if len(profile.timestamps) > 1:
            interval = timestamp - profile.timestamps[-2]
            profile.intervals.append(interval)
        
        # Keep memory bounded
        if len(profile.timestamps) > 500:
            profile.timestamps = profile.timestamps[-250:]
            profile.intervals = profile.intervals[-249:]
            profile.byte_sizes = profile.byte_sizes[-250:]
        
        # Analyze if we have enough data
        if len(profile.timestamps) >= self.min_connections:
            self._analyze_profile(key, profile)
    
    def _analyze_profile(self, key: str, profile: ConnectionProfile):
        """Analyze a connection profile for beacon patterns"""
        if len(profile.intervals) < self.min_connections - 1:
            return
        
        # Check duration
        if profile.last_seen and profile.first_seen:
            duration = profile.last_seen - profile.first_seen
            if duration < self.min_duration:
                return
        
        try:
            # 1. Interval Analysis
            mean_interval = statistics.mean(profile.intervals)
            if mean_interval <= 0:
                return
            
            stdev_interval = statistics.stdev(profile.intervals) if len(profile.intervals) > 1 else 0
            jitter_percent = (stdev_interval / mean_interval) * 100
            
            # 2. Size Analysis (Beacons usually have consistent sizes)
            size_stdev = statistics.stdev(profile.byte_sizes) if len(profile.byte_sizes) > 1 else 0
            mean_size = statistics.mean(profile.byte_sizes)
            size_variance_percent = (size_stdev / mean_size * 100) if mean_size > 0 else 0
            
            # 3. Scoring Formula
            # Start with 0
            score = 0
            
            # Jitter score (0-40 points) — Extended range for adaptive detection
            if jitter_percent < 5:
                score += 40
            elif jitter_percent < 10:
                score += 30
            elif jitter_percent < 20:
                score += 15
            elif jitter_percent < self.max_jitter_percent:
                score += 5
            elif jitter_percent < 50:
                # === FFT-based detection for high-jitter beacons ===
                fft_score = self._fft_periodicity_score(profile.intervals)
                if fft_score > 0.5:
                    score += 10  # Still beacon-like despite high jitter
                    logger.info(
                        f"[FFT] Hidden periodicity found despite {jitter_percent:.0f}% jitter "
                        f"(FFT score: {fft_score:.2f})"
                    )
            
            # Size consistency score (0-20 points)
            if size_variance_percent < 10:
                score += 20
            elif size_variance_percent < 30:
                score += 10
            
            # Regularity check (0-20 points)
            # Check if interval is "human-like" or "machine-like"
            if 30 <= mean_interval <= 3600:  # 30s to 1h is typical beacon
                score += 20
            elif mean_interval < 5:  # Very fast - likely noise/chatty app
                score -= 10
            
            # Persistence score (0-20 points)
            connection_count = len(profile.timestamps)
            if connection_count > 50:
                score += 20
            elif connection_count > 20:
                score += 10
            
            # 4. ML Baseline Adjustment
            if self.baseline_learner and not self.baseline_learner.learning_mode:
                # Check if this destination is unusual
                anomaly_score, _ = self.baseline_learner.get_anomaly_score({
                    'dst_ip': profile.dst_ip,
                    'dst_port': profile.dst_port,
                    'timestamp': time.time()
                })
                
                # Boost score if destination is anomalous
                if anomaly_score > 50:
                    score += 15
                
                # Reduce score if destination is common/whitelisted
                if anomaly_score == 0:
                    score -= 30
            
            profile.beacon_score = max(0, min(100, score))
            
            # Adaptive Threshold
            threshold = 60  # Default
            if self.baseline_learner:
                threshold = self.baseline_learner.get_adaptive_threshold()
            
            # Determine if beacon
            # Allow higher jitter if FFT detected periodicity
            effective_jitter_limit = 50 if jitter_percent > self.max_jitter_percent else self.max_jitter_percent
            is_beacon = (
                score >= threshold and
                jitter_percent <= effective_jitter_limit and
                len(profile.timestamps) >= self.min_connections
            )
            
            if is_beacon and not profile.is_beacon:
                # Check alert cache to avoid duplicates
                if key not in self.alert_cache:
                    profile.is_beacon = True
                    self.alert_cache.add(key)
                    self._report_beacon(key, profile, mean_interval, jitter_percent)
            
            # Reset is_beacon if behavior changes significantly
            elif not is_beacon and profile.is_beacon and score < threshold - 20:
                profile.is_beacon = False
                if key in self.alert_cache:
                    self.alert_cache.remove(key)
        
        except Exception as e:
            logger.debug(f"Analysis error for {key}: {e}")
    
    def _fft_periodicity_score(self, intervals: List[float]) -> float:
        """
        Use FFT (Fast Fourier Transform) to detect hidden periodicity
        even in high-jitter beacon traffic.
        
        How it works:
        - FFT converts time-domain intervals to frequency-domain
        - A dominant frequency peak indicates periodic behavior
        - Even with 40% jitter, the beacon frequency shows as a peak
        """
        if len(intervals) < 8:
            return 0.0
        
        try:
            import numpy as np
            
            # Normalize intervals
            arr = np.array(intervals)
            mean = np.mean(arr)
            if mean <= 0:
                return 0.0
            
            normalized = (arr - mean) / mean
            
            # Apply FFT
            fft_result = np.fft.fft(normalized)
            magnitudes = np.abs(fft_result[1:len(fft_result)//2])  # Skip DC component
            
            if len(magnitudes) == 0:
                return 0.0
            
            # Find dominant frequency strength
            max_magnitude = np.max(magnitudes)
            mean_magnitude = np.mean(magnitudes)
            
            if mean_magnitude <= 0:
                return 0.0
            
            # Peak-to-average ratio — high ratio = strong periodicity
            peak_ratio = max_magnitude / mean_magnitude
            
            # Normalize to 0-1 score (ratio > 3 is strongly periodic)
            score = min(1.0, peak_ratio / 5.0)
            
            return score
            
        except ImportError:
            # numpy not available — use statistical fallback
            if len(intervals) < 4:
                return 0.0
            
            import statistics
            mean_int = statistics.mean(intervals)
            if mean_int <= 0:
                return 0.0
            
            stdev = statistics.stdev(intervals)
            cv = stdev / mean_int  # Coefficient of variation
            
            # Lower CV = more periodic (even with jitter)
            if cv < 0.3:
                return 0.7
            elif cv < 0.5:
                return 0.4
            else:
                return 0.1
    
    
    def _report_beacon(self, key: str, profile: ConnectionProfile,
                       interval: float, jitter: float):
        """Report a detected beacon with Active Defense and SIEM integration"""
        severity = 'high' if profile.beacon_score > 80 else 'medium'
        
        beacon_info = {
            'src_ip': profile.src_ip,
            'dst_ip': profile.dst_ip,
            'dst_port': profile.dst_port,
            'protocol': profile.protocol,
            'mean_interval': round(interval, 2),
            'jitter_percent': round(jitter, 2),
            'connection_count': len(profile.timestamps),
            'first_seen': profile.first_seen.isoformat() if profile.first_seen else None,
            'last_seen': profile.last_seen.isoformat() if profile.last_seen else None,
            'beacon_score': round(profile.beacon_score, 1),
            'mitre_technique': 'T1071',
            'severity': severity,
            'actions_taken': []
        }
        
        self.detected_beacons.append(beacon_info)
        
        logger.warning(
            f"[BEACON] Detected: {profile.src_ip} -> {profile.dst_ip}:{profile.dst_port} "
            f"(interval: {interval:.1f}s, jitter: {jitter:.1f}%, score: {profile.beacon_score:.0f})"
        )
        
        # === Active Defense: Auto-block high-confidence beacons ===
        if ACTIVE_DEFENSE_AVAILABLE and profile.beacon_score >= 90:
            blocked = active_defense.block_ip(
                profile.dst_ip,
                reason=f"Beacon Score {profile.beacon_score:.0f}/100"
            )
            action = f"ACTION: {'Blocked' if blocked else 'Block failed for'} IP {profile.dst_ip}"
            beacon_info['actions_taken'].append(action)
            logger.warning(f"[ACTIVE DEFENSE] {action}")
        
        # === Wazuh SIEM Integration ===
        if WAZUH_AVAILABLE:
            description = (
                f"C2 Beacon detected: {profile.src_ip} -> {profile.dst_ip}:{profile.dst_port} | "
                f"Score: {profile.beacon_score:.0f}/100 | Interval: {interval:.1f}s"
            )
            wazuh.send_alert(
                event_type='beacon_detected',
                severity=severity,
                description=description,
                src_ip=profile.src_ip,
                dst_ip=profile.dst_ip,
                extra_data={
                    'beacon_score': round(profile.beacon_score, 1),
                    'mean_interval': round(interval, 2),
                    'jitter_percent': round(jitter, 2),
                    'mitre_technique': 'T1071'
                }
            )
            beacon_info['actions_taken'].append('SIEM: Alert forwarded to Wazuh')
        
        log_event('beacon_detected', beacon_info)
    
    def get_beacons(self) -> List[dict]:
        """Get all detected beacons"""
        return self.detected_beacons
    
    def get_statistics(self) -> dict:
        """Get beacon detection statistics"""
        return {
            'total_profiles': len(self.profiles),
            'detected_beacons': len(self.detected_beacons),
            'suspicious_connections': len([p for p in self.profiles.values() if p.beacon_score >= 40])
        }


# Singleton instance
_detector = None

def get_detector() -> BeaconDetector:
    global _detector
    if _detector is None:
        _detector = BeaconDetector()
    return _detector


if __name__ == '__main__':
    import time
    import random
    
    # Demo
    detector = BeaconDetector()
    print("Simulating beacon traffic...")
    
    # Simulate beacon
    base_time = time.time() - 600
    for i in range(20):
        # 30s interval with small jitter
        ts = base_time + (i * 30) + random.uniform(-1, 1)
        detector.add_connection(
            src_ip='192.168.1.100',
            dst_ip='45.33.22.11',
            dst_port=443,
            protocol='tcp',
            timestamp=ts,
            size=1024 + random.randint(0, 50)
        )
    
    print("\nResults:")
    for b in detector.get_beacons():
        print(f"🔴 BEACON DETECTED: {b['dst_ip']} (Score: {b['beacon_score']})")
        print(f"   Interval: {b['mean_interval']}s, Jitter: {b['jitter_percent']}%")
