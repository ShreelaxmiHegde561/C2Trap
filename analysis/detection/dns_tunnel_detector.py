"""
C2Trap DNS Tunneling Detector
Detects data exfiltration through DNS queries.

How DNS Tunneling works:
  Attacker encodes stolen data as DNS subdomains:
    Normal:   www.google.com
    Tunnel:   aGVsbG8gd29ybGQ.evil.com  (base64 encoded "hello world")

Detection methods:
1. Subdomain length analysis (normal < 10 chars, tunnel > 15 chars)
2. Shannon entropy of subdomain (tunnel = high entropy)
3. Query frequency per domain (tunnel = many queries fast)
4. Payload size ratio (large query, tiny response = exfil)
5. Encoding detection (base64, hex patterns)
"""

import math
import time
import re
import logging
import os
import json
from datetime import datetime
from collections import Counter, defaultdict
from typing import Dict, List, Tuple, Optional

logger = logging.getLogger("c2trap.dns_tunnel")

LOG_PATH = os.environ.get('LOG_PATH', '/app/logs/analysis_queue.jsonl')


def log_event(event_type: str, data: dict) -> None:
    """Write event to analysis queue"""
    event = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'source': 'dns_tunnel_detector',
        'event_type': event_type,
        'data': data
    }
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, 'a') as f:
            f.write(json.dumps(event) + '\n')
    except Exception:
        pass


class DNSTunnelDetector:
    """
    Detect DNS tunneling attempts using multi-factor analysis.
    
    DNS tunneling is used by tools like:
    - iodine, dnscat2, dns2tcp
    - Cobalt Strike DNS beacon
    - Custom malware exfiltrating data via DNS
    
    Key insight: Legitimate DNS queries are short and infrequent.
    Tunneling produces long, frequent, high-entropy queries.
    """

    # Base64 character set pattern
    BASE64_PATTERN = re.compile(r'^[A-Za-z0-9+/=_-]+$')
    # Hex pattern
    HEX_PATTERN = re.compile(r'^[0-9a-fA-F]+$')

    def __init__(self,
                 entropy_threshold: float = 3.5,
                 length_threshold: int = 15,
                 frequency_threshold: int = 10,
                 window_seconds: int = 60):
        """
        Args:
            entropy_threshold: Min entropy to flag subdomain
            length_threshold: Min subdomain length to flag
            frequency_threshold: Max queries per domain per window
            window_seconds: Time window for frequency analysis
        """
        self.entropy_threshold = entropy_threshold
        self.length_threshold = length_threshold
        self.frequency_threshold = frequency_threshold
        self.window_seconds = window_seconds

        # Track query frequency per base domain
        self.query_tracker: Dict[str, List[float]] = defaultdict(list)
        # Detected tunnels
        self.detected_tunnels: List[dict] = []
        # Total bytes estimated exfiltrated
        self.estimated_exfil_bytes = 0

    def analyze_query(self, full_domain: str, query_size: int = 0) -> Tuple[float, bool, dict]:
        """
        Analyze a DNS query for tunneling indicators.
        
        Returns:
            (score, is_tunnel, details)
        """
        if not full_domain:
            return 0.0, False, {}

        parts = full_domain.lower().strip('.').split('.')
        if len(parts) < 2:
            return 0.0, False, {}

        # Extract subdomain (everything before the base domain)
        # e.g., "aGVsbG8.evil.com" -> subdomain="aGVsbG8", base="evil.com"
        base_domain = '.'.join(parts[-2:])
        subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ''

        if not subdomain:
            return 0.0, False, {'reason': 'no_subdomain'}

        now = time.time()
        scores = {}

        # === 1. Subdomain Length Score ===
        sub_length = len(subdomain.replace('.', ''))
        if sub_length > self.length_threshold:
            length_score = min(1.0, (sub_length - self.length_threshold) / 30)
        else:
            length_score = 0.0
        scores['length'] = round(length_score, 3)

        # === 2. Entropy Score ===
        entropy = self._shannon_entropy(subdomain.replace('.', ''))
        if entropy > self.entropy_threshold:
            entropy_score = min(1.0, (entropy - self.entropy_threshold) / 1.5)
        else:
            entropy_score = 0.0
        scores['entropy'] = round(entropy_score, 3)
        scores['entropy_value'] = round(entropy, 3)

        # === 3. Encoding Detection ===
        clean_sub = subdomain.replace('.', '')
        encoding_score = 0.0
        encoding_type = 'none'

        if self.BASE64_PATTERN.match(clean_sub) and len(clean_sub) > 10:
            encoding_score = 0.8
            encoding_type = 'base64'
        elif self.HEX_PATTERN.match(clean_sub) and len(clean_sub) > 10:
            encoding_score = 0.7
            encoding_type = 'hex'

        scores['encoding'] = round(encoding_score, 3)
        scores['encoding_type'] = encoding_type

        # === 4. Query Frequency Score ===
        self.query_tracker[base_domain].append(now)
        # Clean old entries
        self.query_tracker[base_domain] = [
            t for t in self.query_tracker[base_domain]
            if now - t < self.window_seconds
        ]
        query_count = len(self.query_tracker[base_domain])

        if query_count > self.frequency_threshold:
            freq_score = min(1.0, (query_count - self.frequency_threshold) / 50)
        else:
            freq_score = 0.0
        scores['frequency'] = round(freq_score, 3)
        scores['query_count'] = query_count

        # === 5. Label Count Score ===
        # Tunneling often uses multiple subdomain labels
        label_count = len(parts) - 2  # Exclude base domain
        label_score = min(1.0, max(0.0, (label_count - 1) / 4))
        scores['labels'] = round(label_score, 3)

        # === Weighted Final Score ===
        final_score = (
            length_score * 0.25 +
            entropy_score * 0.25 +
            encoding_score * 0.20 +
            freq_score * 0.20 +
            label_score * 0.10
        )
        final_score = min(1.0, max(0.0, final_score))

        is_tunnel = final_score >= 0.5

        details = {
            'domain': full_domain,
            'base_domain': base_domain,
            'subdomain': subdomain,
            'subdomain_length': sub_length,
            'score': round(final_score, 3),
            'is_tunnel': is_tunnel,
            'components': scores
        }

        if is_tunnel:
            # Estimate exfiltrated data
            exfil_bytes = len(subdomain) * 3 // 4  # Rough base64 decode size
            self.estimated_exfil_bytes += exfil_bytes

            details['mitre_technique'] = 'T1048'  # Exfiltration Over Alternative Protocol
            details['estimated_exfil_bytes'] = exfil_bytes
            self.detected_tunnels.append(details)

            logger.warning(
                f"[DNS TUNNEL] Suspicious: {full_domain} "
                f"(score: {final_score:.2f}, entropy: {entropy:.2f}, "
                f"encoding: {encoding_type}, length: {sub_length})"
            )
            log_event('dns_tunneling_detected', details)

        return final_score, is_tunnel, details

    def _shannon_entropy(self, text: str) -> float:
        """Calculate Shannon entropy"""
        if not text:
            return 0.0
        counts = Counter(text)
        length = len(text)
        entropy = 0.0
        for count in counts.values():
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy

    def get_stats(self) -> dict:
        """Get detection statistics"""
        return {
            'total_tunnels_detected': len(self.detected_tunnels),
            'estimated_exfil_bytes': self.estimated_exfil_bytes,
            'tracked_domains': len(self.query_tracker)
        }


# Singleton
dns_tunnel_detector = DNSTunnelDetector()


if __name__ == '__main__':
    detector = DNSTunnelDetector()

    print("=" * 65)
    print("  C2Trap DNS Tunneling Detector — Test Suite")
    print("=" * 65)

    test_queries = [
        # Normal DNS
        ("www.google.com", False),
        ("mail.yahoo.com", False),
        ("api.github.com", False),
        ("cdn.cloudflare.net", False),
        # DNS Tunneling (base64 encoded data in subdomain)
        ("aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q.evil.com", True),
        ("dXNlcm5hbWU9YWRtaW4mcGFzc3dvcmQ9MTIzNDU2.c2.bad.org", True),
        ("4d5a90000300000004000000ffff0000b8000000.exfil.net", True),
        # Moderate suspicion
        ("longsubdomaindata.evil.com", False),
        ("a.b.c.d.e.f.multi.label.com", True),
    ]

    correct = 0
    total = 0

    for domain, expected in test_queries:
        score, is_tunnel, details = detector.analyze_query(domain)
        status = "✅" if is_tunnel == expected else "❌"
        if is_tunnel == expected:
            correct += 1
        total += 1

        label = "TUNNEL" if is_tunnel else "SAFE"
        print(f"  {status} {domain[:45]:45s} Score: {score:.3f}  [{label}]")

    print(f"\n  Accuracy: {correct}/{total} ({correct/total*100:.0f}%)")
    print(f"  Estimated exfil: {detector.estimated_exfil_bytes} bytes")
    print()
