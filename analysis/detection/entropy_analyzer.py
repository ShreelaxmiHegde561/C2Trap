#!/usr/bin/env python3
"""
C2Trap Entropy Analyzer
=======================

Detect high-entropy data exfiltration and encoded payloads.
Identifies encrypted, compressed, or encoded data in network traffic.

Features:
- Shannon entropy calculation
- Base64 detection
- DNS tunneling detection
- Encrypted payload identification
- Compression detection
"""

import os
import re
import json
import math
import logging
import base64
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from collections import Counter
from dataclasses import dataclass

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('entropy_analyzer')

LOG_PATH = os.environ.get('LOG_PATH', '/app/logs/analysis_queue.jsonl')


def log_event(event_type: str, data: dict) -> None:
    """Write event to analysis queue"""
    event = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'source': 'entropy_analyzer',
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
class EntropyAnalysis:
    """Entropy analysis result"""
    entropy: float
    is_suspicious: bool
    encoding_type: str
    confidence: float
    indicators: List[str]


class EntropyAnalyzer:
    """
    Analyze data entropy for exfiltration detection
    
    High entropy data may indicate:
    - Encrypted payloads
    - Compressed data
    - Base64/hex encoded content
    - Data exfiltration attempts
    """
    
    # Entropy thresholds
    HIGH_ENTROPY_THRESHOLD = 7.5  # Very high (likely encrypted)
    MEDIUM_ENTROPY_THRESHOLD = 6.0  # Medium (encoded/compressed)
    
    # Base64 character set
    BASE64_CHARS = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
    BASE32_CHARS = set('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=')
    HEX_CHARS = set('0123456789abcdefABCDEF')
    
    def __init__(self):
        self.analyses_count = 0
        self.suspicious_count = 0
        self.dns_tunnel_detections = 0
    
    def analyze_payload(self, data: bytes) -> EntropyAnalysis:
        """
        Analyze payload entropy and encoding
        
        Args:
            data: Raw bytes to analyze
            
        Returns:
            EntropyAnalysis result
        """
        self.analyses_count += 1
        
        if not data:
            return EntropyAnalysis(
                entropy=0.0, is_suspicious=False,
                encoding_type="empty", confidence=0.0, indicators=[]
            )
        
        indicators = []
        
        # Calculate entropy
        entropy = self._calculate_entropy(data)
        
        # Detect encoding type
        try:
            text = data.decode('utf-8', errors='ignore')
            encoding_type = self._detect_encoding(text)
        except:
            encoding_type = "binary"
        
        # Determine suspiciousness
        is_suspicious = False
        confidence = 0.0
        
        if entropy >= self.HIGH_ENTROPY_THRESHOLD:
            is_suspicious = True
            confidence = 0.9
            indicators.append(f"Very high entropy: {entropy:.2f}")
            indicators.append("Likely encrypted or compressed")
        elif entropy >= self.MEDIUM_ENTROPY_THRESHOLD:
            if encoding_type in ['base64', 'base32', 'hex']:
                is_suspicious = True
                confidence = 0.7
                indicators.append(f"High entropy with encoding: {encoding_type}")
            else:
                confidence = 0.4
                indicators.append(f"Elevated entropy: {entropy:.2f}")
        
        if encoding_type != "plaintext":
            indicators.append(f"Detected encoding: {encoding_type}")
        
        # Check payload size relative to entropy
        if len(data) > 1024 and entropy > self.MEDIUM_ENTROPY_THRESHOLD:
            is_suspicious = True
            confidence = max(confidence, 0.7)
            indicators.append(f"Large encoded payload: {len(data)} bytes")
        
        if is_suspicious:
            self.suspicious_count += 1
            log_event('high_entropy_detected', {
                'entropy': entropy,
                'encoding': encoding_type,
                'size': len(data),
                'confidence': confidence,
                'indicators': indicators
            })
        
        return EntropyAnalysis(
            entropy=round(entropy, 4),
            is_suspicious=is_suspicious,
            encoding_type=encoding_type,
            confidence=confidence,
            indicators=indicators
        )
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        byte_counts = Counter(data)
        length = len(data)
        
        entropy = 0.0
        for count in byte_counts.values():
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _detect_encoding(self, text: str) -> str:
        """Detect the encoding type of text"""
        if not text:
            return "empty"
        
        # Remove whitespace for analysis
        cleaned = text.replace(' ', '').replace('\n', '').replace('\r', '')
        
        if not cleaned:
            return "whitespace"
        
        # Check character distribution
        char_set = set(cleaned)
        
        # Base64 detection
        if self._is_base64(cleaned):
            return "base64"
        
        # Base32 detection
        if char_set.issubset(self.BASE32_CHARS) and len(cleaned) >= 8:
            return "base32"
        
        # Hex detection
        if char_set.issubset(self.HEX_CHARS) and len(cleaned) >= 8:
            return "hex"
        
        # Check if mostly printable ASCII
        printable_ratio = sum(1 for c in text if c.isprintable()) / len(text)
        if printable_ratio > 0.95:
            return "plaintext"
        
        return "binary"
    
    def _is_base64(self, text: str) -> bool:
        """Check if text is valid base64"""
        # Remove padding
        text = text.rstrip('=')
        
        if len(text) < 8:
            return False
        
        # Check characters
        if not all(c in self.BASE64_CHARS for c in text):
            return False
        
        # Try to decode
        try:
            # Add padding if needed
            padding = 4 - (len(text) % 4) if len(text) % 4 else 0
            base64.b64decode(text + '=' * padding)
            return True
        except:
            return False
    
    def detect_dns_tunneling(self, dns_queries: List[str]) -> Tuple[bool, float, List[str]]:
        """
        Detect DNS tunneling from query patterns
        
        DNS tunneling characteristics:
        - Long subdomains
        - High entropy subdomains
        - High query frequency
        - Unusual record types (TXT, NULL)
        
        Args:
            dns_queries: List of DNS query names
            
        Returns:
            Tuple of (is_tunneling, confidence, indicators)
        """
        if not dns_queries:
            return False, 0.0, []
        
        indicators = []
        suspicious_count = 0
        
        for query in dns_queries:
            # Extract subdomain (everything before the main domain)
            parts = query.lower().rstrip('.').split('.')
            
            if len(parts) < 2:
                continue
            
            # Get subdomain portion
            subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else parts[0]
            
            if not subdomain:
                continue
            
            # Check subdomain length
            if len(subdomain) > 40:
                suspicious_count += 1
                if len(indicators) < 5:
                    indicators.append(f"Long subdomain: {len(subdomain)} chars")
            
            # Check entropy
            entropy = self._calculate_string_entropy(subdomain.replace('.', ''))
            if entropy > 3.5:
                suspicious_count += 1
                if len(indicators) < 5:
                    indicators.append(f"High entropy subdomain: {entropy:.2f}")
            
            # Check for encoded patterns
            if self._looks_encoded(subdomain):
                suspicious_count += 1
                if len(indicators) < 5:
                    indicators.append("Encoded subdomain pattern")
        
        # Calculate detection confidence
        if len(dns_queries) == 0:
            confidence = 0.0
        else:
            suspicious_ratio = suspicious_count / len(dns_queries)
            confidence = min(suspicious_ratio * 1.5, 1.0)
        
        is_tunneling = confidence >= 0.5
        
        if is_tunneling:
            self.dns_tunnel_detections += 1
            log_event('dns_tunneling_detected', {
                'query_count': len(dns_queries),
                'suspicious_count': suspicious_count,
                'confidence': confidence,
                'indicators': indicators,
                'mitre_technique': 'T1071.004'
            })
            
            logger.warning(f"[DNS TUNNEL] Detected with confidence {confidence:.2f}")
        
        return is_tunneling, confidence, indicators
    
    def _calculate_string_entropy(self, text: str) -> float:
        """Calculate entropy of a string"""
        if not text:
            return 0.0
        
        freq = Counter(text)
        length = len(text)
        
        entropy = 0.0
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        
        return entropy
    
    def _looks_encoded(self, text: str) -> bool:
        """Check if text looks like encoded data"""
        # Remove common separators
        cleaned = text.replace('.', '').replace('-', '')
        
        if len(cleaned) < 10:
            return False
        
        # Base32-like pattern (common in DNS tunneling)
        char_set = set(cleaned.upper())
        if char_set.issubset(self.BASE32_CHARS):
            return True
        
        # Hex pattern
        if char_set.issubset(self.HEX_CHARS):
            return True
        
        return False
    
    def analyze_http_body(self, body: bytes, content_type: str = "") -> EntropyAnalysis:
        """
        Analyze HTTP body for suspicious content
        
        Args:
            body: HTTP body bytes
            content_type: Content-Type header value
            
        Returns:
            EntropyAnalysis result
        """
        analysis = self.analyze_payload(body)
        
        # Adjust based on content type
        if 'json' in content_type or 'text' in content_type:
            if analysis.entropy > self.MEDIUM_ENTROPY_THRESHOLD:
                analysis.indicators.append(f"High entropy for {content_type}")
                analysis.is_suspicious = True
        
        # Check for large encoded payloads
        if len(body) > 4096:
            if analysis.encoding_type in ['base64', 'base32']:
                analysis.indicators.append("Large encoded payload detected")
                analysis.confidence = max(analysis.confidence, 0.8)
                
                log_event('large_encoded_payload', {
                    'size': len(body),
                    'encoding': analysis.encoding_type,
                    'content_type': content_type,
                    'mitre_technique': 'T1048'
                })
        
        return analysis
    
    def get_statistics(self) -> Dict:
        """Get analyzer statistics"""
        return {
            'total_analyses': self.analyses_count,
            'suspicious_count': self.suspicious_count,
            'dns_tunnel_detections': self.dns_tunnel_detections,
            'detection_rate': self.suspicious_count / self.analyses_count if self.analyses_count > 0 else 0
        }


# Singleton
_analyzer = None

def get_analyzer() -> EntropyAnalyzer:
    global _analyzer
    if _analyzer is None:
        _analyzer = EntropyAnalyzer()
    return _analyzer


if __name__ == '__main__':
    # Demo
    analyzer = EntropyAnalyzer()
    
    print("Entropy Analyzer Demo")
    print("=" * 60)
    
    # Test payloads
    test_cases = [
        ("Plain text", b"Hello, this is a normal message"),
        ("Base64", base64.b64encode(b"This is encoded data for exfiltration")),
        ("Encrypted-like", os.urandom(256)),
        ("JSON", b'{"user": "admin", "password": "secret123"}'),
        ("Hex encoded", b"48656c6c6f20576f726c64"),
    ]
    
    for name, data in test_cases:
        result = analyzer.analyze_payload(data)
        status = "🔴" if result.is_suspicious else "✅"
        print(f"\n{status} {name}")
        print(f"   Entropy: {result.entropy:.2f}")
        print(f"   Encoding: {result.encoding_type}")
        print(f"   Suspicious: {result.is_suspicious} (confidence: {result.confidence:.2f})")
        if result.indicators:
            print(f"   Indicators: {', '.join(result.indicators)}")
    
    # Test DNS tunneling
    print("\n" + "=" * 60)
    print("DNS Tunneling Detection")
    
    normal_queries = [
        "www.google.com",
        "api.github.com",
        "cdn.cloudflare.net"
    ]
    
    tunnel_queries = [
        "JBSWY3DPEHPK3PXP.data.evil.com",
        "KRUGS4ZANFZSAYJAORSXG5A.exfil.bad.xyz",
        "48656c6c6f576f726c64.tunnel.malware.top",
        "base32encodeddata12345.c2.bad.net"
    ]
    
    print("\nNormal DNS queries:")
    is_tunnel, conf, indicators = analyzer.detect_dns_tunneling(normal_queries)
    print(f"   Tunneling: {is_tunnel}, Confidence: {conf:.2f}")
    
    print("\nSuspicious DNS queries:")
    is_tunnel, conf, indicators = analyzer.detect_dns_tunneling(tunnel_queries)
    print(f"   Tunneling: {is_tunnel}, Confidence: {conf:.2f}")
    print(f"   Indicators: {indicators}")
    
    print(f"\nStatistics: {analyzer.get_statistics()}")
