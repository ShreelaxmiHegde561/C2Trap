"""
C2Trap TLS Anomaly Detector
Detects suspicious TLS/SSL connections that may indicate C2 communication.

What advanced attackers do with TLS:
1. Self-signed certificates (no CA verification)
2. Expired certificates (lazy C2 setup)
3. Rare/weak cipher suites (old/custom TLS implementations)
4. SNI mismatch (domain fronting — CDN header says "google.com" but cert says "evil.com")
5. Known malicious JA3 hashes (Cobalt Strike, Metasploit default fingerprints)

This module analyzes TLS metadata WITHOUT decrypting traffic.
"""

import logging
import os
import json
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set

logger = logging.getLogger("c2trap.tls_anomaly")

LOG_PATH = os.environ.get('LOG_PATH', '/app/logs/analysis_queue.jsonl')


def log_event(event_type: str, data: dict) -> None:
    """Write event to analysis queue"""
    event = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'source': 'tls_anomaly_detector',
        'event_type': event_type,
        'data': data
    }
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, 'a') as f:
            f.write(json.dumps(event) + '\n')
    except Exception:
        pass


class TLSAnomalyDetector:
    """
    Detect suspicious TLS connections without decryption.
    
    Works by analyzing metadata:
    - JA3 fingerprint (hash of TLS Client Hello parameters)
    - Certificate properties (self-signed, expired, short-lived)
    - Cipher suite selection (weak/unusual)
    - SNI (Server Name Indication) analysis
    """

    # Known malicious JA3 hashes (Cobalt Strike, Metasploit, etc.)
    MALICIOUS_JA3_HASHES: Set[str] = {
        # Cobalt Strike default
        "72a589da586844d7f0818ce684948eea",
        "a0e9f5d64349fb13191bc781f81f42e1",
        # Metasploit Meterpreter
        "5d65ea3fb1d4aa7d826733d2f2cbbb1d",
        # Empire C2
        "e7d705a3286e19ea42f587b344ee6865",
        # Covenant C2
        "51c64c77e60f3980eea90869b68c58a8",
        # Mythic C2
        "b20b44b18b853f23d7f0a3d2b6c0d2e6",
        # PoshC2
        "3b5074b1b5d032e5620f69f9f700ff0e",
        # Generic suspicious (default TLS implementations)
        "e35c3930e4a9b00e0e9e5a8e7c9a1e21",
        "6734f37431670b3ab4292b8f60f29984",
    }

    # Suspicious/weak cipher suites
    WEAK_CIPHERS = {
        'TLS_RSA_WITH_RC4_128_SHA',
        'TLS_RSA_WITH_RC4_128_MD5',
        'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
        'TLS_RSA_WITH_DES_CBC_SHA',
        'TLS_RSA_EXPORT_WITH_RC4_40_MD5',
        'TLS_RSA_WITH_NULL_SHA',
        'TLS_RSA_WITH_NULL_MD5',
    }

    def __init__(self):
        self.detected_anomalies: List[dict] = []
        self.ja3_cache: Dict[str, int] = {}  # ja3_hash -> hit count
        self.cert_cache: Dict[str, dict] = {}  # cert fingerprint -> info

    def analyze_connection(self,
                           dst_ip: str,
                           dst_port: int,
                           ja3_hash: Optional[str] = None,
                           sni: Optional[str] = None,
                           cert_subject: Optional[str] = None,
                           cert_issuer: Optional[str] = None,
                           cert_self_signed: bool = False,
                           cert_days_valid: Optional[int] = None,
                           cipher_suite: Optional[str] = None,
                           tls_version: Optional[str] = None
                           ) -> Tuple[float, bool, dict]:
        """
        Analyze a TLS connection for anomalies.
        
        Returns:
            (score, is_suspicious, details)
        """
        scores = {}
        alerts = []

        # === 1. JA3 Fingerprint Check ===
        ja3_score = 0.0
        if ja3_hash:
            self.ja3_cache[ja3_hash] = self.ja3_cache.get(ja3_hash, 0) + 1

            if ja3_hash in self.MALICIOUS_JA3_HASHES:
                ja3_score = 1.0
                alerts.append(f"KNOWN MALICIOUS JA3: {ja3_hash}")
        scores['ja3'] = ja3_score

        # === 2. Self-Signed Certificate ===
        cert_score = 0.0
        if cert_self_signed:
            cert_score += 0.6
            alerts.append("Self-signed certificate detected")

        if cert_issuer and cert_subject and cert_issuer == cert_subject:
            cert_score = max(cert_score, 0.6)
            alerts.append("Certificate issuer equals subject (self-signed)")

        # Short-lived certificates (< 30 days) are suspicious
        if cert_days_valid is not None:
            if cert_days_valid < 0:
                cert_score = max(cert_score, 0.8)
                alerts.append(f"EXPIRED certificate ({cert_days_valid} days)")
            elif cert_days_valid < 30:
                cert_score = max(cert_score, 0.4)
                alerts.append(f"Short-lived certificate ({cert_days_valid} days)")

        scores['certificate'] = round(cert_score, 3)

        # === 3. Cipher Suite Analysis ===
        cipher_score = 0.0
        if cipher_suite:
            if cipher_suite in self.WEAK_CIPHERS:
                cipher_score = 0.7
                alerts.append(f"Weak cipher suite: {cipher_suite}")
        scores['cipher'] = cipher_score

        # === 4. TLS Version Check ===
        version_score = 0.0
        if tls_version:
            if tls_version in ['SSLv3', 'TLSv1.0']:
                version_score = 0.6
                alerts.append(f"Deprecated TLS version: {tls_version}")
            elif tls_version == 'TLSv1.1':
                version_score = 0.3
                alerts.append(f"Outdated TLS version: {tls_version}")
        scores['tls_version'] = version_score

        # === 5. SNI Mismatch (Domain Fronting) ===
        sni_score = 0.0
        if sni and cert_subject:
            # Simple check: does the cert match the SNI?
            cert_domain = cert_subject.replace('CN=', '').replace('*.', '')
            if cert_domain and sni not in cert_subject:
                sni_score = 0.5
                alerts.append(f"SNI mismatch: SNI={sni}, Cert={cert_subject}")
        scores['sni_mismatch'] = sni_score

        # === 6. Non-standard port ===
        port_score = 0.0
        if dst_port not in [443, 8443, 993, 995, 465, 636]:
            port_score = 0.3
            alerts.append(f"TLS on non-standard port: {dst_port}")
        scores['port'] = port_score

        # === Weighted Final Score ===
        final_score = (
            ja3_score * 0.30 +
            cert_score * 0.25 +
            cipher_score * 0.15 +
            version_score * 0.10 +
            sni_score * 0.10 +
            port_score * 0.10
        )
        final_score = min(1.0, max(0.0, final_score))

        is_suspicious = final_score >= 0.4

        details = {
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'score': round(final_score, 3),
            'is_suspicious': is_suspicious,
            'alerts': alerts,
            'components': scores,
            'ja3_hash': ja3_hash,
            'sni': sni,
            'tls_version': tls_version
        }

        if is_suspicious:
            details['mitre_technique'] = 'T1573'  # Encrypted Channel
            self.detected_anomalies.append(details)

            logger.warning(
                f"[TLS ANOMALY] {dst_ip}:{dst_port} "
                f"(score: {final_score:.2f}) — {'; '.join(alerts)}"
            )
            log_event('tls_anomaly_detected', details)

        return final_score, is_suspicious, details

    def get_stats(self) -> dict:
        """Get detection statistics"""
        return {
            'total_anomalies': len(self.detected_anomalies),
            'unique_ja3_hashes': len(self.ja3_cache),
            'malicious_ja3_seen': sum(
                1 for h in self.ja3_cache if h in self.MALICIOUS_JA3_HASHES
            )
        }


# Singleton
tls_anomaly_detector = TLSAnomalyDetector()


if __name__ == '__main__':
    detector = TLSAnomalyDetector()

    print("=" * 65)
    print("  C2Trap TLS Anomaly Detector — Test Suite")
    print("=" * 65)

    tests = [
        {
            'name': 'Normal HTTPS (Google)',
            'dst_ip': '142.250.80.46', 'dst_port': 443,
            'ja3_hash': 'abc123def456', 'sni': 'www.google.com',
            'cert_subject': 'CN=*.google.com', 'cert_issuer': 'CN=Google Trust',
            'cert_self_signed': False, 'cert_days_valid': 365,
            'tls_version': 'TLSv1.3',
            'expected': False
        },
        {
            'name': 'Cobalt Strike (known JA3)',
            'dst_ip': '45.33.22.11', 'dst_port': 443,
            'ja3_hash': '72a589da586844d7f0818ce684948eea',
            'sni': 'update.microsoft.com',
            'cert_subject': 'CN=Major Cobalt Inc', 'cert_issuer': 'CN=Major Cobalt Inc',
            'cert_self_signed': True, 'cert_days_valid': 7,
            'tls_version': 'TLSv1.2',
            'expected': True
        },
        {
            'name': 'Self-signed + expired cert',
            'dst_ip': '10.0.0.50', 'dst_port': 8443,
            'cert_self_signed': True, 'cert_days_valid': -30,
            'cert_subject': 'CN=localhost', 'cert_issuer': 'CN=localhost',
            'tls_version': 'TLSv1.0',
            'expected': True
        },
        {
            'name': 'Domain Fronting attempt',
            'dst_ip': '104.16.1.1', 'dst_port': 443,
            'sni': 'cdn.cloudflare.com',
            'cert_subject': 'CN=evil-c2.darkweb.onion',
            'cert_issuer': 'CN=Lets Encrypt',
            'cert_self_signed': False, 'cert_days_valid': 90,
            'tls_version': 'TLSv1.3',
            'expected': True
        },
    ]

    for test in tests:
        expected = test.pop('expected')
        name = test.pop('name')
        score, is_sus, details = detector.analyze_connection(**test)
        status = "✅" if is_sus == expected else "❌"
        label = "SUSPICIOUS" if is_sus else "CLEAN"
        print(f"  {status} {name:35s} Score: {score:.3f}  [{label}]")
        if details.get('alerts'):
            for alert in details['alerts']:
                print(f"      ⚠  {alert}")

    print()
