"""
C2Trap JA3 TLS Fingerprinting
Generate JA3 hashes from TLS Client Hello messages
"""

import os
import json
import hashlib
import logging
from datetime import datetime
from typing import Optional, Dict, List, Tuple

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('ja3_generator')

LOG_PATH = os.environ.get('LOG_PATH', '/app/logs/analysis_queue.jsonl')
JA3_DB_PATH = os.environ.get('JA3_DB_PATH', '/app/data/ja3_database.json')

# Known malware JA3 fingerprints (sample database)
KNOWN_MALWARE_JA3 = {
    'a0e9f5d64349fb13191bc781f81f42e1': {'name': 'Cobalt Strike', 'severity': 'high'},
    '72a589da586844d7f0818ce684948eea': {'name': 'Metasploit', 'severity': 'high'},
    '3b5074b1b5d032e5620f69f9f700ff0e': {'name': 'TrickBot', 'severity': 'critical'},
    '51c64c77e60f3980eea90869b68c58a8': {'name': 'Emotet', 'severity': 'critical'},
    'e7d705a3286e19ea42f587b344ee6865': {'name': 'Ryuk', 'severity': 'critical'},
    '6734f37431670b3ab4292b8f60f29984': {'name': 'Dridex', 'severity': 'high'},
    '078ce53c0447e6bf5daecf04d0f6b158': {'name': 'QakBot', 'severity': 'high'},
    'b32309a26951912be7dba376398abc3b': {'name': 'IcedID', 'severity': 'high'},
    '3b5074b1b5d032e5620f69f9f700ff0e': {'name': 'BazarLoader', 'severity': 'high'},
    '7dcce5b76c8b17472d024758970a406b': {'name': 'AsyncRAT', 'severity': 'medium'},
}


def log_event(event_type: str, data: dict) -> None:
    """Write event to analysis queue"""
    event = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'source': 'ja3_generator',
        'event_type': event_type,
        'data': data
    }
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, 'a') as f:
            f.write(json.dumps(event) + '\n')
    except Exception as e:
        logger.error(f"Failed to write log: {e}")


class JA3Generator:
    """Generate JA3 fingerprints from TLS Client Hello"""
    
    def __init__(self):
        self.known_fingerprints = KNOWN_MALWARE_JA3.copy()
        self.seen_fingerprints: Dict[str, dict] = {}
        self._load_database()
    
    def _load_database(self):
        """Load JA3 database from file"""
        try:
            if os.path.exists(JA3_DB_PATH):
                with open(JA3_DB_PATH, 'r') as f:
                    db = json.load(f)
                    self.known_fingerprints.update(db.get('known', {}))
                    self.seen_fingerprints = db.get('seen', {})
        except Exception as e:
            logger.error(f"Failed to load JA3 database: {e}")
    
    def _save_database(self):
        """Save JA3 database to file"""
        try:
            os.makedirs(os.path.dirname(JA3_DB_PATH), exist_ok=True)
            with open(JA3_DB_PATH, 'w') as f:
                json.dump({
                    'known': self.known_fingerprints,
                    'seen': self.seen_fingerprints
                }, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save JA3 database: {e}")
    
    def parse_client_hello(self, packet_bytes: bytes) -> Optional[dict]:
        """
        Parse TLS Client Hello from raw packet bytes
        Returns parsed components or None if not valid Client Hello
        """
        try:
            if len(packet_bytes) < 43:
                return None
            
            # TLS Record Header
            content_type = packet_bytes[0]
            if content_type != 0x16:  # Handshake
                return None
            
            tls_version = (packet_bytes[1] << 8) | packet_bytes[2]
            record_length = (packet_bytes[3] << 8) | packet_bytes[4]
            
            # Handshake Header
            handshake_type = packet_bytes[5]
            if handshake_type != 0x01:  # Client Hello
                return None
            
            # Skip to Client Hello content
            pos = 9  # Skip record header (5) + handshake header (4)
            
            # Client Version
            client_version = (packet_bytes[pos] << 8) | packet_bytes[pos + 1]
            pos += 2
            
            # Random (32 bytes)
            pos += 32
            
            # Session ID
            session_id_len = packet_bytes[pos]
            pos += 1 + session_id_len
            
            # Cipher Suites
            cipher_suites_len = (packet_bytes[pos] << 8) | packet_bytes[pos + 1]
            pos += 2
            cipher_suites = []
            for i in range(0, cipher_suites_len, 2):
                if pos + i + 1 < len(packet_bytes):
                    cs = (packet_bytes[pos + i] << 8) | packet_bytes[pos + i + 1]
                    # Skip GREASE values
                    if not self._is_grease(cs):
                        cipher_suites.append(cs)
            pos += cipher_suites_len
            
            # Compression Methods
            if pos >= len(packet_bytes):
                return None
            compression_len = packet_bytes[pos]
            pos += 1 + compression_len
            
            # Extensions
            extensions = []
            elliptic_curves = []
            ec_point_formats = []
            
            if pos + 2 <= len(packet_bytes):
                extensions_len = (packet_bytes[pos] << 8) | packet_bytes[pos + 1]
                pos += 2
                ext_end = pos + extensions_len
                
                while pos + 4 <= ext_end and pos + 4 <= len(packet_bytes):
                    ext_type = (packet_bytes[pos] << 8) | packet_bytes[pos + 1]
                    ext_len = (packet_bytes[pos + 2] << 8) | packet_bytes[pos + 3]
                    pos += 4
                    
                    # Skip GREASE values
                    if not self._is_grease(ext_type):
                        extensions.append(ext_type)
                    
                    # Supported Groups (Elliptic Curves)
                    if ext_type == 10 and pos + 2 <= len(packet_bytes):
                        ec_len = (packet_bytes[pos] << 8) | packet_bytes[pos + 1]
                        for i in range(2, ec_len, 2):
                            if pos + i + 1 < len(packet_bytes):
                                ec = (packet_bytes[pos + i] << 8) | packet_bytes[pos + i + 1]
                                if not self._is_grease(ec):
                                    elliptic_curves.append(ec)
                    
                    # EC Point Formats
                    if ext_type == 11 and pos < len(packet_bytes):
                        ecpf_len = packet_bytes[pos]
                        for i in range(1, ecpf_len + 1):
                            if pos + i < len(packet_bytes):
                                ec_point_formats.append(packet_bytes[pos + i])
                    
                    pos += ext_len
            
            return {
                'version': client_version,
                'cipher_suites': cipher_suites,
                'extensions': extensions,
                'elliptic_curves': elliptic_curves,
                'ec_point_formats': ec_point_formats
            }
        
        except Exception as e:
            logger.debug(f"Failed to parse Client Hello: {e}")
            return None
    
    def _is_grease(self, value: int) -> bool:
        """Check if value is GREASE (RFC 8701)"""
        grease_values = [
            0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
            0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
            0xcaca, 0xdada, 0xeaea, 0xfafa
        ]
        return value in grease_values
    
    def generate_ja3(self, parsed: dict) -> Tuple[str, str]:
        """
        Generate JA3 string and hash from parsed Client Hello
        Returns (ja3_string, ja3_hash)
        """
        # JA3 format: Version,Ciphers,Extensions,EllipticCurves,ECPointFormats
        version = str(parsed['version'])
        ciphers = '-'.join(str(c) for c in parsed['cipher_suites'])
        extensions = '-'.join(str(e) for e in parsed['extensions'])
        curves = '-'.join(str(c) for c in parsed['elliptic_curves'])
        ec_formats = '-'.join(str(f) for f in parsed['ec_point_formats'])
        
        ja3_string = f"{version},{ciphers},{extensions},{curves},{ec_formats}"
        ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
        
        return ja3_string, ja3_hash
    
    def process_packet(self, packet_bytes: bytes, src_ip: str, dst_ip: str,
                       src_port: int, dst_port: int) -> Optional[dict]:
        """
        Process a packet and generate JA3 if it's a TLS Client Hello
        Returns fingerprint info or None
        """
        parsed = self.parse_client_hello(packet_bytes)
        if not parsed:
            return None
        
        ja3_string, ja3_hash = self.generate_ja3(parsed)
        
        # Check against known malware
        match = self.known_fingerprints.get(ja3_hash)
        is_malware = match is not None
        
        result = {
            'ja3_hash': ja3_hash,
            'ja3_string': ja3_string,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'tls_version': parsed['version'],
            'cipher_count': len(parsed['cipher_suites']),
            'extension_count': len(parsed['extensions']),
            'is_known_malware': is_malware,
            'malware_info': match,
            'mitre_technique': 'T1573.002' if is_malware else None
        }
        
        # Track seen fingerprints
        if ja3_hash not in self.seen_fingerprints:
            self.seen_fingerprints[ja3_hash] = {
                'first_seen': datetime.utcnow().isoformat(),
                'count': 0,
                'sources': []
            }
        
        self.seen_fingerprints[ja3_hash]['count'] += 1
        if src_ip not in self.seen_fingerprints[ja3_hash]['sources']:
            self.seen_fingerprints[ja3_hash]['sources'].append(src_ip)
        
        # Log event
        log_event('ja3_fingerprint', result)
        
        if is_malware:
            logger.warning(f"[JA3] MALWARE MATCH: {match['name']} from {src_ip}")
            log_event('malware_detected', {
                'type': 'ja3_match',
                'malware': match['name'],
                'severity': match['severity'],
                'src_ip': src_ip,
                'ja3_hash': ja3_hash
            })
        else:
            logger.info(f"[JA3] Fingerprint: {ja3_hash[:16]}... from {src_ip}")
        
        return result
    
    def add_known_fingerprint(self, ja3_hash: str, name: str, severity: str = 'medium'):
        """Add a fingerprint to the known malware database"""
        self.known_fingerprints[ja3_hash] = {
            'name': name,
            'severity': severity,
            'added': datetime.utcnow().isoformat()
        }
        self._save_database()
    
    def get_statistics(self) -> dict:
        """Get JA3 processing statistics"""
        return {
            'known_fingerprints': len(self.known_fingerprints),
            'seen_fingerprints': len(self.seen_fingerprints),
            'total_matches': sum(f['count'] for f in self.seen_fingerprints.values())
        }


# Singleton instance
_generator = None

def get_generator() -> JA3Generator:
    global _generator
    if _generator is None:
        _generator = JA3Generator()
    return _generator


def generate_ja3_from_bytes(packet_bytes: bytes, src_ip: str = '0.0.0.0',
                           dst_ip: str = '0.0.0.0', src_port: int = 0,
                           dst_port: int = 0) -> Optional[dict]:
    """Convenience function to generate JA3 from packet bytes"""
    return get_generator().process_packet(packet_bytes, src_ip, dst_ip, src_port, dst_port)


if __name__ == '__main__':
    # Example usage
    gen = JA3Generator()
    print(f"Loaded {len(gen.known_fingerprints)} known malware fingerprints")
    print("JA3 Generator ready")
