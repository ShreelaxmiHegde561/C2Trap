"""
C2Trap DNS Honeypot
Captures and logs all DNS queries, responds with configurable IPs
"""

import os
import json
import socket
import logging
from datetime import datetime
from dnslib import DNSRecord, QTYPE, RR, A, AAAA, MX, TXT, NS, CNAME
from dnslib.server import DNSServer, BaseResolver

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('dns_decoy')

LOG_PATH = os.environ.get('LOG_PATH', '/app/logs/analysis_queue.jsonl')
DEFAULT_IP = os.environ.get('DEFAULT_IP', '127.0.0.1')


def log_event(event_type: str, data: dict) -> None:
    """Write event to analysis queue"""
    event = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'source': 'dns_decoy',
        'event_type': event_type,
        'data': data
    }
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, 'a') as f:
            f.write(json.dumps(event) + '\n')
    except Exception as e:
        logger.error(f"Failed to write log: {e}")


class C2TrapResolver(BaseResolver):
    """Custom DNS resolver that logs all queries and returns fake responses"""
    
    def __init__(self, default_ip: str = '127.0.0.1'):
        self.default_ip = default_ip
        # Known suspicious TLDs and patterns
        self.suspicious_tlds = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq']
        self.suspicious_patterns = ['c2', 'beacon', 'cmd', 'update', 'gate', 'panel']
    
    def resolve(self, request, handler):
        reply = request.reply()
        qname = str(request.q.qname).rstrip('.')
        qtype = QTYPE[request.q.qtype]
        client_ip = handler.client_address[0]
        
        # Check for suspicious indicators
        is_suspicious = False
        suspicion_reason = []
        
        # Check TLD
        for tld in self.suspicious_tlds:
            if qname.endswith(tld):
                is_suspicious = True
                suspicion_reason.append(f'suspicious_tld:{tld}')
        
        # Check patterns
        qname_lower = qname.lower()
        for pattern in self.suspicious_patterns:
            if pattern in qname_lower:
                is_suspicious = True
                suspicion_reason.append(f'suspicious_pattern:{pattern}')
        
        # Check for DGA-like domains (high entropy, random-looking)
        if self._looks_like_dga(qname):
            is_suspicious = True
            suspicion_reason.append('possible_dga')
        
        # Log the query
        log_data = {
            'client_ip': client_ip,
            'query_name': qname,
            'query_type': qtype,
            'suspicious': is_suspicious,
            'suspicion_reason': suspicion_reason,
            'mitre_technique': 'T1071.004' if is_suspicious else None
        }
        log_event('dns_query', log_data)
        
        if is_suspicious:
            logger.warning(f"[DNS] SUSPICIOUS query for {qname} ({qtype}) from {client_ip}")
        else:
            logger.info(f"[DNS] Query for {qname} ({qtype}) from {client_ip}")
        
        # Build response based on query type
        if qtype == 'A':
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(self.default_ip), ttl=60))
        elif qtype == 'AAAA':
            reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA('::1'), ttl=60))
        elif qtype == 'MX':
            reply.add_answer(RR(qname, QTYPE.MX, rdata=MX(f'mail.{qname}'), ttl=60))
        elif qtype == 'TXT':
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT('v=c2trap'), ttl=60))
        elif qtype == 'NS':
            reply.add_answer(RR(qname, QTYPE.NS, rdata=NS(f'ns1.{qname}'), ttl=60))
        elif qtype == 'CNAME':
            reply.add_answer(RR(qname, QTYPE.CNAME, rdata=CNAME(qname), ttl=60))
        else:
            # Default A record for unknown types
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(self.default_ip), ttl=60))
        
        return reply
    
    def _looks_like_dga(self, domain: str) -> bool:
        """Simple heuristic to detect DGA-like domains"""
        # Remove TLD
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        name = parts[0]
        if len(name) < 8:
            return False
        
        # Check consonant/vowel ratio
        vowels = set('aeiouAEIOU')
        consonants = sum(1 for c in name if c.isalpha() and c not in vowels)
        vowel_count = sum(1 for c in name if c in vowels)
        
        if vowel_count == 0:
            return len(name) > 8
        
        ratio = consonants / vowel_count
        # DGA domains often have unusual consonant/vowel ratios
        return ratio > 4 or ratio < 0.3


def main():
    port = int(os.environ.get('DNS_PORT', 53))
    default_ip = os.environ.get('DEFAULT_IP', '127.0.0.1')
    
    resolver = C2TrapResolver(default_ip=default_ip)
    
    # Create UDP and TCP servers
    udp_server = DNSServer(resolver, port=port, address='0.0.0.0', tcp=False)
    tcp_server = DNSServer(resolver, port=port, address='0.0.0.0', tcp=True)
    
    logger.info(f"Starting DNS Decoy on port {port}")
    logger.info(f"Default response IP: {default_ip}")
    
    udp_server.start_thread()
    tcp_server.start_thread()
    
    try:
        while True:
            udp_server.isAlive() or tcp_server.isAlive()
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down DNS Decoy")
        udp_server.stop()
        tcp_server.stop()


if __name__ == '__main__':
    main()
