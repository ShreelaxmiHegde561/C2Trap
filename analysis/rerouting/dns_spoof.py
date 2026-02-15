"""
C2Trap DNS Spoofing Module
Redirect known C2 domains to fake servers
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, Set, Optional
from dnslib import DNSRecord, QTYPE, RR, A
from dnslib.server import DNSServer, BaseResolver

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('dns_spoof')

LOG_PATH = os.environ.get('LOG_PATH', '/app/logs/analysis_queue.jsonl')


def log_event(event_type: str, data: dict) -> None:
    """Write event to analysis queue"""
    event = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'source': 'dns_spoof',
        'event_type': event_type,
        'data': data
    }
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, 'a') as f:
            f.write(json.dumps(event) + '\n')
    except Exception as e:
        logger.error(f"Failed to write log: {e}")


class C2DomainManager:
    """Manage list of C2 domains to intercept"""
    
    def __init__(self):
        self.blocked_domains: Set[str] = set()
        self.blocked_patterns: Set[str] = set()
        self.redirect_ip: str = '127.0.0.1'
        
        # Load default blocklist
        self._load_defaults()
    
    def _load_defaults(self):
        """Load default known-bad domains and patterns"""
        # Known C2 patterns
        self.blocked_patterns = {
            'c2.', 'c2-', 'cmd.', 'command.',
            'beacon.', 'stage.', 'payload.',
            'update.', 'download.', 'gate.',
            'panel.', 'admin.', 'control.'
        }
        
        # High-risk TLDs often used by malware
        self.blocked_tlds = {
            '.xyz', '.top', '.tk', '.ml', '.ga',
            '.cf', '.gq', '.work', '.click', '.link'
        }
    
    def add_domain(self, domain: str):
        """Add a domain to the blocklist"""
        self.blocked_domains.add(domain.lower().rstrip('.'))
        logger.info(f"Added domain to blocklist: {domain}")
    
    def remove_domain(self, domain: str):
        """Remove a domain from the blocklist"""
        self.blocked_domains.discard(domain.lower().rstrip('.'))
    
    def add_pattern(self, pattern: str):
        """Add a pattern to block (prefix matching)"""
        self.blocked_patterns.add(pattern.lower())
    
    def should_intercept(self, domain: str) -> bool:
        """Check if a domain should be intercepted"""
        domain = domain.lower().rstrip('.')
        
        # Exact match
        if domain in self.blocked_domains:
            return True
        
        # Pattern match
        for pattern in self.blocked_patterns:
            if domain.startswith(pattern) or pattern in domain:
                return True
        
        # TLD check
        for tld in self.blocked_tlds:
            if domain.endswith(tld):
                return True
        
        return False
    
    def set_redirect_ip(self, ip: str):
        """Set the IP to redirect blocked domains to"""
        self.redirect_ip = ip
    
    def get_redirect_ip(self) -> str:
        """Get the redirect IP"""
        return self.redirect_ip
    
    def get_blocked_domains(self) -> Set[str]:
        """Get all explicitly blocked domains"""
        return self.blocked_domains.copy()


class SpoofingResolver(BaseResolver):
    """DNS resolver that spoofs responses for C2 domains"""
    
    def __init__(self, domain_manager: C2DomainManager, 
                 upstream_dns: str = '8.8.8.8'):
        self.domain_manager = domain_manager
        self.upstream_dns = upstream_dns
    
    def resolve(self, request, handler):
        reply = request.reply()
        qname = str(request.q.qname).rstrip('.')
        qtype = QTYPE[request.q.qtype]
        client_ip = handler.client_address[0]
        
        # Check if domain should be intercepted
        if self.domain_manager.should_intercept(qname):
            redirect_ip = self.domain_manager.get_redirect_ip()
            
            logger.warning(f"[DNS-SPOOF] Intercepting {qname} -> {redirect_ip}")
            
            log_event('dns_spoofed', {
                'client_ip': client_ip,
                'domain': qname,
                'query_type': qtype,
                'redirect_ip': redirect_ip,
                'mitre_technique': 'T1071.004'
            })
            
            # Return spoofed response
            if qtype == 'A':
                reply.add_answer(RR(qname, QTYPE.A, 
                                   rdata=A(redirect_ip), ttl=60))
            return reply
        
        # For non-blocked domains, forward to upstream (or just return empty)
        # In production, you'd forward to upstream DNS
        logger.debug(f"[DNS] Passing through: {qname}")
        log_event('dns_passthrough', {
            'client_ip': client_ip,
            'domain': qname,
            'query_type': qtype
        })
        
        # Return empty response (or forward to upstream in production)
        return reply


class DNSSpoofServer:
    """DNS Spoofing Server"""
    
    def __init__(self, listen_ip: str = '0.0.0.0', listen_port: int = 5353,
                 redirect_ip: str = '127.0.0.1'):
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        
        self.domain_manager = C2DomainManager()
        self.domain_manager.set_redirect_ip(redirect_ip)
        
        self.resolver = SpoofingResolver(self.domain_manager)
        self.udp_server = None
        self.tcp_server = None
    
    def add_c2_domain(self, domain: str):
        """Add a C2 domain to intercept"""
        self.domain_manager.add_domain(domain)
    
    def add_c2_domains(self, domains: list):
        """Add multiple C2 domains"""
        for domain in domains:
            self.domain_manager.add_domain(domain)
    
    def start(self):
        """Start the DNS spoofing server"""
        logger.info(f"Starting DNS Spoof Server on {self.listen_ip}:{self.listen_port}")
        logger.info(f"Redirecting to: {self.domain_manager.get_redirect_ip()}")
        
        self.udp_server = DNSServer(self.resolver, 
                                    port=self.listen_port,
                                    address=self.listen_ip,
                                    tcp=False)
        self.tcp_server = DNSServer(self.resolver,
                                    port=self.listen_port,
                                    address=self.listen_ip,
                                    tcp=True)
        
        self.udp_server.start_thread()
        self.tcp_server.start_thread()
        
        logger.info("DNS Spoof Server started")
    
    def stop(self):
        """Stop the DNS spoofing server"""
        if self.udp_server:
            self.udp_server.stop()
        if self.tcp_server:
            self.tcp_server.stop()
        logger.info("DNS Spoof Server stopped")
    
    def run_forever(self):
        """Run server until interrupted"""
        self.start()
        try:
            import time
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutting down...")
            self.stop()


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='C2Trap DNS Spoofing')
    parser.add_argument('-p', '--port', type=int, default=5353, 
                       help='Listen port')
    parser.add_argument('-r', '--redirect', default='127.0.0.1',
                       help='IP to redirect blocked domains to')
    parser.add_argument('-d', '--domains', nargs='+', default=[],
                       help='Additional domains to block')
    args = parser.parse_args()
    
    server = DNSSpoofServer(listen_port=args.port, redirect_ip=args.redirect)
    
    # Add any additional domains
    for domain in args.domains:
        server.add_c2_domain(domain)
    
    print(f"DNS Spoof Server")
    print(f"  Listen: 0.0.0.0:{args.port}")
    print(f"  Redirect: {args.redirect}")
    print(f"  Blocked patterns: {server.domain_manager.blocked_patterns}")
    
    server.run_forever()
