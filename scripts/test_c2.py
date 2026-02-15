#!/usr/bin/env python3
"""
C2Trap Test C2 Simulator
Simulates malware C2 beaconing for testing the detection system
"""

import os
import sys
import time
import random
import string
import argparse
import requests
import socket
from datetime import datetime

# Suppress SSL warnings for testing
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def log(msg, level="INFO"):
    """Print log message with timestamp"""
    ts = datetime.now().strftime("%H:%M:%S")
    colors = {"INFO": "\033[94m", "WARN": "\033[93m", "OK": "\033[92m", "ERR": "\033[91m"}
    reset = "\033[0m"
    print(f"{colors.get(level, '')}{ts} [{level}]{reset} {msg}")


class C2Simulator:
    """Simulate various C2 beacon patterns"""
    
    def __init__(self, target_host: str = "localhost", http_port: int = 8888, 
                 dns_port: int = 53, ftp_port: int = 21):
        self.target_host = target_host
        self.http_port = http_port
        self.dns_port = dns_port
        self.ftp_port = ftp_port
        self.session_id = ''.join(random.choices(string.hexdigits, k=16))
    
    def http_beacon(self, endpoint: str = "/api/beacon", interval: int = 10, 
                    count: int = 5, jitter: float = 0.2):
        """Simulate HTTP beaconing"""
        log(f"Starting HTTP beacon to {self.target_host}:{self.http_port}{endpoint}")
        log(f"Interval: {interval}s, Jitter: {jitter*100}%, Count: {count}")
        
        url = f"http://{self.target_host}:{self.http_port}{endpoint}"
        
        for i in range(count):
            try:
                # Add jitter
                sleep_time = interval * (1 + random.uniform(-jitter, jitter))
                
                # Send beacon
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) C2Trap-Test",
                    "X-Session-ID": self.session_id,
                    "X-Beacon-Seq": str(i + 1)
                }
                
                data = {
                    "id": self.session_id,
                    "seq": i + 1,
                    "hostname": socket.gethostname(),
                    "timestamp": datetime.utcnow().isoformat()
                }
                
                response = requests.post(url, json=data, headers=headers, timeout=10)
                log(f"Beacon #{i+1}: {response.status_code} - {response.text[:50]}", "OK")
                
                if i < count - 1:
                    log(f"Sleeping {sleep_time:.1f}s...")
                    time.sleep(sleep_time)
                    
            except requests.RequestException as e:
                log(f"Beacon #{i+1} failed: {e}", "ERR")
    
    def dns_beacon(self, domain_pattern: str = "beacon{n}.c2.evil.com", count: int = 5):
        """Simulate DNS beaconing"""
        log(f"Starting DNS beacon queries to {self.target_host}:{self.dns_port}")
        
        for i in range(count):
            try:
                # Generate domain with numbered subdomain
                domain = domain_pattern.replace("{n}", str(i + 1))
                
                # Try DNS query
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(5)
                
                # Simple DNS query packet
                query = self._build_dns_query(domain)
                sock.sendto(query, (self.target_host, self.dns_port))
                
                try:
                    response, _ = sock.recvfrom(1024)
                    log(f"DNS query #{i+1}: {domain} - Response received", "OK")
                except socket.timeout:
                    log(f"DNS query #{i+1}: {domain} - Timeout (expected if trapped)", "WARN")
                
                sock.close()
                time.sleep(random.uniform(1, 3))
                
            except Exception as e:
                log(f"DNS query #{i+1} failed: {e}", "ERR")
    
    def _build_dns_query(self, domain: str) -> bytes:
        """Build a simple DNS query packet"""
        # Transaction ID
        query = bytes([random.randint(0, 255), random.randint(0, 255)])
        # Flags (standard query)
        query += b'\x01\x00'
        # Questions: 1, Answer RRs: 0, Authority RRs: 0, Additional RRs: 0
        query += b'\x00\x01\x00\x00\x00\x00\x00\x00'
        # Domain name
        for part in domain.split('.'):
            query += bytes([len(part)]) + part.encode()
        query += b'\x00'
        # Type A, Class IN
        query += b'\x00\x01\x00\x01'
        return query
    
    def ftp_beacon(self, username: str = "malware", password: str = "c2pass"):
        """Simulate FTP connection"""
        log(f"Starting FTP connection to {self.target_host}:{self.ftp_port}")
        
        try:
            from ftplib import FTP
            
            ftp = FTP()
            ftp.connect(self.target_host, self.ftp_port, timeout=10)
            log(f"FTP connected: {ftp.getwelcome()}", "OK")
            
            ftp.login(username, password)
            log(f"FTP login successful as {username}", "OK")
            
            # Try to list directory
            files = ftp.nlst()
            log(f"FTP directory listing: {files}", "OK")
            
            ftp.quit()
            log("FTP session closed", "OK")
            
        except Exception as e:
            log(f"FTP beacon failed: {e}", "ERR")
    
    def c2_endpoints(self):
        """Test various C2 endpoints"""
        log("Testing common C2 endpoints...")
        
        endpoints = [
            ("/api/beacon", "POST", {"id": self.session_id}),
            ("/check", "GET", None),
            ("/update", "POST", {"task": "sleep"}),
            ("/gate", "POST", {"data": "check-in"}),
            ("/c2", "GET", None),
            ("/submit", "POST", {"exfil": "test_data"}),
            ("/beacon", "POST", {"seq": 1}),
            ("/cmd", "GET", None),
        ]
        
        base_url = f"http://{self.target_host}:{self.http_port}"
        
        for endpoint, method, data in endpoints:
            try:
                if method == "GET":
                    response = requests.get(f"{base_url}{endpoint}", timeout=5)
                else:
                    response = requests.post(f"{base_url}{endpoint}", json=data, timeout=5)
                
                log(f"{method} {endpoint}: {response.status_code}", "OK")
                time.sleep(0.5)
                
            except requests.RequestException as e:
                log(f"{method} {endpoint}: Failed - {e}", "ERR")
    
    def full_simulation(self):
        """Run a complete C2 simulation"""
        log("=" * 60)
        log("C2Trap Test Simulator - Full Simulation")
        log("=" * 60)
        log(f"Target: {self.target_host}")
        log(f"Session ID: {self.session_id}")
        log("=" * 60)
        
        # Phase 1: Initial C2 check-in
        log("\n[Phase 1] Initial C2 Check-in", "WARN")
        self.c2_endpoints()
        
        time.sleep(2)
        
        # Phase 2: HTTP Beaconing
        log("\n[Phase 2] HTTP Beaconing", "WARN")
        self.http_beacon(endpoint="/api/beacon", interval=5, count=3, jitter=0.1)
        
        time.sleep(2)
        
        # Phase 3: DNS Beaconing
        log("\n[Phase 3] DNS Beaconing", "WARN")
        self.dns_beacon(count=3)
        
        time.sleep(2)
        
        # Phase 4: FTP Activity
        log("\n[Phase 4] FTP Activity", "WARN")
        self.ftp_beacon()
        
        log("\n" + "=" * 60)
        log("Simulation Complete!", "OK")
        log("Check the C2Trap dashboard at http://localhost:8000")
        log("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="C2Trap Test C2 Simulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python test_c2.py                    # Run full simulation
  python test_c2.py --http-only        # HTTP beaconing only
  python test_c2.py --dns-only         # DNS queries only
  python test_c2.py -t 10.0.0.1        # Custom target
        """
    )
    
    parser.add_argument("-t", "--target", default="localhost", help="Target host")
    parser.add_argument("-p", "--http-port", type=int, default=8888, help="HTTP port")
    parser.add_argument("--dns-port", type=int, default=53, help="DNS port")
    parser.add_argument("--ftp-port", type=int, default=21, help="FTP port")
    parser.add_argument("--http-only", action="store_true", help="HTTP beacon only")
    parser.add_argument("--dns-only", action="store_true", help="DNS beacon only")
    parser.add_argument("--ftp-only", action="store_true", help="FTP connection only")
    parser.add_argument("--endpoints", action="store_true", help="Test C2 endpoints only")
    parser.add_argument("-n", "--count", type=int, default=5, help="Beacon count")
    parser.add_argument("-i", "--interval", type=int, default=10, help="Beacon interval")
    
    args = parser.parse_args()
    
    sim = C2Simulator(
        target_host=args.target,
        http_port=args.http_port,
        dns_port=args.dns_port,
        ftp_port=args.ftp_port
    )
    
    if args.http_only:
        sim.http_beacon(count=args.count, interval=args.interval)
    elif args.dns_only:
        sim.dns_beacon(count=args.count)
    elif args.ftp_only:
        sim.ftp_beacon()
    elif args.endpoints:
        sim.c2_endpoints()
    else:
        sim.full_simulation()


if __name__ == "__main__":
    main()
