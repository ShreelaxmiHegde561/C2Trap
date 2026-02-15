#!/usr/bin/env python3
"""
C2Trap Enhanced Demo Traffic Generator
Generates realistic mixed traffic (clean + malicious) to demonstrate classification capabilities

Features:
- Random timing with configurable jitter
- Mix of legitimate and malicious traffic
- MITRE ATT&CK technique coverage
- Realistic User-Agents and payloads
"""

import os
import sys
import time
import random
import string
import argparse
import json
import hashlib
import socket
import threading
from datetime import datetime, timezone
from typing import List, Tuple, Optional

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# =============================================
# Configuration
# =============================================

class Config:
    """Configuration for the demo traffic generator"""
    HTTP_PORT = 8888
    DNS_PORT = 53
    FTP_PORT = 21
    TARGET = "localhost"
    
    # Realistic User-Agents
    USER_AGENTS = [
        # Legitimate browsers
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        # Suspicious/malware-like
        "Mozilla/5.0 (Windows NT 6.1) Cobalt Strike",
        "python-requests/2.28.0",  # Often used by malware
        "curl/7.88.0",
        "Wget/1.21",
    ]
    
    # MITRE ATT&CK technique mappings
    MITRE_TECHNIQUES = {
        "beacon": {"id": "T1071.001", "name": "Application Layer Protocol: Web", "tactic": "command-and-control"},
        "dns_beacon": {"id": "T1071.004", "name": "Application Layer Protocol: DNS", "tactic": "command-and-control"},
        "exfiltration": {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "exfiltration"},
        "credential_access": {"id": "T1078", "name": "Valid Accounts", "tactic": "credential-access"},
        "dga": {"id": "T1568.002", "name": "Dynamic Resolution: DGA", "tactic": "command-and-control"},
        "discovery": {"id": "T1082", "name": "System Information Discovery", "tactic": "discovery"},
    }
    
    # Legitimate domains for clean traffic
    LEGITIMATE_DOMAINS = [
        "google.com", "microsoft.com", "github.com", "stackoverflow.com",
        "cloudflare.com", "amazon.com", "apple.com", "mozilla.org",
    ]
    
    # C2-like domains for malicious traffic
    C2_DOMAINS = [
        "beacon.c2.evil.com", "malware-control.top", "c2.evil.com",
        "command.c2server.xyz", "update.trojan.link", "payload.backdoor.work",
    ]


# =============================================
# Logger
# =============================================

class Logger:
    """Colored logging with timestamps"""
    
    COLORS = {
        "INFO": "\033[94m",      # Blue
        "OK": "\033[92m",        # Green
        "WARN": "\033[93m",      # Yellow
        "ERR": "\033[91m",       # Red
        "CLEAN": "\033[96m",     # Cyan
        "MALICIOUS": "\033[95m", # Magenta
    }
    RESET = "\033[0m"
    
    @staticmethod
    def log(msg: str, level: str = "INFO"):
        ts = datetime.now().strftime("%H:%M:%S")
        color = Logger.COLORS.get(level, "")
        print(f"{color}{ts} [{level:^9}]{Logger.RESET} {msg}")


log = Logger.log


# =============================================
# Traffic Generators
# =============================================

class CleanTrafficGenerator:
    """Generate legitimate-looking traffic"""
    
    def __init__(self, target: str, http_port: int, dns_port: int):
        self.target = target
        self.http_port = http_port
        self.dns_port = dns_port
        self.session = requests.Session()
    
    def generate_http_browse(self) -> dict:
        """Simulate normal web browsing"""
        endpoints = ["/", "/index.html", "/about", "/contact", "/products", "/api/health"]
        endpoint = random.choice(endpoints)
        
        headers = {
            "User-Agent": random.choice(Config.USER_AGENTS[:4]),  # Only legitimate UAs
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        }
        
        try:
            url = f"http://{self.target}:{self.http_port}{endpoint}"
            response = self.session.get(url, headers=headers, timeout=5)
            return {
                "type": "clean_http",
                "endpoint": endpoint,
                "status": response.status_code,
                "classification": "legitimate"
            }
        except Exception as e:
            return {"type": "clean_http", "error": str(e)}
    
    def generate_api_healthcheck(self) -> dict:
        """Simulate API health check"""
        headers = {
            "User-Agent": random.choice(Config.USER_AGENTS[:4]),
            "Content-Type": "application/json",
            "X-Request-ID": ''.join(random.choices(string.hexdigits, k=16)),
        }
        
        try:
            url = f"http://{self.target}:{self.http_port}/api/health"
            response = self.session.get(url, headers=headers, timeout=5)
            return {
                "type": "clean_api",
                "endpoint": "/api/health",
                "status": response.status_code,
                "classification": "legitimate"
            }
        except Exception as e:
            return {"type": "clean_api", "error": str(e)}
    
    def generate_dns_lookup(self) -> dict:
        """Simulate normal DNS lookup"""
        domain = random.choice(Config.LEGITIMATE_DOMAINS)
        
        try:
            # Build simple DNS query
            query = self._build_dns_query(domain)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(query, (self.target, self.dns_port))
            
            try:
                sock.recvfrom(1024)
                result = "response"
            except socket.timeout:
                result = "timeout"
            sock.close()
            
            return {
                "type": "clean_dns",
                "domain": domain,
                "result": result,
                "classification": "legitimate"
            }
        except Exception as e:
            return {"type": "clean_dns", "domain": domain, "error": str(e)}
    
    def _build_dns_query(self, domain: str) -> bytes:
        query = bytes([random.randint(0, 255), random.randint(0, 255)])
        query += b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        for part in domain.split('.'):
            query += bytes([len(part)]) + part.encode()
        query += b'\x00\x00\x01\x00\x01'
        return query


class MaliciousTrafficGenerator:
    """Generate malicious-looking traffic for detection testing"""
    
    def __init__(self, target: str, http_port: int, dns_port: int, ftp_port: int):
        self.target = target
        self.http_port = http_port
        self.dns_port = dns_port
        self.ftp_port = ftp_port
        self.session_id = ''.join(random.choices(string.hexdigits, k=16))
        self.beacon_seq = 0
    
    def generate_c2_beacon(self) -> dict:
        """Simulate C2 beacon check-in (T1071.001)"""
        self.beacon_seq += 1
        
        endpoints = ["/api/beacon", "/beacon", "/gate", "/c2", "/cmd", "/update", "/check"]
        endpoint = random.choice(endpoints)
        
        headers = {
            "User-Agent": random.choice(Config.USER_AGENTS[4:]),  # Suspicious UAs
            "X-Session-ID": self.session_id,
            "X-Beacon-Seq": str(self.beacon_seq),
        }
        
        # Beacon payload with system info (like real malware)
        payload = {
            "id": self.session_id,
            "seq": self.beacon_seq,
            "hostname": socket.gethostname(),
            "os": "Windows NT 10.0",
            "arch": "x64",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        
        try:
            url = f"http://{self.target}:{self.http_port}{endpoint}"
            response = requests.post(url, json=payload, headers=headers, timeout=5)
            
            return {
                "type": "c2_beacon",
                "endpoint": endpoint,
                "status": response.status_code,
                "session_id": self.session_id,
                "seq": self.beacon_seq,
                "mitre": Config.MITRE_TECHNIQUES["beacon"],
                "classification": "malicious"
            }
        except Exception as e:
            return {"type": "c2_beacon", "error": str(e)}
    
    def generate_dns_beacon(self) -> dict:
        """Simulate DNS beaconing (T1071.004)"""
        domain = random.choice(Config.C2_DOMAINS)
        subdomain = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        full_domain = f"{subdomain}.{domain}"
        
        try:
            query = self._build_dns_query(full_domain)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(query, (self.target, self.dns_port))
            
            try:
                sock.recvfrom(1024)
                result = "response"
            except socket.timeout:
                result = "timeout"
            sock.close()
            
            return {
                "type": "dns_beacon",
                "domain": full_domain,
                "result": result,
                "mitre": Config.MITRE_TECHNIQUES["dns_beacon"],
                "classification": "malicious"
            }
        except Exception as e:
            return {"type": "dns_beacon", "domain": full_domain, "error": str(e)}
    
    def generate_dga_domain(self) -> dict:
        """Simulate DGA domain lookup (T1568.002)"""
        # Generate DGA-like domain with high entropy
        dga_chars = string.ascii_lowercase + string.digits
        dga_length = random.randint(12, 20)
        dga_domain = ''.join(random.choices(dga_chars, k=dga_length))
        tld = random.choice([".xyz", ".top", ".club", ".work", ".link", ".click"])
        full_domain = dga_domain + tld
        
        try:
            query = self._build_dns_query(full_domain)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.sendto(query, (self.target, self.dns_port))
            
            try:
                sock.recvfrom(1024)
                result = "response"
            except socket.timeout:
                result = "timeout"
            sock.close()
            
            return {
                "type": "dga_domain",
                "domain": full_domain,
                "entropy": self._calculate_entropy(dga_domain),
                "result": result,
                "mitre": Config.MITRE_TECHNIQUES["dga"],
                "classification": "malicious"
            }
        except Exception as e:
            return {"type": "dga_domain", "domain": full_domain, "error": str(e)}
    
    def generate_data_exfiltration(self) -> dict:
        """Simulate data exfiltration (T1048)"""
        # Generate fake "stolen" data
        fake_data = {
            "credentials": [
                {"user": "admin", "hash": hashlib.md5(b"password123").hexdigest()},
                {"user": "backup", "hash": hashlib.md5(b"backup2024").hexdigest()},
            ],
            "system_info": {
                "hostname": socket.gethostname(),
                "users": ["admin", "user1", "service_account"],
            },
            "files": [
                "/etc/passwd", "/etc/shadow", "C:\\Users\\Admin\\Documents\\passwords.txt"
            ]
        }
        
        headers = {
            "User-Agent": random.choice(Config.USER_AGENTS[4:]),
            "Content-Type": "application/json",
            "X-Exfil-ID": hashlib.sha256(str(time.time()).encode()).hexdigest()[:16],
        }
        
        try:
            url = f"http://{self.target}:{self.http_port}/submit"
            response = requests.post(url, json={"exfil": fake_data}, headers=headers, timeout=5)
            
            return {
                "type": "exfiltration",
                "size": len(json.dumps(fake_data)),
                "status": response.status_code,
                "mitre": Config.MITRE_TECHNIQUES["exfiltration"],
                "classification": "malicious"
            }
        except Exception as e:
            return {"type": "exfiltration", "error": str(e)}
    
    def generate_credential_attack(self) -> dict:
        """Simulate credential theft via FTP (T1078)"""
        usernames = ["malware", "admin", "root", "backup", "service"]
        passwords = ["c2pass", "password123", "admin123", "letmein"]
        
        username = random.choice(usernames)
        password = random.choice(passwords)
        
        try:
            from ftplib import FTP
            ftp = FTP()
            ftp.connect(self.target, self.ftp_port, timeout=5)
            ftp.login(username, password)
            files = ftp.nlst()
            ftp.quit()
            
            return {
                "type": "credential_attack",
                "username": username,
                "files_accessed": files,
                "mitre": Config.MITRE_TECHNIQUES["credential_access"],
                "classification": "malicious"
            }
        except Exception as e:
            return {"type": "credential_attack", "username": username, "error": str(e)}
    
    def generate_system_discovery(self) -> dict:
        """Simulate system discovery requests (T1082)"""
        discovery_endpoints = [
            "/api/system/info",
            "/api/users",
            "/api/network",
            "/api/processes",
        ]
        
        headers = {
            "User-Agent": random.choice(Config.USER_AGENTS[4:]),
            "X-Discovery-ID": ''.join(random.choices(string.hexdigits, k=8)),
        }
        
        endpoint = random.choice(discovery_endpoints)
        
        try:
            url = f"http://{self.target}:{self.http_port}{endpoint}"
            response = requests.get(url, headers=headers, timeout=5)
            
            return {
                "type": "discovery",
                "endpoint": endpoint,
                "status": response.status_code,
                "mitre": Config.MITRE_TECHNIQUES["discovery"],
                "classification": "malicious"
            }
        except Exception as e:
            return {"type": "discovery", "error": str(e)}
    
    def _build_dns_query(self, domain: str) -> bytes:
        query = bytes([random.randint(0, 255), random.randint(0, 255)])
        query += b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        for part in domain.split('.'):
            query += bytes([len(part)]) + part.encode()
        query += b'\x00\x00\x01\x00\x01'
        return query
    
    def _calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of a string"""
        from collections import Counter
        import math
        if not s:
            return 0.0
        counts = Counter(s)
        length = len(s)
        return -sum((c/length) * math.log2(c/length) for c in counts.values())


# =============================================
# Demo Orchestrator
# =============================================

class DemoTrafficOrchestrator:
    """Orchestrate mixed clean/malicious traffic generation"""
    
    def __init__(self, clean_ratio: float = 0.6, target: str = "localhost",
                 http_port: int = 8888, dns_port: int = 53, ftp_port: int = 21):
        self.clean_ratio = clean_ratio
        self.target = target
        
        self.clean_gen = CleanTrafficGenerator(target, http_port, dns_port)
        self.malicious_gen = MaliciousTrafficGenerator(target, http_port, dns_port, ftp_port)
        
        # Stats
        self.stats = {
            "total": 0,
            "clean": 0,
            "malicious": 0,
            "errors": 0,
            "by_type": {},
        }
    
    def generate_single_traffic(self) -> dict:
        """Generate a single traffic event (clean or malicious based on ratio)"""
        is_clean = random.random() < self.clean_ratio
        
        if is_clean:
            # Clean traffic generators
            generators = [
                self.clean_gen.generate_http_browse,
                self.clean_gen.generate_api_healthcheck,
                self.clean_gen.generate_dns_lookup,
            ]
        else:
            # Malicious traffic generators (weighted)
            generators = [
                self.malicious_gen.generate_c2_beacon,
                self.malicious_gen.generate_c2_beacon,  # More beacons
                self.malicious_gen.generate_dns_beacon,
                self.malicious_gen.generate_dga_domain,
                self.malicious_gen.generate_data_exfiltration,
                self.malicious_gen.generate_credential_attack,
                self.malicious_gen.generate_system_discovery,
            ]
        
        generator = random.choice(generators)
        result = generator()
        
        # Update stats
        self.stats["total"] += 1
        if result.get("classification") == "legitimate":
            self.stats["clean"] += 1
        elif result.get("classification") == "malicious":
            self.stats["malicious"] += 1
        
        if "error" in result:
            self.stats["errors"] += 1
        
        traffic_type = result.get("type", "unknown")
        self.stats["by_type"][traffic_type] = self.stats["by_type"].get(traffic_type, 0) + 1
        
        return result
    
    def run_demo(self, duration: int = 60, min_interval: float = 0.5, max_interval: float = 3.0):
        """Run the demo for specified duration with random intervals"""
        log("=" * 60, "INFO")
        log("C2Trap Enhanced Demo Traffic Generator", "INFO")
        log("=" * 60, "INFO")
        log(f"Target: {self.target}")
        log(f"Duration: {duration}s")
        log(f"Clean/Malicious Ratio: {int(self.clean_ratio*100)}:{int((1-self.clean_ratio)*100)}")
        log("=" * 60, "INFO")
        
        start_time = time.time()
        
        while time.time() - start_time < duration:
            # Generate traffic
            result = self.generate_single_traffic()
            
            # Log result
            classification = result.get("classification", "unknown")
            traffic_type = result.get("type", "unknown")
            
            if "error" in result:
                log(f"[{traffic_type}] Error: {result['error']}", "ERR")
            elif classification == "legitimate":
                detail = result.get("endpoint") or result.get("domain", "")
                log(f"[{traffic_type}] {detail}", "CLEAN")
            else:
                detail = result.get("endpoint") or result.get("domain", "")
                mitre = result.get("mitre", {}).get("id", "")
                log(f"[{traffic_type}] {detail} ({mitre})", "MALICIOUS")
            
            # Random interval with jitter
            interval = random.uniform(min_interval, max_interval)
            time.sleep(interval)
        
        # Print summary
        self._print_summary()
    
    def run_burst(self, count: int = 20, burst_delay: float = 0.1):
        """Run a quick burst of traffic"""
        log("=" * 60, "INFO")
        log(f"Running burst: {count} events", "INFO")
        log("=" * 60, "INFO")
        
        for i in range(count):
            result = self.generate_single_traffic()
            classification = result.get("classification", "unknown")
            traffic_type = result.get("type", "unknown")
            
            if classification == "legitimate":
                log(f"[{i+1}/{count}] {traffic_type}", "CLEAN")
            else:
                mitre = result.get("mitre", {}).get("id", "")
                log(f"[{i+1}/{count}] {traffic_type} ({mitre})", "MALICIOUS")
            
            time.sleep(burst_delay)
        
        self._print_summary()
    
    def _print_summary(self):
        """Print traffic summary"""
        log("", "INFO")
        log("=" * 60, "INFO")
        log("Demo Complete - Summary", "OK")
        log("=" * 60, "INFO")
        log(f"Total Events:      {self.stats['total']}")
        log(f"Clean Traffic:     {self.stats['clean']} ({self.stats['clean']/max(1,self.stats['total'])*100:.1f}%)", "CLEAN")
        log(f"Malicious Traffic: {self.stats['malicious']} ({self.stats['malicious']/max(1,self.stats['total'])*100:.1f}%)", "MALICIOUS")
        log(f"Errors:            {self.stats['errors']}", "WARN" if self.stats['errors'] > 0 else "INFO")
        log("")
        log("Traffic Types:")
        for ttype, count in sorted(self.stats["by_type"].items(), key=lambda x: -x[1]):
            log(f"  {ttype}: {count}")
        log("")
        log("Check the C2Trap dashboard at http://localhost:8000", "OK")
        log("=" * 60, "INFO")


# =============================================
# Main
# =============================================

def main():
    parser = argparse.ArgumentParser(
        description="C2Trap Enhanced Demo Traffic Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python demo_traffic.py                           # Run 60s demo
  python demo_traffic.py --duration 120            # Run 2 minute demo
  python demo_traffic.py --ratio 70:30             # 70% clean, 30% malicious
  python demo_traffic.py --burst 50                # Quick burst of 50 events
  python demo_traffic.py -t 192.168.1.100          # Custom target
        """
    )
    
    parser.add_argument("-t", "--target", default="localhost", help="Target host")
    parser.add_argument("-p", "--http-port", type=int, default=8888, help="HTTP port")
    parser.add_argument("--dns-port", type=int, default=53, help="DNS port")
    parser.add_argument("--ftp-port", type=int, default=21, help="FTP port")
    parser.add_argument("-d", "--duration", type=int, default=60, help="Demo duration in seconds")
    parser.add_argument("-r", "--ratio", default="60:40", help="Clean:Malicious ratio (e.g., 60:40)")
    parser.add_argument("--burst", type=int, help="Run quick burst of N events instead of timed demo")
    parser.add_argument("--min-interval", type=float, default=0.5, help="Min interval between events")
    parser.add_argument("--max-interval", type=float, default=3.0, help="Max interval between events")
    
    args = parser.parse_args()
    
    # Parse ratio
    try:
        clean, malicious = map(int, args.ratio.split(":"))
        clean_ratio = clean / (clean + malicious)
    except:
        log(f"Invalid ratio format: {args.ratio}. Using 60:40", "WARN")
        clean_ratio = 0.6
    
    # Create orchestrator
    orchestrator = DemoTrafficOrchestrator(
        clean_ratio=clean_ratio,
        target=args.target,
        http_port=args.http_port,
        dns_port=args.dns_port,
        ftp_port=args.ftp_port,
    )
    
    # Run demo
    if args.burst:
        orchestrator.run_burst(count=args.burst)
    else:
        orchestrator.run_demo(
            duration=args.duration,
            min_interval=args.min_interval,
            max_interval=args.max_interval,
        )


if __name__ == "__main__":
    main()
