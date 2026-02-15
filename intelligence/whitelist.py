"""
C2Trap Smart Whitelist Module
Provides a list of known safe domains and IPs to reduce false positives.
"""
import ipaddress
import logging

logger = logging.getLogger("c2trap.whitelist")

class SmartWhitelist:
    def __init__(self):
        # Top domains that are generally safe (Sample list)
        self.safe_domains = {
            "google.com", "googleapis.com", "gstatic.com", "youtube.com",
            "microsoft.com", "windowsupdate.com", "live.com", "office.com", "azure.com",
            "amazon.com", "aws.amazon.com", "cloudfront.net",
            "facebook.com", "instagram.com", "whatsapp.com",
            "apple.com", "icloud.com", "cdn-apple.com",
            "cloudflare.com", "akamai.net", "fastly.net",
            "github.com", "gitlab.com", "stackoverflow.com",
            "zoom.us", "slack.com", "spotify.com", "netflix.com"
        }
        
        # Local network ranges (RFC1918)
        self.safe_networks = [
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("169.254.0.0/16") # Link-local
        ]

    def is_safe_domain(self, domain: str) -> bool:
        """Check if a domain is in the safe list"""
        if not domain:
            return False
            
        domain = domain.lower()
        
        # Direct match
        if domain in self.safe_domains:
            return True
            
        # Subdomain match (e.g., mail.google.com)
        for safe in self.safe_domains:
            if domain.endswith("." + safe):
                return True
                
        return False

    def is_safe_ip(self, ip: str) -> bool:
        """Check if an IP is in a safe network range"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for network in self.safe_networks:
                if ip_obj in network:
                    return True
        except ValueError:
            pass # Invalid IP
            
        return False

# Singleton instance
whitelist = SmartWhitelist()
