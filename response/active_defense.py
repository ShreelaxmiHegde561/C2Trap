"""
C2Trap Active Defense Module
Handles automated response actions like IP blocking using iptables.
Designed with safety checks to prevent self-lockout.
"""
import os
import logging
import subprocess
from intelligence.whitelist import whitelist

logger = logging.getLogger("c2trap.response")

class ActiveDefense:
    def __init__(self, dry_run=True):
        self.dry_run = dry_run
        self.blocked_ips = set()
        
        if self.dry_run:
            logger.info("ActiveDefense initialized in DRY-RUN mode. No actual blocks will occur.")
        else:
            logger.warning("ActiveDefense initialized in LIVE mode. Real IP blocking enabled.")

    def block_ip(self, ip: str, reason: str = "Malicious Activity"):
        """
        Block an IP address using iptables (Linux).
        Includes safety checks for localhost/LAN.
        """
        # 1. Safety Check: Never block whitelist/local items
        if whitelist.is_safe_ip(ip):
            logger.warning(f"SAFETY: Prevented blocking of safe IP: {ip}")
            return False

        if ip in self.blocked_ips:
            return True # Already blocked

        # 2. Execute Block
        command = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        
        if self.dry_run:
            logger.info(f"[SIMULATION] Would execute: {' '.join(command)}")
            logger.info(f"ActiveDefense: Simulated BLOCK of {ip} due to {reason}")
        else:
            try:
                subprocess.run(command, check=True)
                logger.info(f"ActiveDefense: BLOCKED {ip} due to {reason}")
                self.blocked_ips.add(ip)
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to block IP {ip}: {e}")
                return False
                
        return True

# Singleton instance
active_defense = ActiveDefense(dry_run=True) # Default to Safe Mode
