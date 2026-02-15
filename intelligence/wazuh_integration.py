"""
C2Trap Wazuh SIEM Integration
Formats and forwards C2Trap alerts to Wazuh for centralized monitoring.

Wazuh reads JSON alerts from a log file. This module writes alerts
in Wazuh-compatible format so they appear in the Wazuh dashboard.

If Wazuh is not installed, alerts are written to a local file.
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional

logger = logging.getLogger("c2trap.wazuh")

# Wazuh default log path (Linux)
WAZUH_LOG_PATH = os.environ.get(
    'WAZUH_LOG_PATH',
    '/var/ossec/logs/c2trap_alerts.json'
)

# Fallback if Wazuh is not installed
LOCAL_WAZUH_LOG = os.environ.get(
    'LOCAL_WAZUH_LOG',
    'logs/wazuh_alerts.json'
)


class WazuhIntegration:
    """
    Wazuh SIEM Integration for C2Trap
    
    Writes alerts in Wazuh-compatible JSON format:
    - rule.id:          C2Trap rule identifier
    - rule.level:       Severity (1-15, Wazuh scale)
    - rule.description: Human-readable alert description
    - data.srcip:       Source IP of the threat
    - data.dstip:       Destination IP
    - decoder.name:     Always "c2trap"
    """

    # Map C2Trap severity to Wazuh levels (1-15)
    SEVERITY_MAP = {
        'low': 3,
        'medium': 7,
        'high': 10,
        'critical': 13
    }

    # Custom rule IDs for C2Trap events
    RULE_IDS = {
        'beacon_detected': 100001,
        'malware_detected': 100002,
        'dns_tunneling': 100003,
        'data_exfil_attempt': 100004,
        'ja3_fingerprint': 100005,
        'ip_blocked': 100006,
        'whitelist_skip': 100007,
        'c2_direct': 100008,
    }

    def __init__(self):
        self.log_path = self._determine_log_path()
        self.alert_count = 0
        logger.info(f"Wazuh integration initialized. Logging to: {self.log_path}")

    def _determine_log_path(self) -> str:
        """Use Wazuh path if available, otherwise use local fallback"""
        wazuh_dir = os.path.dirname(WAZUH_LOG_PATH)
        if os.path.exists(wazuh_dir) and os.access(wazuh_dir, os.W_OK):
            logger.info(f"Wazuh detected at {wazuh_dir}")
            return WAZUH_LOG_PATH
        else:
            logger.info("Wazuh not found. Using local log file.")
            os.makedirs(os.path.dirname(LOCAL_WAZUH_LOG), exist_ok=True)
            return LOCAL_WAZUH_LOG

    def send_alert(self,
                   event_type: str,
                   severity: str,
                   description: str,
                   src_ip: Optional[str] = None,
                   dst_ip: Optional[str] = None,
                   extra_data: Optional[Dict[str, Any]] = None):
        """
        Send an alert to Wazuh in compatible JSON format.
        
        Args:
            event_type: Type of event (e.g., 'beacon_detected')
            severity: C2Trap severity ('low', 'medium', 'high', 'critical')
            description: Human-readable description
            src_ip: Source IP address
            dst_ip: Destination IP address
            extra_data: Additional data fields
        """
        rule_id = self.RULE_IDS.get(event_type, 100099)
        wazuh_level = self.SEVERITY_MAP.get(severity.lower(), 5)

        alert = {
            "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "rule": {
                "id": str(rule_id),
                "level": wazuh_level,
                "description": description,
                "groups": ["c2trap", "threat_detection", event_type]
            },
            "agent": {
                "id": "c2trap-001",
                "name": "C2Trap-Sensor",
                "ip": "127.0.0.1"
            },
            "decoder": {
                "name": "c2trap"
            },
            "data": {
                "srcip": src_ip or "unknown",
                "dstip": dst_ip or "unknown",
                "event_type": event_type,
                "severity": severity,
                **(extra_data or {})
            },
            "location": "c2trap-analysis-engine"
        }

        try:
            with open(self.log_path, 'a') as f:
                f.write(json.dumps(alert) + '\n')
            self.alert_count += 1
            logger.info(
                f"[WAZUH] Alert #{self.alert_count} | "
                f"Rule:{rule_id} Level:{wazuh_level} | "
                f"{description}"
            )
        except Exception as e:
            logger.error(f"Failed to write Wazuh alert: {e}")

    def get_stats(self) -> dict:
        """Get integration statistics"""
        return {
            'log_path': self.log_path,
            'alerts_sent': self.alert_count,
            'wazuh_detected': self.log_path == WAZUH_LOG_PATH
        }


# Singleton instance
wazuh = WazuhIntegration()
