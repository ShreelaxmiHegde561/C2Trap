
import sys
import os

# Mock the EventStore class and _is_alertable function to test logic without full environment
class MockEventStore:
    def _is_alertable(self, event: dict) -> bool:
        """Check if event should generate an alert"""
        alertable_types = [
            'beacon_detected', 'malware_detected', 'malicious_ip_detected',
            'malicious_domain_detected', 'cobalt_strike_beacon', 'c2_direct',
            'data_exfil_attempt', 'ja3_fingerprint',
            'dga_domain_detected', 'dns_tunneling_detected', 'tls_anomaly_detected',
            'c2_beacon', 'c2_task_request'
        ]
        event_type = event.get('event_type', '')
        source = event.get('source', '')
        data = event.get('data', {})
        
        # Alert on decoy/trap hits ONLY if they are significant
        # This prevents 1:1 event/alert ratio for raw connection logs
        if 'decoy' in source or 'trap' in source or 'sinkhole' in source:
            # If it's a specific detection event (e.g. cmd_injection), always alert
            if event_type not in ['http_connection', 'http_request', 'dns_query', 'ftp_connection']:
                return True
            # For raw connections, only alert if flagged as suspicious/malicious
            is_suspicious = data.get('suspicious') or data.get('is_malicious') or data.get('is_known_malware')
            if is_suspicious:
                 return True
            return False

        # Don't alert on raw events unless they have high severity flags
        if event_type in ['dns_query', 'http_request', 'http_connection', 'tls_handshake']:
             return data.get('is_malicious') or data.get('is_known_malware')

        return (
            event_type in alertable_types or
            data.get('suspicious') or
            data.get('is_malicious') or
            data.get('is_known_malware')
        )

def test_logic():
    store = MockEventStore()
    
    # CASE 1: Benign Decoy Traffic (Should be FALSE)
    benign_event = {
        'source': 'http_decoy',
        'event_type': 'http_connection',
        'data': {
            'remote_ip': '192.168.1.50',
            'method': 'GET'
        }
    }
    
    # CASE 2: Malicious Decoy Traffic (Should be TRUE)
    malicious_event = {
        'source': 'http_decoy',
        'event_type': 'cmd_injection_detected',
        'data': {
            'remote_ip': '192.168.1.100',
            'suspicious': True
        }
    }
    
    # CASE 3: Suspicious Raw Traffic (Should be TRUE)
    suspicious_raw = {
        'source': 'http_decoy',
        'event_type': 'http_connection',
        'data': {
            'remote_ip': '192.168.1.101',
            'suspicious': True
        }
    }

    print(f"Testing Benign Event... Expecting False -> Got {store._is_alertable(benign_event)}")
    print(f"Testing Malicious Event... Expecting True -> Got {store._is_alertable(malicious_event)}")
    print(f"Testing Suspicious Raw... Expecting True -> Got {store._is_alertable(suspicious_raw)}")

    if not store._is_alertable(benign_event) and store._is_alertable(malicious_event) and store._is_alertable(suspicious_raw):
        print("SUCCESS: Logic is correct.")
    else:
        print("FAILURE: Logic is flawed.")
        sys.exit(1)

if __name__ == "__main__":
    test_logic()
