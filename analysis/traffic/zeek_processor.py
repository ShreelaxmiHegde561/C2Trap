import os
import json
import time
import logging
import threading
from datetime import datetime

logger = logging.getLogger('zeek_processor')

# MITRE technique mappings for Zeek events
MITRE_MAPPINGS = {
    'dns_query': 'T1071.004',      # DNS C2
    'http_request': 'T1071.001',   # Web Protocols
    'tls_handshake': 'T1573.002',  # Encrypted Channel
    'zeek_notice': 'T1071',        # Application Layer Protocol
}

class ZeekProcessor:
    """Processes Zeek JSON logs and converts them to C2Trap events"""
    
    def __init__(self, log_dir='/app/logs/zeek', callback=None):
        self.log_dir = log_dir
        self.callback = callback
        self.running = False
        self.observed_files = {}  # filename: last_position
        self.threads = []

    def start(self):
        self.running = True
        logger.info(f"Starting Zeek log processor on {self.log_dir}")
        # Watch for specific logs including notice.log for alerts
        watch_targets = ['conn.log', 'dns.log', 'http.log', 'ssl.log', 'notice.log']
        for target in watch_targets:
            t = threading.Thread(target=self._tail_log, args=(target,), daemon=True)
            t.start()
            self.threads.append(t)

    def _tail_log(self, filename):
        path = os.path.join(self.log_dir, filename)
        logger.info(f"Tailing Zeek log: {path}")
        
        while self.running:
            if not os.path.exists(path):
                time.sleep(2)
                continue
                
            try:
                with open(path, 'r') as f:
                    # Check for file truncation/rotation
                    f.seek(0, os.SEEK_END)
                    current_size = f.tell()
                    
                    if path not in self.observed_files:
                        self.observed_files[path] = current_size
                    elif current_size < self.observed_files[path]:
                        logger.info(f"Log rotated or truncated: {path}")
                        self.observed_files[path] = 0
                    
                    f.seek(self.observed_files[path])
                    
                    while True:
                        line = f.readline()
                        if not line:
                            self.observed_files[path] = f.tell()
                            break
                            
                        # Process the JSON line
                        try:
                            data = json.loads(line.strip())
                            self._process_line(filename, data)
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                logger.error(f"Error reading {path}: {e}")
            
            time.sleep(1)

    def _process_line(self, log_type, data):
        """Standardize Zeek logs into C2Trap events"""
        log_name = log_type.split(".")[0]
        event = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'source': f'zeek:{log_name}',
            'event_type': 'zeek_activity',
            'data': self._clean_zeek_data(data, log_name)
        }
        
        # Enrich event type based on log
        if log_name == 'dns':
            event['event_type'] = 'dns_query'
            event['data']['mitre_technique'] = MITRE_MAPPINGS.get('dns_query')
        elif log_name == 'http':
            event['event_type'] = 'http_request'
            event['data']['mitre_technique'] = MITRE_MAPPINGS.get('http_request')
        elif log_name == 'ssl':
            event['event_type'] = 'tls_handshake'
            event['data']['mitre_technique'] = MITRE_MAPPINGS.get('tls_handshake')
            if 'ja3' in data:
                event['event_type'] = 'ja3_fingerprint'
                event['data']['ja3_hash'] = data.get('ja3')
        elif log_name == 'notice':
            event['event_type'] = 'zeek_notice'
            event['data']['mitre_technique'] = MITRE_MAPPINGS.get('zeek_notice')
            # Mark notices as suspicious for alert generation
            event['data']['suspicious'] = True
            event['data']['notice_type'] = data.get('note', 'Unknown')
            event['data']['message'] = data.get('msg', '')
        elif log_name == 'conn':
            event['event_type'] = 'connection'
        
        if self.callback:
            self.callback(event)

    def _clean_zeek_data(self, data, log_name):
        """Map Zeek fields to C2Trap common fields"""
        cleaned = {}
        
        # Copy original data
        for key, value in data.items():
            # Skip internal Zeek fields
            if not key.startswith('_'):
                cleaned[key] = value
        
        # Common Zeek field mappings
        field_mappings = {
            'id.orig_h': 'src_ip',
            'id.resp_h': 'dst_ip', 
            'id.resp_p': 'dst_port',
            'id.orig_p': 'src_port',
            'proto': 'protocol',
            'query': 'query_name',
            'host': 'domain',
            'uri': 'path',
            'method': 'method',
            'user_agent': 'user_agent',
            'server_name': 'sni',
        }
        
        for zeek_field, c2trap_field in field_mappings.items():
            if zeek_field in data:
                cleaned[c2trap_field] = data[zeek_field]
        
        # Set remote_ip for IOC extraction (use destination for outbound)
        if 'dst_ip' in cleaned:
            cleaned['remote_ip'] = cleaned['dst_ip']
        elif 'src_ip' in cleaned:
            cleaned['remote_ip'] = cleaned['src_ip']
        
        # Extract domain from HTTP host or DNS query
        if 'domain' not in cleaned:
            if 'query_name' in cleaned:
                cleaned['domain'] = cleaned['query_name']
        
        return cleaned

    def stop(self):
        self.running = False
        for t in self.threads:
            t.join(timeout=1)
