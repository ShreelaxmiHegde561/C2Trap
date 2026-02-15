#!/usr/bin/env python3
"""
Zeek Log Parser for C2Trap
Monitors Zeek TSV log files and converts them to C2Trap event format
"""

import os
import time
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import glob

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s'
)
logger = logging.getLogger('zeek_parser')

# Paths
ZEEK_LOG_DIR = os.environ.get('ZEEK_LOG_DIR', '/usr/local/zeek/logs')
OUTPUT_LOG = os.environ.get('OUTPUT_LOG', '/app/logs/analysis_queue.jsonl')
STATE_FILE = '/tmp/zeek_parser_state.json'

# Zeek log types to monitor
LOG_TYPES = {
    'conn.log': 'zeek:conn',
    'dns.log': 'zeek:dns',
    'http.log': 'zeek:http',
    'ssl.log': 'zeek:ssl',
    'notice.log': 'zeek:notice'
}


class ZeekParser:
    """Parser for Zeek TSV log files"""
    
    def __init__(self, log_dir: str, output_file: str):
        self.log_dir = Path(log_dir)
        self.output_file = Path(output_file)
        self.state = self._load_state()
        self.field_mappings = {}
        
    def _load_state(self) -> Dict[str, int]:
        """Load last read positions for each log file"""
        try:
            if os.path.exists(STATE_FILE):
                with open(STATE_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"Could not load state: {e}")
        return {}
    
    def _save_state(self):
        """Save current read positions"""
        try:
            with open(STATE_FILE, 'w') as f:
                json.dump(self.state, f)
        except Exception as e:
            logger.error(f"Could not save state: {e}")
    
    def _parse_zeek_header(self, lines: List[str]) -> Optional[List[str]]:
        """Extract field names from Zeek log header"""
        for line in lines:
            if line.startswith('#fields'):
                # Remove #fields prefix and split by tab
                fields = line.replace('#fields', '').strip().split('\t')
                return [f.strip() for f in fields if f.strip()]
        return None
    
    def _convert_timestamp(self, ts: str) -> str:
        """Convert Zeek timestamp to ISO format"""
        try:
            # Zeek uses epoch time with decimals
            epoch = float(ts)
            dt = datetime.utcfromtimestamp(epoch)
            return dt.isoformat() + 'Z'
        except:
            return datetime.utcnow().isoformat() + 'Z'
    
    def _parse_conn_log(self, fields: List[str], values: List[str]) -> Dict[str, Any]:
        """Parse connection log entry"""
        data = dict(zip(fields, values))
        
        return {
            'timestamp': self._convert_timestamp(data.get('ts', '0')),
            'source': 'zeek:conn',
            'event_type': 'network_connection',
            'data': {
                'uid': data.get('uid', ''),
                'src_ip': data.get('id.orig_h', ''),
                'src_port': int(data.get('id.orig_p', 0)) if data.get('id.orig_p', '').isdigit() else 0,
                'dst_ip': data.get('id.resp_h', ''),
                'dst_port': int(data.get('id.resp_p', 0)) if data.get('id.resp_p', '').isdigit() else 0,
                'proto': data.get('proto', ''),
                'service': data.get('service', ''),
                'duration': float(data.get('duration', 0)) if data.get('duration', '-') != '-' else 0,
                'orig_bytes': int(data.get('orig_bytes', 0)) if data.get('orig_bytes', '-') != '-' else 0,
                'resp_bytes': int(data.get('resp_bytes', 0)) if data.get('resp_bytes', '-') != '-' else 0,
                'conn_state': data.get('conn_state', ''),
            }
        }
    
    def _parse_dns_log(self, fields: List[str], values: List[str]) -> Dict[str, Any]:
        """Parse DNS log entry"""
        data = dict(zip(fields, values))
        
        return {
            'timestamp': self._convert_timestamp(data.get('ts', '0')),
            'source': 'zeek:dns',
            'event_type': 'dns_query',
            'data': {
                'uid': data.get('uid', ''),
                'src_ip': data.get('id.orig_h', ''),
                'dst_ip': data.get('id.resp_h', ''),
                'query_name': data.get('query', ''),
                'qtype': data.get('qtype_name', ''),
                'rcode': data.get('rcode_name', ''),
                'answers': data.get('answers', '').split(',') if data.get('answers', '-') != '-' else [],
            }
        }
    
    def _parse_http_log(self, fields: List[str], values: List[str]) -> Dict[str, Any]:
        """Parse HTTP log entry"""
        data = dict(zip(fields, values))
        
        return {
            'timestamp': self._convert_timestamp(data.get('ts', '0')),
            'source': 'zeek:http',
            'event_type': 'http_request',
            'data': {
                'uid': data.get('uid', ''),
                'src_ip': data.get('id.orig_h', ''),
                'dst_ip': data.get('id.resp_h', ''),
                'method': data.get('method', ''),
                'host': data.get('host', ''),
                'uri': data.get('uri', ''),
                'user_agent': data.get('user_agent', ''),
                'status_code': int(data.get('status_code', 0)) if data.get('status_code', '-') != '-' else 0,
                'response_body_len': int(data.get('response_body_len', 0)) if data.get('response_body_len', '-') != '-' else 0,
            }
        }
    
    def _parse_ssl_log(self, fields: List[str], values: List[str]) -> Dict[str, Any]:
        """Parse SSL/TLS log entry"""
        data = dict(zip(fields, values))
        
        return {
            'timestamp': self._convert_timestamp(data.get('ts', '0')),
            'source': 'zeek:ssl',
            'event_type': 'tls_handshake',
            'data': {
                'uid': data.get('uid', ''),
                'src_ip': data.get('id.orig_h', ''),
                'dst_ip': data.get('id.resp_h', ''),
                'server_name': data.get('server_name', ''),
                'version': data.get('version', ''),
                'cipher': data.get('cipher', ''),
                'ja3_hash': data.get('ja3', ''),
                'ja3s_hash': data.get('ja3s', ''),
            }
        }
    
    def _parse_notice_log(self, fields: List[str], values: List[str]) -> Dict[str, Any]:
        """Parse notice/alert log entry"""
        data = dict(zip(fields, values))
        
        return {
            'timestamp': self._convert_timestamp(data.get('ts', '0')),
            'source': 'zeek:notice',
            'event_type': 'zeek_alert',
            'data': {
                'uid': data.get('uid', ''),
                'src_ip': data.get('id.orig_h', ''),
                'dst_ip': data.get('id.resp_h', ''),
                'note': data.get('note', ''),
                'msg': data.get('msg', ''),
                'sub': data.get('sub', ''),
                'actions': data.get('actions', '').split(',') if data.get('actions', '-') != '-' else [],
            }
        }
    
    def parse_log_entry(self, log_type: str, fields: List[str], values: List[str]) -> Optional[Dict[str, Any]]:
        """Parse a single log entry based on type"""
        try:
            if log_type == 'conn.log':
                return self._parse_conn_log(fields, values)
            elif log_type == 'dns.log':
                return self._parse_dns_log(fields, values)
            elif log_type == 'http.log':
                return self._parse_http_log(fields, values)
            elif log_type == 'ssl.log':
                return self._parse_ssl_log(fields, values)
            elif log_type == 'notice.log':
                return self._parse_notice_log(fields, values)
            else:
                logger.warning(f"Unknown log type: {log_type}")
                return None
        except Exception as e:
            logger.error(f"Error parsing {log_type} entry: {e}")
            return None
    
    def process_log_file(self, log_file: Path, log_type: str):
        """Process a single Zeek log file"""
        try:
            if not log_file.exists():
                return
            
            # Get last processed position
            file_key = str(log_file)
            last_pos = self.state.get(file_key, 0)
            
            with open(log_file, 'r', errors='ignore') as f:
                # Seek to last position
                f.seek(last_pos)
                
                # Read all lines
                lines = f.readlines()
                if not lines:
                    return
                
                # Extract field mapping from header
                fields = None
                new_events = 0
                
                for line in lines:
                    line = line.strip()
                    
                    # Skip empty lines and comments (except fields)
                    if not line or (line.startswith('#') and not line.startswith('#fields')):
                        if line.startswith('#fields'):
                            fields = self._parse_zeek_header([line])
                        continue
                    
                    # If we have fields and this is data
                    if fields and not line.startswith('#'):
                        values = line.split('\t')
                        
                        # Parse the event
                        event = self.parse_log_entry(log_type, fields, values)
                        if event:
                            # Write to output
                            self._write_event(event)
                            new_events += 1
                
                # Update position
                self.state[file_key] = f.tell()
                
                if new_events > 0:
                    logger.info(f"Processed {new_events} events from {log_type}")
                
        except Exception as e:
            logger.error(f"Error processing {log_file}: {e}")
    
    def _write_event(self, event: Dict[str, Any]):
        """Write event to output file"""
        try:
            # Ensure output directory exists
            self.output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.output_file, 'a') as f:
                f.write(json.dumps(event) + '\n')
        except Exception as e:
            logger.error(f"Error writing event: {e}")
    
    def run(self, interval: int = 5):
        """Main loop - monitor and parse Zeek logs"""
        logger.info(f"Starting Zeek parser, monitoring {self.log_dir}")
        logger.info(f"Output: {self.output_file}")
        
        while True:
            try:
                # Process each log type
                for log_filename, source_prefix in LOG_TYPES.items():
                    log_path = self.log_dir / log_filename
                    if log_path.exists():
                        self.process_log_file(log_path, log_filename)
                
                # Save state
                self._save_state()
                
                # Wait before next check
                time.sleep(interval)
                
            except KeyboardInterrupt:
                logger.info("Shutting down...")
                self._save_state()
                break
            except Exception as e:
                logger.error(f"Error in main loop: {e}")
                time.sleep(interval)


def main():
    """Entry point"""
    parser = ZeekParser(ZEEK_LOG_DIR, OUTPUT_LOG)
    parser.run(interval=5)


if __name__ == '__main__':
    main()
