"""
C2Trap Packet Capture Module
Real-time network traffic capture and analysis using Scapy
"""

import os
import json
import logging
import threading
from datetime import datetime
from typing import Optional, Callable, Dict, Any
from collections import defaultdict

try:
    from scapy.all import (
        sniff, IP, TCP, UDP, DNS, DNSQR, Raw,
        get_if_list, conf
    )
except ImportError:
    print("Scapy not installed. Run: pip install scapy")
    raise

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('packet_capture')

LOG_PATH = os.environ.get('LOG_PATH', '/app/logs/analysis_queue.jsonl')


def log_event(event_type: str, data: dict) -> None:
    """Write event to analysis queue"""
    event = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'source': 'packet_capture',
        'event_type': event_type,
        'data': data
    }
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, 'a') as f:
            f.write(json.dumps(event) + '\n')
    except Exception as e:
        logger.error(f"Failed to write log: {e}")


class PacketCapture:
    """Network packet capture and analysis engine"""
    
    def __init__(self, interface: str = 'eth0', callback: Optional[Callable] = None):
        self.interface = interface
        self.callback = callback
        self.running = False
        self.capture_thread = None
        self.stats = defaultdict(int)
        
        # Connection tracking
        self.connections: Dict[str, Dict[str, Any]] = {}
    
    def _get_connection_key(self, src_ip: str, dst_ip: str, 
                            src_port: int, dst_port: int, proto: str) -> str:
        """Generate unique connection identifier"""
        return f"{proto}:{src_ip}:{src_port}-{dst_ip}:{dst_port}"
    
    def _process_packet(self, packet):
        """Process captured packet"""
        try:
            if not packet.haslayer(IP):
                return
            
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = 'unknown'
            src_port = 0
            dst_port = 0
            
            packet_data = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': protocol,
                'size': len(packet)
            }
            
            # TCP packet
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                src_port = tcp.sport
                dst_port = tcp.dport
                protocol = 'tcp'
                packet_data.update({
                    'protocol': 'tcp',
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'flags': str(tcp.flags),
                    'seq': tcp.seq,
                    'ack': tcp.ack
                })
                
                # Detect HTTP
                if dst_port in [80, 8080, 8000, 8888] or src_port in [80, 8080, 8000, 8888]:
                    packet_data['app_protocol'] = 'http'
                    self._process_http(packet, packet_data)
                
                # Detect HTTPS/TLS
                elif dst_port in [443, 8443] or src_port in [443, 8443]:
                    packet_data['app_protocol'] = 'https'
                    self._process_tls(packet, packet_data)
                
                # Track connection
                conn_key = self._get_connection_key(src_ip, dst_ip, src_port, dst_port, 'tcp')
                self._track_connection(conn_key, packet_data)
            
            # UDP packet
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                src_port = udp.sport
                dst_port = udp.dport
                protocol = 'udp'
                packet_data.update({
                    'protocol': 'udp',
                    'src_port': src_port,
                    'dst_port': dst_port
                })
                
                # Detect DNS
                if packet.haslayer(DNS):
                    packet_data['app_protocol'] = 'dns'
                    self._process_dns(packet, packet_data)
            
            # Update stats
            self.stats['packets'] += 1
            self.stats[protocol] += 1
            
            # Call callback if provided
            if self.callback:
                self.callback(packet_data)
            
            # Log significant events
            if packet_data.get('app_protocol'):
                # Create a copy for logging without bytes
                log_data = {k: v for k, v in packet_data.items() if not isinstance(v, bytes)}
                log_event('packet_captured', log_data)
            
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def _process_http(self, packet, packet_data: dict):
        """Extract HTTP information"""
        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                lines = payload.split('\r\n')
                
                if lines:
                    first_line = lines[0]
                    # Request
                    if first_line.startswith(('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH')):
                        parts = first_line.split(' ')
                        if len(parts) >= 2:
                            packet_data['http_method'] = parts[0]
                            packet_data['http_path'] = parts[1]
                    # Response
                    elif first_line.startswith('HTTP/'):
                        parts = first_line.split(' ')
                        if len(parts) >= 2:
                            packet_data['http_status'] = parts[1]
                    
                    # Extract headers
                    headers = {}
                    for line in lines[1:]:
                        if ': ' in line:
                            key, value = line.split(': ', 1)
                            headers[key.lower()] = value
                    
                    if 'host' in headers:
                        packet_data['http_host'] = headers['host']
                    if 'user-agent' in headers:
                        packet_data['user_agent'] = headers['user-agent']
            except:
                pass
    
    def _process_tls(self, packet, packet_data: dict):
        """Detect TLS and mark for JA3 processing"""
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)
            # Check for TLS Client Hello (0x16 0x03 + version, then 0x01 for Client Hello)
            if len(payload) > 5:
                if payload[0] == 0x16 and payload[1] == 0x03:
                    packet_data['tls_detected'] = True
                    packet_data['tls_record_type'] = 'handshake'
                    # Check if Client Hello
                if len(payload) > 9 and payload[5] == 0x01:
                        packet_data['tls_handshake'] = 'client_hello'
                        packet_data['requires_ja3'] = True
                        packet_data['raw_payload'] = payload
    
    def _process_dns(self, packet, packet_data: dict):
        """Extract DNS query information"""
        dns = packet[DNS]
        if dns.qr == 0:  # Query
            if packet.haslayer(DNSQR):
                query = packet[DNSQR]
                packet_data['dns_query'] = query.qname.decode('utf-8', errors='ignore').rstrip('.')
                packet_data['dns_type'] = query.qtype
                packet_data['dns_class'] = query.qclass
        else:  # Response
            packet_data['dns_response'] = True
            packet_data['dns_rcode'] = dns.rcode
    
    def _track_connection(self, conn_key: str, packet_data: dict):
        """Track connection for beacon detection"""
        now = datetime.utcnow()
        
        if conn_key not in self.connections:
            self.connections[conn_key] = {
                'first_seen': now.isoformat(),
                'last_seen': now.isoformat(),
                'packet_count': 0,
                'bytes': 0,
                'timestamps': []
            }
        
        conn = self.connections[conn_key]
        conn['last_seen'] = now.isoformat()
        conn['packet_count'] += 1
        conn['bytes'] += packet_data.get('size', 0)
        conn['timestamps'].append(now.timestamp())
        
        # Keep only last 100 timestamps for memory efficiency
        if len(conn['timestamps']) > 100:
            conn['timestamps'] = conn['timestamps'][-100:]
    
    def start(self, filter_str: str = "tcp or udp"):
        """Start packet capture"""
        if self.running:
            logger.warning("Capture already running")
            return
        
        self.running = True
        logger.info(f"Starting capture on {self.interface} with filter: {filter_str}")
        
        def capture_loop():
            try:
                sniff(
                    iface=self.interface,
                    prn=self._process_packet,
                    filter=filter_str,
                    store=False,
                    stop_filter=lambda x: not self.running
                )
            except Exception as e:
                logger.error(f"Capture error: {e}")
                self.running = False
        
        self.capture_thread = threading.Thread(target=capture_loop, daemon=True)
        self.capture_thread.start()
    
    def stop(self):
        """Stop packet capture"""
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        logger.info("Capture stopped")
    
    def get_stats(self) -> dict:
        """Get capture statistics"""
        return dict(self.stats)
    
    def get_connections(self) -> dict:
        """Get tracked connections"""
        return self.connections


def main():
    """Run standalone packet capture"""
    import argparse
    
    parser = argparse.ArgumentParser(description='C2Trap Packet Capture')
    parser.add_argument('-i', '--interface', default='eth0', help='Network interface')
    parser.add_argument('-f', '--filter', default='tcp or udp', help='BPF filter')
    args = parser.parse_args()
    
    def packet_callback(data):
        if data.get('app_protocol'):
            print(f"[{data['protocol'].upper()}] {data['src_ip']}:{data.get('src_port', 0)} -> "
                  f"{data['dst_ip']}:{data.get('dst_port', 0)} ({data.get('app_protocol', 'unknown')})")
    
    capture = PacketCapture(interface=args.interface, callback=packet_callback)
    
    print(f"Starting capture on {args.interface}")
    print(f"Available interfaces: {get_if_list()}")
    
    capture.start(filter_str=args.filter)
    
    try:
        while True:
            import time
            time.sleep(10)
            stats = capture.get_stats()
            print(f"Stats: {stats}")
    except KeyboardInterrupt:
        print("\nStopping capture...")
        capture.stop()


if __name__ == '__main__':
    main()
