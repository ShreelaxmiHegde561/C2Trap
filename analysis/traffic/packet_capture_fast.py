"""
C2Trap Fast Packet Capture Module
Uses Linux raw sockets (AF_PACKET) for high-performance capture.
10x faster than Scapy — zero external dependencies.

Falls back to Scapy-based capture if raw sockets are unavailable.
"""

import os
import sys
import json
import socket
import struct
import logging
import threading
import time
from datetime import datetime
from typing import Optional, Callable, Dict, Any
from collections import defaultdict

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('fast_capture')

LOG_PATH = os.environ.get('LOG_PATH', '/app/logs/analysis_queue.jsonl')


def log_event(event_type: str, data: dict) -> None:
    """Write event to analysis queue (JSONL - no SQLite)"""
    event = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'source': 'fast_capture',
        'event_type': event_type,
        'data': data
    }
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, 'a') as f:
            f.write(json.dumps(event) + '\n')
    except Exception as e:
        logger.error(f"Failed to write log: {e}")


class FastPacketCapture:
    """
    High-performance packet capture using Linux raw sockets.
    
    Performance Comparison:
    - Scapy:       ~1,000-5,000 packets/sec (Python object overhead)
    - Raw Sockets: ~50,000-100,000 packets/sec (direct kernel access)
    
    Uses AF_PACKET with ETH_P_ALL to capture all Ethernet frames,
    then manually parses headers using struct.unpack for speed.
    """

    # Ethernet header: 14 bytes
    ETH_HEADER_LEN = 14
    # IP header: 20 bytes (minimum)
    IP_HEADER_LEN = 20
    # TCP header: 20 bytes (minimum)
    TCP_HEADER_LEN = 20
    # UDP header: 8 bytes
    UDP_HEADER_LEN = 8

    def __init__(self, interface: str = 'eth0', callback: Optional[Callable] = None):
        self.interface = interface
        self.callback = callback
        self.running = False
        self.capture_thread = None
        self.raw_socket = None
        self.stats = defaultdict(int)
        self.connections: Dict[str, Dict[str, Any]] = {}
        self._use_fallback = False

    def _create_raw_socket(self):
        """Create a raw socket for packet capture"""
        try:
            # ETH_P_ALL = 0x0003 captures all protocols
            sock = socket.socket(
                socket.AF_PACKET,
                socket.SOCK_RAW,
                socket.ntohs(0x0003)
            )
            sock.bind((self.interface, 0))
            sock.settimeout(1.0)  # 1s timeout so we can check self.running
            logger.info(f"[FAST MODE] Raw socket created on {self.interface}")
            return sock
        except (PermissionError, OSError) as e:
            logger.warning(f"Raw socket failed ({e}). Falling back to Scapy.")
            self._use_fallback = True
            return None

    def _parse_ethernet(self, raw_data: bytes):
        """Parse Ethernet frame header (14 bytes)"""
        if len(raw_data) < self.ETH_HEADER_LEN:
            return None
        
        eth_header = struct.unpack('!6s6sH', raw_data[:self.ETH_HEADER_LEN])
        eth_protocol = socket.ntohs(eth_header[2])
        
        return {
            'dst_mac': self._format_mac(eth_header[0]),
            'src_mac': self._format_mac(eth_header[1]),
            'protocol': eth_protocol
        }

    def _parse_ip(self, raw_data: bytes, offset: int = 14):
        """Parse IP header"""
        if len(raw_data) < offset + self.IP_HEADER_LEN:
            return None
        
        ip_header = struct.unpack('!BBHHHBBH4s4s',
                                  raw_data[offset:offset + self.IP_HEADER_LEN])
        
        version_ihl = ip_header[0]
        ihl = (version_ihl & 0xF) * 4  # Header length in bytes
        protocol = ip_header[6]
        src_ip = socket.inet_ntoa(ip_header[8])
        dst_ip = socket.inet_ntoa(ip_header[9])
        total_length = ip_header[2]
        
        return {
            'ihl': ihl,
            'protocol': protocol,  # 6=TCP, 17=UDP
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'total_length': total_length
        }

    def _parse_tcp(self, raw_data: bytes, offset: int):
        """Parse TCP header"""
        if len(raw_data) < offset + self.TCP_HEADER_LEN:
            return None
        
        tcp_header = struct.unpack('!HHLLBBHHH',
                                   raw_data[offset:offset + self.TCP_HEADER_LEN])
        
        return {
            'src_port': tcp_header[0],
            'dst_port': tcp_header[1],
            'seq': tcp_header[2],
            'ack': tcp_header[3],
            'flags': tcp_header[5]
        }

    def _parse_udp(self, raw_data: bytes, offset: int):
        """Parse UDP header"""
        if len(raw_data) < offset + self.UDP_HEADER_LEN:
            return None
        
        udp_header = struct.unpack('!HHHH',
                                   raw_data[offset:offset + self.UDP_HEADER_LEN])
        
        return {
            'src_port': udp_header[0],
            'dst_port': udp_header[1],
            'length': udp_header[2]
        }

    def _format_mac(self, mac_bytes: bytes) -> str:
        """Format MAC address bytes to string"""
        return ':'.join(f'{b:02x}' for b in mac_bytes)

    def _process_raw_packet(self, raw_data: bytes):
        """Process a raw packet from the socket"""
        try:
            # Parse Ethernet
            eth = self._parse_ethernet(raw_data)
            if not eth or eth['protocol'] != 8:  # 8 = IPv4
                return

            # Parse IP
            ip_info = self._parse_ip(raw_data)
            if not ip_info:
                return

            packet_data = {
                'src_ip': ip_info['src_ip'],
                'dst_ip': ip_info['dst_ip'],
                'size': ip_info['total_length'],
                'timestamp': time.time()
            }

            ip_header_end = self.ETH_HEADER_LEN + ip_info['ihl']

            # TCP (protocol 6)
            if ip_info['protocol'] == 6:
                tcp = self._parse_tcp(raw_data, ip_header_end)
                if tcp:
                    packet_data.update({
                        'protocol': 'tcp',
                        'src_port': tcp['src_port'],
                        'dst_port': tcp['dst_port'],
                        'flags': tcp['flags']
                    })

                    # Detect application protocol
                    if tcp['dst_port'] in [80, 8080, 8000, 8888]:
                        packet_data['app_protocol'] = 'http'
                    elif tcp['dst_port'] in [443, 8443]:
                        packet_data['app_protocol'] = 'https'

            # UDP (protocol 17)
            elif ip_info['protocol'] == 17:
                udp = self._parse_udp(raw_data, ip_header_end)
                if udp:
                    packet_data.update({
                        'protocol': 'udp',
                        'src_port': udp['src_port'],
                        'dst_port': udp['dst_port']
                    })

                    if udp['dst_port'] == 53 or udp['src_port'] == 53:
                        packet_data['app_protocol'] = 'dns'
                        # Parse DNS query name from payload
                        dns_offset = ip_header_end + self.UDP_HEADER_LEN
                        self._parse_dns_query(raw_data, dns_offset, packet_data)

            else:
                return  # Skip non-TCP/UDP

            # Update stats
            self.stats['packets'] += 1
            self.stats[packet_data.get('protocol', 'other')] += 1

            # Track connection
            if 'src_port' in packet_data:
                conn_key = f"{packet_data['protocol']}:{packet_data['src_ip']}:{packet_data['src_port']}-{packet_data['dst_ip']}:{packet_data['dst_port']}"
                self._track_connection(conn_key, packet_data)

            # Callback
            if self.callback:
                self.callback(packet_data)

            # Log significant events
            if packet_data.get('app_protocol'):
                log_data = {k: v for k, v in packet_data.items()
                            if not isinstance(v, bytes)}
                log_event('packet_captured', log_data)

        except Exception as e:
            logger.debug(f"Packet parse error: {e}")

    def _parse_dns_query(self, raw_data: bytes, offset: int, packet_data: dict):
        """Extract DNS query name from raw packet"""
        try:
            if len(raw_data) < offset + 12:
                return
            
            # Skip DNS header (12 bytes)
            qname_offset = offset + 12
            labels = []
            
            while qname_offset < len(raw_data):
                length = raw_data[qname_offset]
                if length == 0:
                    break
                qname_offset += 1
                label = raw_data[qname_offset:qname_offset + length].decode('ascii', errors='ignore')
                labels.append(label)
                qname_offset += length
            
            if labels:
                packet_data['dns_query'] = '.'.join(labels)
        except Exception:
            pass

    def _track_connection(self, conn_key: str, packet_data: dict):
        """Track connection for beacon detection"""
        now = time.time()
        
        if conn_key not in self.connections:
            self.connections[conn_key] = {
                'first_seen': now,
                'last_seen': now,
                'packet_count': 0,
                'bytes': 0,
                'timestamps': []
            }
        
        conn = self.connections[conn_key]
        conn['last_seen'] = now
        conn['packet_count'] += 1
        conn['bytes'] += packet_data.get('size', 0)
        conn['timestamps'].append(now)
        
        # Memory bounded
        if len(conn['timestamps']) > 100:
            conn['timestamps'] = conn['timestamps'][-100:]

    def start(self, filter_str: str = "tcp or udp"):
        """Start packet capture"""
        if self.running:
            logger.warning("Capture already running")
            return

        self.running = True

        # Try raw socket first
        self.raw_socket = self._create_raw_socket()

        if self._use_fallback:
            logger.info("[FALLBACK] Using Scapy-based capture")
            self._start_scapy_fallback(filter_str)
            return

        logger.info(f"[FAST MODE] Starting raw capture on {self.interface}")

        def capture_loop():
            while self.running:
                try:
                    raw_data = self.raw_socket.recv(65535)
                    self._process_raw_packet(raw_data)
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        logger.error(f"Capture error: {e}")
                    break

        self.capture_thread = threading.Thread(target=capture_loop, daemon=True)
        self.capture_thread.start()

    def _start_scapy_fallback(self, filter_str: str):
        """Fallback to Scapy if raw sockets are unavailable"""
        try:
            from analysis.traffic.packet_capture import PacketCapture
            self._fallback = PacketCapture(
                interface=self.interface,
                callback=self.callback
            )
            self._fallback.start(filter_str)
        except ImportError:
            logger.error("Scapy fallback also unavailable. No capture possible.")

    def stop(self):
        """Stop packet capture"""
        self.running = False
        if self.raw_socket:
            self.raw_socket.close()
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        logger.info("Fast capture stopped")

    def get_stats(self) -> dict:
        """Get capture statistics"""
        return dict(self.stats)

    def get_connections(self) -> dict:
        """Get tracked connections"""
        return self.connections


if __name__ == '__main__':
    def packet_handler(data):
        proto = data.get('app_protocol', data.get('protocol', '?'))
        src = f"{data.get('src_ip', '?')}:{data.get('src_port', '?')}"
        dst = f"{data.get('dst_ip', '?')}:{data.get('dst_port', '?')}"
        print(f"[{proto.upper()}] {src} -> {dst} ({data.get('size', 0)}B)")

    import argparse
    parser = argparse.ArgumentParser(description='C2Trap Fast Packet Capture')
    parser.add_argument('-i', '--interface', default='eth0', help='Network interface')
    args = parser.parse_args()

    capture = FastPacketCapture(interface=args.interface, callback=packet_handler)
    print(f"Starting FAST capture on {args.interface}...")
    capture.start()

    try:
        while True:
            time.sleep(10)
            stats = capture.get_stats()
            print(f"[STATS] Packets: {stats.get('packets', 0)} | "
                  f"TCP: {stats.get('tcp', 0)} | UDP: {stats.get('udp', 0)}")
    except KeyboardInterrupt:
        print("\nStopping...")
        capture.stop()
