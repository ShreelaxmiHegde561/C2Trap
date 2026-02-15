import os
import sys
import time
import threading
import logging

# Add current dir and project root to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Use Fast Packet Capture (raw sockets) with Scapy fallback
try:
    from traffic.packet_capture_fast import FastPacketCapture as PacketCapture, log_event
    FAST_CAPTURE = True
except ImportError:
    from traffic.packet_capture import PacketCapture, log_event
    FAST_CAPTURE = False

from traffic.beacon_detector import BeaconDetector
from traffic.zeek_processor import ZeekProcessor
from ja3.ja3_generator import JA3Generator
from rerouting.dns_spoof import DNSSpoofServer
import auto_analyze

# Import enhanced detection modules
try:
    from detection.dga_detector import DGADetector
    from detection.entropy_analyzer import EntropyAnalyzer
    from ml.baseline_learner import BaselineLearner
    ENHANCED_DETECTION = True
except ImportError as e:
    ENHANCED_DETECTION = False
    print(f"Enhanced detection modules not available: {e}")

# Import advanced detection modules
try:
    from detection.dns_tunnel_detector import DNSTunnelDetector
    DNS_TUNNEL_AVAILABLE = True
except ImportError:
    DNS_TUNNEL_AVAILABLE = False

try:
    from detection.tls_anomaly_detector import TLSAnomalyDetector
    TLS_ANOMALY_AVAILABLE = True
except ImportError:
    TLS_ANOMALY_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('analysis_engine')

def main():
    interface = os.environ.get('INTERFACE', 'eth0')
    redirect_ip = os.environ.get('REDIRECT_IP', '172.28.0.5') # Default to http-decoy IP
    dns_port = int(os.environ.get('DNS_SPOOF_PORT', 5353))
    
    logger.info(f"Starting Analysis Engine on interface {interface}")
    if FAST_CAPTURE:
        logger.info("[PERFORMANCE] Using Fast Packet Capture (raw sockets)")
    else:
        logger.info("[FALLBACK] Using Scapy Packet Capture")

    # 1. Initialize Components
    beacon_detector = BeaconDetector()
    ja3_generator = JA3Generator()
    
    # Initialize enhanced detection if available
    dga_detector = None
    entropy_analyzer = None
    baseline_learner = None
    dns_tunnel_detector = None
    tls_anomaly_detector = None
    
    if ENHANCED_DETECTION:
        dga_detector = DGADetector()
        entropy_analyzer = EntropyAnalyzer()
        baseline_learner = BaselineLearner(learning_mode=True)
        logger.info("Enhanced detection modules loaded (DGA, Entropy, Baseline)")
    
    if DNS_TUNNEL_AVAILABLE:
        dns_tunnel_detector = DNSTunnelDetector()
        logger.info("DNS Tunneling Detector loaded")
    
    if TLS_ANOMALY_AVAILABLE:
        tls_anomaly_detector = TLSAnomalyDetector()
        logger.info("TLS Anomaly Detector loaded")
    
    # 2. Start DNS Spoof Server
    dns_server = DNSSpoofServer(listen_port=dns_port, redirect_ip=redirect_ip)
    # Add common C2 domains for testing (including demo malware domains)
    dns_server.add_c2_domains([
        'c2.evil.com', 
        'malware-control.top', 
        'beacon.c2.io',
        'beacon.malware.top',
        'command.c2server.xyz',
        'update.trojan.link',
        'payload.backdoor.work'
    ])
    
    dns_thread = threading.Thread(target=dns_server.start, daemon=True)
    dns_thread.start()
    logger.info(f"DNS Spoof Server started on port {dns_port} (Redirecting to {redirect_ip})")

    # 3. Start Malware Analysis Watcher
    watcher_thread = threading.Thread(target=auto_analyze.start_watcher, daemon=True)
    watcher_thread.start()
    logger.info("Malware Analysis Watcher started")

    # 4. Initialize Zeek Processor
    zeek_processor = ZeekProcessor(log_dir='/app/logs/zeek', callback=log_event)
    zeek_processor.start()
    logger.info("Zeek Log Processor started")

    def packet_callback(packet_data):
        # Pass to beacon detector (with domain for whitelist check)
        if 'src_ip' in packet_data and 'dst_ip' in packet_data:
            beacon_detector.add_connection(
                src_ip=packet_data['src_ip'],
                dst_ip=packet_data['dst_ip'],
                dst_port=packet_data.get('dst_port', 0),
                protocol=packet_data.get('protocol', 'tcp'),
                timestamp=time.time(),
                size=packet_data.get('size', 0),
                domain=packet_data.get('dns_query', packet_data.get('http_host', None))
            )
            
            # Enhanced detection: Learn baseline
            if baseline_learner:
                baseline_learner.learn({
                    'src_ip': packet_data['src_ip'],
                    'dst_ip': packet_data['dst_ip'],
                    'dst_port': packet_data.get('dst_port', 0),
                    'domain': packet_data.get('domain', ''),
                    'size': packet_data.get('size', 0),
                    'timestamp': time.time()
                })
        
        # === DGA Detection on DNS queries ===
        domain = packet_data.get('dns_query', packet_data.get('http_host', ''))
        if dga_detector and domain:
            score, is_dga, details = dga_detector.analyze(domain)
            if is_dga:
                log_event('dga_domain_detected', {
                    'domain': domain,
                    'score': score,
                    'components': details.get('components', {}),
                    'mitre_technique': 'T1568.002',
                    'severity': 'high'
                })
        
        # === DNS Tunneling Detection ===
        if dns_tunnel_detector and domain:
            score, is_tunnel, details = dns_tunnel_detector.analyze_query(domain)
            if is_tunnel:
                log_event('dns_tunneling_detected', {
                    'domain': domain,
                    'score': score,
                    'encoding': details.get('components', {}).get('encoding_type', 'unknown'),
                    'subdomain_length': details.get('subdomain_length', 0),
                    'estimated_exfil_bytes': details.get('estimated_exfil_bytes', 0),
                    'mitre_technique': 'T1048',
                    'severity': 'high'
                })
        
        # === TLS Anomaly Detection ===
        if tls_anomaly_detector and packet_data.get('tls_detected'):
            score, is_suspicious, details = tls_anomaly_detector.analyze_connection(
                dst_ip=packet_data.get('dst_ip', ''),
                dst_port=packet_data.get('dst_port', 0),
                ja3_hash=packet_data.get('ja3_hash'),
                sni=packet_data.get('sni'),
                cert_subject=packet_data.get('cert_subject'),
                cert_issuer=packet_data.get('cert_issuer'),
                cert_self_signed=packet_data.get('cert_self_signed', False),
                tls_version=packet_data.get('tls_version')
            )
            if is_suspicious:
                log_event('tls_anomaly_detected', {
                    'dst_ip': packet_data.get('dst_ip'),
                    'dst_port': packet_data.get('dst_port'),
                    'score': score,
                    'alerts': details.get('alerts', []),
                    'mitre_technique': 'T1573',
                    'severity': 'high' if score > 0.7 else 'medium'
                })
        
        # Enhanced detection: Entropy check for payloads
        if entropy_analyzer and 'raw_payload' in packet_data:
            payload = packet_data['raw_payload']
            if len(payload) > 100:  # Only check substantial payloads
                entropy_result = entropy_analyzer.analyze_payload(payload)
                if entropy_result.is_suspicious:
                    log_event('high_entropy_payload', {
                        'src_ip': packet_data.get('src_ip'),
                        'dst_ip': packet_data.get('dst_ip'),
                        'entropy': entropy_result.entropy,
                        'encoding': entropy_result.encoding_type,
                        'indicators': entropy_result.indicators,
                        'mitre_technique': 'T1048',
                        'severity': 'medium'
                    })
        
        # Pass to JA3 generator if needed
        if packet_data.get('requires_ja3') and 'raw_payload' in packet_data:
             ja3_generator.process_packet(
                 packet_bytes=packet_data['raw_payload'],
                 src_ip=packet_data['src_ip'],
                 dst_ip=packet_data['dst_ip'],
                 src_port=packet_data.get('src_port', 0),
                 dst_port=packet_data.get('dst_port', 0)
             )

    capture = PacketCapture(interface=interface, callback=packet_callback)

    # Start packet capture
    capture.start()
    
    logger.info("Analysis Engine components started")
    
    # Check for baseline learning completion periodically
    def baseline_checker():
        while True:
            time.sleep(3600)  # Check every hour
            if baseline_learner and baseline_learner.is_learning_complete():
                baseline_learner.switch_to_detection_mode()
                logger.info("Baseline learning complete, switching to detection mode")
                break
    
    if baseline_learner:
        baseline_thread = threading.Thread(target=baseline_checker, daemon=True)
        baseline_thread.start()

    try:
        while True:
            time.sleep(10)
            stats = capture.get_stats()
            
            # Log detection stats periodically
            if dga_detector:
                dga_stats = dga_detector.get_stats()
                if dga_stats.get('dga_detected', 0) > 0:
                    logger.info(f"DGA Detections: {dga_stats['dga_detected']}")
            
            if dns_tunnel_detector:
                tunnel_stats = dns_tunnel_detector.get_stats()
                if tunnel_stats.get('total_tunnels_detected', 0) > 0:
                    logger.info(f"DNS Tunnels: {tunnel_stats['total_tunnels_detected']}")
            
            if tls_anomaly_detector:
                tls_stats = tls_anomaly_detector.get_stats()
                if tls_stats.get('total_anomalies', 0) > 0:
                    logger.info(f"TLS Anomalies: {tls_stats['total_anomalies']}")
                    
    except KeyboardInterrupt:
        logger.info("Shutting down engine...")
        capture.stop()

if __name__ == '__main__':
    main()
