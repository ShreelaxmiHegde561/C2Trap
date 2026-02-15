"""
C2Trap Falco Event Listener
Process Falco alerts and integrate with C2Trap pipeline
"""

import os
import json
import logging
import subprocess
import threading
from datetime import datetime
from typing import Optional, Callable

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('falco_listener')

LOG_PATH = os.environ.get('LOG_PATH', '/app/logs/analysis_queue.jsonl')
FALCO_OUTPUT = os.environ.get('FALCO_OUTPUT', '/var/log/falco/falco_output.json')


def log_event(event_type: str, data: dict) -> None:
    """Write event to analysis queue"""
    event = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'source': 'falco',
        'event_type': event_type,
        'data': data
    }
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, 'a') as f:
            f.write(json.dumps(event) + '\n')
    except Exception as e:
        logger.error(f"Failed to write log: {e}")


class FalcoListener:
    """Listen to Falco alerts and process them"""
    
    # Map Falco priorities to our severity levels
    PRIORITY_MAP = {
        'EMERGENCY': 'critical',
        'ALERT': 'critical',
        'CRITICAL': 'critical',
        'ERROR': 'high',
        'WARNING': 'medium',
        'NOTICE': 'low',
        'INFORMATIONAL': 'info',
        'DEBUG': 'debug'
    }
    
    # MITRE technique mapping based on Falco tags
    MITRE_MAP = {
        'shell': 'T1059',
        'c2': 'T1071',
        'beacon': 'T1071',
        'persistence': 'T1053',
        'exfiltration': 'T1041',
        'evasion': 'T1027',
        'network': 'T1071',
        'download': 'T1105',
    }
    
    def __init__(self, callback: Optional[Callable] = None):
        self.callback = callback
        self.running = False
        self.listener_thread = None
        self.alerts_processed = 0
    
    def process_alert(self, alert: dict):
        """Process a Falco alert"""
        try:
            # Extract key fields
            priority = alert.get('priority', 'NOTICE')
            rule = alert.get('rule', 'Unknown Rule')
            output = alert.get('output', '')
            tags = alert.get('tags', [])
            
            # Map to MITRE technique
            mitre_technique = None
            for tag in tags:
                if tag in self.MITRE_MAP:
                    mitre_technique = self.MITRE_MAP[tag]
                    break
            
            # Build processed alert
            processed = {
                'rule': rule,
                'priority': priority,
                'severity': self.PRIORITY_MAP.get(priority, 'medium'),
                'output': output,
                'tags': tags,
                'timestamp': alert.get('time', datetime.utcnow().isoformat()),
                'mitre_technique': mitre_technique,
                'output_fields': alert.get('output_fields', {})
            }
            
            # Log the event
            log_event('falco_alert', processed)
            self.alerts_processed += 1
            
            logger.info(f"[FALCO] {priority}: {rule}")
            
            # Callback if provided
            if self.callback:
                self.callback(processed)
            
            return processed
            
        except Exception as e:
            logger.error(f"Error processing Falco alert: {e}")
            return None
    
    def listen_file(self, file_path: str = FALCO_OUTPUT):
        """Listen to Falco JSON output file (tail -f style)"""
        logger.info(f"Listening to Falco output at {file_path}")
        
        self.running = True
        
        try:
            # Use tail -f to follow the file
            process = subprocess.Popen(
                ['tail', '-f', file_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            while self.running:
                line = process.stdout.readline()
                if line:
                    try:
                        alert = json.loads(line.strip())
                        self.process_alert(alert)
                    except json.JSONDecodeError:
                        pass
            
            process.terminate()
            
        except FileNotFoundError:
            logger.error(f"Falco output file not found: {file_path}")
        except Exception as e:
            logger.error(f"Error listening to Falco: {e}")
    
    def start(self, file_path: str = FALCO_OUTPUT):
        """Start listening in background thread"""
        if self.running:
            logger.warning("Listener already running")
            return
        
        self.listener_thread = threading.Thread(
            target=self.listen_file,
            args=(file_path,),
            daemon=True
        )
        self.listener_thread.start()
        logger.info("Falco listener started")
    
    def stop(self):
        """Stop the listener"""
        self.running = False
        if self.listener_thread:
            self.listener_thread.join(timeout=5)
        logger.info("Falco listener stopped")
    
    def get_stats(self) -> dict:
        """Get listener statistics"""
        return {
            'running': self.running,
            'alerts_processed': self.alerts_processed
        }


def check_falco_installed() -> bool:
    """Check if Falco is installed"""
    try:
        result = subprocess.run(['falco', '--version'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            logger.info(f"Falco installed: {result.stdout.strip()}")
            return True
    except FileNotFoundError:
        pass
    logger.warning("Falco not installed")
    return False


def install_falco_instructions():
    """Print Falco installation instructions"""
    instructions = """
╔═══════════════════════════════════════════════════════════════╗
║          Falco Installation Instructions (Kali Linux)         ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║  1. Add Falco repository:                                     ║
║     curl -fsSL https://falco.org/repo/falcosecurity-packages. ║
║         key | sudo gpg --dearmor -o /usr/share/keyrings/      ║
║         falco-archive-keyring.gpg                             ║
║                                                               ║
║  2. Add apt source:                                           ║
║     echo "deb [signed-by=/usr/share/keyrings/falco-archive-   ║
║         keyring.gpg] https://download.falco.org/packages/deb  ║
║         stable main" | sudo tee /etc/apt/sources.list.d/      ║
║         falcosecurity.list                                    ║
║                                                               ║
║  3. Install Falco:                                            ║
║     sudo apt update && sudo apt install -y falco              ║
║                                                               ║
║  4. Copy custom rules:                                        ║
║     sudo cp falco/custom_rules.yaml /etc/falco/rules.d/       ║
║                                                               ║
║  5. Start Falco:                                              ║
║     sudo systemctl start falco                                ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"""
    print(instructions)


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Falco Event Listener')
    parser.add_argument('--check', action='store_true', help='Check if Falco is installed')
    parser.add_argument('--install', action='store_true', help='Show install instructions')
    parser.add_argument('-f', '--file', default=FALCO_OUTPUT, help='Falco output file')
    args = parser.parse_args()
    
    if args.check:
        check_falco_installed()
    elif args.install:
        install_falco_instructions()
    else:
        listener = FalcoListener()
        
        def alert_callback(alert):
            print(f"Alert: {alert['rule']} ({alert['severity']})")
        
        listener.callback = alert_callback
        listener.start(args.file)
        
        try:
            while True:
                import time
                time.sleep(10)
                stats = listener.get_stats()
                print(f"Stats: {stats}")
        except KeyboardInterrupt:
            listener.stop()
