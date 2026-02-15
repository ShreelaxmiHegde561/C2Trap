"""
C2Trap FTP Honeypot
Accepts any credentials and logs all file operations
"""

import os
import json
import logging
from datetime import datetime
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('ftp_decoy')

LOG_PATH = os.environ.get('LOG_PATH', '/app/logs/analysis_queue.jsonl')
FTP_DIR = '/tmp/ftp_root'


def log_event(event_type: str, data: dict) -> None:
    """Write event to analysis queue"""
    event = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'source': 'ftp_decoy',
        'event_type': event_type,
        'data': data
    }
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, 'a') as f:
            f.write(json.dumps(event) + '\n')
    except Exception as e:
        logger.error(f"Failed to write log: {e}")


class C2TrapFTPHandler(FTPHandler):
    """Custom FTP handler that logs all operations"""
    
    def on_connect(self):
        log_event('ftp_connect', {
            'remote_ip': self.remote_ip,
            'remote_port': self.remote_port
        })
        logger.info(f"[FTP] Connection from {self.remote_ip}:{self.remote_port}")
    
    def on_disconnect(self):
        log_event('ftp_disconnect', {
            'remote_ip': self.remote_ip,
            'username': getattr(self, 'username', 'anonymous')
        })
    
    def on_login(self, username):
        log_event('ftp_login', {
            'remote_ip': self.remote_ip,
            'username': username,
            'mitre_technique': 'T1071.002'
        })
        logger.info(f"[FTP] Login: {username} from {self.remote_ip}")
    
    def on_login_failed(self, username, password):
        log_event('ftp_login_failed', {
            'remote_ip': self.remote_ip,
            'username': username,
            'password': password[:20] + '...' if len(password) > 20 else password
        })
        logger.warning(f"[FTP] Failed login: {username} from {self.remote_ip}")
    
    def on_file_sent(self, file):
        log_event('ftp_download', {
            'remote_ip': self.remote_ip,
            'file': file,
            'mitre_technique': 'T1105'
        })
        logger.info(f"[FTP] File sent: {file} to {self.remote_ip}")
    
    def on_file_received(self, file):
        log_event('ftp_upload', {
            'remote_ip': self.remote_ip,
            'file': file,
            'mitre_technique': 'T1041'  # Exfiltration Over C2 Channel
        })
        logger.warning(f"[FTP] File received: {file} from {self.remote_ip}")
    
    def on_incomplete_file_sent(self, file):
        log_event('ftp_incomplete_download', {
            'remote_ip': self.remote_ip,
            'file': file
        })
    
    def on_incomplete_file_received(self, file):
        log_event('ftp_incomplete_upload', {
            'remote_ip': self.remote_ip,
            'file': file
        })


class OpenAuthorizer(DummyAuthorizer):
    """Accept any username/password combination"""
    
    def validate_authentication(self, username, password, handler):
        """Always return True - accept any credentials"""
        return True
    
    def get_home_dir(self, username):
        return FTP_DIR
    
    def has_user(self, username):
        return True
    
    def has_perm(self, username, perm, path=None):
        return True
    
    def get_perms(self, username):
        return 'elradfmw'
    
    def get_msg_login(self, username):
        return f"Welcome {username}!"
    
    def get_msg_quit(self, username):
        return "Goodbye!"


def main():
    # Create FTP root directory
    os.makedirs(FTP_DIR, exist_ok=True)
    
    # Create some fake files to make it look real
    with open(os.path.join(FTP_DIR, 'readme.txt'), 'w') as f:
        f.write("Welcome to the server\n")
    
    port = int(os.environ.get('FTP_PORT', 21))
    passive_ports = os.environ.get('PASSIVE_PORTS', '30000-30009')
    
    # Parse passive ports
    start, end = map(int, passive_ports.split('-'))
    
    authorizer = OpenAuthorizer()
    
    handler = C2TrapFTPHandler
    handler.authorizer = authorizer
    handler.passive_ports = range(start, end + 1)
    handler.banner = "220 FTP Server Ready"
    
    server = FTPServer(('0.0.0.0', port), handler)
    server.max_cons = 50
    server.max_cons_per_ip = 10
    
    logger.info(f"Starting FTP Decoy on port {port}")
    logger.info(f"Passive ports: {passive_ports}")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down FTP Decoy")
        server.close_all()


if __name__ == '__main__':
    main()
