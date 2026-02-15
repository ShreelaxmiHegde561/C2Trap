"""
C2Trap HTTP/HTTPS Honeypot
Fake C2 server that captures malware beacon attempts
"""

import os
import json
import logging
from datetime import datetime
from flask import Flask, request, jsonify
from functools import wraps

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('http_decoy')

app = Flask(__name__)

# Log file path
LOG_PATH = os.environ.get('LOG_PATH', '/app/logs/analysis_queue.jsonl')


def log_event(event_type: str, data: dict) -> None:
    """Write event to analysis queue"""
    event = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'source': 'http_decoy',
        'event_type': event_type,
        'data': data
    }
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, 'a') as f:
            f.write(json.dumps(event) + '\n')
    except Exception as e:
        logger.error(f"Failed to write log: {e}")


def capture_request(f):
    """Decorator to capture all incoming request details"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Extract request metadata
        data = {
            'remote_ip': request.remote_addr,
            'method': request.method,
            'path': request.path,
            'query_string': request.query_string.decode('utf-8', errors='ignore'),
            'headers': dict(request.headers),
            'user_agent': request.headers.get('User-Agent', ''),
            'content_type': request.content_type,
            'content_length': request.content_length,
        }
        
        # Capture body for POST/PUT
        if request.method in ['POST', 'PUT', 'PATCH']:
            try:
                if request.is_json:
                    data['body'] = request.get_json(silent=True)
                else:
                    data['body'] = request.get_data(as_text=True)[:4096]  # Limit size
            except:
                data['body'] = '<binary data>'
        
        # Log the connection
        event_type = 'http_connection'
        mitre_technique = None
        suspicion_reason = []

        # Simple Signature Detection
        payloads = [
            (request.query_string.decode('utf-8', errors='ignore'), 'query'),
            (str(data.get('body', '')), 'body')
        ]
        
        signatures = {
            'sqli': (['union select', 'drop table', 'or 1=1', "' or '1'='1", '--'], 'T1190'),
            'xss': (['<script>', 'javascript:', 'alert(', 'onerror='], 'T1190'),
            'cmd_injection': (['cmd.exe', '/bin/sh', '; cat', '| wget', 'powershell', 'nc -e'], 'T1059'),
            'path_traversal': (['../', '..\\', '/etc/passwd', 'c:\\windows'], 'T1083')
        }

        for content, source in payloads:
            content_lower = content.lower()
            for attack_type, (sigs, mitre) in signatures.items():
                if any(s in content_lower for s in sigs):
                    event_type = f'{attack_type}_detected'
                    mitre_technique = mitre
                    suspicion_reason.append(f"{attack_type} in {source}")
                    data['suspicious'] = True
                    data['is_malicious'] = True
                    # Upgrade detected events for stricter alerting
                    if attack_type in ['cmd_injection', 'sqli']:
                         data['is_known_malware'] = True # Force critical alert

        if mitre_technique:
            data['mitre_technique'] = mitre_technique
            data['suspicion_reason'] = suspicion_reason

        log_event(event_type, data)
        logger.info(f"[HTTP] {request.method} {request.path} from {request.remote_addr} [{event_type}]")
        
        return f(*args, **kwargs)
    return decorated_function


# ============================================
# Fake C2 Endpoints - Mimic common C2 patterns
# ============================================

@app.route('/api/beacon', methods=['GET', 'POST'])
@capture_request
def beacon():
    """Fake beacon endpoint - common in many C2 frameworks"""
    log_event('c2_beacon', {
        'remote_ip': request.remote_addr,
        'endpoint': '/api/beacon',
        'mitre_technique': 'T1071.001'
    })
    return jsonify({
        'status': 'ok',
        'id': 'beacon-12345',
        'sleep': 60,
        'jitter': 10
    })


@app.route('/check', methods=['GET', 'POST'])
@capture_request
def check():
    """Health check endpoint"""
    return jsonify({'alive': True, 'version': '2.1.0'})


@app.route('/update', methods=['POST'])
@capture_request
def update():
    """Fake update/task endpoint"""
    log_event('c2_task_request', {
        'remote_ip': request.remote_addr,
        'endpoint': '/update',
        'mitre_technique': 'T1105'
    })
    return jsonify({
        'tasks': [],
        'next_check': 300
    })


@app.route('/gate', methods=['GET', 'POST'])
@capture_request
def gate():
    """Common panel gate endpoint"""
    return jsonify({'gate': 'open', 'session': 'abc123'})


@app.route('/panel', methods=['GET', 'POST'])
@capture_request
def panel():
    """Fake panel access"""
    return jsonify({'auth': 'success', 'redirect': '/dashboard'})


@app.route('/c2', methods=['GET', 'POST'])
@capture_request
def c2_direct():
    """Direct C2 endpoint"""
    log_event('c2_direct', {
        'remote_ip': request.remote_addr,
        'endpoint': '/c2'
    })
    return jsonify({'cmd': 'sleep', 'args': [60]})


@app.route('/submit', methods=['POST'])
@capture_request
def submit():
    """Data exfiltration endpoint"""
    log_event('data_exfil_attempt', {
        'remote_ip': request.remote_addr,
        'endpoint': '/submit',
        'size': request.content_length,
        'mitre_technique': 'T1041'
    })
    return jsonify({'received': True})


@app.route('/download/<path:filename>', methods=['GET'])
@capture_request
def download(filename):
    """Fake payload download"""
    log_event('payload_request', {
        'remote_ip': request.remote_addr,
        'filename': filename,
        'mitre_technique': 'T1105'
    })
    # Return empty payload
    return '', 200


# ============================================
# Advanced C2 Emulation - Cobalt Strike / Metasploit
# ============================================

@app.route('/beacon', methods=['GET', 'POST'])
@capture_request
def cs_beacon():
    """Cobalt Strike beacon endpoint"""
    log_event('cobalt_strike_beacon', {
        'remote_ip': request.remote_addr,
        'endpoint': '/beacon',
        'mitre_technique': 'T1071.001'
    })
    # Return fake tasking (empty = sleep)
    return '', 200

@app.route('/submit.php', methods=['POST'])
@capture_request
def cs_submit():
    """Cobalt Strike data submission"""
    log_event('cobalt_strike_submit', {
        'remote_ip': request.remote_addr,
        'endpoint': '/submit.php',
        'size': request.content_length,
        'mitre_technique': 'T1041'
    })
    return '', 200

@app.route('/meterpreter', methods=['GET', 'POST'])
@capture_request
def msf_meterpreter():
    """Meterpreter endpoint"""
    log_event('meterpreter_beacon', {
        'remote_ip': request.remote_addr,
        'endpoint': '/meterpreter',
        'mitre_technique': 'T1071.001'
    })
    return '\x00' * 4, 200

@app.route('/reverse_https', methods=['GET', 'POST'])
@capture_request
def msf_reverse_https():
    """Metasploit reverse HTTPS"""
    return jsonify({'status': 'ok'})

# ============================================
# Generic RAT Emulation
# ============================================

@app.route('/rat/register', methods=['POST'])
@capture_request
def rat_register():
    """RAT registration"""
    import random, string
    log_event('rat_registration', {
        'remote_ip': request.remote_addr,
        'mitre_technique': 'T1071.001'
    })
    return jsonify({
        'id': ''.join(random.choices(string.ascii_lowercase + string.digits, k=12)),
        'registered': True
    })

@app.route('/rat/heartbeat', methods=['POST'])
@capture_request
def rat_heartbeat():
    """RAT heartbeat"""
    return jsonify({'alive': True, 'interval': 60})

@app.route('/rat/command', methods=['GET'])
@capture_request
def rat_command():
    """RAT command retrieval"""
    return jsonify({'commands': [], 'pending': False})

# Catch-all for any other paths
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
@capture_request
def catch_all(path):
    """Capture any request to unknown endpoints"""
    return jsonify({'status': 'ok'})


# Error handlers
@app.errorhandler(404)
def not_found(e):
    log_event('http_404', {'path': request.path, 'remote_ip': request.remote_addr})
    return jsonify({'error': 'not found'}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'internal'}), 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8888))
    logger.info(f"Starting HTTP Decoy on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
