"""
C2Trap C2 Traffic Rerouting - Fake C2 Server
Responds to malware commands and logs interactions
"""

import os
import json
import logging
import base64
import random
import string
from datetime import datetime
from flask import Flask, request, jsonify, Response
from functools import wraps

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('fake_c2')

LOG_PATH = os.environ.get('LOG_PATH', '/app/logs/analysis_queue.jsonl')

app = Flask(__name__)


def log_event(event_type: str, data: dict) -> None:
    """Write event to analysis queue"""
    event = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'source': 'fake_c2_server',
        'event_type': event_type,
        'data': data
    }
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, 'a') as f:
            f.write(json.dumps(event) + '\n')
    except Exception as e:
        logger.error(f"Failed to write log: {e}")


def capture_c2(f):
    """Decorator to capture all C2 interactions"""
    @wraps(f)
    def decorated(*args, **kwargs):
        data = {
            'remote_ip': request.remote_addr,
            'method': request.method,
            'path': request.path,
            'headers': dict(request.headers),
            'user_agent': request.headers.get('User-Agent', ''),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if request.method in ['POST', 'PUT']:
            try:
                if request.is_json:
                    data['body'] = request.get_json(silent=True)
                else:
                    raw = request.get_data()
                    try:
                        data['body'] = raw.decode('utf-8')[:4096]
                    except:
                        data['body_base64'] = base64.b64encode(raw[:1024]).decode()
            except:
                pass
        
        log_event('c2_interaction', data)
        logger.warning(f"[FAKE-C2] {request.method} {request.path} from {request.remote_addr}")
        
        return f(*args, **kwargs)
    return decorated


# =============================================
# Cobalt Strike-style endpoints
# =============================================

@app.route('/beacon', methods=['GET', 'POST'])
@capture_c2
def cs_beacon():
    """Cobalt Strike beacon endpoint"""
    log_event('cobalt_strike_beacon', {
        'remote_ip': request.remote_addr,
        'mitre_technique': 'T1071.001'
    })
    
    # Return fake tasking (empty = sleep)
    return Response(b'', status=200, mimetype='application/octet-stream')


@app.route('/submit.php', methods=['POST'])
@capture_c2
def cs_submit():
    """Cobalt Strike data submission"""
    log_event('cobalt_strike_submit', {
        'remote_ip': request.remote_addr,
        'size': request.content_length,
        'mitre_technique': 'T1041'
    })
    return Response(b'', status=200)


# =============================================
# Metasploit-style endpoints
# =============================================

@app.route('/meterpreter', methods=['GET', 'POST'])
@capture_c2
def msf_meterpreter():
    """Meterpreter endpoint"""
    log_event('meterpreter_beacon', {
        'remote_ip': request.remote_addr,
        'mitre_technique': 'T1071.001'
    })
    return Response(b'\x00' * 4, status=200, mimetype='application/octet-stream')


@app.route('/reverse_https', methods=['GET', 'POST'])
@capture_c2
def msf_reverse_https():
    """Metasploit reverse HTTPS"""
    return jsonify({'status': 'ok'})


# =============================================
# Generic C2 endpoints
# =============================================

@app.route('/api/v1/check', methods=['GET', 'POST'])
@capture_c2
def api_check():
    """Generic check-in endpoint"""
    return jsonify({
        'id': ''.join(random.choices(string.hexdigits, k=16)),
        'status': 'active',
        'tasks': [],
        'sleep': 60
    })


@app.route('/api/v1/task', methods=['GET', 'POST'])
@capture_c2
def api_task():
    """Task retrieval endpoint"""
    return jsonify({
        'tasks': [],
        'pending': 0
    })


@app.route('/api/v1/result', methods=['POST'])
@capture_c2
def api_result():
    """Task result submission"""
    log_event('task_result_submitted', {
        'remote_ip': request.remote_addr,
        'mitre_technique': 'T1041'
    })
    return jsonify({'received': True})


@app.route('/gate.php', methods=['GET', 'POST'])
@capture_c2
def gate_php():
    """Common gate.php endpoint"""
    return Response('OK', status=200)


@app.route('/panel.php', methods=['GET', 'POST'])
@capture_c2
def panel_php():
    """Panel access endpoint"""
    return Response('OK', status=200)


@app.route('/cmd', methods=['GET', 'POST'])
@capture_c2
def cmd_endpoint():
    """Command endpoint"""
    return jsonify({'cmd': 'sleep', 'duration': 300})


@app.route('/upload', methods=['POST'])
@capture_c2
def upload():
    """File upload endpoint"""
    log_event('file_upload', {
        'remote_ip': request.remote_addr,
        'content_type': request.content_type,
        'size': request.content_length,
        'mitre_technique': 'T1041'
    })
    return jsonify({'uploaded': True, 'id': random.randint(1000, 9999)})


@app.route('/download/<path:filename>', methods=['GET'])
@capture_c2
def download(filename):
    """Fake file download"""
    log_event('file_download_request', {
        'remote_ip': request.remote_addr,
        'filename': filename,
        'mitre_technique': 'T1105'
    })
    # Return empty file
    return Response(b'', status=200, mimetype='application/octet-stream')


# =============================================
# RAT-style endpoints
# =============================================

@app.route('/rat/register', methods=['POST'])
@capture_c2
def rat_register():
    """RAT registration"""
    log_event('rat_registration', {
        'remote_ip': request.remote_addr,
        'mitre_technique': 'T1071.001'
    })
    return jsonify({
        'id': ''.join(random.choices(string.ascii_lowercase + string.digits, k=12)),
        'registered': True
    })


@app.route('/rat/heartbeat', methods=['POST'])
@capture_c2
def rat_heartbeat():
    """RAT heartbeat"""
    return jsonify({'alive': True, 'interval': 60})


@app.route('/rat/command', methods=['GET'])
@capture_c2
def rat_command():
    """RAT command retrieval"""
    return jsonify({'commands': [], 'pending': False})


# =============================================
# Catch-all for unknown paths
# =============================================

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
@capture_c2
def catch_all(path):
    """Capture any unknown endpoint"""
    return jsonify({'status': 'ok'})


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 9999))
    logger.info(f"Starting Fake C2 Server on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
