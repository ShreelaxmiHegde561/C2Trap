
import http.server
import socketserver
import json
import time
import os
from datetime import datetime

PORT = 8888
LOG_FILE = "logs/analysis_queue.jsonl"

class MockC2Handler(http.server.SimpleHTTPRequestHandler):
    def _log_event(self, event_type, data):
        event = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "source": "c2trap-mock",
            "event_type": event_type,
            "data": data
        }
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(event) + "\n")
        print(f"Logged event: {event_type}")

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        if self.path == "/api/beacon":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"command: sleep 30")
            
            self._log_event("beacon_detected", {
                "remote_ip": self.client_address[0],
                "domain": self.headers.get("Host", "unknown"),
                "sc_status": 200,
                "method": "POST",
                "uri": self.path,
                "user_agent": self.headers.get("User-Agent", "unknown"),
                "suspicious": True,
                "confidence": 0.9,
                "mitre_technique": "T1071.001"
            })
            
        elif self.path == "/upload":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"upload success")
            
            self._log_event("data_exfil_attempt", {
                "remote_ip": self.client_address[0],
                "domain": self.headers.get("Host", "unknown"),
                "size": content_length,
                "suspicious": True,
                "mitre_technique": "T1041"
            })
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Mock C2 Active")

os.makedirs("logs", exist_ok=True)
print(f"Mock C2 listening on port {PORT}")
with socketserver.TCPServer(("", PORT), MockC2Handler) as httpd:
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
