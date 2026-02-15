import json
import os
import hashlib
from datetime import datetime

CACHE_DIR = "data/ioc_cache"

def mock_domain(domain, malicious_count=45, threat_score=100):
    key = hashlib.md5(domain.encode()).hexdigest()
    filename = os.path.join(CACHE_DIR, f"domain_{key}.json")
    
    data = {
        "cached_at": datetime.utcnow().isoformat(),
        "ioc_type": "domain",
        "ioc_value": domain,
        "result": {
            "domain": domain,
            "registrar": "Mock Threat Registrar",
            "malicious": malicious_count,
            "suspicious": 5,
            "harmless": 2,
            "undetected": 41,
            "is_malicious": True,
            "threat_score": threat_score,
            "categories": {"malware": "C2 Server"}
        }
    }
    
    with open(filename, 'w') as f:
        json.dump(data, f)
    print(f"[+] Mocked {domain} as Critical (Score: {threat_score})")

if __name__ == "__main__":
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR)
        
    mock_domain("beacon1.c2.evil.com")
    mock_domain("beacon2.c2.evil.com")
    mock_domain("beacon3.c2.evil.com")
