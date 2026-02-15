import sys
import os
import json
from pathlib import Path

# Fix path to import intelligence
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from intelligence.virustotal.vt_client import VTClient

def debug_vt(ioc_type, value):
    client = VTClient()
    print(f"\n[*] Debugging {ioc_type}: {value}")
    
    # Bypass cache for debug
    result = client._make_request(f"{'ip_addresses' if ioc_type == 'ip' else 'domains'}/{value}")
    if not result:
        print("[!] No response from VT")
        return

    data = result.get('data', {})
    attributes = data.get('attributes', {})
    stats = attributes.get('last_analysis_stats', {})
    
    print(f"[*] Raw stats: {json.dumps(stats, indent=2)}")
    
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    total = stats.get('malicious', 0) + stats.get('suspicious', 0) + \
            stats.get('harmless', 0) + stats.get('undetected', 0)
            
    print(f"[*] Malicious: {malicious}")
    print(f"[*] Suspicious: {suspicious}")
    print(f"[*] Total: {total}")
    
    score = client._calculate_threat_score(stats)
    print(f"[+] Calculated Score: {score}")

if __name__ == '__main__':
    # Test a known malicious-leaning IP (e.g. 1.1.1.1 is clean usually, but let's see how stats look)
    debug_vt('ip', '1.1.1.1')
    # Test a common "bad" IP if we know one, otherwise just look at the stats of a few.
    debug_vt('ip', '8.8.8.8')
