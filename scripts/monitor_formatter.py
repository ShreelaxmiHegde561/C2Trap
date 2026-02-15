#!/usr/bin/env python3
import sys
import json
import time
from datetime import datetime

# ANSI Colors
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
CYAN = '\033[96m'
RESET = '\033[0m'
BOLD = '\033[1m'

def format_falco(event):
    priority = event.get('priority', 'INFO')
    color = RED if priority in ['Critical', 'Emergency'] else YELLOW if priority == 'Warning' else BLUE
    rule = event.get('rule', 'Unknown Rule')
    output = event.get('output', '')
    
    return f"{color}[RUNTIME] [{priority}] {rule}: {output}{RESET}"

def format_analysis(event):
    event_type = event.get('event_type', 'unknown')
    data = event.get('data', {})
    
    if event_type == 'heartbeat':
        return None
        
    severity = 'INFO'
    color = BLUE
    
    if data.get('is_malicious'):
        severity = 'MALICIOUS'
        color = RED
    elif data.get('suspicious'):
        severity = 'SUSPICIOUS'
        color = YELLOW
        
    source = event.get('source', 'unknown')
    desc = f"{event_type} from {source}"
    
    # Enrichment
    if 'domain' in data:
        desc += f" Domain: {data['domain']}"
    if 'remote_ip' in data:
        desc += f" IP: {data['remote_ip']}"
        
    return f"{color}[ANALYSIS] [{severity}] {desc}{RESET}"

import os

try:
    from scripts.common_banner import print_banner
except ImportError:
    from common_banner import print_banner

def main():
    if not os.environ.get("NO_BANNER"):
        print_banner()
    else:
        print(f"{CYAN}=== C2Trap Event Monitor ==={RESET}")
        
    print(f"{CYAN}Watching for Sandbox & Runtime Events...{RESET}\n")
    
    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break
                
            line = line.strip()
            if not line:
                continue
                
            # Skip file headers from tail
            if line.startswith('==>'):
                continue
                
            try:
                event = json.loads(line)
                
                # Determine source based on fields
                if 'rule' in event and 'output' in event:
                    print(format_falco(event))
                else:
                    msg = format_analysis(event)
                    if msg: print(msg)
                    
            except json.JSONDecodeError:
                continue
                
        except KeyboardInterrupt:
            break
        except Exception as e:
            continue

if __name__ == "__main__":
    main()
