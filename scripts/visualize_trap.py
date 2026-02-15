#!/usr/bin/env python3
import sys
import json
import time
import random

# ANSI Colors
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
CYAN = '\033[96m'
MAGENTA = '\033[95m'
RESET = '\033[0m'
BOLD = '\033[1m'

import os

try:
    from scripts.common_banner import print_banner
except ImportError:
    from common_banner import print_banner

def print_redirect_animation(event):
# ... (rest of function)

def main():
    if not os.environ.get("NO_BANNER"):
        print_banner()
    else:
        print(f"{CYAN}{BOLD}=== C2Trap Traffic Interceptor ==={RESET}")
        
    print(f"{CYAN}Waiting for malware beacons...{RESET}\n")
    
    # Track file position (tail from end)
    filename = "logs/analysis_queue.jsonl"
    try:
        with open(filename, "r") as f:
            f.seek(0, 2) # Go to end
            
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                
                try:
                    event = json.loads(line)
                    etype = event.get('event_type', '').lower()
                    
                    # Only show interesting traffic for visualization
                    if any(x in etype for x in ['beacon', 'exfil', 'c2', 'inject', 'upload']):
                        print_redirect_animation(event)
                        
                except json.JSONDecodeError:
                    continue
                    
    except KeyboardInterrupt:
        print(f"\n{RED}Stopping Interceptor.{RESET}")
    except FileNotFoundError:
        print(f"{RED}Log file not found: {filename}{RESET}")

if __name__ == "__main__":
    main()
