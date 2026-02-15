#!/usr/bin/env python3
"""
C2Trap Analysis Testing Tool
Manual trigger for Sandbox and VirusTotal components
"""

import os
import sys
import argparse
import logging
import json
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.append(str(PROJECT_ROOT))

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger('test_analysis')

# Set environment variables for local execution (before imports)
if 'LOG_PATH' not in os.environ:
    os.environ['LOG_PATH'] = str(PROJECT_ROOT / 'logs' / 'analysis_queue.jsonl')
if 'SANDBOX_QUEUE' not in os.environ:
    os.environ['SANDBOX_QUEUE'] = str(PROJECT_ROOT / 'logs' / 'sandbox_queue.jsonl')
if 'REPORTS_PATH' not in os.environ:
    os.environ['REPORTS_PATH'] = str(PROJECT_ROOT / 'logs' / 'sandbox')
if 'CACHE_PATH' not in os.environ:
    os.environ['CACHE_PATH'] = str(PROJECT_ROOT / 'data' / 'ioc_cache')

# Ensure directories exist
Path(os.environ['REPORTS_PATH']).mkdir(parents=True, exist_ok=True)
Path(os.environ['CACHE_PATH']).mkdir(parents=True, exist_ok=True)

def test_sandbox(file_path: str):
    """Test Sandbox execution"""
    from sandbox.executor import get_executor
    
    logger.info(f"Testing Sandbox with file: {file_path}")
    if not os.path.exists(file_path):
        logger.error(f"File not found: {file_path}")
        return

    executor = get_executor()
    if not executor.docker_client:
        logger.error("Docker not available. Cannot run sandbox.")
        return

    logger.info("Submitting sample to sandbox...")
    report = executor.analyze_sample(file_path, timeout=60)
    
    print("\n" + "="*50)
    print("SANDBOX REPORT")
    print("="*50)
    print(f"Status: {report.get('status')}")
    print(f"Sandbox ID: {report.get('sandbox_id')}")
    print(f"Sample Hash: {report.get('sample_hash')}")
    
    if 'command_outputs' in report:
        print("\nCommand Outputs:")
        for cmd_res in report['command_outputs']:
            print(f"\n$ {cmd_res['command']}")
            print("-" * 20)
            if cmd_res.get('stdout'):
                print(cmd_res['stdout'].strip())
            if cmd_res.get('stderr'):
                print(f"[STDERR] {cmd_res['stderr'].strip()}")
    
    if report.get('error'):
        print(f"\nError: {report['error']}")
    print("="*50 + "\n")

def test_virustotal(target: str, target_type: str):
    """Test VirusTotal lookup"""
    from intelligence.virustotal.vt_client import get_client
    
    logger.info(f"Testing VirusTotal lookup for {target} ({target_type})")
    
    client = get_client()
    if not client.api_key or client.api_key == 'your_api_key_here':
        logger.warning("VT_API_KEY not configured in environment or config!")
        logger.warning("Please edit config/virustotal.env or export VT_API_KEY")
        # Proceed anyway, client might handle it or just fail
    
    result = None
    if target_type == 'ip':
        result = client.lookup_ip(target)
    elif target_type == 'domain':
        result = client.lookup_domain(target)
    elif target_type == 'hash':
        result = client.lookup_hash(target)
    
    print("\n" + "="*50)
    print("VIRUSTOTAL REPORT")
    print("="*50)
    
    if result:
        print(json.dumps(result, indent=2))
        
        score = result.get('threat_score', 0)
        print("\n" + "-"*20)
        print(f"Threat Score: {score}/100")
        if score > 80:
            print("Verdict: MALICIOUS 🔴")
        elif score > 50:
            print("Verdict: SUSPICIOUS 🟠")
        else:
            print("Verdict: BENIGN 🟢")
    else:
        print("No result found or API error.")
    print("="*50 + "\n")

def main():
    parser = argparse.ArgumentParser(description="C2Trap Analysis Testing Tool")
    
    # Subcommands? Or just flags. Flags are simpler for now.
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--sandbox', action='store_true', help="Run Sandbox analysis")
    group.add_argument('--vt', action='store_true', help="Run VirusTotal lookup")
    
    parser.add_argument('--file', help="File path for sandbox analysis")
    parser.add_argument('--ip', help="IP address for VT lookup")
    parser.add_argument('--domain', help="Domain for VT lookup")
    parser.add_argument('--hash', help="File hash for VT lookup")
    
    args = parser.parse_args()
    
    # Load env vars for VT
    env_file = PROJECT_ROOT / 'config' / 'virustotal.env'
    if env_file.exists():
        with open(env_file) as f:
            for line in f:
                if line.strip() and not line.startswith('#'):
                    key, val = line.strip().split('=', 1)
                    os.environ[key] = val

    if args.sandbox:
        if not args.file:
            print("Error: --file is required for sandbox mode")
            sys.exit(1)
        test_sandbox(args.file)
        
    elif args.vt:
        if args.ip:
            test_virustotal(args.ip, 'ip')
        elif args.domain:
            test_virustotal(args.domain, 'domain')
        elif args.hash:
            test_virustotal(args.hash, 'hash')
        else:
            print("Error: Provide --ip, --domain, or --hash for VT mode")
            sys.exit(1)

if __name__ == "__main__":
    main()
