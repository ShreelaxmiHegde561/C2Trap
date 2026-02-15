"""
Automatic Malware Analysis Watcher
Watches quarantine/ directory for new files and automatically analyzes them via Sandbox and VirusTotal.
"""
import os
import sys
import time
import shutil
import logging
from pathlib import Path

# Fix imports to allow running from scripts/ directory or root
# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sandbox.executor import get_executor
from intelligence.virustotal.vt_client import get_client

# Log setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger('auto')

QUARANTINE_DIR = Path('quarantine')
PROCESSED_DIR = QUARANTINE_DIR / 'processed'

def process_file(file_path: Path):
    logger.info(f"[*] Detected new file: {file_path.name}")
    
    try:
        # 1. Automatic Sandbox Analysis
        logger.info("   [+] Starting Sandbox Analysis...")
        executor = get_executor()
        report = executor.analyze_sample(str(file_path))
        
        sandbox_id = report.get('sandbox_id', 'unknown')
        status = report.get('status', 'unknown')
        logger.info(f"   [+] Sandbox Completed: {status.upper()} (ID: {sandbox_id})")
        logger.info(f"   [+] Report saved: logs/sandbox/{report['sample_hash'][:16]}.json")
        
        # 2. VirusTotal Check
        logger.info("   [+] Checking VirusTotal...")
        try:
            vt = get_client()
            if vt:
                vt_result = vt.enrich_ioc('hash', report['sample_hash'])
                if vt_result:
                    score = vt_result.get('threat_score', 0)
                    malicious = vt_result.get('malicious', 0)
                    logger.info(f"   [!] VirusTotal Score: {score}/100 | Malicious: {malicious}")
                    
                    # Notify Dashboard to update UI
                    try:
                        requests.post('http://localhost:8000/api/enrich', json={
                            'value': report['sample_hash'],
                            'type': 'hash'
                        }, timeout=2)
                        logger.info("   [+] Dashboard updated")
                    except Exception as e:
                        logger.warning(f"   [-] Failed to update dashboard: {e}")
                else:
                    logger.info("   [-] No VirusTotal results found")
        except Exception as e:
            logger.error(f"   [-] VT Check failed: {e}")
            
        # 3. Move to processed
        PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
        dest = PROCESSED_DIR / file_path.name
        
        # Handle duplicate names
        if dest.exists():
            timestamp = int(time.time())
            dest = PROCESSED_DIR / f"{file_path.stem}_{timestamp}{file_path.suffix}"
            
        shutil.move(str(file_path), str(dest))
        logger.info(f"   [+] Moved file to: {dest}")
        print("-" * 50)
        
    except Exception as e:
        logger.error(f"   [x] Failed to process file {file_path}: {e}")

def start_watcher():
    # Ensure directories
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    
    logger.info(f"🔎 Starting Automatic Malware Analyzer on {QUARANTINE_DIR.absolute()}")
    
    try:
        while True:
            if QUARANTINE_DIR.exists():
                for item in QUARANTINE_DIR.iterdir():
                    if item.is_file():
                        process_file(item)
            time.sleep(2)
    except Exception as e:
        logger.error(f"Watcher error: {e}")

def main():
    try:
        start_watcher()
    except KeyboardInterrupt:
        print("\nStopping watcher...")

if __name__ == '__main__':
    main()
