"""
C2Trap Sandbox Executor
Execute malware in isolated Docker containers
"""

import os
import sys
import json
import logging
import uuid
import time
import shutil
from datetime import datetime
from typing import Optional, Dict, List
from pathlib import Path

# Add project root to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import enhanced analyzer
try:
    from sandbox.analyzer import FileAnalyzer
    ENHANCED_ANALYSIS = True
except ImportError:
    ENHANCED_ANALYSIS = False
    print("Enhanced file analyzer not available")

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('sandbox')

LOG_PATH = os.environ.get('LOG_PATH', '/app/logs/analysis_queue.jsonl')
SANDBOX_QUEUE = os.environ.get('SANDBOX_QUEUE', '/app/logs/sandbox_queue.jsonl')
REPORTS_PATH = os.environ.get('REPORTS_PATH', '/app/logs/sandbox')


def log_event(event_type: str, data: dict) -> None:
    """Write event to analysis queue"""
    event = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'source': 'sandbox',
        'event_type': event_type,
        'data': data
    }
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, 'a') as f:
            f.write(json.dumps(event) + '\n')
    except Exception as e:
        logger.error(f"Failed to write log: {e}")


class SandboxExecutor:
    """Execute samples in isolated Docker containers"""
    
    def __init__(self):
        self.docker_client = None
        self._init_docker()
        self.active_containers: Dict[str, dict] = {}
        self.completed_analyses: List[dict] = []
        
        # Create reports directory
        os.makedirs(REPORTS_PATH, exist_ok=True)
        
        if ENHANCED_ANALYSIS:
            self.file_analyzer = FileAnalyzer()
            logger.info("Enhanced file analysis enabled")
        else:
            self.file_analyzer = None
    
    def _init_docker(self):
        """Initialize Docker client"""
        try:
            import docker
            self.docker_client = docker.from_env()
            logger.info("Docker client initialized")
        except ImportError:
            logger.warning("Docker SDK not installed. Install with: pip install docker")
        except Exception as e:
            logger.error(f"Failed to initialize Docker: {e}")
    
    def create_sandbox(self, sample_path: Optional[str] = None, 
                       sample_hash: Optional[str] = None,
                       timeout: int = 120) -> str:
        """
        Create an isolated sandbox for malware execution
        
        Args:
            sample_path: Path to sample file
            sample_hash: SHA256 hash of sample
            timeout: Max execution time in seconds
        
        Returns:
            Sandbox ID
        """
        sandbox_id = str(uuid.uuid4())[:8]
        
        if not self.docker_client:
            logger.error("Docker client not available")
            return sandbox_id
        
        try:
            # Create a temp dir for the sample to mount it
            host_sample_dir = f"/tmp/c2trap_samples/{sandbox_id}"
            os.makedirs(host_sample_dir, exist_ok=True)
            
            # Copy sample if provided
            if sample_path and os.path.exists(sample_path):
                filename = os.path.basename(sample_path)
                shutil.copy2(sample_path, os.path.join(host_sample_dir, filename))
            
            # Container configuration
            container_config = {
                'image': 'python:3.11-slim',  # Base image
                'name': f'c2trap-sandbox-{sandbox_id}',
                'detach': True,
                'network_mode': 'none',  # No network access
                'mem_limit': '256m',
                'cpu_period': 100000,
                'cpu_quota': 50000,  # 50% CPU
                'read_only': False,
                'security_opt': ['no-new-privileges'],
                'cap_drop': ['ALL'],
                'environment': {
                    'SANDBOX_ID': sandbox_id,
                    'SAMPLE_HASH': sample_hash or 'unknown'
                },
                'volumes': {
                    host_sample_dir: {'bind': '/sample', 'mode': 'ro'}
                }
            }
            
            # Create container
            container = self.docker_client.containers.run(
                command='/bin/sh -c "sleep infinity"',
                **container_config
            )
            
            self.active_containers[sandbox_id] = {
                'container_id': container.id,
                'created': datetime.utcnow().isoformat(),
                'sample_hash': sample_hash,
                'status': 'running',
                'timeout': timeout,
                'host_dir': host_sample_dir
            }
            
            log_event('sandbox_created', {
                'sandbox_id': sandbox_id,
                'container_id': container.id[:12],
                'sample_hash': sample_hash
            })
            
            logger.info(f"[SANDBOX] Created: {sandbox_id}")
            return sandbox_id
            
        except Exception as e:
            logger.error(f"Failed to create sandbox: {e}")
            return sandbox_id
    
    def execute_in_sandbox(self, sandbox_id: str, command: str) -> Optional[dict]:
        """Execute a command in sandbox"""
        if sandbox_id not in self.active_containers:
            logger.error(f"Sandbox not found: {sandbox_id}")
            return None
        
        if not self.docker_client:
            return None
        
        try:
            container_id = self.active_containers[sandbox_id]['container_id']
            container = self.docker_client.containers.get(container_id)
            
            # Execute command
            exit_code, output = container.exec_run(command, demux=True)
            
            stdout = output[0].decode() if output[0] else ''
            stderr = output[1].decode() if output[1] else ''
            
            result = {
                'sandbox_id': sandbox_id,
                'command': command,
                'exit_code': exit_code,
                'stdout': stdout[:4096],
                'stderr': stderr[:4096]
            }
            
            log_event('sandbox_execution', result)
            return result
            
        except Exception as e:
            logger.error(f"Execution failed: {e}")
            return None
    
    def destroy_sandbox(self, sandbox_id: str) -> bool:
        """Destroy a sandbox container"""
        if sandbox_id not in self.active_containers:
            return False
        
        if not self.docker_client:
            return False
        
        try:
            container_id = self.active_containers[sandbox_id]['container_id']
            container = self.docker_client.containers.get(container_id)
            
            # Force remove
            container.remove(force=True)
            
            # Clean up host dir
            host_dir = self.active_containers[sandbox_id].get('host_dir')
            if host_dir and os.path.exists(host_dir):
                try:
                    shutil.rmtree(host_dir)
                except:
                    pass
            
            # Update status
            self.active_containers[sandbox_id]['status'] = 'destroyed'
            self.active_containers[sandbox_id]['destroyed'] = datetime.utcnow().isoformat()
            
            log_event('sandbox_destroyed', {
                'sandbox_id': sandbox_id
            })
            
            logger.info(f"[SANDBOX] Destroyed: {sandbox_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to destroy sandbox: {e}")
            return False
    
    def analyze_sample(self, sample_path: str, timeout: int = 60) -> dict:
        """
        Full analysis workflow for a sample
        
        Returns analysis report
        """
        import hashlib
        
        # Calculate hash
        with open(sample_path, 'rb') as f:
            sample_hash = hashlib.sha256(f.read()).hexdigest()
        
        report = {
            'sample_hash': sample_hash,
            'sample_path': sample_path,
            'started': datetime.utcnow().isoformat(),
            'status': 'pending',
            'findings': []
        }
        
        # 1. Static Analysis (Enhanced)
        if self.file_analyzer:
            logger.info(f"Running enhanced static analysis on {sample_path}")
            try:
                static_report = self.file_analyzer.analyze(sample_path)
                report['static_analysis'] = static_report
                report['verdict'] = static_report.get('verdict')
                report['threat_score'] = static_report.get('threat_score')
            except Exception as e:
                logger.error(f"Static analysis failed: {e}")
                report['static_analysis_error'] = str(e)
        
        # 2. Dynamic Analysis (Sandbox)
        sandbox_id = self.create_sandbox(sample_path, sample_hash, timeout)
        report['sandbox_id'] = sandbox_id
        
        if sandbox_id not in self.active_containers:
            report['status'] = 'failed'
            report['error'] = 'Failed to create sandbox'
            return report
        
        try:
            report['status'] = 'analyzing'
            
            # Basic analysis commands
            analysis_commands = [
                'cat /etc/os-release',
                'id',
                'whoami',
                'ls -la /sample',
                'file /sample/*',
                'sleep 5',  # Keep alive for demo visibility
            ]
            
            report['command_outputs'] = []
            for cmd in analysis_commands:
                result = self.execute_in_sandbox(sandbox_id, cmd)
                if result:
                    report['command_outputs'].append(result)
            
            report['status'] = 'completed'
            report['completed'] = datetime.utcnow().isoformat()
            
        except Exception as e:
            report['status'] = 'error'
            report['error'] = str(e)
        
        finally:
            # Cleanup
            self.destroy_sandbox(sandbox_id)
        
        # Save report
        self._save_report(report)
        self.completed_analyses.append(report)
        
        log_event('analysis_completed', {
            'sample_hash': sample_hash,
            'sandbox_id': sandbox_id,
            'status': report['status'],
            'verdict': report.get('verdict', 'UNKNOWN'),
            'score': report.get('threat_score', 0)
        })
        
        return report
    
    def _save_report(self, report: dict):
        """Save analysis report to file"""
        try:
            report_file = Path(REPORTS_PATH) / f"{report['sample_hash'][:16]}.json"
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Failed to save report: {e}")
    
    def get_active_sandboxes(self) -> List[dict]:
        """Get list of active sandboxes"""
        return [
            {
                'sandbox_id': sid,
                'status': info['status'],
                'created': info['created'],
                'sample_hash': info['sample_hash']
            }
            for sid, info in self.active_containers.items()
            if info['status'] == 'running'
        ]
    
    def get_completed_analyses(self, limit: int = 10) -> List[dict]:
        """Get recent completed analyses"""
        return self.completed_analyses[-limit:]
    
    def cleanup_all(self):
        """Cleanup all sandbox containers"""
        for sandbox_id in list(self.active_containers.keys()):
            if self.active_containers[sandbox_id]['status'] == 'running':
                self.destroy_sandbox(sandbox_id)
        logger.info("All sandboxes cleaned up")


# Singleton instance
_executor = None

def get_executor() -> SandboxExecutor:
    global _executor
    if _executor is None:
        _executor = SandboxExecutor()
    return _executor


if __name__ == '__main__':
    executor = SandboxExecutor()
    print(f"Docker available: {executor.docker_client is not None}")
    print(f"Enhanced analysis: {executor.file_analyzer is not None}")
