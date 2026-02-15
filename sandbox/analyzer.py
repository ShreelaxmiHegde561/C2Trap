#!/usr/bin/env python3
"""
C2Trap Enhanced File Analyzer
=============================

Deep file analysis engine with professional report formatting.
Provides VirusTotal-like analysis reports for dropped samples.

Features:
- PE/ELF header parsing
- String extraction
- Entropy analysis
- Import/export analysis
- Behavioral indicators
- Threat scoring
"""

import os
import re
import json
import math
import struct
import hashlib
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
from dataclasses import dataclass, asdict
from collections import Counter

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('file_analyzer')

LOG_PATH = os.environ.get('LOG_PATH', '/app/logs/analysis_queue.jsonl')


def log_event(event_type: str, data: dict) -> None:
    """Write event to analysis queue"""
    event = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'source': 'file_analyzer',
        'event_type': event_type,
        'data': data
    }
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, 'a') as f:
            f.write(json.dumps(event) + '\n')
    except Exception as e:
        logger.error(f"Failed to write log: {e}")


@dataclass
class FileInfo:
    """Basic file information"""
    path: str
    filename: str
    size: int
    md5: str
    sha1: str
    sha256: str
    magic_bytes: str
    file_type: str
    entropy: float


@dataclass
class PEInfo:
    """PE file information"""
    is_pe: bool = False
    machine: str = ""
    timestamp: str = ""
    subsystem: str = ""
    dll: bool = False
    imports: List[str] = None
    exports: List[str] = None
    sections: List[Dict] = None
    suspicious_imports: List[str] = None
    
    def __post_init__(self):
        self.imports = self.imports or []
        self.exports = self.exports or []
        self.sections = self.sections or []
        self.suspicious_imports = self.suspicious_imports or []


@dataclass  
class ELFInfo:
    """ELF file information"""
    is_elf: bool = False
    arch: str = ""
    abi: str = ""
    type: str = ""
    entry_point: str = ""
    sections: List[Dict] = None
    symbols: List[str] = None
    
    def __post_init__(self):
        self.sections = self.sections or []
        self.symbols = self.symbols or []


@dataclass
class StringsAnalysis:
    """Extracted strings analysis"""
    total_count: int = 0
    urls: List[str] = None
    ips: List[str] = None
    domains: List[str] = None
    emails: List[str] = None
    file_paths: List[str] = None
    registry_keys: List[str] = None
    suspicious: List[str] = None
    base64_encoded: List[str] = None
    
    def __post_init__(self):
        self.urls = self.urls or []
        self.ips = self.ips or []
        self.domains = self.domains or []
        self.emails = self.emails or []
        self.file_paths = self.file_paths or []
        self.registry_keys = self.registry_keys or []
        self.suspicious = self.suspicious or []
        self.base64_encoded = self.base64_encoded or []


@dataclass
class BehaviorIndicators:
    """Behavioral indicators"""
    network_capability: bool = False
    file_operations: bool = False
    process_manipulation: bool = False
    registry_access: bool = False
    crypto_capability: bool = False
    anti_analysis: bool = False
    persistence_mechanisms: bool = False
    data_exfiltration: bool = False
    command_execution: bool = False
    privilege_escalation: bool = False
    indicators: List[str] = None
    
    def __post_init__(self):
        self.indicators = self.indicators or []


class FileAnalyzer:
    """Enhanced file analysis engine"""
    
    # Suspicious import functions
    SUSPICIOUS_IMPORTS = {
        # Process injection
        'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect',
        'WriteProcessMemory', 'CreateRemoteThread', 'NtCreateThreadEx',
        'QueueUserAPC', 'SetThreadContext', 'ResumeThread',
        
        # Code execution
        'WinExec', 'ShellExecute', 'ShellExecuteEx', 'CreateProcess',
        'system', 'popen', 'exec', 'execve', 'fork',
        
        # Network
        'WSASocket', 'connect', 'send', 'recv', 'InternetOpen',
        'HttpOpenRequest', 'URLDownloadToFile', 'socket',
        
        # Crypto
        'CryptAcquireContext', 'CryptEncrypt', 'CryptDecrypt',
        'CryptGenKey', 'CryptImportKey',
        
        # Anti-debug
        'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
        'NtQueryInformationProcess', 'GetTickCount',
        
        # Keylogging
        'GetAsyncKeyState', 'GetKeyState', 'SetWindowsHookEx',
        
        # Registry
        'RegCreateKey', 'RegSetValue', 'RegOpenKey',
        
        # File
        'DeleteFile', 'MoveFile', 'CopyFile'
    }
    
    # Suspicious string patterns
    SUSPICIOUS_STRINGS = [
        'password', 'passwd', 'pwd', 'credential',
        'bitcoin', 'wallet', 'crypto', 'ransom',
        'encrypt', 'decrypt', 'cipher',
        'backdoor', 'rootkit', 'trojan', 'malware',
        'keylog', 'screenshot', 'webcam',
        'c2', 'beacon', 'callback', 'reverse',
        'shell', 'cmd.exe', 'powershell', '/bin/sh', '/bin/bash',
        'admin', 'administrator', 'root',
        'hidden', 'stealth', 'persist'
    ]
    
    def __init__(self):
        self.reports_dir = os.environ.get('REPORTS_PATH', '/app/logs/sandbox')
        os.makedirs(self.reports_dir, exist_ok=True)
    
    def analyze(self, file_path: str) -> Dict:
        """
        Perform comprehensive file analysis
        
        Returns a detailed analysis report
        """
        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}
        
        logger.info(f"[ANALYZER] Starting analysis of: {file_path}")
        
        # Read file content
        with open(file_path, 'rb') as f:
            content = f.read()
        
        # Basic file info
        file_info = self._analyze_file_info(file_path, content)
        
        # Format-specific analysis
        pe_info = self._analyze_pe(content) if file_info.file_type.startswith('PE') else PEInfo()
        elf_info = self._analyze_elf(content) if file_info.file_type.startswith('ELF') else ELFInfo()
        
        # Archive/Document analysis
        archive_info = {}
        if file_info.file_type == 'ZIP archive':
            archive_info = self._analyze_zip(file_path)
        elif file_info.file_type == 'PDF document':
            archive_info = self._analyze_pdf(content)
        
        # String analysis
        strings_analysis = self._analyze_strings(content)
        
        # Behavior indicators
        behavior = self._analyze_behavior(content, strings_analysis, pe_info)
        
        # Add archive indicators to behavior
        if archive_info.get('suspicious_content'):
            behavior.indicators.extend(archive_info['suspicious_content'])
            if 'script' in str(archive_info['suspicious_content']).lower():
                behavior.command_execution = True
        
        # Calculate threat score
        threat_score = self._calculate_threat_score(
            file_info, pe_info, elf_info, strings_analysis, behavior
        )
        
        # Boost score for malicious archives
        if archive_info.get('suspicious_content'):
            # High impact for hidden executables or scripts in archives
            threat_score += 30  # Base penalty for suspicious archive
            threat_score += 50 * len(archive_info['suspicious_content'])
            threat_score = min(threat_score, 100)
        
        # Build report
        report = {
            "analysis_id": hashlib.md5(f"{file_path}{datetime.utcnow().isoformat()}".encode()).hexdigest()[:16],
            "analysis_time": datetime.utcnow().isoformat() + "Z",
            "file_info": asdict(file_info),
            "pe_info": asdict(pe_info) if pe_info.is_pe else None,
            "elf_info": asdict(elf_info) if elf_info.is_elf else None,
            "archive_info": archive_info if archive_info else None,
            "strings": asdict(strings_analysis),
            "behavior": asdict(behavior),
            "threat_score": threat_score,
            "verdict": self._get_verdict(threat_score),
            "mitre_techniques": self._map_mitre_techniques(behavior)
        }
        
        # Save report
        self._save_report(report, file_info.sha256)
        
        # Log event
        log_event('file_analysis_complete', {
            'file_hash': file_info.sha256,
            'file_type': file_info.file_type,
            'threat_score': threat_score,
            'verdict': report['verdict']
        })
        
        logger.info(f"[ANALYZER] Complete - Score: {threat_score}, Verdict: {report['verdict']}")
        
        return report

    def _analyze_zip(self, file_path: str) -> Dict:
        """Analyze ZIP archive contents"""
        info = {
            "file_count": 0,
            "files": [],
            "suspicious_content": []
        }
        
        try:
            import zipfile
            with zipfile.ZipFile(file_path, 'r') as zf:
                info['file_count'] = len(zf.namelist())
                
                for name in zf.namelist():
                    info['files'].append(name)
                    
                    # Check for suspicious extensions
                    ext = os.path.splitext(name)[1].lower()
                    if ext in ['.exe', '.vbs', '.js', '.bat', '.ps1', '.cmd', '.scr', '.pif']:
                        info['suspicious_content'].append(f"Contains executable file: {name}")
                    
                    # Check for double extensions
                    if re.search(r'\.[a-z]{3,4}\.exe$', name.lower()):
                        info['suspicious_content'].append(f"Double extension detected: {name}")
                        
        except Exception as e:
            logger.error(f"ZIP analysis error: {e}")
            info['error'] = str(e)
            
        return info

    def _analyze_pdf(self, content: bytes) -> Dict:
        """Analyze PDF document"""
        info = {
            "version": "Unknown",
            "suspicious_content": []
        }
        
        try:
            # Extract version
            m = re.match(rb'%PDF-(\d\.\d)', content)
            if m:
                info['version'] = m.group(1).decode()
            
            # Check for JS
            if b'/JavaScript' in content or b'/JS' in content:
                info['suspicious_content'].append("Contains JavaScript")
            
            # Check for auto-action
            if b'/OpenAction' in content or b'/AA' in content:
                info['suspicious_content'].append("Contains automatic action (OpenAction)")
            
            # Check for launch
            if b'/Launch' in content:
                info['suspicious_content'].append("Contains external program launch")
                
        except Exception as e:
            logger.error(f"PDF analysis error: {e}")
            info['error'] = str(e)
            
        return info
    
    def _analyze_file_info(self, path: str, content: bytes) -> FileInfo:
        """Extract basic file information"""
        magic = content[:16].hex() if len(content) >= 16 else content.hex()
        
        # Detect file type from magic bytes
        file_type = self._detect_file_type(content[:16])
        
        return FileInfo(
            path=path,
            filename=os.path.basename(path),
            size=len(content),
            md5=hashlib.md5(content).hexdigest(),
            sha1=hashlib.sha1(content).hexdigest(),
            sha256=hashlib.sha256(content).hexdigest(),
            magic_bytes=magic[:32],
            file_type=file_type,
            entropy=self._calculate_entropy(content)
        )
    
    def _detect_file_type(self, magic: bytes) -> str:
        """Detect file type from magic bytes"""
        if magic[:2] == b'MZ':
            return 'PE32 executable (Windows)'
        elif magic[:4] == b'\x7fELF':
            arch = 'x64' if magic[4] == 2 else 'x86'
            return f'ELF {arch} executable (Linux)'
        elif magic[:4] == b'\xca\xfe\xba\xbe':
            return 'Mach-O executable (macOS)'
        elif magic[:2] == b'PK':
            return 'ZIP archive'
        elif magic[:6] == b'Rar!\x1a\x07':
            return 'RAR archive'
        elif magic[:3] == b'\x1f\x8b\x08':
            return 'GZIP archive'
        elif magic[:4] == b'%PDF':
            return 'PDF document'
        elif magic[:5] == b'{\\rtf':
            return 'RTF document'
        elif len(magic) >= 8 and magic[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
            return 'Microsoft Office document'
        else:
            # Check if it's text/script
            try:
                magic.decode('utf-8')
                if magic.startswith(b'#!'):
                    return 'Script file'
                return 'Text file'
            except:
                return 'Unknown binary'
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        byte_counts = Counter(data)
        length = len(data)
        
        entropy = 0.0
        for count in byte_counts.values():
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        
        return round(entropy, 4)
    
    def _analyze_pe(self, content: bytes) -> PEInfo:
        """Analyze PE file structure"""
        if len(content) < 64 or content[:2] != b'MZ':
            return PEInfo()
        
        try:
            # Get PE header offset
            pe_offset = struct.unpack('<I', content[60:64])[0]
            
            if pe_offset + 24 > len(content):
                return PEInfo()
            
            # Check PE signature
            if content[pe_offset:pe_offset+4] != b'PE\x00\x00':
                return PEInfo()
            
            # Parse COFF header
            machine = struct.unpack('<H', content[pe_offset+4:pe_offset+6])[0]
            timestamp = struct.unpack('<I', content[pe_offset+8:pe_offset+12])[0]
            characteristics = struct.unpack('<H', content[pe_offset+22:pe_offset+24])[0]
            
            machine_types = {
                0x14c: 'i386',
                0x8664: 'AMD64',
                0x1c0: 'ARM',
                0xaa64: 'ARM64'
            }
            
            # Find imports (simplified)
            imports = []
            suspicious = []
            
            # Search for DLL names in content
            dll_pattern = rb'[A-Za-z0-9_]+\.dll'
            dlls = set(re.findall(dll_pattern, content, re.IGNORECASE))
            imports = [dll.decode() for dll in dlls][:20]
            
            # Find suspicious imports
            for func in self.SUSPICIOUS_IMPORTS:
                if func.encode() in content:
                    suspicious.append(func)
            
            return PEInfo(
                is_pe=True,
                machine=machine_types.get(machine, f'Unknown ({hex(machine)})'),
                timestamp=datetime.fromtimestamp(timestamp).isoformat() if timestamp > 0 else 'Invalid',
                dll=(characteristics & 0x2000) != 0,
                imports=imports,
                suspicious_imports=suspicious[:20]
            )
            
        except Exception as e:
            logger.error(f"PE parsing error: {e}")
            return PEInfo()
    
    def _analyze_elf(self, content: bytes) -> ELFInfo:
        """Analyze ELF file structure"""
        if len(content) < 52 or content[:4] != b'\x7fELF':
            return ELFInfo()
        
        try:
            # ELF class (32/64 bit)
            elf_class = content[4]
            is_64 = elf_class == 2
            
            # Architecture
            arch = 'x86_64' if is_64 else 'x86'
            
            # ABI
            abi_map = {0: 'UNIX/None', 3: 'Linux', 6: 'Solaris'}
            abi = abi_map.get(content[7], f'Unknown ({content[7]})')
            
            # Type
            elf_type = struct.unpack('<H', content[16:18])[0]
            type_map = {1: 'Relocatable', 2: 'Executable', 3: 'Shared object', 4: 'Core'}
            
            # Entry point
            if is_64:
                entry = struct.unpack('<Q', content[24:32])[0]
            else:
                entry = struct.unpack('<I', content[24:28])[0]
            
            return ELFInfo(
                is_elf=True,
                arch=arch,
                abi=abi,
                type=type_map.get(elf_type, f'Unknown ({elf_type})'),
                entry_point=hex(entry)
            )
            
        except Exception as e:
            logger.error(f"ELF parsing error: {e}")
            return ELFInfo()
    
    def _analyze_strings(self, content: bytes) -> StringsAnalysis:
        """Extract and analyze strings from binary"""
        # Extract printable strings (min 4 chars)
        ascii_strings = re.findall(rb'[\x20-\x7e]{4,}', content)
        strings = [s.decode('ascii', errors='ignore') for s in ascii_strings]
        
        # Unicode strings
        unicode_strings = re.findall(rb'(?:[\x20-\x7e]\x00){4,}', content)
        strings.extend([s.decode('utf-16-le', errors='ignore') for s in unicode_strings])
        
        analysis = StringsAnalysis(total_count=len(strings))
        
        # URLs
        url_pattern = r'https?://[^\s<>"\'{}|\\^`\[\]]+' 
        analysis.urls = list(set(re.findall(url_pattern, ' '.join(strings))))[:20]
        
        # IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        analysis.ips = list(set(re.findall(ip_pattern, ' '.join(strings))))[:20]
        
        # Domains
        domain_pattern = r'\b[a-zA-Z0-9][a-zA-Z0-9-]{0,61}\.[a-zA-Z]{2,}\b'
        potential_domains = re.findall(domain_pattern, ' '.join(strings))
        analysis.domains = list(set([d for d in potential_domains if '.' in d and not d[0].isdigit()]))[:20]
        
        # File paths
        path_patterns = [
            r'[A-Za-z]:\\[^\s<>"\']+',  # Windows
            r'/(?:usr|var|tmp|home|etc|bin|opt)[^\s<>"\']*',  # Linux
        ]
        for pattern in path_patterns:
            analysis.file_paths.extend(re.findall(pattern, ' '.join(strings)))
        analysis.file_paths = list(set(analysis.file_paths))[:20]
        
        # Registry keys
        reg_pattern = r'HKEY_[A-Z_]+\\[^\s<>"\']+|Software\\[^\s<>"\']+'
        analysis.registry_keys = list(set(re.findall(reg_pattern, ' '.join(strings), re.IGNORECASE)))[:20]
        
        # Suspicious strings  
        for string in strings:
            lower = string.lower()
            for sus in self.SUSPICIOUS_STRINGS:
                if sus in lower and string not in analysis.suspicious:
                    analysis.suspicious.append(string[:100])
                    if len(analysis.suspicious) >= 30:
                        break
        
        # Base64 detection
        b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        potential_b64 = re.findall(b64_pattern, ' '.join(strings))
        for b in potential_b64[:10]:
            if len(b) >= 20 and len(b) % 4 == 0:
                analysis.base64_encoded.append(b[:50] + '...' if len(b) > 50 else b)
        
        return analysis
    
    def _analyze_behavior(self, content: bytes, strings: StringsAnalysis, 
                          pe_info: PEInfo) -> BehaviorIndicators:
        """Analyze behavioral indicators"""
        behavior = BehaviorIndicators()
        
        # Network capability
        network_indicators = ['socket', 'connect', 'send', 'recv', 'http', 'https', 'ftp']
        if any(ind.encode() in content.lower() for ind in network_indicators) or strings.urls or strings.ips:
            behavior.network_capability = True
            behavior.indicators.append("Network communication capability detected")
        
        # File operations
        file_indicators = ['createfile', 'writefile', 'deletefile', 'fopen', 'fwrite']
        if any(ind.encode() in content.lower() for ind in file_indicators):
            behavior.file_operations = True
            behavior.indicators.append("File manipulation capability detected")
        
        # Process manipulation
        if pe_info.is_pe and any(s in pe_info.suspicious_imports for s in 
                                  ['VirtualAlloc', 'WriteProcessMemory', 'CreateRemoteThread']):
            behavior.process_manipulation = True
            behavior.indicators.append("Process injection capability detected")
        
        # Registry access
        if strings.registry_keys:
            behavior.registry_access = True
            behavior.indicators.append("Registry access detected")
        
        # Crypto capability
        crypto_indicators = ['crypt', 'encrypt', 'decrypt', 'aes', 'rsa', 'cipher']
        if any(ind.encode() in content.lower() for ind in crypto_indicators):
            behavior.crypto_capability = True
            behavior.indicators.append("Cryptographic capability detected")
        
        # Anti-analysis
        anti_indicators = ['isdebuggerpresent', 'checkremote', 'gettickcount', 'sleep']
        if any(ind.encode() in content.lower() for ind in anti_indicators):
            behavior.anti_analysis = True
            behavior.indicators.append("Anti-analysis techniques detected")
        
        # Command execution
        cmd_indicators = ['cmd.exe', 'powershell', '/bin/sh', '/bin/bash', 'system(', 'exec(']
        if any(ind.encode() in content for ind in cmd_indicators):
            behavior.command_execution = True
            behavior.indicators.append("Command execution capability detected")
        
        # Data exfil
        if behavior.network_capability and (strings.suspicious or behavior.crypto_capability):
            behavior.data_exfiltration = True
            behavior.indicators.append("Potential data exfiltration capability")
        
        return behavior
    
    def _calculate_threat_score(self, file_info: FileInfo, pe_info: PEInfo,
                                elf_info: ELFInfo, strings: StringsAnalysis,
                                behavior: BehaviorIndicators) -> int:
        """Calculate overall threat score (0-100)"""
        score = 0
        
        # High entropy (possible packing/encryption)
        if file_info.entropy > 7.0:
            score += 20
        elif file_info.entropy > 6.5:
            score += 10
        
        # Suspicious imports
        if pe_info.suspicious_imports:
            score += min(len(pe_info.suspicious_imports) * 3, 25)
        
        # Network indicators
        if strings.urls:
            score += 10
        if strings.ips:
            score += 5
        
        # Suspicious strings
        score += min(len(strings.suspicious) * 2, 20)
        
        # Behavior indicators
        if behavior.process_manipulation:
            score += 15
        if behavior.command_execution:
            score += 10
        if behavior.anti_analysis:
            score += 10
        if behavior.crypto_capability:
            score += 5
        if behavior.data_exfiltration:
            score += 10
        
        return min(score, 100)
    
    def _get_verdict(self, score: int) -> str:
        """Get verdict based on threat score"""
        if score >= 70:
            return "MALICIOUS"
        elif score >= 40:
            return "SUSPICIOUS"
        elif score >= 20:
            return "POTENTIALLY_UNWANTED"
        else:
            return "CLEAN"
    
    def _map_mitre_techniques(self, behavior: BehaviorIndicators) -> List[Dict]:
        """Map behaviors to MITRE ATT&CK techniques"""
        techniques = []
        
        if behavior.process_manipulation:
            techniques.append({
                "id": "T1055",
                "name": "Process Injection",
                "tactic": "Defense Evasion"
            })
        
        if behavior.command_execution:
            techniques.append({
                "id": "T1059",
                "name": "Command and Scripting Interpreter", 
                "tactic": "Execution"
            })
        
        if behavior.network_capability:
            techniques.append({
                "id": "T1071",
                "name": "Application Layer Protocol",
                "tactic": "Command and Control"
            })
        
        if behavior.anti_analysis:
            techniques.append({
                "id": "T1497",
                "name": "Virtualization/Sandbox Evasion",
                "tactic": "Defense Evasion"
            })
        
        if behavior.crypto_capability:
            techniques.append({
                "id": "T1486",
                "name": "Data Encrypted for Impact",
                "tactic": "Impact"
            })
        
        if behavior.data_exfiltration:
            techniques.append({
                "id": "T1041",
                "name": "Exfiltration Over C2 Channel",
                "tactic": "Exfiltration"
            })
        
        return techniques
    
    def _save_report(self, report: Dict, file_hash: str):
        """Save analysis report"""
        report_path = Path(self.reports_dir) / f"{file_hash[:16]}_analysis.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        logger.info(f"Report saved: {report_path}")


def analyze_file(path: str) -> Dict:
    """Convenience function for analyzing a file"""
    analyzer = FileAnalyzer()
    return analyzer.analyze(path)


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python analyzer.py <file_path>")
        sys.exit(1)
    
    result = analyze_file(sys.argv[1])
    print(json.dumps(result, indent=2))
