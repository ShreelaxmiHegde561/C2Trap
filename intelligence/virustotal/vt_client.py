"""
C2Trap VirusTotal Integration
Enrich IOCs with threat intelligence from VirusTotal
"""

import os
import json
import logging
import hashlib
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from pathlib import Path

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('vt_client')

LOG_PATH = os.environ.get('LOG_PATH', '/app/logs/analysis_queue.jsonl')
CACHE_PATH = os.environ.get('CACHE_PATH', '/app/data/ioc_cache')
VT_API_KEY = os.environ.get('VT_API_KEY', '')


def log_event(event_type: str, data: dict) -> None:
    """Write event to analysis queue"""
    event = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'source': 'virustotal',
        'event_type': event_type,
        'data': data
    }
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, 'a') as f:
            f.write(json.dumps(event) + '\n')
    except Exception as e:
        logger.error(f"Failed to write log: {e}")


class VTCache:
    """Simple file-based cache for VT results"""
    
    def __init__(self, cache_dir: str = CACHE_PATH, ttl_hours: int = 24):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl = timedelta(hours=ttl_hours)
    
    def _get_cache_key(self, ioc_type: str, ioc_value: str) -> str:
        """Generate cache key"""
        value_hash = hashlib.md5(ioc_value.encode()).hexdigest()
        return f"{ioc_type}_{value_hash}"
    
    def get(self, ioc_type: str, ioc_value: str) -> Optional[dict]:
        """Get cached result"""
        key = self._get_cache_key(ioc_type, ioc_value)
        cache_file = self.cache_dir / f"{key}.json"
        
        if not cache_file.exists():
            return None
        
        try:
            with open(cache_file, 'r') as f:
                data = json.load(f)
            
            # Check TTL
            cached_time = datetime.fromisoformat(data.get('cached_at', '2000-01-01'))
            if datetime.utcnow() - cached_time > self.ttl:
                cache_file.unlink()
                return None
            
            return data.get('result')
        except:
            return None
    
    def set(self, ioc_type: str, ioc_value: str, result: dict):
        """Cache a result"""
        key = self._get_cache_key(ioc_type, ioc_value)
        cache_file = self.cache_dir / f"{key}.json"
        
        try:
            with open(cache_file, 'w') as f:
                json.dump({
                    'cached_at': datetime.utcnow().isoformat(),
                    'ioc_type': ioc_type,
                    'ioc_value': ioc_value,
                    'result': result
                }, f)
        except Exception as e:
            logger.error(f"Cache write failed: {e}")


class VTClient:
    """VirusTotal API v3 Client"""
    
    def __init__(self, api_key: str = VT_API_KEY):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.cache = VTCache()
        self.rate_limit_delay = 15  # Free tier: 4 requests/min
        self.last_request_time = 0
        
        # Try to import requests
        try:
            import requests
            self.requests = requests
        except ImportError:
            logger.warning("requests library not available")
            self.requests = None
    
    def _rate_limit(self):
        """Enforce rate limiting"""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - elapsed)
        self.last_request_time = time.time()
    
    def _make_request(self, endpoint: str) -> Optional[dict]:
        """Make API request"""
        if not self.requests:
            return None
        
        if not self.api_key or self.api_key == 'your_api_key_here':
            logger.warning("VirusTotal API key not configured")
            return None
        
        self._rate_limit()
        
        headers = {"x-apikey": self.api_key}
        url = f"{self.base_url}/{endpoint}"
        
        try:
            response = self.requests.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return {"status": "not_found"}
            elif response.status_code == 429:
                logger.warning("VT rate limit exceeded")
                return None
            else:
                logger.error(f"VT API error: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"VT request failed: {e}")
            return None
    
    def lookup_ip(self, ip: str) -> Optional[dict]:
        """Look up IP reputation"""
        # Check cache
        cached = self.cache.get('ip', ip)
        if cached:
            logger.debug(f"Cache hit for IP: {ip}")
            return cached
        
        result = self._make_request(f"ip_addresses/{ip}")
        if not result:
            return None
        
        if result.get('status') == 'not_found':
            parsed = {
                'ip': ip,
                'status': 'no_data',
                'is_malicious': False,
                'threat_score': 0,
                'malicious': 0,
                'suspicious': 0
            }
        else:
            # Parse response
            data = result.get('data', {})
            attributes = data.get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            parsed = {
                'ip': ip,
                'country': attributes.get('country', 'unknown'),
                'asn': attributes.get('asn'),
                'as_owner': attributes.get('as_owner'),
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'reputation': attributes.get('reputation', 0),
                'is_malicious': stats.get('malicious', 0) > 0,
                'threat_score': self._calculate_threat_score(stats)
            }
        
        self.cache.set('ip', ip, parsed)
        
        if parsed['is_malicious']:
            log_event('malicious_ip_detected', {
                'ip': ip,
                'malicious_count': parsed['malicious'],
                'mitre_technique': 'T1071'
            })
        
        return parsed
    
    def lookup_domain(self, domain: str) -> Optional[dict]:
        """Look up domain reputation"""
        # Check cache
        cached = self.cache.get('domain', domain)
        if cached:
            return cached
        
        result = self._make_request(f"domains/{domain}")
        if not result:
            return None
            
        if result.get('status') == 'not_found':
            parsed = {
                'domain': domain,
                'status': 'no_data',
                'is_malicious': False,
                'threat_score': 0,
                'malicious': 0,
                'suspicious': 0
            }
        else:
            data = result.get('data', {})
            attributes = data.get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            parsed = {
                'domain': domain,
                'registrar': attributes.get('registrar'),
                'creation_date': attributes.get('creation_date'),
                'categories': attributes.get('categories', {}),
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'is_malicious': stats.get('malicious', 0) > 0,
                'threat_score': self._calculate_threat_score(stats)
            }
        
        self.cache.set('domain', domain, parsed)
        
        if parsed['is_malicious']:
            log_event('malicious_domain_detected', {
                'domain': domain,
                'malicious_count': parsed['malicious'],
                'mitre_technique': 'T1071'
            })
        
        return parsed
    
    def lookup_hash(self, file_hash: str) -> Optional[dict]:
        """Look up file hash"""
        # Check cache
        cached = self.cache.get('hash', file_hash)
        if cached:
            return cached
        
        result = self._make_request(f"files/{file_hash}")
        if not result:
            return None
            
        if result.get('status') == 'not_found':
            parsed = {
                'hash': file_hash,
                'status': 'no_data',
                'is_malicious': False,
                'threat_score': 0,
                'malicious': 0,
                'suspicious': 0
            }
        else:
            data = result.get('data', {})
            attributes = data.get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            parsed = {
                'hash': file_hash,
                'file_name': attributes.get('meaningful_name'),
                'file_type': attributes.get('type_description'),
                'size': attributes.get('size'),
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'is_malicious': stats.get('malicious', 0) > 0,
                'threat_score': self._calculate_threat_score(stats),
                'popular_threat_name': attributes.get('popular_threat_classification', {}).get('suggested_threat_label')
            }
        
        self.cache.set('hash', file_hash, parsed)
        
        if parsed['is_malicious']:
            log_event('malicious_file_detected', {
                'hash': file_hash,
                'threat_name': parsed['popular_threat_name'],
                'malicious_count': parsed['malicious']
            })
        
        return parsed
    
    def _calculate_threat_score(self, stats: dict) -> int:
        """Calculate threat score 0-100 with heavier weighting for hits"""
        if not stats:
            return 0
            
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        total = stats.get('malicious', 0) + stats.get('suspicious', 0) + \
                stats.get('harmless', 0) + stats.get('undetected', 0)
        
        if total == 0:
            return 0
            
        if malicious > 3:
            return 100
        if malicious > 0:
            return max(70, int((malicious / total) * 100) + 50)
        if suspicious > 2:
            return max(30, int((suspicious / total) * 100) + 20)
            
        return 0
    
    def enrich_ioc(self, ioc_type: str, ioc_value: str) -> Optional[dict]:
        """Generic IOC enrichment"""
        if ioc_type == 'ip':
            return self.lookup_ip(ioc_value)
        elif ioc_type == 'domain':
            return self.lookup_domain(ioc_value)
        elif ioc_type in ['md5', 'sha1', 'sha256', 'hash']:
            return self.lookup_hash(ioc_value)
        else:
            logger.warning(f"Unknown IOC type: {ioc_type}")
            return None


# Singleton instance
_client = None

def get_client() -> VTClient:
    global _client
    if _client is None:
        _client = VTClient()
    return _client


if __name__ == '__main__':
    client = VTClient()
    print(f"VT Client initialized")
    print(f"API Key configured: {bool(client.api_key and client.api_key != 'your_api_key_here')}")
