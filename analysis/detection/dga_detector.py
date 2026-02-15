"""
C2Trap DGA (Domain Generation Algorithm) Detector
Detects algorithmically generated domains used by advanced malware.

Techniques used:
1. Character frequency analysis (consonant-vowel ratio)
2. Bigram (2-char pair) frequency scoring
3. Shannon entropy of domain name
4. Domain length analysis
5. Digit ratio analysis

Real domains: "google", "amazon", "facebook" — natural language patterns
DGA domains:  "xk4mf9q2z", "brdtn7kp" — random character distribution
"""

import math
import logging
import os
import json
from datetime import datetime
from collections import Counter
from typing import Dict, Tuple, List, Optional

logger = logging.getLogger("c2trap.dga")

LOG_PATH = os.environ.get('LOG_PATH', '/app/logs/analysis_queue.jsonl')


def log_event(event_type: str, data: dict) -> None:
    """Write event to analysis queue"""
    event = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'source': 'dga_detector',
        'event_type': event_type,
        'data': data
    }
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, 'a') as f:
            f.write(json.dumps(event) + '\n')
    except Exception:
        pass


class DGADetector:
    """
    Detect Domain Generation Algorithm (DGA) domains.
    
    DGA is used by malware families like:
    - Conficker (generates 50,000 domains/day)
    - CryptoLocker (1,000 domains/day)
    - Emotet, TrickBot, Dridex
    
    Our approach uses statistical analysis without ML,
    making it lightweight and deterministic.
    """

    VOWELS = set('aeiou')
    CONSONANTS = set('bcdfghjklmnpqrstvwxyz')

    # Common English bigrams (letter pairs) — real domains use these frequently
    COMMON_BIGRAMS = {
        'th', 'he', 'in', 'er', 'an', 'on', 'en', 'at', 'es', 'ed',
        'or', 'te', 'of', 'it', 'is', 'al', 'ar', 'st', 'to', 'nd',
        'ha', 're', 'ou', 'se', 'le', 'ce', 'el', 'li', 'ne', 'de',
        'ma', 'co', 'ca', 'ta', 'ti', 'io', 'si', 'om', 'oo', 'go',
        'am', 'ap', 'bo', 'ch', 'cl', 'cr', 'do', 'fa', 'fi', 'fo',
    }

    # Known legitimate TLDs that are commonly used by DGA
    SUSPICIOUS_TLDS = {
        'tk', 'ml', 'ga', 'cf', 'gq',  # Free TLDs often used by DGA
        'xyz', 'top', 'club', 'online', 'site', 'icu', 'buzz'
    }

    def __init__(self, threshold: float = 0.65):
        """
        Args:
            threshold: Score above which a domain is flagged as DGA (0-1)
        """
        self.threshold = threshold
        self.detected_dga: List[dict] = []
        self.cache: Dict[str, float] = {}  # domain -> score cache

    def analyze(self, domain: str) -> Tuple[float, bool, dict]:
        """
        Analyze a domain for DGA characteristics.
        
        Returns:
            (score, is_dga, details)
            score: 0.0 (definitely legitimate) to 1.0 (definitely DGA)
        """
        if not domain:
            return 0.0, False, {}

        # Extract the second-level domain (e.g., "xk4mf9" from "xk4mf9.evil.com")
        parts = domain.lower().strip('.').split('.')
        if len(parts) < 2:
            return 0.0, False, {}

        sld = parts[-2]  # Second-level domain
        tld = parts[-1]

        # Check cache
        if domain in self.cache:
            score = self.cache[domain]
            return score, score >= self.threshold, {'cached': True}

        # Skip very short domains
        if len(sld) < 4:
            return 0.0, False, {'reason': 'too_short'}

        # === Scoring Components ===
        scores = {}

        # 1. Entropy Score (0-1)
        entropy = self._shannon_entropy(sld)
        max_entropy = math.log2(26)  # ~4.7 for uniform lowercase
        entropy_score = min(1.0, entropy / max_entropy)
        scores['entropy'] = round(entropy_score, 3)

        # 2. Consonant-Vowel Ratio (0-1)
        cv_score = self._consonant_vowel_score(sld)
        scores['consonant_vowel'] = round(cv_score, 3)

        # 3. Bigram Frequency (0-1)
        bigram_score = self._bigram_score(sld)
        scores['bigram'] = round(bigram_score, 3)

        # 4. Length Score (0-1) — DGA domains tend to be longer
        length_score = min(1.0, max(0.0, (len(sld) - 6) / 20))
        scores['length'] = round(length_score, 3)

        # 5. Digit Ratio (0-1) — DGA domains often contain numbers
        digit_count = sum(1 for c in sld if c.isdigit())
        digit_score = digit_count / len(sld) if sld else 0
        scores['digit_ratio'] = round(digit_score, 3)

        # 6. Suspicious TLD bonus
        tld_bonus = 0.1 if tld in self.SUSPICIOUS_TLDS else 0.0
        scores['tld_bonus'] = tld_bonus

        # === Weighted Final Score ===
        final_score = (
            entropy_score * 0.25 +
            cv_score * 0.25 +
            bigram_score * 0.25 +
            length_score * 0.10 +
            digit_score * 0.15 +
            tld_bonus
        )
        final_score = min(1.0, max(0.0, final_score))

        # Cache result
        self.cache[domain] = final_score

        is_dga = final_score >= self.threshold

        details = {
            'domain': domain,
            'sld': sld,
            'score': round(final_score, 3),
            'is_dga': is_dga,
            'components': scores
        }

        if is_dga:
            details['mitre_technique'] = 'T1568.002'  # DGA
            self.detected_dga.append(details)
            logger.warning(
                f"[DGA] Suspicious domain: {domain} "
                f"(score: {final_score:.2f}, entropy: {entropy:.2f})"
            )
            log_event('dga_detected', details)

        return final_score, is_dga, details

    def _shannon_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0.0
        counts = Counter(text)
        length = len(text)
        entropy = 0.0
        for count in counts.values():
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy

    def _consonant_vowel_score(self, text: str) -> float:
        """
        Score based on consonant-to-vowel ratio.
        Natural language: ~60% consonants, ~40% vowels
        DGA: often 80%+ consonants or random distribution
        """
        alpha_chars = [c for c in text.lower() if c.isalpha()]
        if not alpha_chars:
            return 0.5

        vowel_count = sum(1 for c in alpha_chars if c in self.VOWELS)
        vowel_ratio = vowel_count / len(alpha_chars)

        # Ideal ratio is ~0.35-0.45
        # Score how far from ideal
        ideal = 0.40
        deviation = abs(vowel_ratio - ideal)

        # Also check for consecutive consonants (unnatural)
        max_consecutive = 0
        current = 0
        for c in text.lower():
            if c in self.CONSONANTS:
                current += 1
                max_consecutive = max(max_consecutive, current)
            else:
                current = 0

        consecutive_score = min(1.0, max_consecutive / 5)

        return min(1.0, deviation * 2 + consecutive_score * 0.3)

    def _bigram_score(self, text: str) -> float:
        """
        Score based on bigram (2-char pair) frequency.
        Real words use common pairs like "th", "er", "in".
        DGA domains use rare pairs like "qz", "xk", "jf".
        """
        if len(text) < 2:
            return 0.5

        bigrams = [text[i:i+2] for i in range(len(text) - 1)]
        common_count = sum(1 for bg in bigrams if bg in self.COMMON_BIGRAMS)
        common_ratio = common_count / len(bigrams)

        # Invert: low common ratio = high DGA score
        return 1.0 - common_ratio

    def get_stats(self) -> dict:
        """Get detection statistics"""
        return {
            'total_analyzed': len(self.cache),
            'dga_detected': len(self.detected_dga),
            'cache_size': len(self.cache)
        }


# Singleton
dga_detector = DGADetector()


if __name__ == '__main__':
    detector = DGADetector()

    print("=" * 60)
    print("  C2Trap DGA Detector — Test Suite")
    print("=" * 60)

    # Test domains
    test_domains = [
        # Legitimate
        ("google.com", False),
        ("amazon.com", False),
        ("stackoverflow.com", False),
        ("github.com", False),
        ("microsoft.com", False),
        # DGA-like
        ("xk4mf9q2z.com", True),
        ("brdtn7kp.tk", True),
        ("qwzxjfm.xyz", True),
        ("a8d3f7k2m9.net", True),
        ("jklm4nop8rst.club", True),
        # Edge cases
        ("t.co", False),         # Short (Twitter)
        ("fb.com", False),       # Short (Facebook)
    ]

    correct = 0
    total = 0

    for domain, expected_dga in test_domains:
        score, is_dga, details = detector.analyze(domain)
        status = "✅" if is_dga == expected_dga else "❌"
        if is_dga == expected_dga:
            correct += 1
        total += 1

        label = "DGA" if is_dga else "LEGIT"
        print(f"  {status} {domain:30s} Score: {score:.3f}  [{label}]")

    print(f"\n  Accuracy: {correct}/{total} ({correct/total*100:.0f}%)")
    print()
