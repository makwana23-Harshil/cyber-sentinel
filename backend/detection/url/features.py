import re
from urllib.parse import urlparse
import tldextract

PHISH_WORDS = ['login', 'signin', 'account', 'secure', 'verify', 'update',
               'confirm', 'bank', 'paypal', 'ebay', 'amazon', 'apple',
               'microsoft', 'google', 'facebook', 'urgent', 'suspended']

SUSPICIOUS_TLDS = ['.xyz', '.top', '.club', '.work', '.click', '.link',
                    '.online', '.site', '.ru', '.cn', '.tk', '.ml', '.ga', '.cf']

IP_PATTERN = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')


def extract_url_features(url: str) -> list:
    """15 numerical features from a URL, in a fixed, documented order."""
    if not url.startswith('http'):
        url = 'http://' + url
    parsed = urlparse(url)
    ext = tldextract.extract(url)

    features = []
    features.append(len(url))                                                       # 1  length
    features.append(url.count('.'))                                                 # 2  dot count
    features.append(1 if parsed.scheme == 'https' else 0)                          # 3  HTTPS
    features.append(1 if IP_PATTERN.search(url) else 0)                            # 4  raw IP in URL
    special_chars = sum(url.count(c) for c in ['@', '!', '#', '$', '%', '^', '&', '*'])
    features.append(special_chars)                                                  # 5  special chars
    features.append(len(ext.subdomain.split('.')) if ext.subdomain else 0)         # 6  subdomain count
    features.append(1 if '@' in url else 0)                                        # 7  @ symbol
    features.append(1 if '//' in parsed.path else 0)                               # 8  double slash in path
    features.append(sum(1 for w in PHISH_WORDS if w in url.lower()))               # 9  phishing keywords
    features.append(len(ext.domain) if ext.domain else 0)                          # 10 domain length
    features.append(len(parsed.path))                                              # 11 path length
    features.append(ext.domain.count('-') if ext.domain else 0)                    # 12 dashes in domain
    features.append(1 if ext.domain and any(c.isdigit() for c in ext.domain) else 0)  # 13 digits in domain
    features.append(len(parsed.query))                                             # 14 query length
    features.append(1 if any(url.lower().endswith(t) for t in SUSPICIOUS_TLDS) else 0)  # 15 suspicious TLD
    return features


def build_url_notes(url: str, features: list) -> list:
    """Human-readable explanation of which lexical signals fired."""
    notes = []
    if features[2] == 0:
        notes.append('No HTTPS protocol')
    if features[3] == 1:
        notes.append('URL contains raw IP address')
    if features[6] == 1:
        notes.append('@ symbol in URL — potential misdirection')
    if features[8] > 2:
        notes.append(f'{int(features[8])} phishing-related keywords in URL')
    if features[1] > 5:
        notes.append(f'Many dots ({int(features[1])}) in URL — possible subdomain abuse')
    if features[14] == 1:
        notes.append('Suspicious top-level domain (TLD)')
    if features[11] > 0:
        notes.append(f'{int(features[11])} dashes in domain name')
    if not notes:
        notes.append('Lexical URL structure is standard')
    return notes
