"""
Improved Feature Extractor for PhishTrace.
Converts raw URL strings into features the ML model expects.
Implements as many features as possible without external APIs.
"""

import re
from urllib.parse import urlparse, parse_qs
import tldextract

# Known URL shorteners
SHORTENERS = [
    'bit.ly', 'goo.gl', 'tinyurl', 'ow.ly', 't.co', 'is.gd',
    'buff.ly', 'adf.ly', 'bit.do', 'mcaf.ee', 'su.pr', 'twurl.nl'
]

# Suspicious TLDs
SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.buzz', '.click', '.link']

# Phishing keywords
PHISHING_WORDS = [
    'login', 'signin', 'verify', 'account', 'update', 'secure',
    'banking', 'confirm', 'password', 'credential', 'alert', 'suspend'
]


def extract_features(url):
    """
    Extract 30 features from a raw URL.
    Returns a list of numeric values in the exact order the model expects.
    """
    # Normalize URL
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    parsed = urlparse(url)
    hostname = parsed.netloc
    path = parsed.path
    query = parsed.query
    full_url = url

    # Domain extraction
    extracted = tldextract.extract(url)
    domain = extracted.domain or ''
    subdomain = extracted.subdomain or ''
    suffix = extracted.suffix or ''

    f = {}  # features dict

    # 1. having_IP_Address: -1 if IP, 1 if not
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$'
    f['having_IP_Address'] = -1 if re.match(ip_pattern, hostname) else 1

    # 2. URL_Length: 1 if <54, 0 if 54-75, -1 if >75
    length = len(full_url)
    if length < 54:
        f['URL_Length'] = 1
    elif length <= 75:
        f['URL_Length'] = 0
    else:
        f['URL_Length'] = -1

    # 3. Shortining_Service: -1 if shortener, 1 otherwise
    f['Shortining_Service'] = -1 if any(s in hostname.lower() for s in SHORTENERS) else 1

    # 4. having_At_Symbol: -1 if @ present, 1 otherwise
    f['having_At_Symbol'] = -1 if '@' in full_url else 1

    # 5. double_slash_redirecting: -1 if // in path, 1 otherwise
    f['double_slash_redirecting'] = -1 if '//' in path else 1

    # 6. Prefix_Suffix: -1 if hyphen in domain, 1 otherwise
    f['Prefix_Suffix'] = -1 if '-' in domain else 1

    # 7. having_Sub_Domain: 1 if none, 0 if one, -1 if multiple
    subdomain_parts = [p for p in subdomain.split('.') if p]
    if len(subdomain_parts) == 0:
        f['having_Sub_Domain'] = 1
    elif len(subdomain_parts) == 1:
        f['having_Sub_Domain'] = 0
    else:
        f['having_Sub_Domain'] = -1

    # 8. SSLfinal_State: 
    #   1 = HTTPS, 0 = HTTP but domain looks normal, -1 = HTTP + suspicious
    if parsed.scheme == 'https':
        f['SSLfinal_State'] = 1
    else:
        # Check if domain looks suspicious (IP, suspicious TLD, keywords)
        is_suspicious = (
            re.match(ip_pattern, hostname) or
            any(tld in suffix.lower() for tld in SUSPICIOUS_TLDS) or
            any(word in domain.lower() for word in PHISHING_WORDS)
        )
        f['SSLfinal_State'] = -1 if is_suspicious else 0

    # 9. Domain_registeration_length: 
    #   Cannot check WHOIS without API. Use heuristic.
    #   -1 if suspicious TLD or very short domain, else 1
    if any(tld in suffix.lower() for tld in SUSPICIOUS_TLDS):
        f['Domain_registeration_length'] = -1
    elif len(domain) < 3:
        f['Domain_registeration_length'] = -1
    else:
        f['Domain_registeration_length'] = 1

    # 10. Favicon: Cannot check without HTTP request. Heuristic:
    #     -1 if domain contains phishing words
    if any(word in domain.lower() for word in PHISHING_WORDS):
        f['Favicon'] = -1
    else:
        f['Favicon'] = 1

    # 11. port: -1 if non-standard port, 1 otherwise
    if ':' in hostname:
        try:
            port = int(hostname.split(':')[1])
            f['port'] = 1 if port in (80, 443) else -1
        except:
            f['port'] = 1
    else:
        f['port'] = 1

    # 12. HTTPS_token: -1 if 'https' in domain name (trick), 1 otherwise
    f['HTTPS_token'] = -1 if 'https' in domain.lower() else 1

    # 13. Request_URL: Cannot check without HTML. Heuristic:
    #     -1 if URL has many external-looking resources or query params
    if len(parse_qs(query)) > 3:
        f['Request_URL'] = -1
    else:
        f['Request_URL'] = 1

    # 14. URL_of_Anchor: Cannot check without HTML. Heuristic: 1
    f['URL_of_Anchor'] = 1

    # 15. Links_in_tags: Cannot check without HTML. Heuristic: 1
    f['Links_in_tags'] = 1

    # 16. SFH: (Server Form Handler) Cannot check. Heuristic:
    #     -1 if 'mailto:' appears in URL
    f['SFH'] = -1 if 'mailto:' in full_url.lower() else 1

    # 17. Submitting_to_email: -1 if mailto:, 1 otherwise
    f['Submitting_to_email'] = -1 if 'mailto:' in full_url.lower() else 1

    # 18. Abnormal_URL: -1 if URL structure is unusual
    #     Heuristic: -1 if domain not in URL hostname (spoofing) or double protocol
    abnormal = False
    if full_url.count('http') > 1:
        abnormal = True
    if '//' in path:
        abnormal = True
    f['Abnormal_URL'] = -1 if abnormal else 1

    # 19. Redirect: -1 if multiple redirect indicators
    redirect_indicators = ['redirect', 'url=', 'next=', 'goto=', 'return=']
    if sum(1 for r in redirect_indicators if r in full_url.lower()) >= 2:
        f['Redirect'] = -1
    elif any(r in full_url.lower() for r in redirect_indicators):
        f['Redirect'] = 0
    else:
        f['Redirect'] = 1

    # 20. on_mouseover: Cannot check without HTML. Heuristic: 1
    f['on_mouseover'] = 1

    # 21. RightClick: Cannot check without HTML. Heuristic: 1
    f['RightClick'] = 1

    # 22. popUpWidnow: Cannot check without HTML. Heuristic: 1
    f['popUpWidnow'] = 1

    # 23. Iframe: Cannot check without HTML. Heuristic: 1
    f['Iframe'] = 1

    # 24. age_of_domain: Cannot check WHOIS. Heuristic based on TLD
    if any(tld in suffix.lower() for tld in SUSPICIOUS_TLDS):
        f['age_of_domain'] = -1
    else:
        f['age_of_domain'] = 1

    # 25. DNSRecord: Cannot check DNS here. Heuristic based on IP pattern
    if re.match(ip_pattern, hostname):
        f['DNSRecord'] = -1
    else:
        f['DNSRecord'] = 1

    # 26. web_traffic: Cannot check Alexa. Heuristic:
    #     -1 if suspicious TLD, else 1
    if any(tld in suffix.lower() for tld in SUSPICIOUS_TLDS):
        f['web_traffic'] = -1
    else:
        f['web_traffic'] = 1

    # 27. Page_Rank: Cannot check. Heuristic based on domain length
    if len(domain) < 4 or any(tld in suffix.lower() for tld in SUSPICIOUS_TLDS):
        f['Page_Rank'] = -1
    else:
        f['Page_Rank'] = 1

    # 28. Google_Index: Cannot check. Heuristic: 1
    f['Google_Index'] = 1

    # 29. Links_pointing_to_page: Cannot check. Heuristic: 1
    f['Links_pointing_to_page'] = 1

    # 30. Statistical_report: -1 if URL matches known phishing patterns
    suspicious_count = 0
    if re.match(ip_pattern, hostname):
        suspicious_count += 1
    if any(tld in suffix.lower() for tld in SUSPICIOUS_TLDS):
        suspicious_count += 1
    if any(word in full_url.lower() for word in PHISHING_WORDS):
        suspicious_count += 1
    if '@' in full_url:
        suspicious_count += 1

    f['Statistical_report'] = -1 if suspicious_count >= 3 else 1

    # Return in the exact order the model expects
    return [f[name] for name in FEATURE_ORDER]


# Exact feature order from training data
FEATURE_ORDER = [
    'having_IP_Address', 'URL_Length', 'Shortining_Service', 'having_At_Symbol',
    'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain', 'SSLfinal_State',
    'Domain_registeration_length', 'Favicon', 'port', 'HTTPS_token',
    'Request_URL', 'URL_of_Anchor', 'Links_in_tags', 'SFH',
    'Submitting_to_email', 'Abnormal_URL', 'Redirect', 'on_mouseover',
    'RightClick', 'popUpWidnow', 'Iframe', 'age_of_domain',
    'DNSRecord', 'web_traffic', 'Page_Rank', 'Google_Index',
    'Links_pointing_to_page', 'Statistical_report'
]


if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "https://github.com",
        "http://192.168.1.1/login/verify",
        "http://secure-login-verify.tk/account/update?user=admin@bank.com",
    ]

    for url in test_urls:
        print(f"\nURL: {url}")
        features = extract_features(url)
        print(f"Features: {features}")