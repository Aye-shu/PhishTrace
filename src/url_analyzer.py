"""
URL Analyzer - Detects basic phishing indicators in URLs.
Part of PhishTrace project.
"""

from urllib.parse import urlparse
import re


def analyze_url(url):
    """
    Analyze a URL for phishing indicators.
    
    Returns:
        dict: Contains 'score', 'reasons', and 'verdict'
    """
    score = 0
    reasons = []
    
    # Parse the URL
    parsed = urlparse(url)
    hostname = parsed.netloc
    
    # Check 1: IP address instead of domain name
    if re.match(r'\d+\.\d+\.\d+\.\d+', hostname):
        score += 30
        reasons.append("Uses IP address instead of domain name")
    
    # Check 2: Suspicious top-level domains
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.buzz']
    if any(tld in url.lower() for tld in suspicious_tlds):
        score += 20
        reasons.append("Suspicious top-level domain")
    
    # Check 3: Too many hyphens
    if url.count('-') > 3:
        score += 15
        reasons.append("Too many hyphens in URL")
    
    # Check 4: @ symbol (can hide real destination)
    if '@' in url:
        score += 25
        reasons.append("Contains @ symbol (can hide real destination)")
    
    # Check 5: Long URL
    if len(url) > 75:
        score += 10
        reasons.append("URL is unusually long")
    
    # Check 6: Phishing keywords
    keywords = ['login', 'verify', 'account', 'secure', 'update', 
                'banking', 'confirm', 'password', 'signin']
    found_keywords = [kw for kw in keywords if kw in url.lower()]
    if found_keywords:
        score += 10
        reasons.append(f"Contains phishing keywords: {', '.join(found_keywords)}")
    
    # Determine verdict
    if score >= 50:
        verdict = "PHISHING"
    elif score >= 25:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"
    
    return {
        "url": url,
        "score": score,
        "reasons": reasons,
        "verdict": verdict
    }


def print_report(result):
    """Print a formatted analysis report."""
    print("=" * 50)
    print("PHISHTRACE URL ANALYSIS")
    print("=" * 50)
    print(f"URL: {result['url']}")
    print(f"Risk Score: {result['score']}/100")
    print(f"Verdict: {result['verdict']}")
    print("-" * 50)
    print("Reasons:")
    for reason in result['reasons']:
        print(f"  - {reason}")
    print("=" * 50)


# Test the analyzer
if __name__ == "__main__":
    # Safe URL
    print("\n--- Testing Safe URL ---")
    result = analyze_url("https://www.google.com")
    print_report(result)
    
    # Suspicious URL
    print("\n--- Testing Suspicious URL ---")
    result = analyze_url("http://192.168.1.1/login/verify-account.php")
    print_report(result)
    
    # Phishing URL
    print("\n--- Testing Phishing URL ---")
    result = analyze_url(
        "http://secure-login-verify.tk/account/update?user=admin@bank.com"
    )
    print_report(result)