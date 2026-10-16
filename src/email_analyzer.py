"""
Email Analyzer for PhishTrace.
Parses .eml files and detects phishing indicators.
"""

import email
from email import policy
import re
import os
import sys

# Add src to path so we can import url_analyzer
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from url_analyzer_ml import predict_url
except ImportError:
    from src.url_analyzer_ml import predict_url


# Suspicious subject keywords
SUSPICIOUS_SUBJECT_WORDS = [
    'urgent', 'immediate', 'suspended', 'verify', 'account locked',
    'action required', 'warning', 'alert', 'confirm', 'unusual activity',
    'limited', 'restricted', 'security', 'unauthorized'
]

# Suspicious body phrases
URGENT_PHRASES = [
    'click here', 'verify your account', 'update your information',
    'confirm your identity', 'limited time', 'act now',
    'your account will be', 'failure to comply', 'within 24 hours',
    'immediately', 'urgent action', 'account has been',
    'unusual sign-in', 'suspicious activity', 'verify immediately'
]


def analyze_email(filepath):
    """
    Analyze an .eml file for phishing indicators.

    Args:
        filepath: Path to .eml file

    Returns:
        dict: Analysis results
    """
    if not os.path.exists(filepath):
        return {
            'input_type': 'Email',
            'filepath': filepath,
            'score': 0,
            'reasons': [f"File not found: {filepath}"],
            'verdict': 'ERROR',
            'urls_found': [],
            'url_analyses': []
        }

    # Load the email
    with open(filepath, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    result = {
        'input_type': 'Email',
        'filepath': filepath,
        'score': 0,
        'reasons': [],
        'verdict': 'UNKNOWN',
        'urls_found': [],
        'url_analyses': [],
        'headers': {},
        'has_attachments': False,
        'attachment_names': []
    }

    # Extract headers
    from_addr = msg['From'] or 'Unknown'
    reply_to = msg['Reply-To'] or ''
    return_path = msg['Return-Path'] or ''
    subject = msg['Subject'] or 'No subject'
    date = msg['Date'] or 'Unknown'

    result['headers'] = {
        'from': from_addr,
        'reply_to': reply_to,
        'return_path': return_path,
        'subject': subject,
        'date': date
    }

    result['from'] = from_addr
    result['reply_to'] = reply_to
    result['subject'] = subject

    score = 0
    reasons = []

    # CHECK 1: Reply-To differs from From
    if reply_to and from_addr:
        from_email = re.search(r'[\w\.-]+@[\w\.-]+', from_addr)
        reply_email = re.search(r'[\w\.-]+@[\w\.-]+', reply_to)
        if from_email and reply_email:
            if from_email.group() != reply_email.group():
                score += 20
                reasons.append(
                    f"Reply-To ({reply_email.group()}) differs from From ({from_email.group()})"
                )

    # CHECK 2: Return-Path mismatch
    if return_path and from_addr:
        rp_email = re.search(r'[\w\.-]+@[\w\.-]+', return_path)
        from_email = re.search(r'[\w\.-]+@[\w\.-]+', from_addr)
        if rp_email and from_email:
            if rp_email.group() != from_email.group():
                score += 15
                reasons.append("Return-Path differs from From address")

    # CHECK 3: Authentication results (SPF, DKIM, DMARC)
    headers_text = str(msg).lower()

    if 'spf=fail' in headers_text or 'spf=softfail' in headers_text:
        score += 25
        reasons.append("SPF authentication failed")

    if 'dkim=fail' in headers_text:
        score += 25
        reasons.append("DKIM authentication failed")

    if 'dmarc=fail' in headers_text:
        score += 30
        reasons.append("DMARC authentication failed")

    # CHECK 4: Suspicious subject
    for word in SUSPICIOUS_SUBJECT_WORDS:
        if word in subject.lower():
            score += 10
            reasons.append(f"Subject contains suspicious language: '{word}'")
            break

    # CHECK 5: Extract body
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))

            # Skip attachments
            if "attachment" in content_disposition:
                result['has_attachments'] = True
                filename = part.get_filename()
                if filename:
                    result['attachment_names'].append(filename)
                continue

            if content_type == 'text/plain':
                try:
                    body = part.get_content()
                except Exception:
                    pass
            elif content_type == 'text/html' and not body:
                try:
                    html = part.get_content()
                    body = re.sub(r'<[^>]+>', ' ', html)
                except Exception:
                    pass
    else:
        try:
            body = msg.get_content()
        except Exception:
            body = str(msg.get_payload())

    # CHECK 6: Suspicious body phrases
    found_phrases = [p for p in URGENT_PHRASES if p in body.lower()]
    if found_phrases:
        score += 15
        reasons.append(
            f"Contains suspicious phrases: {', '.join(found_phrases[:3])}"
        )

    # CHECK 7: Extract URLs
    url_pattern = r'https?://[^\s<>"\')\]]+'
    urls = re.findall(url_pattern, body)

    # Deduplicate and clean
    seen = set()
    unique_urls = []
    for url in urls:
        url = url.rstrip('.,;:!?')
        if url not in seen:
            seen.add(url)
            unique_urls.append(url)

    result['urls_found'] = unique_urls[:10]

    # CHECK 8: Analyze each URL
    for url in result['urls_found']:
        url_result = predict_url(url)
        result['url_analyses'].append(url_result)

        if url_result['verdict'] == 'PHISHING':
            score += 20
            reasons.append(f"Contains phishing URL: {url[:60]}...")
        elif url_result['verdict'] == 'SUSPICIOUS':
            score += 10
            reasons.append(f"Contains suspicious URL: {url[:60]}...")

    # CHECK 9: Suspicious attachments
    dangerous_extensions = ['.exe', '.scr', '.bat', '.cmd', '.js', '.vbs', '.jar', '.zip']
    for att in result['attachment_names']:
        if any(att.lower().endswith(ext) for ext in dangerous_extensions):
            score += 25
            reasons.append(f"Dangerous attachment: {att}")

    # Set final score and verdict
    result['score'] = min(score, 100)
    result['reasons'] = reasons

    if result['score'] >= 50:
        result['verdict'] = 'PHISHING'
    elif result['score'] >= 25:
        result['verdict'] = 'SUSPICIOUS'
    else:
        result['verdict'] = 'SAFE'

    return result


def print_email_report(result):
    """Print formatted email analysis report."""
    print("=" * 70)
    print("PHISHTRACE EMAIL ANALYSIS")
    print("=" * 70)
    print(f"File: {result['filepath']}")
    print(f"From: {result.get('from', 'Unknown')}")
    print(f"Reply-To: {result.get('reply_to', 'N/A')}")
    print(f"Subject: {result.get('subject', 'No subject')}")
    print("-" * 70)
    print(f"Verdict: {result['verdict']}")
    print(f"Risk Score: {result['score']}/100")
    print(f"URLs found: {len(result['urls_found'])}")
    if result.get('has_attachments'):
        print(f"Attachments: {', '.join(result['attachment_names'])}")
    print("-" * 70)

    if result['reasons']:
        print("\nReasons:")
        for reason in result['reasons']:
            print(f"  • {reason}")

    if result['url_analyses']:
        print("\nURL Analysis:")
        for url_result in result['url_analyses'][:5]:
            print(f"  [{url_result['verdict']}] {url_result['url'][:60]}...")

    print("=" * 70)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        filepath = input("Enter .eml file path: ")
    else:
        filepath = sys.argv[1]

    result = analyze_email(filepath)
    print_email_report(result)