"""
URL Analyzer with ML integration.
Combines feature extraction with the trained Random Forest model.
"""

import joblib
import re
import os
import pandas as pd
from urllib.parse import urlparse

from feature_extractor import extract_features, FEATURE_ORDER
from threat_intel import check_virustotal

# Get the project root directory (one level up from src/)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Try to import SHAP explainability
try:
    from explainability import explain_url as get_shap_explanation
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False

# Load trained model
MODEL_PATH = os.path.join(PROJECT_ROOT, 'models', 'phishing_model.pkl')

try:
    model = joblib.load(MODEL_PATH)
    MODEL_LOADED = True
    print(f"Model loaded successfully from {MODEL_PATH}")
except Exception as e:
    MODEL_LOADED = False
    print(f"Warning: Could not load model: {e}")


def predict_url(url):
    """
    Analyze a URL using the ML model and heuristic rules.
    """
    result = {
        'url': url,
        'score': 0,
        'reasons': [],
        'verdict': 'UNKNOWN',
        'ml_prediction': None,
        'ml_confidence': None,
        'shap_explanation': None,
        'threat_intel': None
    }

    if not MODEL_LOADED:
        result['verdict'] = 'ERROR'
        result['reasons'].append("Model not loaded")
        return result

    # Extract features
    features = extract_features(url)

    # ML prediction (use DataFrame to avoid warning)
    feature_df = pd.DataFrame([features], columns=FEATURE_ORDER)
    prediction = model.predict(feature_df)[0]
    probabilities = model.predict_proba(feature_df)[0]
    confidence = max(probabilities)

    # In our mapping: 1 = phishing, 0 = safe
    result['ml_prediction'] = int(prediction)
    result['ml_confidence'] = float(confidence)

    # Convert to score (0-100)
    if prediction == 1:
        result['score'] = int(confidence * 100)
        result['verdict'] = 'PHISHING'
        result['reasons'].append(f"ML model predicts phishing (confidence: {confidence:.2%})")
    else:
        result['score'] = int((1 - confidence) * 100)
        result['verdict'] = 'SAFE'
        result['reasons'].append(f"ML model predicts legitimate (confidence: {confidence:.2%})")

    # Heuristic checks (can override ML for obvious cases)
    parsed = urlparse(url)
    hostname = parsed.netloc

    heuristic_score = 0
    heuristic_reasons = []

    # IP address
    if re.match(r'\d+\.\d+\.\d+\.\d+', hostname):
        heuristic_score += 30
        heuristic_reasons.append("Uses IP address instead of domain")

    # Suspicious TLD
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top']
    if any(tld in url.lower() for tld in suspicious_tlds):
        heuristic_score += 25
        heuristic_reasons.append("Suspicious top-level domain")

    # @ symbol
    if '@' in url:
        heuristic_score += 20
        heuristic_reasons.append("Contains @ symbol (can hide real destination)")

    # Phishing keywords
    keywords = ['login', 'verify', 'account', 'secure', 'update', 'banking']
    found = [kw for kw in keywords if kw in url.lower()]
    if found:
        heuristic_score += 15
        heuristic_reasons.append(f"Contains phishing keywords: {', '.join(found)}")

    # Too many hyphens
    if url.count('-') > 3:
        heuristic_score += 15
        heuristic_reasons.append("Too many hyphens in URL")

    # Combine ML + Heuristic
    if heuristic_score >= 40:
        result['score'] = max(result['score'], heuristic_score)
        result['verdict'] = 'PHISHING' if heuristic_score >= 50 else 'SUSPICIOUS'
        result['reasons'].extend(heuristic_reasons)
    else:
        result['reasons'].extend(heuristic_reasons)
        result['score'] = max(result['score'], heuristic_score)

    # Add SHAP explanation if available
    if SHAP_AVAILABLE:
        try:
            explanation = get_shap_explanation(url)
            result['shap_explanation'] = {
                'top_contributions': explanation['top_contributions'][:5],
                'confidence': explanation['confidence']
            }
        except Exception:
            result['shap_explanation'] = None
    else:
        result['shap_explanation'] = None

    # Add Threat Intelligence Check
    print("    [Debug] Checking VirusTotal...")
    vt_result = check_virustotal(url)
    
    if vt_result['status'] == 'success':
        print(f"    [Debug] VT Success: Malicious={vt_result['malicious_count']}, Suspicious={vt_result['suspicious_count']}")
        result['threat_intel'] = vt_result
        
        # Adjust score based on VirusTotal
        if vt_result['malicious_count'] > 0:
            result['score'] = min(100, result['score'] + 40)
            result['verdict'] = 'PHISHING'
            result['reasons'].extend(vt_result['reasons'])
        elif vt_result['suspicious_count'] > 0:
            result['score'] = min(100, result['score'] + 20)
            result['verdict'] = 'SUSPICIOUS'
            result['reasons'].extend(vt_result['reasons'])
    else:
        print(f"    [Debug] VT Failed/Not Found: {vt_result.get('message')}")
        result['threat_intel'] = vt_result # Save it so the report shows the "Not Found" message

    return result


def print_report(result):
    """Print formatted analysis report."""
    print("=" * 60)
    print("PHISHTRACE URL ANALYSIS")
    print("=" * 60)
    print(f"URL: {result['url']}")
    print(f"Verdict: {result['verdict']}")
    print(f"Risk Score: {result['score']}/100")
    if result['ml_confidence'] is not None:
        print(f"ML Confidence: {result['ml_confidence']:.2%}")
    print("-" * 60)
    print("Reasons:")
    for reason in result['reasons']:
        print(f"  - {reason}")

    # Show SHAP explanation
    if result.get('shap_explanation'):
        print("-" * 60)
        print("Top Contributing Features (SHAP):")
        for exp in result['shap_explanation']['top_contributions']:
            arrow = "▲" if exp['shap_value'] > 0 else "▼"
            sign = "+" if exp['shap_value'] > 0 else ""
            print(f"  {arrow} {exp['feature']:<28} SHAP: {sign}{exp['shap_value']:.4f}")

    print("=" * 60)


if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "https://github.com",
        "http://192.168.1.1/login/verify",
        "http://secure-login-verify.tk/account/update?user=admin@bank.com",
    ]

    for url in test_urls:
        result = predict_url(url)
        print_report(result)
        print()