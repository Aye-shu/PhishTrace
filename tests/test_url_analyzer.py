"""
Tests for the URL analyzer (ML + heuristics).
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from url_analyzer_ml import predict_url


def test_safe_google():
    """Test that Google is classified as SAFE."""
    result = predict_url("https://www.google.com")
    assert result['verdict'] == 'SAFE', f"Google should be SAFE, got {result['verdict']}"


def test_safe_github():
    """Test that GitHub is classified as SAFE."""
    result = predict_url("https://github.com")
    assert result['verdict'] == 'SAFE', f"GitHub should be SAFE, got {result['verdict']}"


def test_ip_url_suspicious():
    """Test that IP-based URL is SUSPICIOUS or PHISHING."""
    result = predict_url("http://192.168.1.1/login/verify")
    assert result['verdict'] in ['SUSPICIOUS', 'PHISHING'], \
        f"IP URL should be flagged, got {result['verdict']}"


def test_phishing_url():
    """Test that obvious phishing URL is flagged."""
    result = predict_url("http://secure-login-verify.tk/account/update")
    assert result['verdict'] in ['SUSPICIOUS', 'PHISHING'], \
        f"Phishing URL should be flagged, got {result['verdict']}"


def test_score_range():
    """Test that scores are within 0-100."""
    result = predict_url("https://www.google.com")
    assert 0 <= result['score'] <= 100, f"Score out of range: {result['score']}"


def test_reasons_present():
    """Test that reasons are provided."""
    result = predict_url("http://192.168.1.1/login")
    assert len(result['reasons']) > 0, "Should have at least one reason"


def test_ml_confidence_present():
    """Test that ML confidence is calculated."""
    result = predict_url("https://www.google.com")
    assert result['ml_confidence'] is not None, "ML confidence should be present"

def test_shap_explanation_present():
    """Test that SHAP explanation is included."""
    result = predict_url("http://secure-login-verify.tk/account/update")
    assert 'shap_explanation' in result, "SHAP explanation should be present"


def test_shap_has_contributions():
    """Test that SHAP explanation has top contributions."""
    result = predict_url("https://www.google.com")
    if result.get('shap_explanation'):
        assert len(result['shap_explanation']['top_contributions']) > 0, \
            "Should have at least one SHAP contribution"

if __name__ == "__main__":
    test_functions = [
        test_safe_google,
        test_safe_github,
        test_ip_url_suspicious,
        test_phishing_url,
        test_score_range,
        test_reasons_present,
        test_ml_confidence_present,
    ]
    
    passed = 0
    failed = 0
    
    for test in test_functions:
        try:
            test()
            print(f"✅ {test.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"❌ {test.__name__}: {e}")
            failed += 1
    
    print(f"\n{'='*50}")
    print(f"Results: {passed} passed, {failed} failed")
    print(f"{'='*50}")