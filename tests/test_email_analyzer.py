"""
Tests for the email analyzer.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from email_analyzer import analyze_email


def test_phishing_email():
    """Test that the phishing sample is flagged."""
    result = analyze_email('examples/phishing_sample.eml')
    assert result['verdict'] in ['PHISHING', 'SUSPICIOUS'], \
        f"Should be flagged, got {result['verdict']}"


def test_safe_email():
    """Test that the safe sample is not flagged."""
    result = analyze_email('examples/safe_sample.eml')
    assert result['verdict'] == 'SAFE', \
        f"Should be SAFE, got {result['verdict']}"


def test_score_range():
    """Test that scores are within 0-100."""
    result = analyze_email('examples/phishing_sample.eml')
    assert 0 <= result['score'] <= 100


def test_urls_extracted():
    """Test that URLs are extracted from body."""
    result = analyze_email('examples/phishing_sample.eml')
    assert len(result['urls_found']) > 0


def test_reasons_present():
    """Test that reasons are provided for phishing email."""
    result = analyze_email('examples/phishing_sample.eml')
    assert len(result['reasons']) > 0


if __name__ == "__main__":
    test_functions = [
        test_phishing_email,
        test_safe_email,
        test_score_range,
        test_urls_extracted,
        test_reasons_present,
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