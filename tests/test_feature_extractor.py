"""
Tests for the feature extractor.
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from feature_extractor import extract_features, FEATURE_ORDER


def test_feature_count():
    """Test that exactly 30 features are extracted."""
    features = extract_features("https://www.google.com")
    assert len(features) == 30, f"Expected 30 features, got {len(features)}"


def test_ip_detection():
    """Test that IP addresses are detected."""
    features = extract_features("http://192.168.1.1/login")
    idx = FEATURE_ORDER.index('having_IP_Address')
    assert features[idx] == -1, "IP address should be detected as -1"


def test_no_ip_detection():
    """Test that regular domains are not flagged as IP."""
    features = extract_features("https://www.google.com")
    idx = FEATURE_ORDER.index('having_IP_Address')
    assert features[idx] == 1, "Regular domain should be 1"


def test_at_symbol_detection():
    """Test that @ symbol is detected."""
    features = extract_features("http://google.com@evil.com/login")
    idx = FEATURE_ORDER.index('having_At_Symbol')
    assert features[idx] == -1, "@ symbol should be detected as -1"


def test_https_detection():
    """Test that HTTPS is detected."""
    features = extract_features("https://www.google.com")
    idx = FEATURE_ORDER.index('SSLfinal_State')
    assert features[idx] == 1, "HTTPS should be 1"


def test_http_detection():
    """Test that HTTP is flagged."""
    features = extract_features("http://www.example.com")
    idx = FEATURE_ORDER.index('SSLfinal_State')
    assert features[idx] in [-1, 0], "HTTP should be -1 or 0"


def test_url_length():
    """Test URL length feature."""
    long_url = "http://example.com/" + "a" * 100
    features = extract_features(long_url)
    idx = FEATURE_ORDER.index('URL_Length')
    assert features[idx] == -1, "Long URL should be -1"


def test_short_url():
    """Test short URL detection."""
    features = extract_features("http://a.co")
    idx = FEATURE_ORDER.index('URL_Length')
    assert features[idx] == 1, "Short URL should be 1"


if __name__ == "__main__":
    # Run all tests
    test_functions = [
        test_feature_count,
        test_ip_detection,
        test_no_ip_detection,
        test_at_symbol_detection,
        test_https_detection,
        test_http_detection,
        test_url_length,
        test_short_url,
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