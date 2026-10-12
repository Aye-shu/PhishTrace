"""
Explainability module for PhishTrace.
Uses SHAP (SHapley Additive exPlanations) to explain model predictions.
"""

import shap
import joblib
import pandas as pd
import numpy as np
import os

# Get the project root directory (one level up from src/)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Import feature extractor
try:
    from feature_extractor import extract_features, FEATURE_ORDER
except ImportError:
    from src.feature_extractor import extract_features, FEATURE_ORDER


class PhishExplainer:
    """
    Wrapper around SHAP that provides explanations for phishing predictions.
    """
    
    def __init__(self, model_path=None):
        """Load model and create SHAP explainer."""
        if model_path is None:
            model_path = os.path.join(PROJECT_ROOT, 'models', 'phishing_model.pkl')
        
        self.model = joblib.load(model_path)
        self.feature_names = FEATURE_ORDER
        self.explainer = shap.TreeExplainer(self.model)
        print(f"Explainer initialized with {len(self.feature_names)} features")
    
    def _flatten_shap_values(self, shap_values):
        """Handle different SHAP output formats across versions."""
        # Case 1: List of arrays (older versions, binary classification)
        if isinstance(shap_values, list):
            values = shap_values[1]  # Phishing class
        else:
            values = shap_values
        
        # Convert to numpy array
        values = np.array(values)
        
        # Case 2: 3D array (n_samples, n_features, n_classes)
        if values.ndim == 3:
            values = values[0, :, 1]  # First sample, phishing class
        # Case 3: 2D array (n_samples, n_features)
        elif values.ndim == 2:
            values = values[0]  # First sample
        # Case 4: Already 1D
        else:
            pass
        
        return values.flatten()
    
    def explain(self, url):
        """
        Explain why a URL was classified as phishing or legitimate.
        
        Returns:
            dict: Contains url, prediction, confidence, and feature contributions
        """
        # Extract features
        features = extract_features(url)
        feature_df = pd.DataFrame([features], columns=self.feature_names)
        
        # Get prediction
        prediction = self.model.predict(feature_df)[0]
        probabilities = self.model.predict_proba(feature_df)[0]
        confidence = max(probabilities)
        
        # Get SHAP values (with version handling)
        shap_values = self.explainer.shap_values(feature_df)
        shap_vals = self._flatten_shap_values(shap_values)
        
        # Build contribution list
        contributions = []
        for i, feature in enumerate(self.feature_names):
            contributions.append({
                'feature': feature,
                'value': float(feature_df[feature].values[0]),
                'shap_value': float(shap_vals[i]),
                'impact': 'increases risk' if shap_vals[i] > 0 else 'decreases risk'
            })
        
        # Sort by absolute impact
        contributions.sort(key=lambda x: abs(x['shap_value']), reverse=True)
        
        return {
            'url': url,
            'prediction': int(prediction),
            'verdict': 'PHISHING' if prediction == 1 else 'SAFE',
            'confidence': float(confidence),
            'top_contributions': contributions[:10],
            'all_contributions': contributions
        }
    
    def print_explanation(self, url):
        """Print a human-readable explanation."""
        result = self.explain(url)
        
        print("=" * 70)
        print(f"EXPLANATION FOR: {result['url']}")
        print("=" * 70)
        print(f"Verdict: {result['verdict']}")
        print(f"Confidence: {result['confidence']:.2%}")
        print("-" * 70)
        print("\nTop 10 Features Contributing to Prediction:")
        print("-" * 70)
        
        for i, exp in enumerate(result['top_contributions'], 1):
            arrow = "▲" if exp['shap_value'] > 0 else "▼"
            sign = "+" if exp['shap_value'] > 0 else ""
            print(f"{i:2d}. {exp['feature']:<30} (value={exp['value']:>3})")
            print(f"    {arrow} {exp['impact']:<20} SHAP: {sign}{exp['shap_value']:.4f}")
        
        print("=" * 70)
        return result


# Singleton instance for convenience
_explainer_instance = None


def get_explainer():
    """Get or create the singleton explainer."""
    global _explainer_instance
    if _explainer_instance is None:
        _explainer_instance = PhishExplainer()
    return _explainer_instance


def explain_url(url):
    """Convenience function to explain a URL."""
    return get_explainer().explain(url)


def print_explanation(url):
    """Convenience function to print explanation."""
    return get_explainer().print_explanation(url)

if __name__ == "__main__":
    test_urls = [
        # Safe URLs
        "https://www.google.com",
        "https://github.com",
        "https://www.linkedin.com",
        
        # Suspicious URLs
        "http://192.168.1.1/login/verify",
        "http://secure-login-verify.tk/account/update",
        "http://paypal-verify-account.xyz/login?user=admin",
        "http://amazon-security-check.ml/signin",
    ]
    
    for url in test_urls:
        print_explanation(url)
        print()