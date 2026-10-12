"""
Feature importance analysis for PhishTrace.
Shows which features matter most for phishing detection.
"""

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import joblib
import pandas as pd
import os

try:
    from feature_extractor import FEATURE_ORDER
except ImportError:
    from src.feature_extractor import FEATURE_ORDER


def plot_model_feature_importance(model_path='models/phishing_model.pkl',
                                    save_path='reports/figures/feature_importance.png'):
    """Plot built-in feature importance from Random Forest."""
    model = joblib.load(model_path)
    
    # Get feature importances
    importances = model.feature_importances_
    
    # Sort
    indices = np.argsort(importances)[::-1]
    
    # Take top 15
    top_n = 15
    top_indices = indices[:top_n]
    top_features = [FEATURE_ORDER[i] for i in top_indices]
    top_importances = [importances[i] for i in top_indices]
    
    # Plot
    fig, ax = plt.subplots(figsize=(10, 7))
    y_pos = np.arange(len(top_features))
    
    ax.barh(y_pos, top_importances, color='#3498db', edgecolor='black', linewidth=0.5)
    ax.set_yticks(y_pos)
    ax.set_yticklabels(top_features, fontsize=10)
    ax.invert_yaxis()
    ax.set_xlabel('Importance Score', fontsize=11)
    ax.set_title('Top 15 Feature Importances (Random Forest)', fontsize=12, pad=15)
    ax.grid(axis='x', linestyle='--', alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches='tight')
    plt.close()
    
    print(f"✅ Feature importance chart saved: {save_path}")
    
    # Print top 10
    print("\nTop 10 Most Important Features:")
    print("-" * 50)
    for i in range(10):
        idx = indices[i]
        print(f"{i+1:2d}. {FEATURE_ORDER[idx]:<30} {importances[idx]:.4f}")
    
    return top_features, top_importances


if __name__ == "__main__":
    os.makedirs('reports/figures', exist_ok=True)
    plot_model_feature_importance()