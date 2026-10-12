"""
Visualization module for PhishTrace explanations.
Creates charts showing feature contributions.
"""

import matplotlib
matplotlib.use('Agg')  # Non-interactive backend for Codespaces
import matplotlib.pyplot as plt
import numpy as np
import os

try:
    from explainability import get_explainer
except ImportError:
    from src.explainability import get_explainer


def create_contribution_chart(url, save_path, top_n=10):
    """
    Create a horizontal bar chart showing feature contributions.
    
    Args:
        url: URL to explain
        save_path: Where to save the chart
        top_n: Number of top features to show
    """
    explainer = get_explainer()
    result = explainer.explain(url)
    
    # Get top N contributions
    contributions = result['top_contributions'][:top_n]
    
    features = [c['feature'] for c in contributions]
    values = [c['shap_value'] for c in contributions]
    
    # Color: red for increasing risk, green for decreasing
    colors = ['#e74c3c' if v > 0 else '#27ae60' for v in values]
    
    # Create figure
    fig, ax = plt.subplots(figsize=(10, 6))
    y_pos = np.arange(len(features))
    
    bars = ax.barh(y_pos, values, color=colors, edgecolor='black', linewidth=0.5)
    ax.set_yticks(y_pos)
    ax.set_yticklabels(features, fontsize=10)
    ax.invert_yaxis()  # Top feature at top
    ax.axvline(x=0, color='black', linestyle='-', linewidth=0.8)
    ax.set_xlabel('SHAP Value (Impact on Phishing Prediction)', fontsize=11)
    ax.set_title(
        f'Feature Contributions\n{result["verdict"]} (confidence: {result["confidence"]:.1%})\n{url[:60]}',
        fontsize=12, pad=15
    )
    ax.grid(axis='x', linestyle='--', alpha=0.3)
    
    # Add legend
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor='#e74c3c', label='Increases phishing risk'),
        Patch(facecolor='#27ae60', label='Decreases phishing risk')
    ]
    ax.legend(handles=legend_elements, loc='lower right')
    
    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches='tight')
    plt.close()
    
    print(f"✅ Chart saved: {save_path}")
    return save_path


def create_comparison_chart(urls, save_path, top_n=8):
    """
    Create a comparison chart for multiple URLs.
    """
    explainer = get_explainer()
    
    fig, axes = plt.subplots(len(urls), 1, figsize=(12, 4 * len(urls)))
    if len(urls) == 1:
        axes = [axes]
    
    for ax, url in zip(axes, urls):
        result = explainer.explain(url)
        contributions = result['top_contributions'][:top_n]
        
        features = [c['feature'] for c in contributions]
        values = [c['shap_value'] for c in contributions]
        colors = ['#e74c3c' if v > 0 else '#27ae60' for v in values]
        
        y_pos = np.arange(len(features))
        ax.barh(y_pos, values, color=colors, edgecolor='black', linewidth=0.5)
        ax.set_yticks(y_pos)
        ax.set_yticklabels(features, fontsize=9)
        ax.invert_yaxis()
        ax.axvline(x=0, color='black', linestyle='-', linewidth=0.8)
        ax.set_title(
            f'{result["verdict"]} ({result["confidence"]:.0%}) - {url[:50]}',
            fontsize=10
        )
        ax.grid(axis='x', linestyle='--', alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(save_path, dpi=120, bbox_inches='tight')
    plt.close()
    
    print(f"✅ Comparison chart saved: {save_path}")
    return save_path


if __name__ == "__main__":
    os.makedirs('../reports/figures', exist_ok=True)
    
    # Chart 1: Safe URL
    create_contribution_chart(
        "https://www.google.com",
        "../reports/figures/explanation_safe.png"
    )
    
    # Chart 2: Phishing URL
    create_contribution_chart(
        "http://secure-login-verify.tk/account/update",
        "../reports/figures/explanation_phishing.png"
    )
    
    # Chart 3: Comparison
    create_comparison_chart(
        [
            "https://www.google.com",
            "http://192.168.1.1/login/verify",
            "http://secure-login-verify.tk/account/update"
        ],
        "../reports/figures/comparison.png"
    )
    
    print("\n✅ All visualization charts created!")