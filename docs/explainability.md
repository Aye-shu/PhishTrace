# Explainability in PhishTrace

## Why Explainability Matters

In security operations and digital forensics, a decision without explanation is a liability.

| Without Explainability | With Explainability |
|------------------------|---------------------|
| "PHISHING" | "PHISHING because: suspicious TLD, @ symbol, phishing keywords" |
| Black-box decision | Transparent, auditable decision |
| Analysts can't verify | Analysts can confirm and trust |
| Not admissible in court | Forensic-grade evidence |

## How SHAP Works

PhishTrace uses **SHAP (SHapley Additive exPlanations)** to explain every prediction.

### The Core Idea

SHAP assigns each feature a value representing its contribution to the prediction:
- **Positive SHAP value**: Feature increases phishing risk
- **Negative SHAP value**: Feature decreases phishing risk

The sum of all SHAP values equals the difference between the model's prediction and the base rate.

### Why SHAP?

- **Theoretically grounded**: Based on cooperative game theory
- **Consistent**: Same feature gets the same importance across models
- **Local + Global**: Explains both individual predictions and overall behavior

## Implementation

### Component: `src/explainability.py`

```python
from explainability import explain_url

result = explain_url("http://secure-login-verify.tk/account/update")

# result contains:
# - prediction: 0 or 1
# - verdict: "PHISHING" or "SAFE"
# - confidence: 0.0 to 1.0
# - top_contributions: top 10 features with SHAP values
```

### Example Output

For URL: `http://secure-login-verify.tk/account/update`

| Feature | Value | SHAP Value | Impact |
|---------|-------|------------|--------|
| SSLfinal_State | -1 | +0.2668 | Increases risk |
| URL_of_Anchor | 1 | -0.1776 | Decreases risk |
| SFH | 1 | -0.0897 | Decreases risk |
| having_Sub_Domain | 1 | -0.0644 | Decreases risk |
| Domain_registeration_length | 1 | +0.0611 | Increases risk |

**Interpretation**: The model correctly identifies `SSLfinal_State = -1` (HTTP, no SSL) as increasing phishing risk. However, content-based features set to placeholder values suppress the final verdict.

## 🚨 Important Finding: Placeholder Feature Bias

SHAP analysis revealed a **critical limitation** in the current implementation:

**Content-based features (URL_of_Anchor, SFH, having_Sub_Domain, etc.) are set to placeholder values (1 = safe)** because we cannot extract them without fetching actual webpage content.

### Impact

For the URL `http://secure-login-verify.tk/account/update`:
- `SSLfinal_State = -1` correctly contributes **+0.2668** to phishing risk ✅
- But `URL_of_Anchor = 1` (placeholder) contributes **-0.1776** (pulls toward SAFE) ❌
- Net result: ML predicts SAFE

### Why This Matters

This finding **validates the hybrid ML + heuristic approach** — heuristics catch what ML misses due to feature gaps.

### Planned Fix

Phase 3 (Evidence Capture) will fetch actual page content using Playwright, allowing extraction of real values for content-based features. This is expected to significantly improve ML recall on phishing URLs.

## Visualizations

### 1. Contribution Chart
`reports/figures/explanation_safe.png` and `explanation_phishing.png`
Shows top 10 features contributing to a prediction, colored by direction.

### 2. Comparison Chart
`reports/figures/comparison.png`
Side-by-side explanations for safe, suspicious, and phishing URLs.

### 3. Feature Importance
`reports/figures/feature_importance.png`
Shows which features the Random Forest model relies on most across the entire dataset.

## Forensic Value

SHAP explanations provide:

1. **Auditability** — Every decision traces to specific features
2. **Transparency** — Analysts understand why a URL was flagged
3. **Documentation** — Reports include feature-level justification
4. **Defensibility** — Decision logic can be explained in legal proceedings

## Limitations

- SHAP values show correlation, not causation
- Feature interactions are not fully captured
- Placeholder features still contribute to predictions
- Explanations depend on the model, not ground truth