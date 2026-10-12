# PhishTrace Model Evaluation Report

**Project:** PhishTrace - Forensic-first phishing investigation platform  
**Author:** [YOUR NAME]  
**Date:** [TODAY'S DATE]  
**Version:** 1.0 (Phase 1)

---

## 1. Executive Summary

This report documents the design, training, and evaluation of the URL-based phishing detection model that forms the core of PhishTrace. The model achieves **97.51% accuracy** on the UCI Phishing Websites dataset, with a hybrid ML + heuristic approach providing defense-in-depth against missed detections.

---

## 2. Dataset

| Property | Value |
|----------|-------|
| **Source** | UCI Machine Learning Repository - Phishing Websites Dataset |
| **Total Samples** | 11,055 |
| **Features** | 30 |
| **Class Distribution** | 6,157 legitimate (56%) / 4,898 phishing (44%) |
| **Missing Values** | 0 |
| **Format** | ARFF (Attribute-Relation File Format) |

### 2.1 Feature Categories

The 30 features are grouped into four categories:

1. **URL-based features** (e.g., `URL_Length`, `having_IP_Address`, `Shortining_Service`)
2. **Domain-based features** (e.g., `age_of_domain`, `DNSRecord`, `web_traffic`)
3. **HTML/Content-based features** (e.g., `Iframe`, `on_mouseover`, `RightClick`)
4. **Statistical features** (e.g., `Statistical_report`, `Google_Index`)

### 2.2 Data Split

| Set | Samples | Percentage |
|-----|---------|------------|
| Training | 8,844 | 80% |
| Test | 2,211 | 20% |

**Stratified split** was used to maintain class balance in both sets.

---

## 3. Models Evaluated

### 3.1 Logistic Regression
- **Type:** Linear classifier
- **Max iterations:** 1000
- **Random state:** 42

### 3.2 Random Forest
- **Type:** Ensemble of decision trees
- **Estimators:** 100
- **Random state:** 42

---

## 4. Results

### 4.1 Performance Metrics

| Model | Accuracy | Precision | Recall | F1-Score |
|-------|----------|-----------|--------|----------|
| Logistic Regression | 92.76% | 93.43% | 90.00% | 91.68% |
| **Random Forest** | **97.51%** | **97.93%** | **96.43%** | **97.17%** |

### 4.2 Confusion Matrix (Random Forest)

| Metric | Value | Interpretation |
|--------|-------|----------------|
| True Positives | 945 | Correctly identified phishing URLs |
| True Negatives | 1211 | Correctly identified safe URLs |
| False Positives | 20 | Safe URLs wrongly flagged as phishing (1.6%) |
| False Negatives | 35 | Phishing URLs missed (3.6%) |

### 4.3 Why Random Forest Performed Better

Random Forest outperformed Logistic Regression by **4.75 percentage points** because:
- It captures **non-linear relationships** between features
- It handles **feature interactions** naturally
- It is **robust to outliers** and irrelevant features

---

## 5. Hybrid Detection System

### 5.1 The Problem with ML Alone

When tested on real URLs, the ML model alone predicted "SAFE" for obvious phishing URLs because:
- 20 out of 30 features in our extractor are placeholders (set to 1 = safe)
- The model was trained on complete feature data, but we can't extract all features without external APIs

### 5.2 The Hybrid Solution

We added a **heuristic override layer**:

| Heuristic Check | Score Added |
|-----------------|-------------|
| IP address in URL | +30 |
| Suspicious TLD (.tk, .ml, .xyz) | +25 |
| @ symbol in URL | +20 |
| Phishing keywords (login, verify) | +15 |
| Excessive hyphens (>3) | +15 |

**Rule:** If heuristic score ≥ 40, override ML prediction.

### 5.3 Hybrid System Results

| URL | Verdict | Score | ML Alone |
|-----|---------|-------|----------|
| https://www.google.com | SAFE | 1/100 | SAFE ✅ |
| https://github.com | SAFE | 2/100 | SAFE ✅ |
| http://192.168.1.1/login/verify | SUSPICIOUS | 45/100 | SAFE ❌ |
| http://secure-login-verify.tk/account/update | PHISHING | 60/100 | SAFE ❌ |

**Hybrid system caught 2/2 phishing URLs that ML alone missed.**

---

## 6. Limitations

### 6.1 Detection Limitations
- Model trained on pre-engineered features, not raw URLs
- Feature extractor has ~20 placeholder features (requires WHOIS, DNS, page content)
- May not generalize to all phishing techniques
- No real-time monitoring (batch analysis only)

### 6.2 Dataset Limitations
- UCI dataset is from 2012-2015, may not reflect modern phishing
- Balanced dataset may not represent real-world distribution
- No adversarial examples in training

### 6.3 Operational Limitations
- Browser automation not yet implemented (Phase 3)
- No email analysis yet (Phase 5)
- No report generation yet (Phase 4)

---

## 7. Reproducibility

To reproduce these results:

```bash
# Install dependencies
pip install -r requirements.txt

# Train model
python src/train_model.py

# Run URL analyzer
python src/url_analyzer_ml.py