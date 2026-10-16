# 🔍 PhishTrace

**A forensic-first phishing investigation platform**

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Phase%201%20Complete-brightgreen.svg)]()

---

## 📖 Overview

PhishTrace is a phishing detection and investigation tool that combines **machine learning** with **heuristic analysis** to identify malicious URLs. Unlike simple URL checkers, PhishTrace is designed for **forensic readiness** — it explains its decisions, preserves evidence, and generates investigation reports.

**Author:** [YOUR NAME]  
**Institution:** [YOUR UNIVERSITY]  
**Purpose:** Undergraduate research project for fully-funded master's applications in Cybersecurity, Information Security, and Digital Forensics.

---

| Phase | Description | Status |
|-------|-------------|--------|
| **Phase 1** | URL Detector (ML + Heuristics) | ✅ **Complete** |
| **Phase 2** | Explainability (SHAP) | ✅ **Complete** |
| **Phase 3** | Evidence Capture (Screenshots, HTML) | ✅ **Complete** |
| **Phase 4** | Report Generation (HTML) | ✅ **Complete** |
| Phase 5 | Email Analysis (.eml) | ⬜ Planned |
| Phase 6 | Polish & Demo | ⬜ Planned |

---

## 📊 Results So Far

### Model Performance

| Model | Accuracy | Precision | Recall | F1-Score |
|-------|----------|-----------|--------|----------|
| Logistic Regression | 92.76% | 93.43% | 90.00% | 91.68% |
| **Random Forest** | **97.51%** | **97.93%** | **96.43%** | **97.17%** |

### Hybrid Detection Results

| URL | Verdict | Score |
|-----|---------|-------|
| https://www.google.com | SAFE | 1/100 |
| https://github.com | SAFE | 2/100 |
| http://192.168.1.1/login/verify | SUSPICIOUS | 45/100 |
| http://secure-login-verify.tk/account/update | PHISHING | 60/100 |

---

## 🏗️ Architecture

```
┌──────────────┐
│   URL Input  │
└──────┬───────┘
       │
       ▼
┌──────────────────┐
│ Feature Extractor│
│  (30 features)   │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│   ML Model       │
│  (Random Forest) │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Heuristic Layer  │
│  (Rule-based)    │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│   Risk Engine    │
│  (Score 0-100)   │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Output Report   │
│ Verdict + Reasons│
└──────────────────┘
```

---

## 📄 Sample Investigation Report

PhishTrace generates professional HTML investigation reports. Here's what a report includes:

| Section | Content |
|---------|---------|
| **Header** | Report ID, timestamp, analyst |
| **Target** | Investigated URL, page title, final URL |
| **Verdict** | Color-coded verdict with risk score |
| **Indicators** | List of all suspicious signals found |
| **ML Analysis** | Model prediction and confidence |
| **SHAP Explainability** | Feature contribution bars |
| **Evidence** | Screenshots + SHA-256 hashes |
| **Limitations** | Honest disclosure of tool limitations |

**Generate your own report:**
```bash
python src/main_pipeline.py "https://example.com"

----

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- pip

### Installation

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/PhishTrace.git
cd PhishTrace

# Install dependencies
pip install -r requirements.txt

# Train the model (first time only)
python src/train_model.py

# Run URL analysis
python src/url_analyzer_ml.py
```

### Usage Example

```python
from src.url_analyzer_ml import predict_url, print_report

result = predict_url("http://secure-login-verify.tk/account/update")
print_report(result)
```

**Output:**
```
============================================================
PHISHTRACE URL ANALYSIS
============================================================
URL: http://secure-login-verify.tk/account/update
Verdict: PHISHING
Risk Score: 60/100
ML Confidence: 62.50%
------------------------------------------------------------
Reasons:
  - ML model predicts legitimate (confidence: 62.50%)
  - Suspicious top-level domain
  - Contains @ symbol (can hide real destination)
  - Contains phishing keywords: login, verify, account, secure, update
============================================================
```

---

## 📁 Project Structure

```
PhishTrace/
├── README.md
├── requirements.txt
├── .gitignore
├── .vscode/
│   └── settings.json
├── data/
│   └── raw/
│       └── Training Dataset.arff
├── models/
│   ├── phishing_model.pkl
│   └── feature_names.pkl
├── notebooks/
│   └── 01_data_exploration.ipynb
├── src/
│   ├── __init__.py
│   ├── feature_extractor.py
│   ├── train_model.py
│   └── url_analyzer_ml.py
├── tests/
│   ├── test_feature_extractor.py
│   └── test_url_analyzer.py
├── reports/
│   └── model_evaluation.md
└── docs/
    ├── architecture.md
    └── limitations.md
```

---

## 🔬 Technical Details

### Dataset
- **Source:** UCI Machine Learning Repository
- **Samples:** 11,055 URLs
- **Features:** 30
- **Split:** 80% training / 20% testing

### Models
- **Logistic Regression:** Baseline linear classifier
- **Random Forest:** 100 estimators, selected as best model

### Hybrid Approach
The system combines ML predictions with heuristic rules for defense-in-depth. When heuristics strongly indicate phishing (score ≥ 40), they override the ML prediction.

---
## 📚 Documentation

- [Model Evaluation Report](reports/model_evaluation.md)
- [Explainability](docs/explainability.md)
- [Architecture](docs/architecture.md)
- [Limitations](docs/limitations.md)

## 🔍 Explainability

PhishTrace explains every prediction using SHAP values:
Top Contributing Features (SHAP):
▲ SSLfinal_State SHAP: +0.2668
▼ URL_of_Anchor SHAP: -0.1776
▼ SFH SHAP: -0.0897
▲ Domain_registeration_length SHAP: +0.0611
▼ having_Sub_Domain SHAP: -0.0644


See [explainability documentation](docs/explainability.md) for details.

---

## 🛣️ Roadmap

- [x] Phase 1: URL Detector (ML + Heuristics)
- [ ] Phase 2: Explainability (SHAP/LIME)
- [ ] Phase 3: Evidence Capture (Playwright)
- [ ] Phase 4: Report Generation
- [ ] Phase 5: Email Analysis
- [ ] Phase 6: Polish & Demo

---

## ⚠️ Safety Notice

- Only investigate URLs you are authorized to test
- Use isolated VMs for browser automation
- This tool is for **defensive purposes only**
- Evidence should be reviewed by qualified analysts

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

**Built with ❤️ for cybersecurity research**