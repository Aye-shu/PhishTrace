# PhishTrace Demo Guide

## For Scholarship Interviews

This guide helps you demonstrate PhishTrace effectively.

## 2-Minute Demo Script

### Opening (15 seconds)
> "PhishTrace is a forensic-first phishing investigation platform I built to detect malicious URLs and emails. It combines machine learning with heuristic analysis and produces professional investigation reports."

## 🎥 Demo Video

[![PhishTrace Demo](https://img.shields.io/badge/▶️_Watch_Demo-Google_Drive-blue)](YOUR_VIDEO_LINK_HERE)

*2-minute walkthrough of PhishTrace features*

### Live Demo — URL Investigation (45 seconds)
1. Open the Streamlit app (`streamlit run app.py`)
2. Enter: `http://secure-login-verify.tk/account/update`
3. Click "Investigate"
4. Point out:
   - The SUSPICIOUS/PHISHING verdict
   - The risk score
   - The specific indicators found
   - The SHAP explanation showing which features drove the decision
5. Click "Generate Full Investigation Report"
6. Show the downloaded HTML report

### Live Demo — Email Investigation (30 seconds)
1. Upload `examples/phishing_sample.eml`
2. Point out:
   - Header mismatch detection
   - Suspicious language detection
   - URL analysis within the email

### Technical Highlights (30 seconds)
> "The system uses a Random Forest classifier trained on 11,000 URLs, achieving 97.5% accuracy. The SHAP explainability layer makes every decision auditable. The evidence collection module uses Playwright in an isolated Kali Linux VM to capture screenshots and HTML snapshots with SHA-256 integrity hashes. Reports document the full chain of custody."

## Key Talking Points

| Topic | What to Say |
|-------|-------------|
| **ML Model** | Random Forest, 97.51% accuracy, 30 features |
| **Explainability** | SHAP values show feature-level contributions |
| **Forensics** | Screenshots + HTML + SHA-256 hashes + chain of custody |
| **Email Analysis** | SPF/DKIM/DMARC checks, header mismatch detection |
| **Safety** | Isolated Kali VM, Host-Only network, snapshots |
| **Reports** | Professional HTML reports with recommendations |

## Questions You Should Be Ready For

1. **"Why Random Forest?"** — Handles non-linear relationships, robust to outliers, provides feature importance.
2. **"What are the limitations?"** — Placeholder features for content-based analysis; dataset from 2015; no real-time monitoring yet.
3. **"How do you ensure evidence integrity?"** — SHA-256 hashing of every artifact, timestamps, chain of custody documentation.
4. **"How does this relate to your master's goals?"** — Combines digital forensics (evidence handling), information security (email auth, cryptography), and cybersecurity (threat detection).
5. **"What would you improve?"** — Add Playwright evidence capture directly in the pipeline, train on newer datasets, add deep learning models.

## Demo Checklist

- [ ] Streamlit app running
- [ ] Test URL ready: `http://secure-login-verify.tk/account/update`
- [ ] Test email ready: `examples/phishing_sample.eml`
- [ ] Report generation tested
- [ ] GitHub repo open in browser tab
- [ ] Talking points rehearsed