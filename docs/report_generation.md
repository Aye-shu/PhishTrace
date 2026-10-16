# Report Generation in PhishTrace

## Overview

PhishTrace generates professional HTML investigation reports that combine:
- URL analysis results
- Machine learning predictions
- SHAP explainability
- Forensic evidence artifacts
- Chain of custody documentation

## Usage

### Basic Report (URL Analysis Only)

```bash
python src/main_pipeline.py "https://example.com"
```

### Full Report (With Evidence)

```bash
python src/main_pipeline.py "https://example.com" evidence/manifest_XXXX.json
```

## Report Structure

```
┌─────────────────────────────────────┐
│ 🔍 PhishTrace Investigation Report  │
│ Forensic-First Phishing Platform    │
├─────────────────────────────────────┤
│ Report ID | Generated | Analyst     │
├─────────────────────────────────────┤
│ 📋 Investigation Target              │
│   • URL                              │
│   • Page Title                       │
│   • Final URL                        │
├─────────────────────────────────────┤
│ ⚖️ Verdict (Color-coded box)         │
│   • PHISHING / SUSPICIOUS / SAFE     │
│   • Risk Score 0-100                 │
├─────────────────────────────────────┤
│ 🔎 Indicators Found                  │
│   • Suspicious TLD                   │
│   • Phishing keywords                │
│   • etc.                             │
├─────────────────────────────────────┤
│ 🤖 Machine Learning Analysis         │
│   • Prediction                       │
│   • Confidence                       │
├─────────────────────────────────────┤
│ 🧠 Explainability (SHAP)             │
│   • Feature contribution bars        │
├─────────────────────────────────────┤
│ 📁 Evidence Artifacts                │
│   • Screenshot SHA-256               │
│   • HTML SHA-256                     │
├─────────────────────────────────────┤
│ 🖼️ Captured Screenshot               │
├─────────────────────────────────────┤
│ ⚠️ Limitations                       │
├─────────────────────────────────────┤
│ Footer                              │
└─────────────────────────────────────┘
```

## Components

| File | Purpose |
|------|---------|
| `src/report_generator.py` | HTML template and generation logic |
| `src/main_pipeline.py` | End-to-end investigation workflow |
| `reports/investigation_*.html` | Generated output files |

## Forensic Value

Reports include:

1. **Evidence Hashes** — SHA-256 for each artifact (integrity verification)
2. **Timestamps** — When investigation was performed
3. **Chain of Custody** — Documented evidence collection
4. **Explainability** — Feature-level justification (SHAP)
5. **Limitations** — Honest disclosure of tool constraints

## Customization

The HTML template is in `REPORT_TEMPLATE` in `src/report_generator.py`. You can modify:
- Colors and styling (CSS section)
- Sections included
- Branding

## Limitations

- Reports are generated locally and not digitally signed
- No PDF export yet (HTML only)
- No automatic email delivery
- Screenshots must be present in the evidence/ folder to embed