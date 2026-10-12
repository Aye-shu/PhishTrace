# PhishTrace Architecture

## System Overview

PhishTrace is a modular phishing detection system built in Python. It follows a pipeline architecture where each component has a single responsibility.

## Component Diagram

```
┌──────────────┐
│   Input      │
│  (URL/Email) │
└──────┬───────┘
       │
       ▼
┌──────────────────┐
│ Feature Extractor│
│  30 URL features │
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

## Components

### 1. Feature Extractor (`src/feature_extractor.py`)

**Purpose:** Convert raw URL strings into 30 numeric features.

**Input:** URL string (e.g., `http://example.com/login`)

**Output:** List of 30 floats/ints

**Key Functions:**
- `extract_features(url)` — Main extraction function
- Feature categories: URL-based, Domain-based, Content-based, Statistical

### 2. ML Model (`models/phishing_model.pkl`)

**Purpose:** Predict phishing probability based on features.

**Algorithm:** Random Forest (100 estimators)

**Training:** UCI Phishing Websites Dataset (11,055 samples)

**Accuracy:** 97.51%

### 3. Heuristic Layer (`src/url_analyzer_ml.py`)

**Purpose:** Rule-based checks that override ML when necessary.

**Rules:**

| Rule | Score Added |
|------|-------------|
| IP address | +30 |
| Suspicious TLD | +25 |
| @ symbol | +20 |
| Phishing keywords | +15 |
| Excessive hyphens | +15 |

**Override:** If score ≥ 40, override ML prediction.

### 4. Risk Engine

**Purpose:** Combine ML and heuristics into final verdict.

**Logic:**
```
if heuristic_score >= 40:
    verdict = "PHISHING" if score >= 50 else "SUSPICIOUS"
else:
    verdict = ML prediction
```

## Data Flow

1. User provides URL
2. Feature extractor converts URL to 30 features
3. ML model predicts phishing/legitimate + confidence
4. Heuristic layer calculates risk score
5. Risk engine combines both into final verdict
6. Report printer outputs results

## Design Decisions

### Why Random Forest?
- Handles non-linear relationships
- Robust to outliers
- Provides feature importance
- Achieved 97.51% accuracy

### Why Hybrid Approach?
- ML alone missed obvious phishing URLs
- Heuristics provide defense-in-depth
- Combines statistical and rule-based detection

### Why 30 Features?
- Matches the UCI dataset format
- Covers URL, domain, and content aspects
- Balance between accuracy and extractability

## Future Improvements

1. **Replace placeholder features** with real API calls (WHOIS, DNS, Google Safe Browsing)
2. **Add deep learning** (LSTM for URL sequences)
3. **Implement SHAP** for explainability
4. **Add evidence capture** with Playwright
5. **Generate PDF reports** for investigations