# PhishTrace Limitations

## Detection Limitations

### 1. Feature Extraction Gaps
- **20 out of 30 features are placeholders** (set to 1 = safe)
- Requires external APIs for WHOIS, DNS, Google Safe Browsing
- Cannot extract content-based features without fetching HTML

### 2. Dataset Limitations
- Trained on 2012-2015 data
- May not reflect modern phishing techniques
- Balanced dataset may not represent real-world distribution
- No adversarial examples in training

### 3. Model Limitations
- Cannot detect zero-day phishing with novel features
- May produce false positives for legitimate sites with similar patterns
- No real-time monitoring (batch analysis only)

## Forensic Limitations

### 1. Evidence Integrity
- SHA-256 hashes verify integrity, not authenticity
- Timestamps depend on system clock accuracy
- No chain-of-custody documentation yet

### 2. Collection Limitations
- Browser automation not yet implemented
- No screenshot or HTML preservation
- No network traffic capture

## Operational Limitations

### 1. Performance
- Feature extraction is sequential (not parallel)
- Large batch processing not optimized
- No caching for repeated URLs

### 2. Deployment
- No web interface yet
- No browser extension
- No API for integration

## Ethical Considerations

- Tool should only be used for defensive purposes
- Users must have authorization to investigate targets
- Evidence should be reviewed by qualified analysts
- Reports should not be used as sole evidence in legal proceedings

## Planned Fixes (Roadmap)

| Limitation | Planned Fix | Phase |
|------------|-------------|-------|
| Placeholder features | Add WHOIS, DNS, Safe Browsing APIs | Phase 2 |
| No explainability | Add SHAP | Phase 2 |
| No evidence capture | Add Playwright | Phase 3 |
| No report generation | Add HTML/PDF reports | Phase 4 |
| No email analysis | Add .eml parser | Phase 5 |