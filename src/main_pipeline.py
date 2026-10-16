"""
PhishTrace Main Pipeline
Complete investigation workflow: URL or Email → Analysis → Report
"""

import os
import sys
import json

from url_analyzer_ml import predict_url, print_report
from email_analyzer import analyze_email, print_email_report
from report_generator import generate_report


def investigate(target, evidence_manifest=None):
    """
    Run a complete investigation on a URL or .eml email file.
    """
    print(f"\n{'='*60}")
    print(f"PHISHTRACE INVESTIGATION")
    print(f"{'='*60}")
    print(f"Target: {target}\n")

    # Detect input type
    if os.path.exists(target) and target.lower().endswith('.eml'):
        # Email investigation
        print("[1/3] Analyzing email...")
        result = analyze_email(target)
        print_email_report(result)
    else:
        # URL investigation
        print("[1/3] Analyzing URL...")
        result = predict_url(target)
        print_report(result)

    # Evidence (only for URLs)
    evidence = None
    if evidence_manifest and os.path.exists(evidence_manifest):
        print(f"\n[2/3] Loading evidence from {evidence_manifest}...")
        with open(evidence_manifest, 'r') as f:
            evidence = json.load(f)
        print(f"    Artifacts: {len(evidence.get('artifacts', []))}")
    else:
        print("\n[2/3] No evidence manifest provided")

    # Generate report
    print("\n[3/3] Generating investigation report...")
    report_path = generate_report(result, evidence)

    print(f"\n{'='*60}")
    print("INVESTIGATION COMPLETE")
    print(f"{'='*60}")
    print(f"Report: {report_path}")

    return result


if __name__ == "__main__":
    if len(sys.argv) < 2:
        target = input("Enter URL or .eml file path: ")
    else:
        target = sys.argv[1]

    manifest = sys.argv[2] if len(sys.argv) > 2 else None

    investigate(target, manifest)