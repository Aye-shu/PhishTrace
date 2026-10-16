"""
PhishTrace Main Pipeline
Complete investigation workflow: URL → Analysis → Evidence → Report
"""

import os
import sys
import json
from url_analyzer_ml import predict_url, print_report
from report_generator import generate_report

def investigate(url, evidence_manifest=None):
    """
    Run a complete investigation on a URL.

    Args:
        url: The URL to investigate
        evidence_manifest: Path to evidence manifest JSON (optional)

    Returns:
        dict: Complete investigation result
    """
    print(f"\n{'='*60}")
    print(f"PHISHTRACE INVESTIGATION")
    print(f"{'='*60}")
    print(f"Target: {url}\n")

    # Step 1: URL Analysis
    print("[1/3] Analyzing URL...")
    result = predict_url(url)
    print(f"    Verdict: {result['verdict']}")
    print(f"    Score: {result['score']}/100")

    # Step 2: Load evidence if available
    evidence = None
    if evidence_manifest and os.path.exists(evidence_manifest):
        print(f"[2/3] Loading evidence from {evidence_manifest}...")
        with open(evidence_manifest, 'r') as f:
            evidence = json.load(f)
        print(f"    Artifacts: {len(evidence.get('artifacts', []))}")
    else:
        print("[2/3] No evidence manifest provided")

    # Step 3: Generate report
    print("[3/3] Generating investigation report...")
    report_path = generate_report(result, evidence)

    print(f"\n{'='*60}")
    print("INVESTIGATION COMPLETE")
    print(f"{'='*60}")
    print(f"Report: {report_path}")

    return result


if __name__ == "__main__":
    if len(sys.argv) < 2:
        url = input("Enter URL to investigate: ")
    else:
        url = sys.argv[1]

    # Check for evidence manifest
    manifest = sys.argv[2] if len(sys.argv) > 2 else None

    investigate(url, manifest)