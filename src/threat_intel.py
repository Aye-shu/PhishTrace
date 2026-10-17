"""
Threat Intelligence Module for PhishTrace.
Integrates with VirusTotal API to check URL reputation.
"""

import os
import base64
import requests
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
VT_API_URL = "https://www.virustotal.com/api/v3/urls"

def check_virustotal(url):
    """
    Check a URL against VirusTotal's database.
    Returns a dict with the analysis results.
    """
    if not VT_API_KEY:
        return {
            "status": "error",
            "message": "VirusTotal API key not configured.",
            "malicious_count": 0,
            "suspicious_count": 0,
            "total_engines": 0,
            "reasons": []
        }

    # VirusTotal requires the URL to be base64 encoded (without padding)
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }

    try:
        # Query the API
        response = requests.get(f"{VT_API_URL}/{url_id}", headers=headers, timeout=10)
        
        # If the URL has never been scanned, VT returns a 404
        if response.status_code == 404:
            return {
                "status": "not_found",
                "message": "URL not found in VirusTotal database (it has never been scanned).",
                "malicious_count": 0,
                "suspicious_count": 0,
                "total_engines": 0,
                "reasons": []
            }
            
        response.raise_for_status()
        data = response.json()

        # Extract the analysis stats
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        reasons = []
        if malicious > 0:
            reasons.append(f"Flagged by {malicious} security vendors as malicious.")
        if suspicious > 0:
            reasons.append(f"Flagged by {suspicious} security vendors as suspicious.")

        return {
            "status": "success",
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "total_engines": total,
            "reasons": reasons
        }

    except requests.exceptions.RequestException as e:
        return {
            "status": "error",
            "message": f"API Request failed: {str(e)}",
            "malicious_count": 0,
            "suspicious_count": 0,
            "total_engines": 0,
            "reasons": []
        }

if __name__ == "__main__":
    # Test the module
    test_url = "http://secure-login-verify.tk/account/update"
    print(f"Checking: {test_url}")
    result = check_virustotal(test_url)
    print(result)