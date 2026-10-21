"""
PhishTrace API Server
Allows the Chrome Extension to communicate with the Python backend.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import sys

# Add src to path so we can import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from url_analyzer_ml import predict_url

app = Flask(__name__)

# Allow CORS from any origin (this handles the preflight automatically)
CORS(app, resources={r"/*": {"origins": "*"}})

@app.route('/', methods=['GET'])
def home():
    return "<h1>🛡️ PhishTrace API is Running!</h1><p>Send a POST request to /analyze to use the tool.</p>"

@app.route('/analyze', methods=['POST', 'OPTIONS'])
def analyze():
    # Handle the preflight OPTIONS request
    if request.method == 'OPTIONS':
        return jsonify({"status": "ok"}), 200

    data = request.get_json()
    
    if not data or 'url' not in data:
        return jsonify({"error": "Missing 'url' in request body"}), 400
        
    url = data['url']
    
    # Ignore internal browser URLs
    if url.startswith("chrome://") or url.startswith("about:"):
        return jsonify({
            "url": url,
            "verdict": "SAFE",
            "score": 0,
            "reasons": ["Internal browser URL ignored."]
        })

    try:
        # Run the URL through the PhishTrace pipeline
        result = predict_url(url)
        
        return jsonify({
            "url": result['url'],
            "verdict": result['verdict'],
            "score": result['score'],
            "reasons": result['reasons']
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # Run on port 5000
    app.run(host='0.0.0.0', port=5000, debug=True)