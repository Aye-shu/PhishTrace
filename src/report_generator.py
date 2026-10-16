"""
Report Generator for PhishTrace.
Creates professional HTML investigation reports.
"""

import json
import os
import base64
from datetime import datetime
from jinja2 import Template


# HTML Template for the report
REPORT_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>PhishTrace Investigation Report</title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 40px 20px;
            background: #f0f2f5;
            color: #333;
            line-height: 1.6;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: white;
            padding: 30px 40px;
        }
        .header h1 {
            margin: 0;
            font-size: 28px;
            font-weight: 600;
        }
        .header .subtitle {
            margin-top: 8px;
            opacity: 0.8;
            font-size: 14px;
        }
        .content { padding: 40px; }
        h2 {
            color: #1a1a2e;
            border-bottom: 2px solid #e0e0e0;
            padding-bottom: 10px;
            margin-top: 35px;
            font-size: 20px;
        }
        h2:first-child { margin-top: 0; }
        .verdict-box {
            padding: 25px;
            border-radius: 8px;
            text-align: center;
            margin: 20px 0;
            font-weight: 600;
        }
        .verdict-phishing {
            background: #fee;
            border: 2px solid #e74c3c;
            color: #c0392b;
        }
        .verdict-suspicious {
            background: #fff8e1;
            border: 2px solid #f39c12;
            color: #d68910;
        }
        .verdict-safe {
            background: #e8f8f5;
            border: 2px solid #27ae60;
            color: #1e8449;
        }
        .verdict-box .verdict-label {
            font-size: 32px;
            display: block;
            margin-bottom: 8px;
        }
        .verdict-box .score {
            font-size: 18px;
            opacity: 0.8;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            font-size: 14px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e0e0e0;
        }
        th {
            background: #1a1a2e;
            color: white;
            font-weight: 600;
        }
        tr:hover { background: #f8f9fa; }
        .hash {
            font-family: 'Courier New', monospace;
            font-size: 11px;
            word-break: break-all;
            color: #666;
        }
        .reason {
            padding: 12px 16px;
            margin: 8px 0;
            background: #fff5f5;
            border-left: 4px solid #e74c3c;
            border-radius: 0 4px 4px 0;
        }
        .contrib-bar {
            display: flex;
            align-items: center;
            margin: 8px 0;
            font-size: 13px;
        }
        .contrib-bar .feature {
            width: 200px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
        }
        .contrib-bar .bar-container {
            flex: 1;
            height: 20px;
            background: #f0f0f0;
            border-radius: 10px;
            overflow: hidden;
            margin: 0 10px;
            position: relative;
        }
        .contrib-bar .bar {
            height: 100%;
            border-radius: 10px;
        }
        .contrib-bar .bar.positive { background: #e74c3c; }
        .contrib-bar .bar.negative { background: #27ae60; }
        .contrib-bar .value {
            width: 80px;
            text-align: right;
            font-family: 'Courier New', monospace;
            font-size: 12px;
        }
        .screenshot {
            max-width: 100%;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            margin: 15px 0;
        }
        .limitations {
            background: #fff9e6;
            border-left: 4px solid #f39c12;
            padding: 15px 20px;
            border-radius: 0 4px 4px 0;
            margin: 15px 0;
        }
        .footer {
            padding: 20px 40px;
            background: #f8f9fa;
            border-top: 1px solid #e0e0e0;
            font-size: 12px;
            color: #666;
            text-align: center;
        }
        .meta {
            display: flex;
            gap: 30px;
            margin: 15px 0;
            flex-wrap: wrap;
        }
        .meta-item {
            background: #f8f9fa;
            padding: 10px 15px;
            border-radius: 6px;
            font-size: 13px;
        }
        .meta-item strong { display: block; color: #1a1a2e; margin-bottom: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 PhishTrace Investigation Report</h1>
            <div class="subtitle">Forensic-First Phishing Analysis Platform</div>
        </div>

        <div class="content">
            <div class="meta">
                <div class="meta-item">
                    <strong>Report ID</strong>
                    {{ report_id }}
                </div>
                <div class="meta-item">
                    <strong>Generated</strong>
                    {{ timestamp }}
                </div>
                <div class="meta-item">
                    <strong>Analyst</strong>
                    {{ analyst }}
                </div>
            </div>

            <h2>📋 Investigation Target</h2>
            <table>
                <tr><th style="width: 200px;">Input</th><td>{{ url }}</td></tr>
                {% if page_title %}<tr><th>Page Title</th><td>{{ page_title }}</td></tr>{% endif %}
                {% if final_url %}<tr><th>Final URL</th><td>{{ final_url }}</td></tr>{% endif %}
            </table>

            <h2>⚖️ Verdict</h2>
            <div class="verdict-box verdict-{{ verdict_class }}">
                <span class="verdict-label">{{ verdict_icon }} {{ verdict }}</span>
                <span class="score">Risk Score: {{ score }}/100</span>
            </div>

            <h2>🔎 Indicators Found</h2>
            {% if reasons %}
                {% for reason in reasons %}
                <div class="reason">{{ reason }}</div>
                {% endfor %}
            {% else %}
                <p>No suspicious indicators detected.</p>
            {% endif %}

            {% if ml_confidence %}
            <h2>🤖 Machine Learning Analysis</h2>
            <table>
                <tr><th style="width: 200px;">Model Prediction</th><td>{{ ml_prediction_text }}</td></tr>
                <tr><th>ML Confidence</th><td>{{ "%.2f"|format(ml_confidence * 100) }}%</td></tr>
            </table>
            {% endif %}

            {% if shap_contributions %}
            <h2>🧠 Explainability (SHAP)</h2>
            <p style="font-size: 13px; color: #666;">Top features contributing to the model's decision:</p>
            {% for contrib in shap_contributions %}
            <div class="contrib-bar">
                <span class="feature">{{ contrib.feature }}</span>
                <div class="bar-container">
                    <div class="bar {{ 'positive' if contrib.shap_value > 0 else 'negative' }}"
                         style="width: {{ (contrib.shap_value|abs / max_shap * 100)|round(1) }}%;"></div>
                </div>
                <span class="value">{{ "+" if contrib.shap_value > 0 else "" }}{{ "%.4f"|format(contrib.shap_value) }}</span>
            </div>
            {% endfor %}
            {% endif %}

            {% if artifacts %}
            <h2>📁 Evidence Artifacts</h2>
            <table>
                <tr>
                    <th>Type</th>
                    <th>Size</th>
                    <th>SHA-256 Hash</th>
                </tr>
                {% for artifact in artifacts %}
                <tr>
                    <td>{{ artifact.type }}</td>
                    <td>{{ artifact.size_bytes }} bytes</td>
                    <td class="hash">{{ artifact.sha256 }}</td>
                </tr>
                {% endfor %}
            </table>
            {% endif %}

            {% if screenshot_base64 %}
            <h2>🖼️ Captured Screenshot</h2>
            <img src="data:image/png;base64,{{ screenshot_base64 }}" class="screenshot" alt="Captured screenshot">
            {% endif %}

            <h2>⚠️ Limitations</h2>
            <div class="limitations">
                <ul>
                    <li>This report is generated by an automated tool and may contain errors.</li>
                    <li>A "SAFE" verdict does not guarantee the website is harmless.</li>
                    <li>SHA-256 hashes verify integrity but not authenticity.</li>
                    <li>This report should be reviewed by a qualified analyst before use in legal proceedings.</li>
                    <li>The ML model has known limitations with placeholder features.</li>
                </ul>
            </div>

            <h2>📋 Recommendations</h2>
            <div style="background: #e8f4f8; border-left: 4px solid #3498db; padding: 15px 20px; border-radius: 0 4px 4px 0;">
                <ul style="margin: 0; padding-left: 20px;">
                    <li><strong>Do NOT visit this URL</strong> from any device containing sensitive data.</li>
                    <li>If you have already interacted with this URL, <strong>change your passwords immediately</strong>.</li>
                    <li>Report this URL to <a href="https://phishtank.org">PhishTank</a> or your local CERT.</li>
                    <li>For further investigation, consider running this in an isolated sandbox environment.</li>
                </ul>
            </div>
        </div>

        <div class="footer">
            <p><strong>PhishTrace</strong> — Forensic-First Phishing Investigation Platform</p>
            <p>Generated automatically. For educational and defensive purposes only.</p>
        </div>
    </div>
</body>
</html>
"""


def generate_report(analysis_result, evidence=None, output_path=None):
    """
    Generate a professional HTML investigation report.

    Args:
        analysis_result: Dict from predict_url() or analyze_email()
        evidence: Dict from EvidenceCollector.capture() (optional)
        output_path: Where to save the HTML file

    Returns:
        str: Path to generated report
    """
    # Handle email results differently
    if analysis_result.get('input_type') == 'Email':
        return generate_email_report(analysis_result, output_path)

    verdict = analysis_result.get('verdict', 'UNKNOWN')
    verdict_class = verdict.lower()

    # Verdict icons
    icons = {
        'PHISHING': '⚠️',
        'SUSPICIOUS': '🔶',
        'SAFE': '✅',
        'UNKNOWN': '❓'
    }

    # Prepare SHAP contributions
    shap_contributions = []
    max_shap = 0
    if analysis_result.get('shap_explanation'):
        shap_contributions = analysis_result['shap_explanation'].get('top_contributions', [])
        if shap_contributions:
            max_shap = max(abs(c['shap_value']) for c in shap_contributions)

    # Prepare screenshot (base64 encode if available)
    screenshot_base64 = None
    if evidence and evidence.get('artifacts'):
        for artifact in evidence['artifacts']:
            if artifact['type'] == 'screenshot':
                # Look for the screenshot file
                screenshot_path = os.path.join('evidence', artifact['path'])
                if os.path.exists(screenshot_path):
                    with open(screenshot_path, 'rb') as f:
                        screenshot_base64 = base64.b64encode(f.read()).decode('utf-8')
                    break

    # Build template data
    template_data = {
        'report_id': f"PT-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'analyst': 'PhishTrace Automated Analyst',
        'url': analysis_result.get('url', 'N/A'),
        'page_title': evidence.get('page_title') if evidence else None,
        'final_url': evidence.get('final_url') if evidence else None,
        'verdict': verdict,
        'verdict_class': verdict_class,
        'verdict_icon': icons.get(verdict, '❓'),
        'score': analysis_result.get('score', 0),
        'reasons': analysis_result.get('reasons', []),
        'ml_prediction_text': (
            'Phishing' if analysis_result.get('ml_prediction') == 1
            else 'Legitimate' if analysis_result.get('ml_prediction') == 0
            else 'N/A'
        ),
        'ml_confidence': analysis_result.get('ml_confidence'),
        'shap_contributions': shap_contributions,
        'max_shap': max_shap,
        'artifacts': evidence.get('artifacts', []) if evidence else [],
        'screenshot_base64': screenshot_base64
    }

    # Render template
    template = Template(REPORT_TEMPLATE)
    html_content = template.render(**template_data)

    # Save report
    if output_path is None:
        os.makedirs('reports', exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_path = f'reports/investigation_{timestamp}.html'

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f"✅ Report saved: {output_path}")
    return output_path


def generate_email_report(analysis_result, output_path=None):
    """Generate a report for an email investigation."""
    # Build email-specific report HTML
    url_rows = ""
    for url_result in analysis_result.get('url_analyses', []):
        color = {
            'PHISHING': '#e74c3c',
            'SUSPICIOUS': '#f39c12',
            'SAFE': '#27ae60'
        }.get(url_result['verdict'], '#666')

        url_rows += f"""
        <tr>
            <td><span style="color: {color}; font-weight: 600;">{url_result['verdict']}</span></td>
            <td style="word-break: break-all;">{url_result['url']}</td>
            <td>{url_result['score']}/100</td>
        </tr>
        """

    reasons_html = "".join([
        f'<div class="reason">{r}</div>'
        for r in analysis_result.get('reasons', [])
    ])

    html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>PhishTrace Email Report</title>
    <style>
        body {{ font-family: sans-serif; background: #f0f2f5; padding: 40px 20px; }}
        .container {{ max-width: 1000px; margin: 0 auto; background: white;
                     border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #1a1a2e, #16213e);
                  color: white; padding: 30px 40px; border-radius: 12px 12px 0 0; }}
        .content {{ padding: 40px; }}
        h2 {{ color: #1a1a2e; border-bottom: 2px solid #e0e0e0; padding-bottom: 10px; }}
        .verdict {{ padding: 25px; border-radius: 8px; text-align: center;
                   margin: 20px 0; font-weight: 600; font-size: 24px; }}
        .verdict-PHISHING {{ background: #fee; border: 2px solid #e74c3c; color: #c0392b; }}
        .verdict-SUSPICIOUS {{ background: #fff8e1; border: 2px solid #f39c12; color: #d68910; }}
        .verdict-SAFE {{ background: #e8f8f5; border: 2px solid #27ae60; color: #1e8449; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e0e0e0; }}
        th {{ background: #1a1a2e; color: white; }}
        .reason {{ padding: 12px 16px; margin: 8px 0; background: #fff5f5;
                  border-left: 4px solid #e74c3c; }}
        .limitations {{ background: #fff9e6; border-left: 4px solid #f39c12;
                       padding: 15px 20px; margin: 15px 0; }}
        .footer {{ padding: 20px 40px; background: #f8f9fa; text-align: center;
                  color: #666; font-size: 12px; border-radius: 0 0 12px 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📧 PhishTrace Email Investigation Report</h1>
            <div style="opacity: 0.8; margin-top: 8px;">Forensic-First Phishing Analysis</div>
        </div>
        <div class="content">
            <h2>📋 Email Details</h2>
            <table>
                <tr><th style="width: 200px;">From</th><td>{analysis_result.get('from', 'Unknown')}</td></tr>
                <tr><th>Reply-To</th><td>{analysis_result.get('reply_to', 'N/A')}</td></tr>
                <tr><th>Subject</th><td>{analysis_result.get('subject', 'No subject')}</td></tr>
                <tr><th>URLs Found</th><td>{len(analysis_result.get('urls_found', []))}</td></tr>
            </table>

            <h2>⚖️ Verdict</h2>
            <div class="verdict verdict-{analysis_result['verdict']}">
                {analysis_result['verdict']} — Risk Score: {analysis_result['score']}/100
            </div>

            <h2>🔎 Indicators Found</h2>
            {reasons_html if reasons_html else '<p>No suspicious indicators detected.</p>'}

            <h2>🔗 URL Analysis</h2>
            <table>
                <tr><th>Verdict</th><th>URL</th><th>Score</th></tr>
                {url_rows if url_rows else '<tr><td colspan="3">No URLs found in email body.</td></tr>'}
            </table>

            <h2>⚠️ Limitations</h2>
            <div class="limitations">
                <ul>
                    <li>Email authentication results depend on the email headers provided.</li>
                    <li>Missing authentication data does not prove fraud — it is unknown.</li>
                    <li>This report should be reviewed by a qualified analyst.</li>
                </ul>
            </div>
        </div>
        <div class="footer">
            <p><strong>PhishTrace</strong> — Email Investigation Report</p>
        </div>
    </div>
</body>
</html>
"""

    if output_path is None:
        os.makedirs('reports', exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_path = f'reports/email_investigation_{timestamp}.html'

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)

    print(f"✅ Email report saved: {output_path}")
    return output_path


if __name__ == "__main__":
    # Test report generation with sample data
    test_result = {
        'url': 'http://secure-login-verify.tk/account/update',
        'score': 85,
        'verdict': 'PHISHING',
        'reasons': [
            'Uses suspicious top-level domain (.tk)',
            'Contains phishing keywords: login, verify, account',
            'Too many hyphens in URL',
            'ML model predicts phishing (confidence: 92.5%)'
        ],
        'ml_prediction': 1,
        'ml_confidence': 0.925,
        'shap_explanation': {
            'top_contributions': [
                {'feature': 'SSLfinal_State', 'shap_value': 0.2668, 'value': -1},
                {'feature': 'URL_of_Anchor', 'shap_value': -0.1776, 'value': 1},
                {'feature': 'SFH', 'shap_value': -0.0897, 'value': 1},
                {'feature': 'having_Sub_Domain', 'shap_value': -0.0644, 'value': 1},
                {'feature': 'Domain_registeration_length', 'shap_value': 0.0611, 'value': 1},
            ],
            'confidence': 0.925
        }
    }

    generate_report(test_result)
    print("Test report generated successfully!")