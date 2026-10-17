"""
PhishTrace Web Interface
Streamlit app for phishing investigation.
"""

import streamlit as st
import os
import sys
import tempfile
import base64

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from url_analyzer_ml import predict_url
from email_analyzer import analyze_email
from report_generator import generate_report


# Page config
st.set_page_config(
    page_title="PhishTrace",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        padding: 30px;
        border-radius: 12px;
        color: white;
        text-align: center;
        margin-bottom: 30px;
    }
    .main-header h1 { margin: 0; font-size: 36px; }
    .main-header p { margin: 8px 0 0 0; opacity: 0.8; }
    .verdict-box {
        padding: 25px;
        border-radius: 10px;
        text-align: center;
        font-weight: 600;
        margin: 20px 0;
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
    .verdict-unknown {
        background: #f0f0f0;
        border: 2px solid #666;
        color: #333;
    }
    .reason-box {
        padding: 10px 15px;
        margin: 6px 0;
        background: #fff5f5;
        border-left: 4px solid #e74c3c;
        border-radius: 0 4px 4px 0;
    }
    .metric-card {
        background: #f8f9fa;
        padding: 15px;
        border-radius: 8px;
        text-align: center;
    }
    .metric-card h3 { margin: 0; font-size: 28px; color: #1a1a2e; }
    .metric-card p { margin: 5px 0 0 0; color: #666; font-size: 13px; }
</style>
""", unsafe_allow_html=True)


# Header
st.markdown("""
<div class="main-header">
    <h1>🔍 PhishTrace</h1>
    <p>Forensic-First Phishing Investigation Platform</p>
</div>
""", unsafe_allow_html=True)


# Sidebar
with st.sidebar:
    st.header("⚙️ Settings")
    input_type = st.radio(
        "Choose input type:",
        ["URL", "Email (.eml file)"]
    )
    st.markdown("---")
    st.markdown("### 📊 About")
    st.markdown("""
    **PhishTrace** combines:
    - 🤖 Machine Learning (Random Forest)
    - 🧠 SHAP Explainability
    - 🔎 Heuristic Analysis
    - 📁 Forensic Evidence Collection
    - 📄 Professional Reports
    """)
    st.markdown("---")
    st.markdown("### ⚠️ Safety")
    st.markdown("""
    - Only investigate URLs you are authorized to test
    - Use isolated VMs for suspicious URLs
    - This tool is for **defensive purposes only**
    """)


# Main content
if input_type == "URL":
    st.subheader("🔗 Investigate a URL")

    col1, col2 = st.columns([3, 1])
    with col1:
        url = st.text_input(
            "Enter URL to investigate:",
            placeholder="https://example.com",
            label_visibility="collapsed"
        )
    with col2:
        investigate_btn = st.button("🔍 Investigate", type="primary", use_container_width=True)

    if investigate_btn and url:
        with st.spinner("Analyzing URL..."):
            result = predict_url(url)

        # Verdict
        verdict = result['verdict']
        verdict_class = verdict.lower()
        icons = {'PHISHING': '⚠️', 'SUSPICIOUS': '🔶', 'SAFE': '✅', 'UNKNOWN': '❓'}

        st.markdown(f"""
        <div class="verdict-box verdict-{verdict_class}">
            <div style="font-size: 32px;">{icons.get(verdict, '❓')} {verdict}</div>
            <div style="font-size: 18px; margin-top: 8px;">Risk Score: {result['score']}/100</div>
        </div>
        """, unsafe_allow_html=True)

        # Metrics
        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown(f"""
            <div class="metric-card">
                <h3>{result['score']}</h3>
                <p>Risk Score</p>
            </div>
            """, unsafe_allow_html=True)
        with col2:
            conf = result.get('ml_confidence', 0)
            st.markdown(f"""
            <div class="metric-card">
                <h3>{conf * 100:.0f}%</h3>
                <p>ML Confidence</p>
            </div>
            """, unsafe_allow_html=True)
        with col3:
            st.markdown(f"""
            <div class="metric-card">
                <h3>{len(result['reasons'])}</h3>
                <p>Indicators Found</p>
            </div>
            """, unsafe_allow_html=True)

        # Indicators
        st.markdown("### 🔎 Indicators Found")
        for reason in result['reasons']:
            st.markdown(f'<div class="reason-box">{reason}</div>', unsafe_allow_html=True)

        # SHAP Explanation
        if result.get('shap_explanation'):
            st.markdown("### 🧠 Explainability (SHAP)")
            st.markdown("*Top features contributing to the model's decision:*")

            contributions = result['shap_explanation']['top_contributions']
            max_val = max(abs(c['shap_value']) for c in contributions) if contributions else 1

            for contrib in contributions:
                col1, col2 = st.columns([2, 3])
                with col1:
                    st.text(contrib['feature'])
                with col2:
                    bar_value = abs(contrib['shap_value']) / max_val
                    color = "🔴" if contrib['shap_value'] > 0 else "🟢"
                    st.progress(bar_value, text=f"{color} {contrib['shap_value']:+.4f}")

        # Generate Report Button
        st.markdown("---")
        if st.button("📄 Generate Full Investigation Report", type="primary"):
            with st.spinner("Generating report..."):
                report_path = generate_report(result)

            with open(report_path, 'r', encoding='utf-8') as f:
                report_html = f.read()

            st.download_button(
                label="⬇️ Download Report (HTML)",
                data=report_html,
                file_name=os.path.basename(report_path),
                mime="text/html"
            )


elif input_type == "Email (.eml file)":
    st.subheader("📧 Investigate an Email")

    uploaded_file = st.file_uploader(
        "Upload a .eml file:",
        type=['eml'],
        help="Save an email from your email client as .eml and upload it here."
    )

    if uploaded_file is not None:
        # Save to temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.eml') as tmp:
            tmp.write(uploaded_file.getvalue())
            tmp_path = tmp.name

        with st.spinner("Analyzing email..."):
            result = analyze_email(tmp_path)

        # Verdict
        verdict = result['verdict']
        verdict_class = verdict.lower()
        icons = {'PHISHING': '⚠️', 'SUSPICIOUS': '🔶', 'SAFE': '✅', 'UNKNOWN': '❓'}

        st.markdown(f"""
        <div class="verdict-box verdict-{verdict_class}">
            <div style="font-size: 32px;">{icons.get(verdict, '❓')} {verdict}</div>
            <div style="font-size: 18px; margin-top: 8px;">Risk Score: {result['score']}/100</div>
        </div>
        """, unsafe_allow_html=True)

        # Email details
        st.markdown("### 📋 Email Details")
        col1, col2 = st.columns(2)
        with col1:
            st.text_input("From", result.get('from', 'Unknown'), disabled=True)
            st.text_input("Reply-To", result.get('reply_to', 'N/A'), disabled=True)
        with col2:
            st.text_input("Subject", result.get('subject', 'No subject'), disabled=True)
            st.text_input("URLs Found", str(len(result.get('urls_found', []))), disabled=True)

        # Indicators
        st.markdown("### 🔎 Indicators Found")
        for reason in result['reasons']:
            st.markdown(f'<div class="reason-box">{reason}</div>', unsafe_allow_html=True)

        # URL Analysis
        if result.get('url_analyses'):
            st.markdown("### 🔗 URL Analysis")
            for url_result in result['url_analyses']:
                color_map = {
                    'PHISHING': '🔴',
                    'SUSPICIOUS': '🟡',
                    'SAFE': '🟢'
                }
                icon = color_map.get(url_result['verdict'], '⚪')
                st.markdown(f"{icon} **{url_result['verdict']}** — `{url_result['url'][:80]}` (Score: {url_result['score']}/100)")

        # Generate Report
        st.markdown("---")
        if st.button("📄 Generate Email Report", type="primary"):
            with st.spinner("Generating report..."):
                report_path = generate_report(result)

            with open(report_path, 'r', encoding='utf-8') as f:
                report_html = f.read()

            st.download_button(
                label="⬇️ Download Report (HTML)",
                data=report_html,
                file_name=os.path.basename(report_path),
                mime="text/html"
            )

        # Cleanup
        os.unlink(tmp_path)


# Footer
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #666; font-size: 12px;">
    <p><strong>PhishTrace</strong> — Forensic-First Phishing Investigation Platform</p>
    <p>Built for educational and defensive purposes only.</p>
</div>
""", unsafe_allow_html=True)