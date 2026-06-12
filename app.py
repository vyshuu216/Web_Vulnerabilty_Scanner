"""
Automated Web Vulnerability Scanner
====================================
Main application entry point using Streamlit.
Author: Abhinav Rama
"""

import streamlit as st
import time
from datetime import datetime

from modules.header_analyzer import analyze_headers
from modules.ssl_inspector import inspect_ssl
from modules.port_scanner import scan_ports
from modules.server_analyzer import analyze_server
from modules.score_calculator import calculate_score
from modules.report_generator import generate_pdf_report
from database.db_manager import init_db, save_scan, get_scan_history, get_scan_by_id

# ─── Page Config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Web Vulnerability Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ─── Custom CSS ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@300;400;500;600;700&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }

    /* Dark background */
    .stApp {
        background: #0a0e1a;
        color: #e2e8f0;
    }

    /* Sidebar */
    [data-testid="stSidebar"] {
        background: #0d1117 !important;
        border-right: 1px solid #1e2d40;
    }

    /* Metric cards */
    .metric-card {
        background: linear-gradient(135deg, #0d1117 0%, #111827 100%);
        border: 1px solid #1e2d40;
        border-radius: 12px;
        padding: 20px;
        margin: 8px 0;
    }

    /* Score ring */
    .score-container {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        padding: 30px;
        background: linear-gradient(135deg, #0d1117 0%, #111827 100%);
        border: 1px solid #1e2d40;
        border-radius: 16px;
        margin: 10px 0;
    }

    .score-number {
        font-family: 'JetBrains Mono', monospace;
        font-size: 72px;
        font-weight: 700;
        line-height: 1;
        margin: 0;
    }

    .score-label {
        font-size: 13px;
        letter-spacing: 3px;
        text-transform: uppercase;
        color: #64748b;
        margin-top: 8px;
    }

    /* Status badges */
    .badge-pass {
        background: rgba(16, 185, 129, 0.15);
        color: #10b981;
        border: 1px solid rgba(16, 185, 129, 0.3);
        padding: 3px 12px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: 600;
        font-family: 'JetBrains Mono', monospace;
    }

    .badge-fail {
        background: rgba(239, 68, 68, 0.15);
        color: #ef4444;
        border: 1px solid rgba(239, 68, 68, 0.3);
        padding: 3px 12px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: 600;
        font-family: 'JetBrains Mono', monospace;
    }

    .badge-warn {
        background: rgba(245, 158, 11, 0.15);
        color: #f59e0b;
        border: 1px solid rgba(245, 158, 11, 0.3);
        padding: 3px 12px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: 600;
        font-family: 'JetBrains Mono', monospace;
    }

    /* Section headers */
    .section-header {
        font-family: 'JetBrains Mono', monospace;
        font-size: 11px;
        letter-spacing: 3px;
        text-transform: uppercase;
        color: #00d4ff;
        margin: 24px 0 12px 0;
        padding-bottom: 8px;
        border-bottom: 1px solid #1e2d40;
    }

    /* Finding rows */
    .finding-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 12px 16px;
        margin: 4px 0;
        background: #0d1117;
        border: 1px solid #1e2d40;
        border-radius: 8px;
        font-size: 13px;
    }

    .finding-name {
        font-family: 'JetBrains Mono', monospace;
        color: #94a3b8;
    }

    /* Port table */
    .port-open {
        color: #ef4444;
        font-weight: 600;
        font-family: 'JetBrains Mono', monospace;
    }

    .port-closed {
        color: #374151;
        font-family: 'JetBrains Mono', monospace;
    }

    /* SSL info */
    .ssl-valid {
        color: #10b981;
        font-weight: 600;
    }

    .ssl-invalid {
        color: #ef4444;
        font-weight: 600;
    }

    /* Scan button */
    .stButton > button {
        background: linear-gradient(135deg, #00d4ff 0%, #0099cc 100%);
        color: #000;
        border: none;
        font-weight: 700;
        font-family: 'Inter', sans-serif;
        letter-spacing: 1px;
        padding: 12px 32px;
        border-radius: 8px;
        font-size: 14px;
        width: 100%;
        transition: all 0.2s;
    }

    .stButton > button:hover {
        opacity: 0.85;
        transform: translateY(-1px);
    }

    /* Input box */
    .stTextInput > div > div > input {
        background: #0d1117;
        border: 1px solid #1e2d40;
        color: #e2e8f0;
        border-radius: 8px;
        font-family: 'JetBrains Mono', monospace;
    }

    /* Download button */
    .stDownloadButton > button {
        background: linear-gradient(135deg, #7c3aed 0%, #5b21b6 100%);
        color: white;
        border: none;
        font-weight: 600;
        border-radius: 8px;
        width: 100%;
    }

    /* History table */
    .history-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 10px 16px;
        margin: 4px 0;
        background: #0d1117;
        border: 1px solid #1e2d40;
        border-radius: 8px;
        font-size: 12px;
        font-family: 'JetBrains Mono', monospace;
    }

    /* Expander */
    .streamlit-expanderHeader {
        background: #0d1117 !important;
        border: 1px solid #1e2d40 !important;
        border-radius: 8px !important;
        color: #94a3b8 !important;
    }

    /* Divider */
    hr {
        border-color: #1e2d40;
    }

    /* Hide Streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}

    /* Progress bar */
    .stProgress > div > div > div > div {
        background: linear-gradient(90deg, #00d4ff, #7c3aed);
    }
</style>
""", unsafe_allow_html=True)


def render_score_badge(score):
    """Return color based on security score range."""
    if score >= 80:
        return "#10b981", "SECURE"
    elif score >= 60:
        return "#f59e0b", "MODERATE"
    elif score >= 40:
        return "#f97316", "VULNERABLE"
    else:
        return "#ef4444", "CRITICAL"


def render_badge(status):
    """Render a colored status badge."""
    if status in ["PASS", "VALID", "PRESENT", "ENABLED", "YES"]:
        return f'<span class="badge-pass">✓ {status}</span>'
    elif status in ["WARN", "WARNING", "WEAK", "EXPIRING"]:
        return f'<span class="badge-warn">⚠ {status}</span>'
    else:
        return f'<span class="badge-fail">✗ {status}</span>'


# ─── Initialize Database ─────────────────────────────────────────────────────
init_db()

# ─── Sidebar ─────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="text-align:center; padding: 20px 0 10px 0;">
        <div style="font-size: 48px;">🛡️</div>
        <div style="font-family: 'JetBrains Mono', monospace; font-size: 14px;
                    color: #00d4ff; letter-spacing: 2px; margin-top: 8px;">
            WEB VULN SCANNER
        </div>
        <div style="font-size: 11px; color: #4b5563; margin-top: 4px;">
            OWASP Security Assessment Tool
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    page = st.radio(
        "Navigation",
        ["🔍 Scanner", "📋 Scan History", "ℹ️ About"],
        label_visibility="collapsed"
    )

    st.markdown("---")
    st.markdown("""
    <div style="font-size: 11px; color: #374151; text-align: center; padding: 10px;">
        <div style="color: #4b5563;">OWASP Top 10 Coverage</div>
        <div style="margin-top: 8px; color: #10b981;">✓ Security Headers</div>
        <div style="color: #10b981;">✓ SSL/TLS Inspection</div>
        <div style="color: #10b981;">✓ Port Scanning</div>
        <div style="color: #10b981;">✓ Server Fingerprinting</div>
        <div style="color: #10b981;">✓ Misconfiguration Detection</div>
    </div>
    """, unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: SCANNER
# ═══════════════════════════════════════════════════════════════════════════════
if "🔍 Scanner" in page:

    st.markdown("""
    <h1 style="font-family: 'JetBrains Mono', monospace; font-size: 26px;
               color: #e2e8f0; margin-bottom: 4px;">
        Automated Web Vulnerability Scanner
    </h1>
    <p style="color: #4b5563; font-size: 13px; margin-bottom: 24px;">
        OWASP-aligned security assessment • HTTP headers • SSL • Ports • Server fingerprinting
    </p>
    """, unsafe_allow_html=True)

    # URL input
    col_input, col_btn = st.columns([4, 1])
    with col_input:
        target_url = st.text_input(
            "Target URL",
            placeholder="https://example.com",
            label_visibility="collapsed"
        )
    with col_btn:
        scan_clicked = st.button("⚡ SCAN", use_container_width=True)

    # ── Scan Logic ─────────────────────────────────────────────────────────────
    if scan_clicked:
        if not target_url:
            st.error("Please enter a target URL.")
        else:
            # Normalize URL
            if not target_url.startswith("http"):
                target_url = "https://" + target_url

            st.markdown("---")
            st.markdown(f"""
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 12px;
                        color: #00d4ff; margin-bottom: 16px;">
                ▶ Scanning: {target_url}
            </div>
            """, unsafe_allow_html=True)

            progress = st.progress(0)
            status_text = st.empty()

            # Step 1 – Headers
            status_text.markdown(
                '<span style="font-family:JetBrains Mono; font-size:12px; color:#94a3b8;">'
                '[ 1/4 ] Analyzing HTTP Security Headers...</span>',
                unsafe_allow_html=True
            )
            header_results = analyze_headers(target_url)
            progress.progress(25)
            time.sleep(0.3)

            # Step 2 – SSL
            status_text.markdown(
                '<span style="font-family:JetBrains Mono; font-size:12px; color:#94a3b8;">'
                '[ 2/4 ] Inspecting SSL/TLS Certificate...</span>',
                unsafe_allow_html=True
            )
            ssl_results = inspect_ssl(target_url)
            progress.progress(50)
            time.sleep(0.3)

            # Step 3 – Ports
            status_text.markdown(
                '<span style="font-family:JetBrains Mono; font-size:12px; color:#94a3b8;">'
                '[ 3/4 ] Scanning Common Ports...</span>',
                unsafe_allow_html=True
            )
            port_results = scan_ports(target_url)
            progress.progress(75)
            time.sleep(0.3)

            # Step 4 – Server
            status_text.markdown(
                '<span style="font-family:JetBrains Mono; font-size:12px; color:#94a3b8;">'
                '[ 4/4 ] Fingerprinting Server Information...</span>',
                unsafe_allow_html=True
            )
            server_results = analyze_server(target_url)
            progress.progress(100)
            time.sleep(0.3)

            status_text.empty()
            progress.empty()

            # Calculate score
            score, score_breakdown = calculate_score(header_results, ssl_results, port_results, server_results)
            score_color, score_label = render_score_badge(score)

            # Save to DB
            scan_id = save_scan(target_url, score, header_results, ssl_results, port_results, server_results)

            st.markdown("---")

            # ── Results Layout ─────────────────────────────────────────────────
            col_score, col_summary = st.columns([1, 2])

            with col_score:
                st.markdown(f"""
                <div class="score-container">
                    <div class="score-number" style="color: {score_color};">{score}</div>
                    <div class="score-label">Security Score</div>
                    <div style="margin-top: 16px;">
                        <span style="background: {score_color}22; color: {score_color};
                                     border: 1px solid {score_color}44; padding: 4px 18px;
                                     border-radius: 20px; font-size: 13px; font-weight: 700;
                                     font-family: 'JetBrains Mono', monospace; letter-spacing: 2px;">
                            {score_label}
                        </span>
                    </div>
                    <div style="margin-top: 20px; width: 100%; font-size: 12px; color: #4b5563;
                                font-family: 'JetBrains Mono', monospace;">
                        <div style="display:flex; justify-content:space-between; padding: 4px 0;">
                            <span>Headers</span>
                            <span style="color:#94a3b8">{score_breakdown['headers']}/35</span>
                        </div>
                        <div style="display:flex; justify-content:space-between; padding: 4px 0;">
                            <span>SSL/TLS</span>
                            <span style="color:#94a3b8">{score_breakdown['ssl']}/30</span>
                        </div>
                        <div style="display:flex; justify-content:space-between; padding: 4px 0;">
                            <span>Ports</span>
                            <span style="color:#94a3b8">{score_breakdown['ports']}/20</span>
                        </div>
                        <div style="display:flex; justify-content:space-between; padding: 4px 0;">
                            <span>Server</span>
                            <span style="color:#94a3b8">{score_breakdown['server']}/15</span>
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)

            with col_summary:
                # Stats row
                open_ports = [p for p in port_results["ports"] if p["status"] == "OPEN"]
                headers_passed = sum(1 for h in header_results["headers"] if h["status"] == "PASS")
                total_headers = len(header_results["headers"])

                m1, m2, m3 = st.columns(3)
                with m1:
                    st.metric("Open Ports", len(open_ports), delta=f"-{len(open_ports)} risk" if open_ports else "None found", delta_color="inverse")
                with m2:
                    st.metric("Headers Passed", f"{headers_passed}/{total_headers}")
                with m3:
                    ssl_status = ssl_results.get("valid", False)
                    st.metric("SSL Status", "Valid ✓" if ssl_status else "Invalid ✗")

                st.markdown(f"""
                <div style="font-family: 'JetBrains Mono', monospace; font-size: 11px;
                            color: #4b5563; margin-top: 12px; padding: 12px 16px;
                            background: #0d1117; border: 1px solid #1e2d40; border-radius: 8px;">
                    <span style="color:#00d4ff;">TARGET</span> &nbsp; {target_url}<br>
                    <span style="color:#00d4ff;">SCAN ID</span> &nbsp; #{scan_id:04d}<br>
                    <span style="color:#00d4ff;">TIME</span> &nbsp;&nbsp;&nbsp; {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
                    <span style="color:#00d4ff;">SERVER</span> &nbsp; {server_results.get('server', 'Unknown')}
                </div>
                """, unsafe_allow_html=True)

            st.markdown("---")

            # ── Detailed Results Tabs ──────────────────────────────────────────
            tab1, tab2, tab3, tab4 = st.tabs(["🔒 Security Headers", "🔐 SSL / TLS", "🌐 Open Ports", "🖥 Server Info"])

            with tab1:
                st.markdown('<div class="section-header">HTTP SECURITY HEADER ANALYSIS</div>', unsafe_allow_html=True)
                for h in header_results["headers"]:
                    badge = render_badge(h["status"])
                    st.markdown(f"""
                    <div class="finding-row">
                        <div>
                            <span class="finding-name">{h['name']}</span>
                            <div style="font-size: 11px; color: #374151; margin-top: 3px;">{h['description']}</div>
                            {f'<div style="font-size: 11px; color: #4b5563; margin-top: 2px; font-family: JetBrains Mono;">Value: {h["value"]}</div>' if h.get("value") else ""}
                        </div>
                        <div style="flex-shrink:0; margin-left: 16px;">{badge}</div>
                    </div>
                    """, unsafe_allow_html=True)

                if header_results.get("recommendations"):
                    st.markdown('<div class="section-header" style="margin-top:20px;">REMEDIATION RECOMMENDATIONS</div>', unsafe_allow_html=True)
                    for rec in header_results["recommendations"]:
                        st.markdown(f"""
                        <div style="padding: 10px 16px; margin: 4px 0; background: rgba(245,158,11,0.05);
                                    border-left: 3px solid #f59e0b; border-radius: 0 8px 8px 0;
                                    font-size: 12px; color: #94a3b8;">
                            ⚠ {rec}
                        </div>
                        """, unsafe_allow_html=True)

            with tab2:
                st.markdown('<div class="section-header">SSL / TLS CERTIFICATE INSPECTION</div>', unsafe_allow_html=True)
                ssl_fields = [
                    ("Certificate Valid", "valid", lambda v: "VALID" if v else "INVALID"),
                    ("Subject", "subject", str),
                    ("Issuer", "issuer", str),
                    ("Valid From", "not_before", str),
                    ("Valid Until", "not_after", str),
                    ("Days Until Expiry", "days_left", lambda v: f"{v} days"),
                    ("TLS Version", "tls_version", str),
                    ("Self-Signed", "self_signed", lambda v: "YES (Risk)" if v else "NO"),
                    ("Wildcard Certificate", "wildcard", lambda v: "YES" if v else "NO"),
                ]
                for label, key, fmt in ssl_fields:
                    val = ssl_results.get(key, "N/A")
                    if val == "N/A":
                        continue
                    display = fmt(val) if callable(fmt) else str(val)
                    # color logic
                    if key == "valid":
                        color = "#10b981" if val else "#ef4444"
                    elif key == "days_left":
                        color = "#10b981" if isinstance(val, int) and val > 30 else "#f59e0b" if isinstance(val, int) and val > 0 else "#ef4444"
                    elif key == "self_signed":
                        color = "#ef4444" if val else "#10b981"
                    else:
                        color = "#94a3b8"

                    st.markdown(f"""
                    <div class="finding-row">
                        <span class="finding-name">{label}</span>
                        <span style="color:{color}; font-family:'JetBrains Mono',monospace; font-size:12px;">{display}</span>
                    </div>
                    """, unsafe_allow_html=True)

                if ssl_results.get("error"):
                    st.error(f"SSL Error: {ssl_results['error']}")

            with tab3:
                st.markdown('<div class="section-header">PORT SCAN RESULTS — COMMON PORTS</div>', unsafe_allow_html=True)

                open_p = [p for p in port_results["ports"] if p["status"] == "OPEN"]
                closed_p = [p for p in port_results["ports"] if p["status"] == "CLOSED"]

                if open_p:
                    st.markdown(f'<div style="color:#ef4444; font-size:12px; font-family:JetBrains Mono; margin-bottom:8px;">⚠ {len(open_p)} open port(s) detected</div>', unsafe_allow_html=True)

                cols = st.columns(2)
                for i, p in enumerate(port_results["ports"]):
                    with cols[i % 2]:
                        color = "#ef4444" if p["status"] == "OPEN" else "#1e2d40"
                        text_color = "#ef4444" if p["status"] == "OPEN" else "#374151"
                        st.markdown(f"""
                        <div style="display:flex; justify-content:space-between; padding:8px 14px;
                                    margin:3px 0; background:#0d1117; border:1px solid {color};
                                    border-radius:6px; font-size:12px; font-family:'JetBrains Mono',monospace;">
                            <span style="color:#64748b;">{p['port']}/{p['service']}</span>
                            <span style="color:{text_color};">{'● OPEN' if p['status']=='OPEN' else '○ CLOSED'}</span>
                        </div>
                        """, unsafe_allow_html=True)

            with tab4:
                st.markdown('<div class="section-header">SERVER FINGERPRINT & CONFIGURATION</div>', unsafe_allow_html=True)
                server_fields = [
                    ("Server Software", "server"),
                    ("X-Powered-By", "powered_by"),
                    ("Technology Stack", "technology"),
                    ("CMS Detected", "cms"),
                    ("Cookies Secure", "cookies_secure"),
                    ("Redirects to HTTPS", "https_redirect"),
                    ("Response Time", "response_time"),
                    ("HTTP Version", "http_version"),
                ]
                for label, key in server_fields:
                    val = server_results.get(key, "N/A")
                    if val in [None, "", "N/A", "Unknown"]:
                        val_display = '<span style="color:#374151;">Not detected</span>'
                    else:
                        if val in [True, "YES", "Secure"]:
                            val_display = f'<span style="color:#10b981; font-family:JetBrains Mono;">{val}</span>'
                        elif val in [False, "NO", "Insecure"]:
                            val_display = f'<span style="color:#ef4444; font-family:JetBrains Mono;">{val}</span>'
                        else:
                            val_display = f'<span style="color:#94a3b8; font-family:JetBrains Mono;">{val}</span>'

                    st.markdown(f"""
                    <div class="finding-row">
                        <span class="finding-name">{label}</span>
                        <div>{val_display}</div>
                    </div>
                    """, unsafe_allow_html=True)

                if server_results.get("info_disclosure"):
                    st.markdown('<div style="margin-top:16px; padding:12px 16px; background:rgba(239,68,68,0.05); border-left:3px solid #ef4444; border-radius:0 8px 8px 0; font-size:12px; color:#ef4444;">⚠ Information Disclosure Risk: Server banner is exposing software details. Consider removing or masking server headers.</div>', unsafe_allow_html=True)

            # ── PDF Download ───────────────────────────────────────────────────
            st.markdown("---")
            pdf_bytes = generate_pdf_report(
                target_url, score, score_label, score_breakdown,
                header_results, ssl_results, port_results, server_results, scan_id
            )

            col_dl1, col_dl2, col_dl3 = st.columns([1, 2, 1])
            with col_dl2:
                st.download_button(
                    label="📄 Download PDF Security Report",
                    data=pdf_bytes,
                    file_name=f"vuln_scan_{target_url.replace('https://','').replace('http://','').replace('/','_')}_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )
                st.markdown(f'<div style="text-align:center; font-size:11px; color:#374151; margin-top:6px; font-family:JetBrains Mono;">Scan #{scan_id:04d} saved to history</div>', unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: HISTORY
# ═══════════════════════════════════════════════════════════════════════════════
elif "📋 Scan History" in page:
    st.markdown("""
    <h1 style="font-family: 'JetBrains Mono', monospace; font-size: 26px;
               color: #e2e8f0; margin-bottom: 4px;">Scan History</h1>
    <p style="color: #4b5563; font-size: 13px; margin-bottom: 24px;">
        All previous scans stored locally in SQLite
    </p>
    """, unsafe_allow_html=True)

    history = get_scan_history()

    if not history:
        st.markdown("""
        <div style="text-align:center; padding: 60px; color: #374151; font-family: JetBrains Mono; font-size: 13px;">
            No scans yet. Run your first scan from the Scanner page.
        </div>
        """, unsafe_allow_html=True)
    else:
        # Header row
        st.markdown("""
        <div style="display:flex; justify-content:space-between; padding: 8px 16px;
                    font-family:'JetBrains Mono',monospace; font-size:10px;
                    letter-spacing:2px; color:#374151; text-transform:uppercase; margin-bottom:4px;">
            <span>ID</span><span>TARGET</span><span>SCORE</span><span>GRADE</span><span>TIMESTAMP</span>
        </div>
        """, unsafe_allow_html=True)

        for row in history:
            scan_id, url, score, ts = row[0], row[1], row[2], row[3]
            color, label = render_score_badge(score)
            ts_fmt = ts[:16] if ts else "N/A"
            st.markdown(f"""
            <div class="history-row">
                <span style="color:#374151;">#{scan_id:04d}</span>
                <span style="color:#94a3b8; max-width:280px; overflow:hidden; text-overflow:ellipsis;">{url}</span>
                <span style="color:{color}; font-weight:700;">{score}</span>
                <span style="background:{color}22; color:{color}; border:1px solid {color}44;
                             padding:2px 10px; border-radius:12px; font-size:10px;">{label}</span>
                <span style="color:#374151;">{ts_fmt}</span>
            </div>
            """, unsafe_allow_html=True)

        st.markdown(f"""
        <div style="text-align:right; font-family:JetBrains Mono; font-size:11px;
                    color:#374151; margin-top:16px;">
            Total scans: {len(history)}
        </div>
        """, unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: ABOUT
# ═══════════════════════════════════════════════════════════════════════════════
elif "ℹ️ About" in page:
    st.markdown("""
    <h1 style="font-family: 'JetBrains Mono', monospace; font-size: 26px; color: #e2e8f0;">About</h1>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div style="background: #0d1117; border: 1px solid #1e2d40; border-radius: 12px; padding: 28px; margin-bottom: 20px;">
        <div style="font-family: 'JetBrains Mono', monospace; font-size: 18px; color: #00d4ff; margin-bottom: 8px;">
            🛡️ Automated Web Vulnerability Scanner
        </div>
        <div style="font-size: 13px; color: #64748b; line-height: 1.8;">
            A cybersecurity tool for performing OWASP-aligned vulnerability assessments
            on web applications. Built as part of a Cybersecurity internship project.
        </div>
    </div>

    <div style="background: #0d1117; border: 1px solid #1e2d40; border-radius: 12px; padding: 28px; margin-bottom: 20px;">
        <div style="font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #00d4ff;
                    letter-spacing: 2px; text-transform: uppercase; margin-bottom: 16px;">Modules</div>
        <div style="font-size: 13px; color: #64748b; line-height: 2.2;">
            <b style="color:#94a3b8;">HTTP Header Analyzer</b> — Checks for CSP, HSTS, X-Frame-Options, and 7 other critical headers<br>
            <b style="color:#94a3b8;">SSL Inspector</b> — Certificate validity, expiry, issuer, TLS version, and self-signed detection<br>
            <b style="color:#94a3b8;">Port Scanner</b> — Scans 15 common ports including SSH, FTP, Telnet, databases<br>
            <b style="color:#94a3b8;">Server Analyzer</b> — Fingerprints server software, CMS, cookie security, HTTPS redirect<br>
            <b style="color:#94a3b8;">Score Engine</b> — Weighted scoring across all modules (0–100)<br>
            <b style="color:#94a3b8;">PDF Report Generator</b> — Professional downloadable security report via ReportLab<br>
            <b style="color:#94a3b8;">Scan History</b> — SQLite-backed persistent scan storage
        </div>
    </div>

    <div style="background: #0d1117; border: 1px solid #1e2d40; border-radius: 12px; padding: 28px;">
        <div style="font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #00d4ff;
                    letter-spacing: 2px; text-transform: uppercase; margin-bottom: 16px;">Tech Stack</div>
        <div style="display: flex; flex-wrap: wrap; gap: 10px;">
            <span style="background:#1e2d40; color:#94a3b8; padding:4px 14px; border-radius:20px; font-size:12px; font-family:JetBrains Mono;">Python 3.10+</span>
            <span style="background:#1e2d40; color:#94a3b8; padding:4px 14px; border-radius:20px; font-size:12px; font-family:JetBrains Mono;">Streamlit</span>
            <span style="background:#1e2d40; color:#94a3b8; padding:4px 14px; border-radius:20px; font-size:12px; font-family:JetBrains Mono;">Requests</span>
            <span style="background:#1e2d40; color:#94a3b8; padding:4px 14px; border-radius:20px; font-size:12px; font-family:JetBrains Mono;">Socket</span>
            <span style="background:#1e2d40; color:#94a3b8; padding:4px 14px; border-radius:20px; font-size:12px; font-family:JetBrains Mono;">SSL</span>
            <span style="background:#1e2d40; color:#94a3b8; padding:4px 14px; border-radius:20px; font-size:12px; font-family:JetBrains Mono;">ReportLab</span>
            <span style="background:#1e2d40; color:#94a3b8; padding:4px 14px; border-radius:20px; font-size:12px; font-family:JetBrains Mono;">SQLite3</span>
        </div>
    </div>
    """, unsafe_allow_html=True)
