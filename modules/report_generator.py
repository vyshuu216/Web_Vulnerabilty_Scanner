"""
PDF Report Generator
=====================
Generates a professional security assessment PDF report
using the ReportLab library.
"""

import io
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import (
    HexColor, white, black
)
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, HRFlowable, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus import PageBreak

# ── Color Palette ──────────────────────────────────────────────────────────────
COLOR_BG         = HexColor("#0a0e1a")
COLOR_DARK       = HexColor("#0d1117")
COLOR_BORDER     = HexColor("#1e2d40")
COLOR_ACCENT     = HexColor("#00d4ff")
COLOR_TEXT       = HexColor("#e2e8f0")
COLOR_MUTED      = HexColor("#64748b")
COLOR_GREEN      = HexColor("#10b981")
COLOR_RED        = HexColor("#ef4444")
COLOR_YELLOW     = HexColor("#f59e0b")
COLOR_ORANGE     = HexColor("#f97316")
COLOR_PURPLE     = HexColor("#7c3aed")
COLOR_WHITE      = white


def _score_color(score: int):
    if score >= 80:
        return COLOR_GREEN
    elif score >= 60:
        return COLOR_YELLOW
    elif score >= 40:
        return COLOR_ORANGE
    else:
        return COLOR_RED


def _score_label(score: int) -> str:
    if score >= 80:
        return "SECURE"
    elif score >= 60:
        return "MODERATE RISK"
    elif score >= 40:
        return "VULNERABLE"
    else:
        return "CRITICAL RISK"


def _status_color(status: str):
    if status in ["PASS", "VALID", "OPEN"]:  # OPEN ports are red
        if status == "OPEN":
            return COLOR_RED
        return COLOR_GREEN
    elif status in ["WARN", "EXPIRING"]:
        return COLOR_YELLOW
    else:
        return COLOR_RED


def generate_pdf_report(
    url: str,
    score: int,
    score_label_str: str,
    score_breakdown: dict,
    header_results: dict,
    ssl_results: dict,
    port_results: dict,
    server_results: dict,
    scan_id: int
) -> bytes:
    """
    Generate a complete PDF security report.

    Args:
        url              : Target URL that was scanned.
        score            : Overall security score (0–100).
        score_label_str  : Grade label (SECURE, MODERATE, etc.)
        score_breakdown  : Dict of per-module scores.
        header_results   : HTTP header analysis results.
        ssl_results      : SSL inspection results.
        port_results     : Port scan results.
        server_results   : Server analysis results.
        scan_id          : Database scan ID.

    Returns:
        bytes: PDF file content ready for download.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=20*mm,
        leftMargin=20*mm,
        topMargin=20*mm,
        bottomMargin=20*mm
    )

    styles = getSampleStyleSheet()

    # Custom styles
    style_h1 = ParagraphStyle("H1",
        fontSize=22, fontName="Helvetica-Bold",
        textColor=COLOR_TEXT, spaceAfter=4,
        alignment=TA_LEFT
    )
    style_h2 = ParagraphStyle("H2",
        fontSize=11, fontName="Helvetica-Bold",
        textColor=COLOR_ACCENT, spaceAfter=8, spaceBefore=16,
        borderPad=4
    )
    style_body = ParagraphStyle("Body",
        fontSize=9, fontName="Helvetica",
        textColor=COLOR_MUTED, spaceAfter=4, leading=14
    )
    style_mono = ParagraphStyle("Mono",
        fontSize=8, fontName="Courier",
        textColor=HexColor("#94a3b8"), spaceAfter=2
    )
    style_small = ParagraphStyle("Small",
        fontSize=8, fontName="Helvetica",
        textColor=COLOR_MUTED
    )
    style_center = ParagraphStyle("Center",
        fontSize=9, fontName="Helvetica",
        textColor=COLOR_MUTED, alignment=TA_CENTER
    )

    story = []
    W = 170 * mm  # usable width

    # ══════════════════════════════════════════════════════════════════════════
    # HEADER BANNER
    # ══════════════════════════════════════════════════════════════════════════
    header_data = [[
        Paragraph("🛡️  WEB VULNERABILITY SCANNER", ParagraphStyle("Banner",
            fontSize=16, fontName="Helvetica-Bold",
            textColor=COLOR_ACCENT, alignment=TA_LEFT
        )),
        Paragraph(f"Scan #{scan_id:04d}", ParagraphStyle("ScanID",
            fontSize=9, fontName="Courier",
            textColor=COLOR_MUTED, alignment=TA_RIGHT
        ))
    ]]
    header_table = Table(header_data, colWidths=[W * 0.7, W * 0.3])
    header_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), COLOR_DARK),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [COLOR_DARK]),
        ("TOPPADDING", (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
        ("LEFTPADDING", (0, 0), (-1, -1), 16),
        ("RIGHTPADDING", (0, 0), (-1, -1), 16),
        ("ROUNDEDCORNERS", (0, 0), (-1, -1), [8, 8, 8, 8]),
        ("LINEBELOW", (0, 0), (-1, -1), 1, COLOR_ACCENT),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 12))

    # ── Meta info row ──────────────────────────────────────────────────────────
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    meta_data = [[
        Paragraph(f"<b>TARGET</b>", style_small),
        Paragraph(f"<b>DATE</b>", style_small),
        Paragraph(f"<b>STANDARD</b>", style_small),
        Paragraph(f"<b>TOOL</b>", style_small),
    ], [
        Paragraph(url, style_mono),
        Paragraph(ts, style_mono),
        Paragraph("OWASP Top 10 (2021)", style_mono),
        Paragraph("Web Vulnerability Scanner v1.0", style_mono),
    ]]
    meta_table = Table(meta_data, colWidths=[W/4]*4)
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), COLOR_DARK),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("LINEBELOW", (0, 0), (-1, 0), 0.5, COLOR_BORDER),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 16))

    # ══════════════════════════════════════════════════════════════════════════
    # SCORE OVERVIEW
    # ══════════════════════════════════════════════════════════════════════════
    story.append(Paragraph("SECURITY ASSESSMENT SUMMARY", style_h2))

    sc = _score_color(score)
    score_data = [[
        Paragraph(str(score), ParagraphStyle("ScoreBig",
            fontSize=48, fontName="Helvetica-Bold",
            textColor=sc, alignment=TA_CENTER
        )),
        [
            Paragraph(f"<b>{_score_label(score)}</b>", ParagraphStyle("Grade",
                fontSize=14, fontName="Helvetica-Bold",
                textColor=sc
            )),
            Spacer(1, 6),
            Paragraph("Score Breakdown:", style_small),
            Spacer(1, 4),
            _make_breakdown_table(score_breakdown, style_mono, W),
        ]
    ]]
    score_table = Table(score_data, colWidths=[W * 0.25, W * 0.75])
    score_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), COLOR_DARK),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 16),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 16),
        ("LEFTPADDING", (0, 0), (-1, -1), 16),
        ("LINEAFTER", (0, 0), (0, -1), 1, COLOR_BORDER),
    ]))
    story.append(score_table)
    story.append(Spacer(1, 20))

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 1: HTTP HEADERS
    # ══════════════════════════════════════════════════════════════════════════
    story.append(Paragraph("01 — HTTP SECURITY HEADERS", style_h2))
    story.append(HRFlowable(width=W, thickness=0.5, color=COLOR_BORDER))
    story.append(Spacer(1, 8))

    passed = header_results.get("passed", 0)
    total = len(header_results.get("headers", []))
    story.append(Paragraph(
        f"Checked {total} security headers — {passed} passed, {total - passed} failed.",
        style_body
    ))
    story.append(Spacer(1, 8))

    header_table_data = [["HEADER NAME", "STATUS", "OWASP REF"]]
    for h in header_results.get("headers", []):
        status = h["status"]
        color = COLOR_GREEN if status == "PASS" else (COLOR_YELLOW if status == "WARN" else COLOR_RED)
        header_table_data.append([
            Paragraph(h["name"], style_mono),
            Paragraph(status, ParagraphStyle("status", fontSize=8, fontName="Helvetica-Bold", textColor=color)),
            Paragraph(h.get("owasp", "—"), style_small),
        ])

    ht = Table(header_table_data, colWidths=[W * 0.55, W * 0.2, W * 0.25])
    ht.setStyle(_section_table_style())
    story.append(ht)

    # Recommendations
    recs = header_results.get("recommendations", [])
    if recs:
        story.append(Spacer(1, 10))
        story.append(Paragraph("Remediation Recommendations:", ParagraphStyle("RecTitle",
            fontSize=9, fontName="Helvetica-Bold", textColor=COLOR_YELLOW, spaceAfter=4
        )))
        for rec in recs:
            story.append(Paragraph(f"• {rec}", style_body))

    story.append(Spacer(1, 20))

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 2: SSL / TLS
    # ══════════════════════════════════════════════════════════════════════════
    story.append(Paragraph("02 — SSL / TLS CERTIFICATE", style_h2))
    story.append(HRFlowable(width=W, thickness=0.5, color=COLOR_BORDER))
    story.append(Spacer(1, 8))

    ssl_fields = [
        ("Certificate Valid", "valid", lambda v: ("VALID", COLOR_GREEN) if v else ("INVALID", COLOR_RED)),
        ("Subject", "subject", lambda v: (str(v), COLOR_MUTED)),
        ("Issuer", "issuer", lambda v: (str(v), COLOR_MUTED)),
        ("Valid From", "not_before", lambda v: (str(v), COLOR_MUTED)),
        ("Valid Until", "not_after", lambda v: (str(v), COLOR_MUTED)),
        ("Days Until Expiry", "days_left", lambda v: (f"{v} days", COLOR_GREEN if v and v > 30 else COLOR_RED)),
        ("TLS Version", "tls_version", lambda v: (str(v), COLOR_GREEN if "1.3" in str(v) else COLOR_YELLOW)),
        ("Self-Signed", "self_signed", lambda v: ("YES — Risk" if v else "NO", COLOR_RED if v else COLOR_GREEN)),
        ("Wildcard Cert", "wildcard", lambda v: ("YES" if v else "NO", COLOR_MUTED)),
    ]

    ssl_data = [["ATTRIBUTE", "VALUE"]]
    for label, key, fmt in ssl_fields:
        val = ssl_results.get(key, "N/A")
        if val == "N/A":
            continue
        display, color = fmt(val)
        ssl_data.append([
            Paragraph(label, style_small),
            Paragraph(str(display), ParagraphStyle("ssval", fontSize=8, fontName="Courier", textColor=color)),
        ])

    slt = Table(ssl_data, colWidths=[W * 0.35, W * 0.65])
    slt.setStyle(_section_table_style())
    story.append(slt)

    if ssl_results.get("error"):
        story.append(Spacer(1, 8))
        story.append(Paragraph(f"⚠ SSL Error: {ssl_results['error']}", ParagraphStyle(
            "err", fontSize=8, fontName="Helvetica", textColor=COLOR_RED
        )))

    story.append(Spacer(1, 20))

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 3: PORT SCAN
    # ══════════════════════════════════════════════════════════════════════════
    story.append(Paragraph("03 — PORT SCAN RESULTS", style_h2))
    story.append(HRFlowable(width=W, thickness=0.5, color=COLOR_BORDER))
    story.append(Spacer(1, 8))

    open_ports = [p for p in port_results.get("ports", []) if p["status"] == "OPEN"]
    story.append(Paragraph(
        f"Scanned {len(port_results.get('ports', []))} common ports. "
        f"{len(open_ports)} open port(s) detected.",
        style_body
    ))
    story.append(Spacer(1, 8))

    port_data = [["PORT", "SERVICE", "STATUS", "RISK LEVEL"]]
    for p in port_results.get("ports", []):
        s_color = COLOR_RED if p["status"] == "OPEN" else COLOR_MUTED
        r_color = {
            "CRITICAL": COLOR_RED, "HIGH": COLOR_ORANGE,
            "MEDIUM": COLOR_YELLOW, "LOW": COLOR_GREEN, "NONE": COLOR_MUTED
        }.get(p.get("risk", "NONE"), COLOR_MUTED)

        port_data.append([
            Paragraph(str(p["port"]), style_mono),
            Paragraph(p["service"], style_mono),
            Paragraph(p["status"], ParagraphStyle("ps", fontSize=8, fontName="Helvetica-Bold", textColor=s_color)),
            Paragraph(p.get("risk", "—"), ParagraphStyle("pr", fontSize=8, fontName="Helvetica-Bold", textColor=r_color)),
        ])

    pt = Table(port_data, colWidths=[W * 0.15, W * 0.3, W * 0.2, W * 0.35])
    pt.setStyle(_section_table_style())
    story.append(pt)
    story.append(Spacer(1, 20))

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 4: SERVER INFO
    # ══════════════════════════════════════════════════════════════════════════
    story.append(Paragraph("04 — SERVER INFORMATION", style_h2))
    story.append(HRFlowable(width=W, thickness=0.5, color=COLOR_BORDER))
    story.append(Spacer(1, 8))

    srv_fields = [
        ("Server Software", server_results.get("server", "Unknown")),
        ("X-Powered-By", server_results.get("powered_by") or "Not exposed"),
        ("Technology", server_results.get("technology") or "Not detected"),
        ("CMS", server_results.get("cms") or "Not detected"),
        ("HTTPS Redirect", "YES" if server_results.get("https_redirect") else "NO"),
        ("Cookies Secure", str(server_results.get("cookies_secure", "N/A"))),
        ("HTTP Version", server_results.get("http_version", "Unknown")),
        ("Response Time", server_results.get("response_time", "N/A")),
        ("Info Disclosure Risk", "YES — Banner exposed" if server_results.get("info_disclosure") else "NO"),
    ]

    srv_data = [["ATTRIBUTE", "VALUE"]]
    for label, val in srv_fields:
        srv_data.append([
            Paragraph(label, style_small),
            Paragraph(str(val), style_mono),
        ])

    svt = Table(srv_data, colWidths=[W * 0.4, W * 0.6])
    svt.setStyle(_section_table_style())
    story.append(svt)
    story.append(Spacer(1, 30))

    # ══════════════════════════════════════════════════════════════════════════
    # FOOTER
    # ══════════════════════════════════════════════════════════════════════════
    story.append(HRFlowable(width=W, thickness=0.5, color=COLOR_BORDER))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        f"Generated by Automated Web Vulnerability Scanner | Scan #{scan_id:04d} | {ts} | "
        "For authorized security assessment use only.",
        style_center
    ))

    doc.build(story)
    return buffer.getvalue()


def _section_table_style():
    """Return standard table style for section tables."""
    return TableStyle([
        # Header row
        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#111827")),
        ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#00d4ff")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("LETTERSPACINGPADDING", (0, 0), (-1, 0), 2),
        # Data rows
        ("BACKGROUND", (0, 1), (-1, -1), HexColor("#0d1117")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#0d1117"), HexColor("#0a0e1a")]),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("LINEBELOW", (0, 0), (-1, -2), 0.3, HexColor("#1e2d40")),
        ("LINEBELOW", (0, -1), (-1, -1), 0.5, HexColor("#1e2d40")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ])


def _make_breakdown_table(breakdown: dict, style, width):
    """Create the score breakdown mini-table."""
    data = [
        ["Module", "Score", "Max"],
        ["HTTP Headers", str(breakdown.get("headers", 0)), "35"],
        ["SSL / TLS",    str(breakdown.get("ssl", 0)),     "30"],
        ["Port Security",str(breakdown.get("ports", 0)),   "20"],
        ["Server Config",str(breakdown.get("server", 0)),  "15"],
    ]
    t = Table(data, colWidths=[width * 0.35, width * 0.15, width * 0.1])
    t.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#00d4ff")),
        ("TEXTCOLOR", (0, 1), (-1, -1), HexColor("#94a3b8")),
        ("FONTNAME", (0, 1), (-1, -1), "Courier"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LINEBELOW", (0, 0), (-1, 0), 0.3, HexColor("#1e2d40")),
    ]))
    return t
