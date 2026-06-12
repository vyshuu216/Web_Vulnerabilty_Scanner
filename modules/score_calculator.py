"""
Security Score Calculator
===========================
Calculates a weighted security score (0–100) based on
results from all scan modules.

Scoring breakdown:
    - HTTP Headers  : 35 points
    - SSL/TLS       : 30 points
    - Port Security : 20 points
    - Server Config : 15 points
"""


def calculate_score(header_results: dict, ssl_results: dict, port_results: dict, server_results: dict) -> tuple:
    """
    Calculate an overall security score from all module results.

    Args:
        header_results : Output from analyze_headers()
        ssl_results    : Output from inspect_ssl()
        port_results   : Output from scan_ports()
        server_results : Output from analyze_server()

    Returns:
        tuple: (overall_score: int, breakdown: dict)
    """
    breakdown = {
        "headers": 0,
        "ssl": 0,
        "ports": 0,
        "server": 0
    }

    # ── 1. HTTP Security Headers (max 35 pts) ─────────────────────────────────
    total_headers = len(header_results.get("headers", []))
    if total_headers > 0:
        passed = header_results.get("passed", 0)
        # Proportional score
        breakdown["headers"] = round((passed / total_headers) * 35)

    # ── 2. SSL/TLS (max 30 pts) ───────────────────────────────────────────────
    ssl_score = 0

    if ssl_results.get("valid"):
        ssl_score += 15  # Valid certificate is worth most

    days_left = ssl_results.get("days_left")
    if days_left is not None:
        if days_left > 60:
            ssl_score += 8   # Plenty of time before expiry
        elif days_left > 30:
            ssl_score += 4   # Expiring soon — partial credit
        elif days_left > 0:
            ssl_score += 1   # Expiring very soon — minimal credit
        # 0 if expired

    # TLS version bonus
    tls = ssl_results.get("tls_version", "")
    if "TLSv1.3" in str(tls):
        ssl_score += 5  # Latest and most secure
    elif "TLSv1.2" in str(tls):
        ssl_score += 3  # Acceptable

    # Penalty for self-signed certificates
    if ssl_results.get("self_signed"):
        ssl_score = max(0, ssl_score - 5)

    breakdown["ssl"] = min(ssl_score, 30)

    # ── 3. Port Security (max 20 pts) ─────────────────────────────────────────
    port_score = 20  # Start at full marks, deduct per open risky port
    open_ports = [p for p in port_results.get("ports", []) if p["status"] == "OPEN"]

    for port in open_ports:
        risk = port.get("risk", "NONE")
        if risk == "CRITICAL":
            port_score -= 6
        elif risk == "HIGH":
            port_score -= 4
        elif risk == "MEDIUM":
            port_score -= 2
        elif risk == "LOW":
            port_score -= 1

    breakdown["ports"] = max(0, min(port_score, 20))

    # ── 4. Server Configuration (max 15 pts) ──────────────────────────────────
    server_score = 0

    # HTTPS redirect = good practice
    if server_results.get("https_redirect"):
        server_score += 5

    # Cookies with Secure + HttpOnly flags
    cookies_secure = server_results.get("cookies_secure")
    if cookies_secure is True:
        server_score += 4
    elif cookies_secure == "N/A":
        server_score += 2  # No cookies = not a risk factor, partial credit

    # No information disclosure in server banner
    if not server_results.get("info_disclosure"):
        server_score += 4

    # Modern HTTP version
    http_version = server_results.get("http_version", "")
    if "2" in http_version:
        server_score += 2

    breakdown["server"] = min(server_score, 15)

    # ── Final Score ────────────────────────────────────────────────────────────
    total = sum(breakdown.values())
    total = max(0, min(total, 100))  # Clamp between 0 and 100

    return total, breakdown
