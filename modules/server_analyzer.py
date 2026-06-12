"""
Server Information Analyzer
============================
Fingerprints the target web server by analyzing response headers,
cookies, redirect behavior, and response metadata.
"""

import requests
import time
from urllib.parse import urlparse
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Known server/technology indicators for fingerprinting
CMS_INDICATORS = {
    "WordPress": ["wp-content", "wp-includes", "xmlrpc.php", "wp-json"],
    "Drupal": ["drupal", "sites/default", "misc/drupal.js"],
    "Joomla": ["joomla", "/administrator/", "com_content"],
    "Django": ["csrfmiddlewaretoken", "django"],
    "Laravel": ["laravel_session", "XSRF-TOKEN"],
    "Shopify": ["shopify", "myshopify.com", "Shopify.theme"],
    "Next.js": ["__NEXT_DATA__", "_next/static"],
    "React": ["react", "__react"],
}


def analyze_server(url: str) -> dict:
    """
    Perform server fingerprinting and configuration analysis.

    Args:
        url (str): Target URL to analyze.

    Returns:
        dict: Server info including software, cookies, redirect behavior, etc.
    """
    results = {
        "server": "Unknown",
        "powered_by": None,
        "technology": None,
        "cms": None,
        "cookies_secure": False,
        "https_redirect": False,
        "http_version": "Unknown",
        "response_time": None,
        "status_code": None,
        "info_disclosure": False,
        "error": None
    }

    try:
        start_time = time.time()
        response = requests.get(
            url,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0 (Security Scanner / OWASP Assessment)"},
            allow_redirects=True,
            verify=False
        )
        elapsed = round((time.time() - start_time) * 1000)

        results["response_time"] = f"{elapsed} ms"
        results["status_code"] = response.status_code

        headers = {k.lower(): v for k, v in response.headers.items()}

        # ── Server Banner ──────────────────────────────────────────────────
        server_header = headers.get("server", "")
        if server_header:
            results["server"] = server_header
            # Check for information disclosure (version numbers)
            if any(c.isdigit() for c in server_header) or "/" in server_header:
                results["info_disclosure"] = True

        # ── Powered-By ─────────────────────────────────────────────────────
        powered_by = headers.get("x-powered-by", "")
        if powered_by:
            results["powered_by"] = powered_by
            results["info_disclosure"] = True  # Revealing tech stack is a risk

        # ── Technology Detection ────────────────────────────────────────────
        via = headers.get("via", "")
        cf_ray = headers.get("cf-ray", "")
        if cf_ray:
            results["technology"] = "Cloudflare CDN"
        elif "nginx" in server_header.lower():
            results["technology"] = "Nginx"
        elif "apache" in server_header.lower():
            results["technology"] = "Apache"
        elif "iis" in server_header.lower():
            results["technology"] = "Microsoft IIS"
        elif "gunicorn" in server_header.lower():
            results["technology"] = "Gunicorn (Python)"
        elif "express" in powered_by.lower():
            results["technology"] = "Node.js / Express"
        elif powered_by:
            results["technology"] = powered_by

        # ── CMS Detection (from response body) ─────────────────────────────
        try:
            body = response.text[:5000]  # Only check first 5KB
            for cms, indicators in CMS_INDICATORS.items():
                if any(ind.lower() in body.lower() for ind in indicators):
                    results["cms"] = cms
                    break
        except Exception:
            pass

        # ── Cookie Security ────────────────────────────────────────────────
        all_cookies_secure = True
        if response.cookies:
            for cookie in response.cookies:
                if not cookie.secure or not cookie.has_nonstandard_attr("HttpOnly"):
                    all_cookies_secure = False
                    break
        else:
            all_cookies_secure = False  # No cookies to evaluate

        # Also check Set-Cookie header manually
        set_cookie = headers.get("set-cookie", "")
        if set_cookie:
            cookie_flags = set_cookie.lower()
            all_cookies_secure = "secure" in cookie_flags and "httponly" in cookie_flags
            results["cookies_secure"] = all_cookies_secure
        else:
            results["cookies_secure"] = "N/A"  # No cookies set

        # ── HTTPS Redirect Check ────────────────────────────────────────────
        parsed = urlparse(url)
        if parsed.scheme == "https":
            # Check if HTTP version redirects to HTTPS
            try:
                http_url = url.replace("https://", "http://")
                http_resp = requests.get(
                    http_url,
                    timeout=5,
                    allow_redirects=False,
                    verify=False
                )
                # Redirect codes: 301, 302, 307, 308
                if http_resp.status_code in [301, 302, 307, 308]:
                    location = http_resp.headers.get("Location", "")
                    results["https_redirect"] = "https" in location.lower()
                else:
                    results["https_redirect"] = False
            except Exception:
                results["https_redirect"] = False
        else:
            results["https_redirect"] = False

        # ── HTTP Version ────────────────────────────────────────────────────
        # Requests doesn't directly expose HTTP version, check via raw response
        raw_version = getattr(response.raw, "version", None)
        if raw_version == 11:
            results["http_version"] = "HTTP/1.1"
        elif raw_version == 10:
            results["http_version"] = "HTTP/1.0"
        elif raw_version == 20:
            results["http_version"] = "HTTP/2"
        else:
            results["http_version"] = "HTTP/1.1"  # Default assumption

    except requests.exceptions.ConnectionError as e:
        results["error"] = f"Connection error: {str(e)}"
    except requests.exceptions.Timeout:
        results["error"] = "Request timed out."
    except Exception as e:
        results["error"] = f"Error: {str(e)}"

    return results
