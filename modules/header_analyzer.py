"""
HTTP Security Header Analyzer
================================
Checks for the presence and correct configuration of
critical HTTP security response headers based on OWASP recommendations.
"""

import requests

# Security headers to check with descriptions and OWASP references
SECURITY_HEADERS = [
    {
        "name": "Content-Security-Policy",
        "key": "Content-Security-Policy",
        "description": "Prevents XSS and data injection attacks by whitelisting content sources",
        "owasp": "A03:2021"
    },
    {
        "name": "Strict-Transport-Security",
        "key": "Strict-Transport-Security",
        "description": "Forces HTTPS connections and prevents protocol downgrade attacks",
        "owasp": "A02:2021"
    },
    {
        "name": "X-Frame-Options",
        "key": "X-Frame-Options",
        "description": "Prevents clickjacking by controlling frame embedding",
        "owasp": "A05:2021"
    },
    {
        "name": "X-Content-Type-Options",
        "key": "X-Content-Type-Options",
        "description": "Prevents MIME-type sniffing attacks",
        "owasp": "A05:2021"
    },
    {
        "name": "Referrer-Policy",
        "key": "Referrer-Policy",
        "description": "Controls how much referrer information is sent with requests",
        "owasp": "A05:2021"
    },
    {
        "name": "Permissions-Policy",
        "key": "Permissions-Policy",
        "description": "Controls browser features like camera, microphone, geolocation",
        "owasp": "A05:2021"
    },
    {
        "name": "X-XSS-Protection",
        "key": "X-XSS-Protection",
        "description": "Legacy XSS filter for older browsers (deprecated but still checked)",
        "owasp": "A03:2021"
    },
    {
        "name": "Cache-Control",
        "key": "Cache-Control",
        "description": "Prevents sensitive data from being cached by browsers or proxies",
        "owasp": "A02:2021"
    },
    {
        "name": "Cross-Origin-Opener-Policy",
        "key": "Cross-Origin-Opener-Policy",
        "description": "Isolates browsing context from cross-origin documents",
        "owasp": "A05:2021"
    },
    {
        "name": "Cross-Origin-Resource-Policy",
        "key": "Cross-Origin-Resource-Policy",
        "description": "Protects resources from cross-origin read attacks",
        "owasp": "A05:2021"
    },
]


def analyze_headers(url: str) -> dict:
    """
    Perform HTTP security header analysis on the given URL.

    Args:
        url (str): The target URL to analyze.

    Returns:
        dict: Results containing header statuses and recommendations.
    """
    results = {
        "headers": [],
        "raw_headers": {},
        "recommendations": [],
        "total": len(SECURITY_HEADERS),
        "passed": 0,
        "failed": 0,
        "error": None
    }

    try:
        # Send a GET request with a standard browser User-Agent
        response = requests.get(
            url,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0 (Security Scanner)"},
            allow_redirects=True,
            verify=False  # Allow self-signed certs for scanning purposes
        )
        response_headers = {k.lower(): v for k, v in response.headers.items()}
        results["raw_headers"] = dict(response.headers)

    except requests.exceptions.SSLError:
        # Try without SSL verification
        try:
            response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
            response_headers = {k.lower(): v for k, v in response.headers.items()}
            results["raw_headers"] = dict(response.headers)
        except Exception as e:
            results["error"] = str(e)
            results["headers"] = _generate_error_headers()
            return results

    except Exception as e:
        results["error"] = str(e)
        results["headers"] = _generate_error_headers()
        return results

    # Check each security header
    for header_def in SECURITY_HEADERS:
        header_key_lower = header_def["key"].lower()
        present = header_key_lower in response_headers
        value = response_headers.get(header_key_lower, "")

        # Additional value checks for headers that need specific values
        status = _evaluate_header(header_def["key"], present, value)

        entry = {
            "name": header_def["name"],
            "description": header_def["description"],
            "owasp": header_def["owasp"],
            "status": status,
            "value": value if present else None,
            "present": present
        }

        results["headers"].append(entry)

        if status == "PASS":
            results["passed"] += 1
        else:
            results["failed"] += 1
            results["recommendations"].append(
                f"Add '{header_def['name']}' header — {header_def['description']}"
            )

    return results


def _evaluate_header(header_name: str, present: bool, value: str) -> str:
    """
    Evaluate if a header value is correctly configured.

    Returns 'PASS', 'WARN', or 'FAIL'.
    """
    if not present:
        return "FAIL"

    # Header-specific validation rules
    if header_name == "X-Frame-Options":
        if value.upper() not in ["DENY", "SAMEORIGIN"]:
            return "WARN"

    elif header_name == "X-Content-Type-Options":
        if value.lower() != "nosniff":
            return "WARN"

    elif header_name == "Strict-Transport-Security":
        if "max-age" not in value.lower():
            return "WARN"

    elif header_name == "X-XSS-Protection":
        if "1" not in value:
            return "WARN"

    return "PASS"


def _generate_error_headers() -> list:
    """Return FAIL results for all headers when the request fails."""
    return [
        {
            "name": h["name"],
            "description": h["description"],
            "owasp": h["owasp"],
            "status": "FAIL",
            "value": None,
            "present": False
        }
        for h in SECURITY_HEADERS
    ]
