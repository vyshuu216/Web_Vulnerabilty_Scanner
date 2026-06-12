"""
SSL/TLS Certificate Inspector
================================
Inspects the SSL/TLS certificate of a target URL,
checking validity, expiry, issuer, and common misconfigurations.
"""

import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse


def inspect_ssl(url: str) -> dict:
    """
    Inspect the SSL/TLS certificate of a given URL.

    Args:
        url (str): The target URL to inspect.

    Returns:
        dict: Certificate details including validity, expiry, issuer, and risk flags.
    """
    results = {
        "valid": False,
        "subject": "N/A",
        "issuer": "N/A",
        "not_before": "N/A",
        "not_after": "N/A",
        "days_left": None,
        "tls_version": "N/A",
        "serial_number": "N/A",
        "self_signed": False,
        "wildcard": False,
        "san": [],
        "error": None
    }

    # Extract hostname from URL
    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        results["error"] = "Invalid URL — could not extract hostname."
        return results

    # Only inspect if HTTPS
    if parsed.scheme != "https":
        results["error"] = "URL does not use HTTPS. No SSL certificate to inspect."
        results["valid"] = False
        return results

    port = parsed.port or 443

    try:
        # Create SSL context and connect
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()

        results["valid"] = True
        results["tls_version"] = tls_version

        # Extract subject (CN)
        subject_dict = dict(x[0] for x in cert.get("subject", []))
        results["subject"] = subject_dict.get("commonName", "N/A")

        # Detect wildcard certificate
        results["wildcard"] = results["subject"].startswith("*.")

        # Extract issuer
        issuer_dict = dict(x[0] for x in cert.get("issuer", []))
        issuer_cn = issuer_dict.get("commonName", "N/A")
        issuer_org = issuer_dict.get("organizationName", "")
        results["issuer"] = f"{issuer_cn} ({issuer_org})" if issuer_org else issuer_cn

        # Check for self-signed certificate (issuer == subject)
        results["self_signed"] = (
            issuer_dict.get("commonName") == subject_dict.get("commonName")
            and issuer_dict.get("organizationName") == subject_dict.get("organizationName", "")
        )

        # Parse validity dates
        not_before_str = cert.get("notBefore", "")
        not_after_str = cert.get("notAfter", "")

        if not_before_str:
            not_before_dt = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z")
            results["not_before"] = not_before_dt.strftime("%Y-%m-%d")

        if not_after_str:
            not_after_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            results["not_after"] = not_after_dt.strftime("%Y-%m-%d")
            days_left = (not_after_dt - datetime.utcnow()).days
            results["days_left"] = days_left

        # Extract Subject Alternative Names (SANs)
        san_list = cert.get("subjectAltName", [])
        results["san"] = [name for (kind, name) in san_list if kind == "DNS"]

        # Serial number (hex)
        results["serial_number"] = str(cert.get("serialNumber", "N/A"))

    except ssl.SSLCertVerificationError as e:
        # Certificate is invalid (e.g., expired, self-signed not trusted)
        results["valid"] = False
        results["error"] = f"Certificate verification failed: {str(e)}"
        _try_get_cert_without_verification(hostname, port, results)

    except ssl.SSLError as e:
        results["valid"] = False
        results["error"] = f"SSL Error: {str(e)}"

    except socket.timeout:
        results["error"] = "Connection timed out while retrieving SSL certificate."

    except ConnectionRefusedError:
        results["error"] = f"Connection refused on port {port}."

    except Exception as e:
        results["error"] = f"Unexpected error: {str(e)}"

    return results


def _try_get_cert_without_verification(hostname: str, port: int, results: dict):
    """
    Attempt to retrieve certificate info without verifying it.
    Useful for self-signed or expired certificates.
    """
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                results["tls_version"] = ssock.version()

        if cert:
            subject_dict = dict(x[0] for x in cert.get("subject", []))
            results["subject"] = subject_dict.get("commonName", "N/A")
            issuer_dict = dict(x[0] for x in cert.get("issuer", []))
            results["issuer"] = issuer_dict.get("commonName", "N/A")
            results["self_signed"] = (
                issuer_dict.get("commonName") == subject_dict.get("commonName")
            )

            not_after_str = cert.get("notAfter", "")
            if not_after_str:
                not_after_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                results["not_after"] = not_after_dt.strftime("%Y-%m-%d")
                results["days_left"] = (not_after_dt - datetime.utcnow()).days

    except Exception:
        pass  # Silently ignore — we already have the main error
