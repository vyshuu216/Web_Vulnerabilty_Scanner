"""
Port Scanner
============
Scans common TCP ports on the target host to identify
exposed services that may present security risks.
"""

import socket
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# Common ports with associated service names and risk levels
COMMON_PORTS = [
    (21,   "FTP",         "HIGH"),     # File Transfer — often unsecured
    (22,   "SSH",         "MEDIUM"),   # Secure Shell — exposure risk
    (23,   "Telnet",      "CRITICAL"), # Unencrypted — severe risk
    (25,   "SMTP",        "MEDIUM"),   # Mail server
    (53,   "DNS",         "MEDIUM"),   # DNS — amplification attack risk
    (80,   "HTTP",        "LOW"),      # Standard web — should redirect to HTTPS
    (110,  "POP3",        "HIGH"),     # Mail retrieval — often unencrypted
    (143,  "IMAP",        "HIGH"),     # Mail access — often unencrypted
    (443,  "HTTPS",       "LOW"),      # Standard secure web
    (445,  "SMB",         "CRITICAL"), # Windows file sharing — ransomware vector
    (3306, "MySQL",       "CRITICAL"), # Database — should never be public
    (5432, "PostgreSQL",  "CRITICAL"), # Database — should never be public
    (6379, "Redis",       "CRITICAL"), # Cache DB — often misconfigured
    (8080, "HTTP-Alt",    "MEDIUM"),   # Alternate HTTP — dev servers
    (8443, "HTTPS-Alt",   "LOW"),      # Alternate HTTPS
    (27017,"MongoDB",     "CRITICAL"), # NoSQL DB — unauthenticated risk
]

SCAN_TIMEOUT = 1.5  # Seconds per port — keep tight for speed


def _scan_port(host: str, port: int, service: str, risk: str) -> dict:
    """
    Attempt to connect to a single port and return its status.

    Args:
        host: Target hostname or IP.
        port: Port number to scan.
        service: Human-readable service name.
        risk: Risk level if open (LOW/MEDIUM/HIGH/CRITICAL).

    Returns:
        dict: Port scan result with status and metadata.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SCAN_TIMEOUT)
        result = sock.connect_ex((host, port))
        sock.close()

        status = "OPEN" if result == 0 else "CLOSED"
    except (socket.gaierror, OSError):
        status = "CLOSED"

    return {
        "port": port,
        "service": service,
        "status": status,
        "risk": risk if status == "OPEN" else "NONE"
    }


def scan_ports(url: str) -> dict:
    """
    Scan common ports on the target URL's host in parallel.

    Args:
        url (str): The target URL.

    Returns:
        dict: Scan results with port statuses and summary.
    """
    results = {
        "ports": [],
        "open_count": 0,
        "critical_open": [],
        "error": None,
        "host": None
    }

    # Resolve hostname
    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        results["error"] = "Invalid URL."
        return results

    results["host"] = hostname

    # Resolve to IP (for display)
    try:
        ip = socket.gethostbyname(hostname)
        results["resolved_ip"] = ip
    except socket.gaierror:
        results["resolved_ip"] = "Could not resolve"

    # Parallel port scan using ThreadPoolExecutor
    port_results = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {
            executor.submit(_scan_port, hostname, port, service, risk): (port, service, risk)
            for port, service, risk in COMMON_PORTS
        }
        for future in as_completed(futures):
            try:
                port_results.append(future.result())
            except Exception:
                pass

    # Sort by port number for consistent display
    port_results.sort(key=lambda x: x["port"])
    results["ports"] = port_results

    # Summarize findings
    open_ports = [p for p in port_results if p["status"] == "OPEN"]
    results["open_count"] = len(open_ports)
    results["critical_open"] = [
        p for p in open_ports if p["risk"] in ("HIGH", "CRITICAL")
    ]

    return results
