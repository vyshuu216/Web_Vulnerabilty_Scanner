# 🛡️ Automated Web Vulnerability Scanner

> OWASP-aligned security assessment tool for web applications — built with Python & Streamlit

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square\&logo=python\&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.32+-FF4B4B?style=flat-square\&logo=streamlit\&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010-000000?style=flat-square)
![SQLite](https://img.shields.io/badge/SQLite-Local%20Storage-003B57?style=flat-square\&logo=sqlite)

---

## 📌 Overview

The **Automated Web Vulnerability Scanner** is a cybersecurity tool that performs comprehensive security assessments on web applications. It checks for common vulnerabilities aligned with the **OWASP Top 10 (2021)** and generates professional PDF reports with actionable remediation recommendations.

Built as a **Cybersecurity Internship Project**, this tool demonstrates practical knowledge of:

* Web application security concepts
* HTTP protocol and security headers
* SSL/TLS certificate inspection
* Network port scanning
* Threat scoring and risk quantification

---

## ✨ Features

| Module                      | What It Does                                                                        |
| --------------------------- | ----------------------------------------------------------------------------------- |
| 🔒 **HTTP Header Analyzer** | Checks 10 critical security headers (CSP, HSTS, X-Frame-Options, etc.)              |
| 🔐 **SSL/TLS Inspector**    | Certificate validity, expiry countdown, issuer, TLS version, self-signed detection  |
| 🌐 **Port Scanner**         | Scans 16 common ports with parallel threading, flags CRITICAL exposures             |
| 🖥 **Server Analyzer**      | Fingerprints server software, CMS, cookie flags, HTTPS redirect, version disclosure |
| 📊 **Score Engine**         | Weighted 0–100 security score with per-module breakdown                             |
| 📄 **PDF Reports**          | Professional downloadable reports via ReportLab                                     |
| 🗄 **Scan History**         | All scans stored locally in SQLite, viewable on the History page                    |

---

## 🚀 Quick Start

### Prerequisites

* Python 3.10 or higher
* pip

### Installation

```bash
# Clone the repository
git clone REPO URL

# Navigate to project folder
cd Web_Vulnerability_Scanner

# Create virtual environment (optional)
python -m venv venv

# Activate environment
# Windows
venv\Scripts\activate

# Linux/macOS
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run application
streamlit run app.py
```

The application will be available at:

```text
http://localhost:8501
```

---

## 🗂️ Project Structure

```text
web-vulnerability-scanner/
│
├── app.py
│
├── modules/
│   ├── __init__.py
│   ├── header_analyzer.py
│   ├── ssl_inspector.py
│   ├── port_scanner.py
│   ├── server_analyzer.py
│   ├── score_calculator.py
│   └── report_generator.py
│
├── database/
│   ├── __init__.py
│   └── db_manager.py
│
├── .streamlit/
│   └── config.toml
│
├── requirements.txt
├── scans.db
└── README.md
```

---

## 🔍 Security Checks Performed

### HTTP Security Headers (35 Points)

| Header                       | OWASP Ref | Purpose                           |
| ---------------------------- | --------- | --------------------------------- |
| Content-Security-Policy      | A03:2021  | XSS / Injection Prevention        |
| Strict-Transport-Security    | A02:2021  | Forces HTTPS                      |
| X-Frame-Options              | A05:2021  | Clickjacking Protection           |
| X-Content-Type-Options       | A05:2021  | MIME Sniffing Prevention          |
| Referrer-Policy              | A05:2021  | Information Leakage Control       |
| Permissions-Policy           | A05:2021  | Browser Feature Control           |
| X-XSS-Protection             | A03:2021  | Legacy XSS Filter                 |
| Cache-Control                | A02:2021  | Sensitive Data Caching Protection |
| Cross-Origin-Opener-Policy   | A05:2021  | Browsing Context Isolation        |
| Cross-Origin-Resource-Policy | A05:2021  | Cross-Origin Read Protection      |

### SSL / TLS Analysis (30 Points)

* Certificate validity verification
* Expiry monitoring
* TLS version assessment
* Self-signed certificate detection
* Wildcard certificate detection
* Subject Alternative Names (SANs) analysis

### Port Security Analysis (20 Points)

| Risk Level  | Example Ports              |
| ----------- | -------------------------- |
| 🔴 CRITICAL | 3306, 27017, 6379, 23, 445 |
| 🟠 HIGH     | 21, 110, 143               |
| 🟡 MEDIUM   | 22, 25, 53                 |
| 🟢 LOW      | 80, 443                    |

### Server Configuration (15 Points)

* HTTPS Redirect Validation
* Secure Cookie Detection
* HttpOnly Cookie Verification
* Server Banner Disclosure Detection
* HTTP/2 Support Analysis

---

## 📊 Scoring System

```text
Security Score (0–100)

HTTP Headers      → 35 Points
SSL/TLS           → 30 Points
Port Security     → 20 Points
Server Config     → 15 Points

Grade Scale

80–100   ✅ SECURE
60–79    ⚠️ MODERATE RISK
40–59    🟠 VULNERABLE
0–39     🔴 CRITICAL RISK
```

---

## 🛠️ Technology Stack

| Technology         | Purpose                |
| ------------------ | ---------------------- |
| Python 3.10+       | Core Development       |
| Streamlit          | User Interface         |
| Requests           | HTTP Communication     |
| Socket             | TCP Port Scanning      |
| SSL Library        | Certificate Inspection |
| ReportLab          | PDF Report Generation  |
| SQLite3            | Local Database Storage |
| ThreadPoolExecutor | Parallel Processing    |

---

## 👥 Project Team

| Name                             | Email                                                                 | LinkedIn                                                              |
| -------------------------------- | --------------------------------------------------------------------- | -----------------------------------------------------------------     |
| **Samudrala Srinivasa Vyshnavi** | [svyshnavi.samudrala@gmail.com](mailto:svyshnavi.samudrala@gmail.com) | [LinkedIn](https://www.linkedin.com/in/samudrala-vyshnavi-824862282/) |
| **Abhinav Rama**                 | [abhinavrama2005@gmail.com](mailto:abhinavrama2005@gmail.com)         | [LinkedIn](https://www.linkedin.com/in/abhinav-rama-b44302304/)       |
| **Rampelli Rithwik**             | [RampelliRithwik@gmail.com](mailto:RampelliRithwik@gmail.com)         | [LinkedIn](https://www.linkedin.com/in/rithwik-rampelli-2067612b2/)   |
| **Kommidi Vishravas Reddy**      | [vishravasreddy@gmail.com](mailto:vishravasreddy@gmail.com)           | [LinkedIn](https://www.linkedin.com/in/vishravasreddy-kommidi-997463288/)|


---




---

## ⚠️ Disclaimer

This tool is intended for **authorized security testing only**.

Only scan systems that you own or have explicit written permission to test.

Unauthorized scanning of systems may violate local laws and regulations.

---

## 📄 License

This project is licensed under the MIT License.

See the **LICENSE** file for details.
