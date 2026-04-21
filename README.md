# ⚡ VulnScanX

> **Advanced Vulnerability Scanning & Penetration Testing Framework**
> Production-level | Modular | AI-Powered | OWASP-Aligned

---

```
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗██╗  ██╗
██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║╚██╗██╔╝
██║   ██║██║   ██║██║     ██╔██╗ ██║███████╗██║     ███████║██╔██╗ ██║ ╚███╔╝ 
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║██║     ██╔══██║██║╚██╗██║ ██╔██╗ 
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║╚██████╗██║  ██║██║ ╚████║██╔╝ ██╗
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝
                                                         v2.0
```

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)](https://python.org)
[![Flask](https://img.shields.io/badge/dashboard-Flask-green)](https://flask.palletsprojects.com)
[![OWASP Top 10](https://img.shields.io/badge/OWASP-Top%2010%202025-red)](https://owasp.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

---

## ⚠️ Legal Disclaimer

> **VulnScanX must ONLY be used on systems you own or have explicit written authorization to test.
> Unauthorized scanning violates the Computer Fraud and Abuse Act (CFAA) and similar laws worldwide.
> The authors assume ZERO liability for misuse.**

---

## 🏗️ Architecture

```
vulnscanx/
│
├── core/                    # Engine layer
│   ├── engine.py            # VulnScanEngine — orchestrator, thread pool, progress
│   ├── config.py            # Payloads, settings, severity levels, constants
│   ├── models.py            # Finding + ScanResult dataclasses
│   └── template_engine.py  # YAML template parser & executor (Nuclei-inspired)
│
├── modules/
│   ├── recon/               # Reconnaissance modules
│   │   ├── subdomain.py     # DNS brute-force + CT log mining (crt.sh)
│   │   ├── dns_lookup.py    # A/MX/NS/TXT/SOA + zone transfer + SPF/DMARC
│   │   ├── whois_lookup.py  # WHOIS + domain expiry detection
│   │   └── dir_bruteforce.py# HTTP directory/file brute-force
│   │
│   └── vuln/                # Vulnerability modules
│       ├── xss_scanner.py   # Reflected XSS (GET/POST) + DOM XSS sink detection
│       ├── sqli_scanner.py  # Error-based + Time-based + Boolean-based SQLi
│       ├── headers_check.py # Security headers + TLS + info disclosure
│       ├── port_scanner.py  # TCP port scan with service fingerprinting
│       └── dir_traversal.py # Path traversal / LFI with OS signature matching
│
├── templates/               # YAML scanning templates (Nuclei-compatible syntax)
│   ├── xss-reflected.yaml
│   ├── sqli-error-based.yaml
│   ├── sqli-time-based.yaml
│   ├── missing-security-headers.yaml
│   └── open-redirect.yaml
│
├── ai/                      # AI/ML analysis layer
│   ├── classifier.py        # Random Forest severity classifier (scikit-learn)
│   └── explainer.py         # Human-readable vulnerability explanations
│
├── reports/                 # Report generation
│   ├── json_reporter.py     # Structured JSON output
│   ├── html_reporter.py     # Self-contained styled HTML report
│   ├── pdf_reporter.py      # PDF via WeasyPrint
│   ├── sarif_reporter.py    # SARIF 2.1 for GitHub Code Scanning
│   └── report_manager.py   # Report facade
│
├── cli/
│   └── main.py              # argparse CLI — vulnscanx scan <target> [opts]
│
├── web/
│   ├── app.py               # Flask API + dashboard server
│   └── templates/
│       └── dashboard.html   # Full-featured real-time web dashboard
│
├── utils/
│   ├── logger.py            # Colorized console + JSON file logging
│   ├── rate_limiter.py      # Token bucket rate limiter
│   └── helpers.py           # URL normalization, injection, parsing
│
└── tests/                   # pytest test suite
    ├── test_models.py
    ├── test_helpers.py
    └── test_classifier.py
```

---

## 🚀 Installation

### Kali Linux (Recommended)

```bash
# Clone
git clone https://github.com/yourusername/vulnscanx.git
cd vulnscanx

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install as CLI tool
pip install -e .

# Verify
vulnscanx version
```

### Docker

```bash
docker build -t vulnscanx .
docker run -p 5000:5000 vulnscanx web
```

---

## 💻 CLI Usage

### Basic Scans

```bash
# Full scan (all modules)
vulnscanx scan https://example.com

# Quick scan (headers + ports + xss)
vulnscanx scan https://example.com --type quick

# Reconnaissance only
vulnscanx scan https://example.com --type recon

# Vulnerability assessment only
vulnscanx scan https://example.com --type vuln
```

### Advanced Options

```bash
# Specify modules explicitly
vulnscanx scan https://example.com --modules xss,sqli,headers,ports

# Custom threads + proxy (Burp Suite)
vulnscanx scan https://example.com --threads 20 --proxy http://127.0.0.1:8080

# All output formats
vulnscanx scan https://example.com --output html,json,pdf,sarif

# With authenticated session
vulnscanx scan https://example.com --cookie "session=abc123; auth=xyz"
vulnscanx scan https://example.com --header "Authorization: Bearer TOKEN"

# With YAML templates
vulnscanx scan https://example.com --with-templates

# Disable AI analysis (faster)
vulnscanx scan https://example.com --no-ai

# Verbose mode
vulnscanx scan https://example.com --verbose
```

### Template Management

```bash
# List all templates
vulnscanx templates --list
```

---

## 🌐 Web Dashboard

```bash
# Start the web server
python web/app.py

# Navigate to
http://localhost:5000
```

**Dashboard Features:**
- Enter any target URL and select scan type
- Toggle individual modules on/off
- Adjust thread count (5–50)
- Live progress bar with current module display
- Real-time findings table with severity filtering
- Interactive finding cards (click to expand detail)
- AI explanation panel per finding
- Charts: severity distribution + risk score meter
- Terminal-style scan log
- Download reports: JSON / HTML / PDF / SARIF
- Scan history with status and risk scores

### REST API

```bash
# Start scan
POST /api/scan
{
  "target": "https://example.com",
  "scan_type": "full",
  "modules": ["xss", "sqli", "headers"],
  "threads": 10,
  "ai_analysis": true
}

# Poll status
GET /api/scan/{scan_id}/status

# Get findings
GET /api/scan/{scan_id}/findings?severity=HIGH

# Download report
GET /api/scan/{scan_id}/report/html    → HTML report
GET /api/scan/{scan_id}/report/json    → JSON data
GET /api/scan/{scan_id}/report/sarif   → SARIF 2.1
GET /api/scan/{scan_id}/report/pdf     → PDF

# Stop scan
POST /api/scan/{scan_id}/stop

# List all scans
GET /api/scans
```

---

## 🔍 Modules Reference

| Module | Type | Detects | OWASP |
|---|---|---|---|
| `subdomain` | Recon | CT log subdomains + DNS brute-force | A01 |
| `dns` | Recon | DNS records, zone transfer, SPF/DMARC | A02 |
| `whois` | Recon | Registration info, expiry | A01 |
| `dirbrute` | Recon | Hidden files/dirs (`.env`, `.git`, `admin`) | A01 |
| `ports` | Vuln | Open ports, service fingerprinting | A02 |
| `headers` | Vuln | Missing security headers, TLS check | A02 |
| `xss` | Vuln | Reflected XSS (GET/POST), DOM sinks | A03 |
| `sqli` | Vuln | Error/time/boolean SQLi | A03 |
| `traversal` | Vuln | Path traversal / LFI | A01 |

---

## 📝 YAML Templates

Templates live in `templates/`. Create custom ones:

```yaml
id: my-custom-check
name: My Custom Vulnerability Check
author: YourName
severity: high
description: Detects a custom vulnerability pattern
category: Injection
cwe: CWE-78
owasp: A03:2025
cvss: 8.0
tags:
  - custom
  - injection

payloads:
  - "'; ls -la #"
  - "| cat /etc/passwd"

match:
  type: contains_any
  values:
    - "root:x:0:0"
    - "total "

remediation: |
  Sanitize all user input. Use parameterized commands.

references:
  - https://owasp.org
```

Supported match types: `contains_any`, `regex_any`, `response_time`, `response_header`

---

## 📊 Sample Output

```
======================================================
  SCAN SUMMARY  |  Target: http://testphp.vulnweb.com
======================================================
  CRITICAL :  3
  HIGH     :  7
  MEDIUM   : 12
  LOW      :  4
  INFO     :  8
------------------------------------------------------
  TOTAL    : 34 findings
  RISK     : 8.7/10
  DURATION : 47.3s
======================================================

📋 Reports generated:
   [JSON] reports/output/vulnscanx_testphp_20250421_143021.json
   [HTML] reports/output/vulnscanx_testphp_20250421_143021.html
```

---

## 🤖 AI Analysis

The `VulnClassifier` uses scikit-learn's RandomForestClassifier to re-evaluate severity:

- Feature extraction: CVSS score, category hash, parameter presence, payload type
- Falls back to rule-based heuristic when untrained
- `VulnExplainer` generates structured explanations including: what the vuln is, real-world impact, attacker scenario, CVSS context

---

## 🔬 Running Tests

```bash
python -m pytest tests/ -v
python -m pytest tests/ --cov=. --cov-report=html
```

---

## 🛡️ OWASP Top 10 2025 Coverage

| ID | Category | Modules |
|---|---|---|
| A01:2025 | Broken Access Control | `subdomain`, `dirbrute`, `traversal` |
| A02:2025 | Security Misconfiguration | `headers`, `ports`, `dns` |
| A03:2025 | Software Supply Chain Failures | Templates |
| A04:2025 | Cryptographic Failures | `headers` (TLS check) |
| A05:2025 | Injection | `xss`, `sqli`, `traversal` |
| A07:2025 | Authentication Failures | `dirbrute` (admin panel), `headers` |

---

## 🤝 Contributing

1. Fork → `feature/your-feature`
2. Add module in `modules/vuln/` or `modules/recon/`
3. Inherit from `BaseModule`, implement `run() -> List[Finding]`
4. Add YAML template in `templates/`
5. Write tests in `tests/`
6. PR with description

---

*Built for security professionals. Scan responsibly.*
