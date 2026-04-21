"""
VulnScanX — Security Headers Scanner
======================================
Checks for missing, misconfigured, or insecure HTTP response headers.
OWASP Top 10 2025: A02 – Security Misconfiguration
"""

import re
from typing import Dict, List, Optional

import requests

from core import BaseModule, Finding, Severity


HEADER_RULES = {
    "Strict-Transport-Security": {
        "required": True,
        "severity": Severity.HIGH,
        "cvss":     7.4,
        "description": (
            "HTTP Strict Transport Security (HSTS) is missing. Without HSTS, browsers may "
            "downgrade HTTPS connections to HTTP, exposing users to MitM attacks."
        ),
        "remediation": (
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        ),
        "validate": lambda v: "max-age" in v.lower(),
        "invalid_desc": "HSTS header present but max-age is not set.",
    },
    "Content-Security-Policy": {
        "required": True,
        "severity": Severity.HIGH,
        "cvss":     6.5,
        "description": (
            "Content-Security-Policy (CSP) is missing. Without CSP, the application is "
            "vulnerable to XSS and data injection attacks."
        ),
        "remediation": (
            "Define a strict CSP, e.g.: Content-Security-Policy: default-src 'self'; "
            "script-src 'self'; object-src 'none';"
        ),
        "validate": lambda v: "default-src" in v or "script-src" in v,
        "invalid_desc": "CSP header present but lacks default-src or script-src directives.",
    },
    "X-Frame-Options": {
        "required": True,
        "severity": Severity.MEDIUM,
        "cvss":     4.3,
        "description": (
            "X-Frame-Options is missing. This allows the page to be embedded in an iframe, "
            "enabling clickjacking attacks."
        ),
        "remediation": "Add: X-Frame-Options: SAMEORIGIN",
        "validate": lambda v: v.upper() in ("DENY", "SAMEORIGIN"),
        "invalid_desc": "X-Frame-Options has an invalid value. Use DENY or SAMEORIGIN.",
    },
    "X-Content-Type-Options": {
        "required": True,
        "severity": Severity.MEDIUM,
        "cvss":     4.0,
        "description": (
            "X-Content-Type-Options is missing. Browsers may MIME-sniff responses, "
            "leading to XSS via content type confusion."
        ),
        "remediation": "Add: X-Content-Type-Options: nosniff",
        "validate": lambda v: v.lower() == "nosniff",
        "invalid_desc": "X-Content-Type-Options should be set to 'nosniff'.",
    },
    "Referrer-Policy": {
        "required": False,
        "severity": Severity.LOW,
        "cvss":     3.1,
        "description": "Referrer-Policy is missing, potentially leaking sensitive URL data via the Referer header.",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "validate": lambda v: any(
            x in v.lower() for x in
            ["no-referrer", "strict-origin", "same-origin", "no-referrer-when-downgrade"]
        ),
        "invalid_desc": "Referrer-Policy has a permissive or invalid value.",
    },
    "Permissions-Policy": {
        "required": False,
        "severity": Severity.LOW,
        "cvss":     2.6,
        "description": "Permissions-Policy (formerly Feature-Policy) is missing. Browser features are unrestricted.",
        "remediation": "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()",
        "validate": lambda v: "=" in v,
        "invalid_desc": "Permissions-Policy value appears malformed.",
    },
    "X-Powered-By": {
        "required": False,  # This one should NOT be present
        "forbidden": True,
        "severity": Severity.INFO,
        "cvss":     2.0,
        "description": "X-Powered-By header reveals the server technology stack, aiding reconnaissance.",
        "remediation": "Remove the X-Powered-By header from server configuration.",
        "validate": lambda v: False,  # always flag if present
        "invalid_desc": "X-Powered-By is present and reveals technology information.",
    },
    "Server": {
        "forbidden": True,
        "required": False,
        "severity": Severity.INFO,
        "cvss":     2.0,
        "description": "Server header discloses web server version, aiding fingerprinting.",
        "remediation": "Configure the server to suppress or obscure the Server header.",
        "validate": lambda v: len(v.strip()) < 6,  # generic is OK
        "invalid_desc": "Server header reveals specific version information.",
    },
    "Cache-Control": {
        "required": False,
        "severity": Severity.LOW,
        "cvss":     3.7,
        "description": "Cache-Control is missing or permissive, potentially caching sensitive data.",
        "remediation": "For sensitive pages: Cache-Control: no-store, no-cache, must-revalidate",
        "validate": lambda v: any(x in v.lower() for x in ["no-store", "no-cache", "private"]),
        "invalid_desc": "Cache-Control allows caching of potentially sensitive responses.",
    },
}

DANGEROUS_CORS = re.compile(r"Access-Control-Allow-Origin:\s*\*", re.I)


class HeadersScanner(BaseModule):
    NAME        = "headers_scanner"
    DESCRIPTION = "Audit HTTP security headers for misconfigurations"
    TAGS        = ["headers", "misconfiguration", "owasp-a02"]

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.session = requests.Session()
        self.session.verify = False
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def run(self, target: str) -> List[Finding]:
        if not target.startswith(("http://", "https://")):
            target = "https://" + target

        findings = []
        try:
            resp = self.session.get(target, timeout=self.timeout, allow_redirects=True)
        except Exception as e:
            self.log(f"[Headers] Connection failed: {e}")
            return findings

        headers = {k.lower(): v for k, v in resp.headers.items()}
        self.log(f"[Headers] Auditing {len(headers)} headers on {target}")

        for header_name, rule in HEADER_RULES.items():
            key = header_name.lower()
            present = key in headers

            if rule.get("forbidden") and present:
                value = headers[key]
                if not rule["validate"](value):
                    findings.append(Finding(
                        title       = f"Information Disclosure: {header_name} Header",
                        severity    = rule["severity"],
                        cvss_score  = rule["cvss"],
                        target      = target,
                        url         = target,
                        module      = self.NAME,
                        evidence    = f"{header_name}: {value}",
                        description = rule["description"],
                        remediation = rule["remediation"],
                        tags        = ["headers", "information-disclosure"],
                    ))

            elif rule.get("required") and not present:
                findings.append(Finding(
                    title       = f"Missing Security Header: {header_name}",
                    severity    = rule["severity"],
                    cvss_score  = rule["cvss"],
                    target      = target,
                    url         = target,
                    module      = self.NAME,
                    evidence    = f"Header '{header_name}' not found in response",
                    description = rule["description"],
                    remediation = rule["remediation"],
                    tags        = ["headers", "missing-header"],
                ))

            elif present and not rule.get("forbidden"):
                value = headers[key]
                if not rule["validate"](value):
                    findings.append(Finding(
                        title       = f"Misconfigured Header: {header_name}",
                        severity    = rule["severity"],
                        cvss_score  = rule["cvss"],
                        target      = target,
                        url         = target,
                        module      = self.NAME,
                        evidence    = f"{header_name}: {value}",
                        description = rule.get("invalid_desc", rule["description"]),
                        remediation = rule["remediation"],
                        tags        = ["headers", "misconfiguration"],
                    ))

        # CORS wildcard check
        acao = headers.get("access-control-allow-origin", "")
        if acao == "*":
            findings.append(Finding(
                title       = "Insecure CORS: Wildcard Origin Allowed",
                severity    = Severity.HIGH,
                cvss_score  = 7.5,
                target      = target,
                url         = target,
                module      = self.NAME,
                evidence    = f"Access-Control-Allow-Origin: *",
                description = (
                    "CORS is configured to allow any origin. This may allow malicious websites "
                    "to make authenticated cross-origin requests."
                ),
                remediation = (
                    "Restrict CORS to known trusted origins. Avoid wildcard (*) on endpoints "
                    "that handle authenticated data or sensitive operations."
                ),
                tags        = ["cors", "misconfiguration"],
                references  = ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
            ))

        self.log(f"[Headers] Found {len(findings)} header issues")
        return findings


# ---------------------------------------------------------------------------
# Directory Traversal Scanner
# ---------------------------------------------------------------------------

TRAVERSAL_PAYLOADS = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "..%2Fetc%2Fpasswd",
    "..%252Fetc%252Fpasswd",
    "%2e%2e%2fetc%2fpasswd",
    "....//....//etc/passwd",
    "..\\..\\..\\..\\..\\..\\..\\..",
    "..%5C..%5C..%5CWindows%5Cwin.ini",
    "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
    "/etc/passwd%00",
    "php://filter/convert.base64-encode/resource=../etc/passwd",
    "....\\....\\....\\etc\\passwd",
    # LFI to RCE via /proc
    "/proc/self/environ",
    "/proc/self/cmdline",
]

TRAVERSAL_SIGNATURES = [
    re.compile(r"root:.*:0:0:", re.M),       # Unix /etc/passwd
    re.compile(r"\[fonts\]", re.M | re.I),   # Windows win.ini
    re.compile(r"DOCUMENT_ROOT", re.I),       # /proc/self/environ
    re.compile(r"HTTP_HOST", re.I),
]

TRAVERSAL_PARAMS = ["file", "path", "page", "lang", "include",
                    "dir", "doc", "template", "filename", "view", "folder"]


class DirTraversalScanner(BaseModule):
    NAME        = "dir_traversal"
    DESCRIPTION = "Detect path traversal / LFI vulnerabilities"
    TAGS        = ["lfi", "traversal", "owasp-a01"]

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.session = requests.Session()
        self.session.verify = False
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def run(self, target: str) -> List[Finding]:
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        findings = []

        for param in TRAVERSAL_PARAMS:
            for payload in TRAVERSAL_PAYLOADS:
                test_url = f"{target}?{param}={payload}"
                try:
                    resp = self.session.get(test_url, timeout=self.timeout)
                    for sig in TRAVERSAL_SIGNATURES:
                        if sig.search(resp.text):
                            findings.append(Finding(
                                title      = f"Path Traversal / LFI in '{param}' parameter",
                                severity   = Severity.CRITICAL,
                                cvss_score = 9.1,
                                target     = target,
                                url        = test_url,
                                parameter  = param,
                                payload    = payload,
                                evidence   = self._extract(resp.text, sig),
                                module     = self.NAME,
                                description = (
                                    f"Local File Inclusion (LFI) via path traversal was confirmed "
                                    f"in the '{param}' parameter. System files are readable."
                                ),
                                remediation = (
                                    "1. Never pass user input to file-system calls directly. "
                                    "2. Use a whitelist of allowed file names/paths. "
                                    "3. Resolve the real path and verify it starts with the intended base dir. "
                                    "4. Chroot the web process to a restricted directory."
                                ),
                                tags        = ["lfi", "path-traversal", "file-read"],
                                references  = [
                                    "https://owasp.org/www-community/attacks/Path_Traversal",
                                    "https://cwe.mitre.org/data/definitions/22.html",
                                ],
                            ))
                            return findings  # stop after first confirmation
                except Exception:
                    pass
        return findings

    @staticmethod
    def _extract(body: str, pattern: re.Pattern, window: int = 300) -> str:
        m = pattern.search(body)
        if not m:
            return ""
        s = max(0, m.start() - 10)
        e = min(len(body), m.end() + window)
        return body[s:e].strip()
