"""
VulnScanX - SQL Injection Scanner
Custom error-based + time-based + boolean-based SQLi detection.
"""
import re
import time
import requests
from core.models import Finding
from core.config import Severity, SQLI_PAYLOADS, SQL_ERROR_PATTERNS
from core.engine import BaseModule
from utils.helpers import normalize_url, get_all_params, inject_payload


class SQLiScanner(BaseModule):
    name = "sqli"
    description = "Error-based, time-based, and boolean-based SQL injection detection"
    category = "vuln"

    TIME_THRESHOLD = 4.0  # seconds, flag as time-based if response delayed

    def run(self):
        base_url = normalize_url(self.config.target)
        session = requests.Session()
        session.headers["User-Agent"] = self.config.user_agent

        test_urls = self._collect_test_urls(base_url, session)

        for url in test_urls:
            params = get_all_params(url)
            if not params:
                params = {"id": ["1"], "user": ["admin"], "search": ["test"]}
            for param in params:
                self._test_error_based(session, url, param)
                self._test_time_based(session, url, param)
                self._test_boolean_based(session, url, param)

        return self.findings

    def _collect_test_urls(self, base_url, session):
        urls = [base_url]
        try:
            resp = session.get(base_url, timeout=self.config.timeout, verify=False)
            links = re.findall(r'href=["\']([^"\']*\?[^"\']+)["\']', resp.text or "", re.I)
            for link in links[:20]:
                if link.startswith("/"):
                    link = base_url + link
                if base_url in link:
                    urls.append(link)
        except Exception:
            pass
        return list(set(urls))[:10]

    def _test_error_based(self, session, url, param):
        """Inject error-triggering payloads and look for DB error strings."""
        for payload in SQLI_PAYLOADS["error_based"][:10]:
            try:
                test_url = inject_payload(url, param, payload)
                self.rate_limiter.acquire()
                resp = session.get(test_url, timeout=self.config.timeout, verify=False)
                if not resp or not resp.text:
                    continue
                body_lower = resp.text.lower()
                for pattern in SQL_ERROR_PATTERNS:
                    if pattern in body_lower:
                        self._add_sqli_finding(
                            url=test_url, param=param, payload=payload,
                            sqli_type="Error-Based",
                            evidence=f"DB error pattern found: '{pattern}'",
                            resp=resp,
                        )
                        return
            except Exception:
                pass

    def _test_time_based(self, session, url, param):
        """Inject time-delay payloads and measure response time."""
        # First get baseline response time
        try:
            baseline_start = time.time()
            self.rate_limiter.acquire()
            session.get(url, timeout=self.config.timeout, verify=False)
            baseline = time.time() - baseline_start
        except Exception:
            baseline = 1.0

        for payload in SQLI_PAYLOADS["time_based"][:5]:
            try:
                test_url = inject_payload(url, param, payload)
                self.rate_limiter.acquire()
                start = time.time()
                resp = session.get(test_url, timeout=15, verify=False)
                elapsed = time.time() - start

                if elapsed >= self.TIME_THRESHOLD and elapsed > baseline + 3.0:
                    self._add_sqli_finding(
                        url=test_url, param=param, payload=payload,
                        sqli_type="Time-Based Blind",
                        evidence=(
                            f"Response delayed {elapsed:.2f}s "
                            f"(baseline: {baseline:.2f}s)"
                        ),
                        resp=resp,
                        cvss=9.0,
                    )
                    return
            except Exception:
                pass

    def _test_boolean_based(self, session, url, param):
        """Test boolean conditions for differential responses."""
        try:
            # Get baseline
            self.rate_limiter.acquire()
            baseline = session.get(url, timeout=self.config.timeout, verify=False)
            if not baseline:
                return
            baseline_len = len(baseline.text or "")

            true_url = inject_payload(url, param, "' AND 1=1--")
            false_url = inject_payload(url, param, "' AND 1=2--")

            self.rate_limiter.acquire()
            true_resp = session.get(true_url, timeout=self.config.timeout, verify=False)
            self.rate_limiter.acquire()
            false_resp = session.get(false_url, timeout=self.config.timeout, verify=False)

            if not true_resp or not false_resp:
                return

            true_len = len(true_resp.text or "")
            false_len = len(false_resp.text or "")

            # Significant difference indicates boolean injection
            diff = abs(true_len - false_len)
            if diff > 50 and true_len != false_len:
                self._add_sqli_finding(
                    url=true_url, param=param,
                    payload="' AND 1=1-- / ' AND 1=2--",
                    sqli_type="Boolean-Based Blind",
                    evidence=(
                        f"Response length difference: TRUE={true_len} vs FALSE={false_len} "
                        f"(diff: {diff} bytes)"
                    ),
                    resp=true_resp,
                )
        except Exception:
            pass

    def _add_sqli_finding(self, url, param, payload, sqli_type, evidence, resp, cvss=8.6):
        snippet = ""
        if resp and resp.text:
            for pattern in SQL_ERROR_PATTERNS:
                idx = resp.text.lower().find(pattern)
                if idx >= 0:
                    snippet = resp.text[max(0, idx-30):idx+100]
                    break

        self.add_finding(Finding(
            title=f"SQL Injection ({sqli_type}) — Parameter: {param}",
            category="SQL Injection",
            target=self.config.target, url=url, parameter=param,
            severity=Severity.CRITICAL if cvss >= 9.0 else Severity.HIGH,
            cvss_score=cvss, cwe_id="CWE-89", owasp="A03:2025",
            description=(
                f"{sqli_type} SQL injection detected in parameter `{param}`. "
                f"An attacker can read, modify, or delete database contents, "
                f"potentially compromising all application data."
            ),
            proof_of_concept=(
                f"URL: {url}\nParam: {param}\nPayload: {payload}\n"
                f"Evidence: {evidence}\nSnippet: {snippet}"
            ),
            payload_used=payload, response_snippet=snippet,
            remediation=(
                "1. Use parameterized queries / prepared statements.\n"
                "2. Never concatenate user input into SQL.\n"
                "3. Apply principle of least privilege to DB accounts.\n"
                "4. Implement a WAF as additional defense-in-depth."
            ),
            references=[
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            ],
            tags=["sqli", "injection", "critical"],
        ))
