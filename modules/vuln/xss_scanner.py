"""
VulnScanX - XSS Scanner
"""
import re
import requests
from core.models import Finding
from core.config import Severity, XSS_PAYLOADS
from core.engine import BaseModule
from utils.helpers import normalize_url, get_all_params, inject_payload

DOM_SINKS = [
    r"document\.write\s*\(", r"innerHTML\s*=", r"outerHTML\s*=",
    r"eval\s*\(", r"setTimeout\s*\(", r"location\.href\s*=",
]


class XSSScanner(BaseModule):
    name = "xss"
    description = "Reflected & DOM-based XSS detection"
    category = "vuln"

    def run(self):
        base_url = normalize_url(self.config.target)
        session = requests.Session()
        session.headers["User-Agent"] = self.config.user_agent

        test_urls = self._collect_test_urls(base_url, session)

        for url in test_urls:
            params = get_all_params(url)
            if not params:
                params = {"q": ["test"], "search": ["test"], "id": ["1"]}
            for param_name in params:
                self._test_reflected_xss(session, url, param_name)
                self._test_post_xss(session, url, param_name)

        self._check_dom_xss(session, base_url)
        return self.findings

    def _collect_test_urls(self, base_url, session):
        urls = [base_url]
        try:
            resp = session.get(base_url, timeout=self.config.timeout, verify=False)
            if resp.status_code == 200:
                links = re.findall(r'href=["\']([^"\']*\?[^"\']+)["\']', resp.text, re.I)
                for link in links[:20]:
                    if link.startswith("/"):
                        link = base_url + link
                    if base_url in link:
                        urls.append(link)
        except Exception:
            pass
        return list(set(urls))[:15]

    def _test_reflected_xss(self, session, url, param):
        for payload in XSS_PAYLOADS[:8]:
            try:
                test_url = inject_payload(url, param, payload)
                self.rate_limiter.acquire()
                resp = session.get(test_url, timeout=self.config.timeout, verify=False)
                if payload in (resp.text or ""):
                    self._add_xss_finding(url=test_url, param=param, payload=payload,
                                         method="GET", xss_type="Reflected", resp=resp)
                    return
            except Exception:
                pass

    def _test_post_xss(self, session, url, param):
        for payload in XSS_PAYLOADS[:5]:
            try:
                self.rate_limiter.acquire()
                resp = session.post(url, data={param: payload},
                                   timeout=self.config.timeout, verify=False)
                if payload in (resp.text or ""):
                    self._add_xss_finding(url=url, param=param, payload=payload,
                                         method="POST", xss_type="Reflected POST", resp=resp)
                    return
            except Exception:
                pass

    def _check_dom_xss(self, session, url):
        try:
            self.rate_limiter.acquire()
            resp = session.get(url, timeout=self.config.timeout, verify=False)
            for pattern in DOM_SINKS:
                matches = re.findall(pattern, resp.text or "", re.I)
                if matches:
                    self.add_finding(Finding(
                        title=f"Potential DOM XSS Sink: {matches[0]}",
                        category="Cross-Site Scripting (DOM)", target=self.config.target,
                        url=url, severity=Severity.MEDIUM, cvss_score=6.1,
                        cwe_id="CWE-79", owasp="A03:2025",
                        description=f"Dangerous DOM sink: `{matches[0]}`",
                        proof_of_concept=f"Pattern in source: {matches[0]}",
                        remediation="Use textContent instead of innerHTML. Implement DOMPurify.",
                        tags=["xss", "dom-xss"],
                    ))
        except Exception:
            pass

    def _add_xss_finding(self, url, param, payload, method, xss_type, resp):
        snippet = ""
        if resp and resp.text:
            idx = resp.text.find(payload[:20])
            if idx >= 0:
                snippet = resp.text[max(0, idx-50):idx+100]

        self.add_finding(Finding(
            title=f"{xss_type} XSS — Parameter: {param}",
            category="Cross-Site Scripting (XSS)",
            target=self.config.target, url=url, parameter=param, method=method,
            severity=Severity.HIGH, cvss_score=8.2, cwe_id="CWE-79", owasp="A03:2025",
            description=(
                f"Reflected XSS in `{param}`. Application echoes input without sanitization."
            ),
            proof_of_concept=(
                f"URL: {url}\nParam: {param}\nMethod: {method}\nPayload: {payload}\n"
                f"Snippet: ...{snippet}..."
            ),
            payload_used=payload, response_snippet=snippet,
            remediation=(
                "1. HTML-encode all user input.\n2. Implement strict CSP.\n"
                "3. Use frameworks with auto-escaping.\n4. Validate input server-side."
            ),
            references=["https://owasp.org/www-community/attacks/xss/"],
            tags=["xss", "injection", "high"],
        ))
