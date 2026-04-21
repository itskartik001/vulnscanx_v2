"""
VulnScanX — XSS Scanner Module
================================
Detects Reflected XSS, DOM-based XSS hints, and basic stored-XSS simulation
using a curated payload bank and multi-context testing strategy.

OWASP Top 10 2025: A05 – Injection
"""

import re
import urllib.parse
from typing import List, Optional

import requests
from bs4 import BeautifulSoup

from core import BaseModule, Finding, Severity

# ---------------------------------------------------------------------------
# Payload bank — categorized by injection context
# ---------------------------------------------------------------------------
XSS_PAYLOADS = {
    "html_context": [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
    ],
    "attribute_context": [
        "\" onmouseover=\"alert('XSS')\"",
        "' onfocus='alert(1)'",
        "\" autofocus onfocus=\"alert(1)\"",
    ],
    "javascript_context": [
        "';alert('XSS');//",
        "\";alert('XSS');//",
        "`${alert('XSS')}`",
    ],
    "filter_bypass": [
        "<ScRiPt>alert('XSS')</sCrIpT>",
        "<script/src=data:,alert(1)>",
        "<!--<img src=x:x onerror=alert(1)>-->",
        "<<script>alert('XSS')//<</script>",
        "%3Cscript%3Ealert%281%29%3C/script%3E",
        "<details/open/ontoggle=alert(1)>",
        "<math><maction actiontype='statusline#' xlink:href='javascript:alert(1)'>CLICK",
    ],
}

ALL_PAYLOADS = [p for bucket in XSS_PAYLOADS.values() for p in bucket]

# Patterns to detect XSS reflection in response
REFLECTION_PATTERNS = [
    re.compile(r"<script[^>]*>.*?alert.*?</script>", re.I | re.S),
    re.compile(r"onerror\s*=\s*['\"]?alert", re.I),
    re.compile(r"onload\s*=\s*['\"]?alert", re.I),
    re.compile(r"javascript\s*:\s*alert", re.I),
]

DOM_SINK_PATTERNS = [
    re.compile(r"document\.write\s*\(", re.I),
    re.compile(r"innerHTML\s*=", re.I),
    re.compile(r"outerHTML\s*=", re.I),
    re.compile(r"eval\s*\(", re.I),
    re.compile(r"setTimeout\s*\(\s*['\"]", re.I),
    re.compile(r"location\.hash", re.I),
]


class XSSScanner(BaseModule):
    """
    Reflected & DOM-based XSS scanner.

    Strategy:
    1. Crawl forms on the target page.
    2. Inject each payload into every form field & URL parameter.
    3. Analyse response body for payload reflection.
    4. Inspect JavaScript for dangerous DOM sinks (static analysis).
    """

    NAME        = "xss_scanner"
    DESCRIPTION = "Detects reflected and DOM-based XSS vulnerabilities"
    TAGS        = ["xss", "injection", "owasp-a05"]

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "VulnScanX/1.0 (Security Research; +https://github.com/vulnscanx)",
        })
        self.session.verify = False
        # Suppress SSL warnings in research contexts
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # -------------------------------------------------------------- public API
    def run(self, target: str) -> List[Finding]:
        findings: List[Finding] = []
        target = self._normalize_url(target)
        self.log(f"[XSS] Starting scan → {target}")

        try:
            # Phase 1: URL parameter injection
            findings.extend(self._scan_url_params(target))
            # Phase 2: Form-based injection
            findings.extend(self._scan_forms(target))
            # Phase 3: DOM sink analysis
            findings.extend(self._dom_sink_analysis(target))
        except requests.RequestException as e:
            self.log(f"[XSS] Network error: {e}")

        self.log(f"[XSS] Found {len(findings)} XSS issues")
        return findings

    # --------------------------------------------------------- Phase 1: URL params
    def _scan_url_params(self, url: str) -> List[Finding]:
        findings = []
        parsed   = urllib.parse.urlparse(url)
        params   = urllib.parse.parse_qs(parsed.query)

        if not params:
            # Inject a test parameter if none exist
            params = {"q": ["test"], "search": ["test"], "id": ["1"]}

        for param_name in params:
            for payload in ALL_PAYLOADS[:8]:  # limit for performance
                test_params              = dict(params)
                test_params[param_name]  = [payload]
                test_query               = urllib.parse.urlencode(test_params, doseq=True)
                test_url                 = urllib.parse.urlunparse(parsed._replace(query=test_query))

                finding = self._test_url(test_url, payload, param_name)
                if finding:
                    findings.append(finding)
        return findings

    # --------------------------------------------------------- Phase 2: forms
    def _scan_forms(self, url: str) -> List[Finding]:
        findings = []
        try:
            resp = self.session.get(url, timeout=self.timeout)
        except Exception:
            return findings

        soup  = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")
        self.log(f"[XSS] Found {len(forms)} form(s) on {url}")

        for form in forms:
            findings.extend(self._test_form(url, form))
        return findings

    def _test_form(self, base_url: str, form) -> List[Finding]:
        findings = []
        action   = form.get("action", "")
        method   = form.get("method", "get").lower()
        target   = urllib.parse.urljoin(base_url, action)

        inputs = form.find_all(["input", "textarea", "select"])
        for payload in ALL_PAYLOADS[:6]:
            data = {}
            injectable_field = None
            for inp in inputs:
                name = inp.get("name", "")
                if not name:
                    continue
                inp_type = inp.get("type", "text").lower()
                if inp_type in ("submit", "reset", "button", "image", "file"):
                    data[name] = inp.get("value", "submit")
                elif inp_type == "hidden":
                    data[name] = inp.get("value", "hidden")
                else:
                    data[name]       = payload
                    injectable_field = name

            if not injectable_field:
                continue

            try:
                if method == "post":
                    resp = self.session.post(target, data=data, timeout=self.timeout)
                else:
                    resp = self.session.get(target, params=data, timeout=self.timeout)

                if self._payload_reflected(resp.text, payload):
                    findings.append(self._build_finding(
                        target=base_url,
                        url=target,
                        parameter=injectable_field,
                        payload=payload,
                        evidence=self._extract_evidence(resp.text, payload),
                        method=method.upper(),
                    ))
            except Exception:
                pass
        return findings

    # --------------------------------------------------------- Phase 3: DOM analysis
    def _dom_sink_analysis(self, url: str) -> List[Finding]:
        findings = []
        try:
            resp = self.session.get(url, timeout=self.timeout)
        except Exception:
            return findings

        soup    = BeautifulSoup(resp.text, "html.parser")
        scripts = soup.find_all("script")
        sinks_found = []

        for script in scripts:
            src  = script.get("src")
            code = script.string or ""
            for pattern in DOM_SINK_PATTERNS:
                match = pattern.search(code)
                if match:
                    sinks_found.append(match.group(0))

        if sinks_found:
            findings.append(Finding(
                title       = "DOM-Based XSS Sink Detected",
                severity    = Severity.MEDIUM,
                cvss_score  = 5.4,
                target      = url,
                url         = url,
                module      = self.NAME,
                evidence    = "; ".join(set(sinks_found[:5])),
                description = (
                    "Dangerous JavaScript DOM sinks were found in inline scripts. "
                    "If attacker-controlled data flows into these sinks, DOM-based XSS is possible."
                ),
                remediation = (
                    "Avoid using innerHTML, document.write, eval() with untrusted data. "
                    "Use textContent or DOMPurify to sanitize user input before DOM insertion."
                ),
                tags        = ["dom-xss", "static-analysis"],
                references  = [
                    "https://owasp.org/www-community/attacks/DOM_Based_XSS",
                    "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html",
                ],
            ))
        return findings

    # ------------------------------------------------------------ helpers
    def _test_url(self, url: str, payload: str, param: str) -> Optional[Finding]:
        try:
            resp = self.session.get(url, timeout=self.timeout)
            if self._payload_reflected(resp.text, payload):
                return self._build_finding(
                    target=url.split("?")[0],
                    url=url,
                    parameter=param,
                    payload=payload,
                    evidence=self._extract_evidence(resp.text, payload),
                    method="GET",
                )
        except Exception:
            pass
        return None

    @staticmethod
    def _payload_reflected(body: str, payload: str) -> bool:
        """Check if payload appears in response (raw or partial)."""
        if payload in body:
            return True
        for pattern in REFLECTION_PATTERNS:
            if pattern.search(body):
                return True
        # Check encoded reflection
        encoded = urllib.parse.quote(payload)
        if encoded in body:
            return True
        return False

    @staticmethod
    def _extract_evidence(body: str, payload: str, window: int = 100) -> str:
        idx = body.find(payload)
        if idx == -1:
            return payload
        start = max(0, idx - window // 2)
        end   = min(len(body), idx + len(payload) + window // 2)
        return "..." + body[start:end].strip() + "..."

    @staticmethod
    def _build_finding(
        target: str,
        url: str,
        parameter: str,
        payload: str,
        evidence: str,
        method: str = "GET",
    ) -> Finding:
        return Finding(
            title       = f"Reflected XSS in '{parameter}' parameter",
            severity    = Severity.HIGH,
            cvss_score  = 7.2,
            target      = target,
            url         = url,
            parameter   = parameter,
            payload     = payload,
            evidence    = evidence,
            module      = "xss_scanner",
            description = (
                f"A reflected Cross-Site Scripting (XSS) vulnerability was discovered "
                f"in the '{parameter}' parameter via HTTP {method}. "
                f"The server reflects untrusted input back into the page without sanitization."
            ),
            remediation = (
                "1. Encode all user-supplied data before rendering in HTML (use htmlspecialchars / escapeHtml). "
                "2. Implement a strict Content Security Policy (CSP). "
                "3. Use a framework with automatic output encoding. "
                "4. Validate and whitelist input on the server side."
            ),
            tags        = ["xss", "reflected", "owasp-a05", f"method:{method}"],
            references  = [
                "https://owasp.org/www-community/attacks/xss/",
                "https://cwe.mitre.org/data/definitions/79.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            ],
        )

    @staticmethod
    def _normalize_url(url: str) -> str:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url.rstrip("/")
