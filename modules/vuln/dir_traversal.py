"""
VulnScanX - Directory Traversal Scanner
"""
import requests
from core.models import Finding
from core.config import Severity, TRAVERSAL_PAYLOADS
from core.engine import BaseModule
from utils.helpers import normalize_url, get_all_params, inject_payload

# Signatures in response indicating successful traversal
TRAVERSAL_SIGNATURES = [
    "root:x:0:0",         # /etc/passwd
    "root:*:0:0",
    "[boot loader]",       # boot.ini
    "Windows Registry",
    "WINDOWS\\system32",
    "[fonts]",             # win.ini
    "localhost",           # /etc/hosts
    "127.0.0.1",
]


class DirectoryTraversalScanner(BaseModule):
    name = "traversal"
    description = "Path traversal / LFI vulnerability detection"
    category = "vuln"

    def run(self):
        base_url = normalize_url(self.config.target)
        session = requests.Session()
        session.headers["User-Agent"] = self.config.user_agent

        # Test URL parameters
        try:
            self.rate_limiter.acquire()
            resp = session.get(base_url, timeout=self.config.timeout, verify=False)
            import re
            links = re.findall(r'href=["\']([^"\']*\?[^"\']+)["\']', resp.text or "", re.I)
        except Exception:
            links = []

        test_urls = [base_url] + [
            (base_url + l if l.startswith("/") else l)
            for l in links[:10] if base_url in l or l.startswith("/")
        ]

        for url in test_urls:
            params = get_all_params(url)
            # Also test common file-related param names
            file_params = [p for p in params if any(
                kw in p.lower() for kw in ["file", "path", "page", "include", "dir", "doc", "load"]
            )]
            if not file_params:
                file_params = list(params.keys())[:3]

            for param in file_params:
                for payload in TRAVERSAL_PAYLOADS:
                    result = self._test_traversal(session, url, param, payload)
                    if result:
                        break

        return self.findings

    def _test_traversal(self, session, url, param, payload):
        try:
            test_url = inject_payload(url, param, payload)
            self.rate_limiter.acquire()
            resp = session.get(test_url, timeout=self.config.timeout, verify=False)
            if not resp or not resp.text:
                return False

            for sig in TRAVERSAL_SIGNATURES:
                if sig in resp.text:
                    snippet = resp.text[:300]
                    self.add_finding(Finding(
                        title=f"Path Traversal / LFI — Parameter: {param}",
                        category="Path Traversal",
                        target=self.config.target, url=test_url, parameter=param,
                        severity=Severity.HIGH, cvss_score=8.6,
                        cwe_id="CWE-22", owasp="A01:2025",
                        description=(
                            f"Local File Inclusion (LFI) detected in `{param}`. "
                            f"Server file content returned (signature: `{sig}`)."
                        ),
                        proof_of_concept=(
                            f"URL: {test_url}\nPayload: {payload}\n"
                            f"Signature found: {sig}\nResponse: {snippet}"
                        ),
                        payload_used=payload, response_snippet=snippet,
                        remediation=(
                            "1. Never use user input to construct file paths.\n"
                            "2. Implement whitelist of allowed files/paths.\n"
                            "3. Chroot the web server process.\n"
                            "4. Disable PHP allow_url_include."
                        ),
                        references=["https://owasp.org/www-community/attacks/Path_Traversal"],
                        tags=["traversal", "lfi", "file-inclusion"],
                    ))
                    return True
        except Exception:
            pass
        return False
