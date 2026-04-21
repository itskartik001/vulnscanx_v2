"""
VulnScanX - Security Headers Checker
"""
import requests
from core.models import Finding
from core.config import Severity, SECURITY_HEADERS
from core.engine import BaseModule
from utils.helpers import normalize_url


class SecurityHeadersChecker(BaseModule):
    name = "headers"
    description = "HTTP security headers analysis and CSP evaluation"
    category = "vuln"

    def run(self):
        base_url = normalize_url(self.config.target)
        session = requests.Session()
        session.headers["User-Agent"] = self.config.user_agent

        try:
            self.rate_limiter.acquire()
            resp = session.get(base_url, timeout=self.config.timeout,
                             verify=self.config.verify_ssl)
        except Exception as e:
            self.logger.error(f"Headers check failed: {e}")
            return self.findings

        response_headers = {k.lower(): v for k, v in resp.headers.items()}

        # Check each required security header
        for header_name, meta in SECURITY_HEADERS.items():
            header_lower = header_name.lower()
            if header_lower not in response_headers:
                self.add_finding(Finding(
                    title=f"Missing Security Header: {header_name}",
                    category="Security Misconfiguration",
                    target=self.config.target, url=base_url,
                    severity=meta["severity"], cvss_score=5.3,
                    cwe_id="CWE-693", owasp="A02:2025",
                    description=(
                        f"The `{header_name}` header is missing. "
                        f"{meta['description']} not enforced."
                    ),
                    proof_of_concept=f"GET {base_url} — Header `{header_name}` not present in response",
                    remediation=self._get_remediation(header_name),
                    tags=["headers", "misconfiguration"],
                ))

        # Check for information disclosure
        self._check_info_disclosure(response_headers, base_url)

        # Check SSL/TLS
        if base_url.startswith("http://"):
            self.add_finding(Finding(
                title="HTTP Without HTTPS",
                category="Cryptographic Failure",
                target=self.config.target, url=base_url,
                severity=Severity.HIGH, cvss_score=7.4,
                cwe_id="CWE-319", owasp="A02:2025",
                description="Site served over insecure HTTP. Data in transit is unencrypted.",
                proof_of_concept=f"Site accessible at: {base_url}",
                remediation="Redirect all HTTP traffic to HTTPS. Use TLS 1.2 or 1.3.",
                tags=["tls", "encryption", "high"],
            ))

        return self.findings

    def _check_info_disclosure(self, headers, url):
        leaky_headers = {
            "server": "Reveals web server software/version",
            "x-powered-by": "Reveals backend technology (PHP/ASP.NET version)",
            "x-aspnet-version": "Reveals exact ASP.NET version",
            "x-aspnetmvc-version": "Reveals ASP.NET MVC version",
        }
        for header, desc in leaky_headers.items():
            if header in headers:
                self.add_finding(Finding(
                    title=f"Information Disclosure: {header.title()} Header",
                    category="Information Disclosure",
                    target=self.config.target, url=url,
                    severity=Severity.LOW, cvss_score=3.7,
                    cwe_id="CWE-200", owasp="A02:2025",
                    description=f"{desc}. Value: `{headers[header]}`",
                    proof_of_concept=f"{header.title()}: {headers[header]}",
                    remediation=f"Remove or obfuscate the `{header.title()}` header.",
                    tags=["headers", "info-disclosure"],
                ))

    def _get_remediation(self, header):
        remediations = {
            "Strict-Transport-Security": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            "Content-Security-Policy": "Add a restrictive CSP: Content-Security-Policy: default-src 'self'",
            "X-Frame-Options": "Add: X-Frame-Options: DENY",
            "X-Content-Type-Options": "Add: X-Content-Type-Options: nosniff",
            "Referrer-Policy": "Add: Referrer-Policy: strict-origin-when-cross-origin",
            "Permissions-Policy": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
        }
        return remediations.get(header, f"Implement the {header} header with appropriate values.")
