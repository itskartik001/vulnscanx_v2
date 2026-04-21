"""
VulnScanX - Subdomain Enumerator
===================================
DNS brute-force + certificate transparency log mining.
"""
import socket
import concurrent.futures
import requests
from core.models import Finding
from core.config import Severity
from core.engine import BaseModule


COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "portal", "vpn", "remote", "secure", "login", "app", "blog",
    "shop", "store", "cdn", "static", "assets", "images", "media",
    "mx", "ns1", "ns2", "smtp", "pop", "imap", "webmail", "autodiscover",
    "support", "help", "docs", "status", "monitor", "dashboard",
    "git", "gitlab", "jenkins", "jira", "confluence", "wiki",
    "beta", "alpha", "internal", "intranet", "corp", "office",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "s3", "backup", "old", "legacy", "v2", "v3",
]


class SubdomainEnumerator(BaseModule):
    name = "subdomain"
    description = "DNS brute-force subdomain enumeration + CT log lookup"
    category = "recon"

    def run(self):
        from utils.helpers import extract_domain
        domain = extract_domain(self.config.target)
        self.logger.info(f"Enumerating subdomains for: {domain}")

        found = []

        # CT Log lookup via crt.sh (no auth required)
        found += self._ct_log_lookup(domain)

        # DNS brute-force
        found += self._dns_bruteforce(domain)

        # Deduplicate and create findings
        unique = list(set(found))
        for subdomain in unique:
            finding = Finding(
                title=f"Subdomain Discovered: {subdomain}",
                category="Recon",
                target=domain,
                url=f"https://{subdomain}",
                severity=Severity.INFO,
                cvss_score=0.0,
                owasp="A01:2025",
                description=(
                    f"Active subdomain found: {subdomain}. "
                    "Each subdomain expands the attack surface."
                ),
                proof_of_concept=f"DNS resolves: {subdomain}",
                remediation=(
                    "Audit all subdomains. Remove stale/unused subdomains. "
                    "Implement DNS security policies."
                ),
                tags=["recon", "subdomain", "dns"],
            )
            self.add_finding(finding)

        self.logger.info(f"Found {len(unique)} subdomains")
        return self.findings

    def _ct_log_lookup(self, domain: str):
        """Query crt.sh certificate transparency logs."""
        subdomains = []
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%25.{domain}&output=json",
                timeout=15
            )
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lstrip("*.")
                        if sub.endswith(f".{domain}") or sub == domain:
                            subdomains.append(sub)
        except Exception as e:
            self.logger.debug(f"CT log lookup failed: {e}")
        return list(set(subdomains))

    def _dns_bruteforce(self, domain: str):
        """Concurrent DNS resolution of common subdomains."""
        found = []

        def check(sub):
            fqdn = f"{sub}.{domain}"
            try:
                socket.setdefaulttimeout(3)
                socket.gethostbyname(fqdn)
                return fqdn
            except Exception:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
            futures = {ex.submit(check, sub): sub for sub in COMMON_SUBDOMAINS}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
        return found
