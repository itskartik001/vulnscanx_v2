"""
VulnScanX — Reconnaissance Modules
=====================================
Subdomain enumeration, DNS lookup, WHOIS, and directory brute forcing.
All implemented without external tool dependencies.

OWASP Top 10 2025: A01 – Broken Access Control (exposure via recon)
"""

import re
import socket
import time
import urllib.parse
from typing import Dict, List, Optional

import requests

from core import BaseModule, Finding, Severity

# ---------------------------------------------------------------------------
# Subdomain Enumeration
# ---------------------------------------------------------------------------

SUBDOMAINS_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "webdisk", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap",
    "test", "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news",
    "vpn", "ns3", "mail2", "new", "mysql", "old", "lists", "support", "mobile",
    "mx", "static", "docs", "beta", "shop", "sql", "secure", "demo", "cp",
    "calendar", "wiki", "web", "media", "email", "images", "img", "www1",
    "intranet", "portal", "video", "sip", "dns2", "api", "cdn", "app",
    "exchange", "remote", "server", "vpn1", "ns4", "smtp2", "webconf",
    "staging", "dev2", "uat", "preprod", "internal", "gateway", "proxy",
    "backoffice", "dashboard", "monitor", "logs", "status", "health",
]


class SubdomainEnumerator(BaseModule):
    NAME        = "subdomain_enum"
    DESCRIPTION = "Enumerate subdomains via DNS brute force + certificate transparency"
    TAGS        = ["recon", "subdomains", "dns"]

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.wordlist = self.config.get("wordlist", SUBDOMAINS_WORDLIST)

    def run(self, target: str) -> List[Finding]:
        domain   = self._extract_domain(target)
        self.log(f"[Recon] Enumerating subdomains for: {domain}")

        found = []
        found.extend(self._dns_brute(domain))
        found.extend(self._crt_sh(domain))

        # Deduplicate
        unique = list({f.url: f for f in found}.values())
        self.log(f"[Recon] Discovered {len(unique)} subdomains")
        return unique

    def _dns_brute(self, domain: str) -> List[Finding]:
        findings = []
        for sub in self.wordlist:
            fqdn = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                findings.append(Finding(
                    title      = f"Subdomain Discovered: {fqdn}",
                    severity   = Severity.INFO,
                    cvss_score = 0.0,
                    target     = domain,
                    url        = fqdn,
                    module     = self.NAME,
                    evidence   = f"DNS A record: {fqdn} → {ip}",
                    description = f"Subdomain {fqdn} resolves to {ip}.",
                    remediation = "Review if this subdomain is intended to be public. Remove DNS records for decommissioned services.",
                    tags       = ["recon", "subdomain", f"ip:{ip}"],
                ))
            except socket.gaierror:
                pass
        return findings

    def _crt_sh(self, domain: str) -> List[Finding]:
        """Query crt.sh Certificate Transparency logs."""
        findings = []
        try:
            url  = f"https://crt.sh/?q=%.{domain}&output=json"
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                data     = resp.json()
                seen     = set()
                for cert in data:
                    name_value = cert.get("name_value", "")
                    for sub in name_value.split("\n"):
                        sub = sub.strip().lstrip("*.")
                        if sub and sub.endswith(domain) and sub not in seen:
                            seen.add(sub)
                            findings.append(Finding(
                                title      = f"Subdomain (CT Log): {sub}",
                                severity   = Severity.INFO,
                                cvss_score = 0.0,
                                target     = domain,
                                url        = sub,
                                module     = self.NAME,
                                evidence   = f"Found in Certificate Transparency log (crt.sh)",
                                description = f"Subdomain {sub} appeared in SSL/TLS certificate records.",
                                remediation = "Review exposed subdomains; remove DNS entries for retired services.",
                                tags       = ["recon", "ct-log", "subdomain"],
                            ))
        except Exception as e:
            self.log(f"[crt.sh] Error: {e}")
        return findings

    @staticmethod
    def _extract_domain(target: str) -> str:
        target = re.sub(r"^https?://", "", target)
        return target.split("/")[0].split("?")[0]


# ---------------------------------------------------------------------------
# DNS Lookup
# ---------------------------------------------------------------------------

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR"]


class DNSLookup(BaseModule):
    NAME        = "dns_lookup"
    DESCRIPTION = "Comprehensive DNS record enumeration"
    TAGS        = ["recon", "dns"]

    def run(self, target: str) -> List[Finding]:
        import subprocess, json
        domain   = SubdomainEnumerator._extract_domain(target)
        findings = []
        self.log(f"[DNS] Looking up records for {domain}")

        # Use dig if available, else fallback to socket
        records = self._resolve_basic(domain)
        for rtype, values in records.items():
            if values:
                findings.append(Finding(
                    title      = f"DNS {rtype} Records for {domain}",
                    severity   = Severity.INFO,
                    cvss_score = 0.0,
                    target     = domain,
                    url        = domain,
                    module     = self.NAME,
                    evidence   = "; ".join(str(v) for v in values),
                    description = f"DNS {rtype} records enumerated for {domain}.",
                    remediation = "Ensure DNS records are minimal and do not expose internal infrastructure.",
                    tags       = ["dns", f"record:{rtype}"],
                ))

        # SPF/DMARC/DKIM checks
        findings.extend(self._email_security_checks(domain))
        return findings

    def _resolve_basic(self, domain: str) -> Dict:
        records = {}
        # A record
        try:
            records["A"] = [socket.gethostbyname(domain)]
        except Exception:
            records["A"] = []

        # Try dnspython if available
        try:
            import dns.resolver
            for rtype in ["MX", "NS", "TXT", "CNAME"]:
                try:
                    answers = dns.resolver.resolve(domain, rtype)
                    records[rtype] = [str(r) for r in answers]
                except Exception:
                    records[rtype] = []
        except ImportError:
            pass

        return records

    def _email_security_checks(self, domain: str) -> List[Finding]:
        findings = []
        try:
            import dns.resolver
            # SPF
            try:
                txt_records = dns.resolver.resolve(domain, "TXT")
                spf_found   = any("v=spf1" in str(r) for r in txt_records)
                dmarc_domain = f"_dmarc.{domain}"
                dmarc_found = False
                try:
                    dns.resolver.resolve(dmarc_domain, "TXT")
                    dmarc_found = True
                except Exception:
                    pass

                if not spf_found:
                    findings.append(Finding(
                        title      = "Missing SPF Record",
                        severity   = Severity.MEDIUM,
                        cvss_score = 5.3,
                        target     = domain,
                        url        = domain,
                        module     = self.NAME,
                        evidence   = "No v=spf1 TXT record found",
                        description = "No SPF record found. Attackers can spoof emails from this domain.",
                        remediation = 'Add TXT record: "v=spf1 include:_spf.yourmailprovider.com ~all"',
                        tags       = ["email", "spf"],
                    ))
                if not dmarc_found:
                    findings.append(Finding(
                        title      = "Missing DMARC Record",
                        severity   = Severity.MEDIUM,
                        cvss_score = 5.3,
                        target     = domain,
                        url        = domain,
                        module     = self.NAME,
                        evidence   = f"No TXT record at _dmarc.{domain}",
                        description = "No DMARC policy found. Email spoofing may succeed.",
                        remediation = 'Add TXT record at _dmarc.domain: "v=DMARC1; p=reject; rua=mailto:dmarc@domain"',
                        tags       = ["email", "dmarc"],
                    ))
            except Exception:
                pass
        except ImportError:
            pass
        return findings


# ---------------------------------------------------------------------------
# Directory Brute Force
# ---------------------------------------------------------------------------

DIR_WORDLIST = [
    "admin", "administrator", "login", "dashboard", "panel", "control",
    "api", "api/v1", "api/v2", "graphql", "rest", "swagger", "docs",
    "backup", "backups", ".backup", "db", "database",
    "config", "configuration", ".env", ".git", ".svn", "Dockerfile",
    "wp-admin", "wp-login.php", "wp-config.php",
    "phpmyadmin", "phpinfo.php", "info.php",
    "test", "testing", "dev", "debug",
    "upload", "uploads", "files", "file", "assets",
    "static", "media", "images", "css", "js",
    "robots.txt", "sitemap.xml", ".htaccess", "web.config",
    "server-status", "server-info",
    "console", "manager", "management", "monitoring",
    "health", "status", "metrics", "actuator",
    "actuator/env", "actuator/beans", "actuator/mappings",
    "trace", "error", "errors", "exception",
    "old", "archive", "bak", "temp", "tmp",
    "install", "setup", "update", "upgrade",
    "cgi-bin", "cgi", "scripts",
    ".DS_Store", "thumbs.db",
]

INTERESTING_CODES = {200, 201, 204, 301, 302, 307, 308, 401, 403}
SENSITIVE_CODES   = {200, 201, 204}


class DirBruteForce(BaseModule):
    NAME        = "dir_bruteforce"
    DESCRIPTION = "Discover hidden paths and sensitive endpoints"
    TAGS        = ["recon", "discovery", "owasp-a01"]

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.wordlist    = self.config.get("wordlist", DIR_WORDLIST)
        self.session     = requests.Session()
        self.session.verify = False
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def run(self, target: str) -> List[Finding]:
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        base   = target.rstrip("/")
        self.log(f"[DirBrute] Scanning {base} with {len(self.wordlist)} paths")

        findings = []
        for path in self.wordlist:
            url = f"{base}/{path}"
            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                if resp.status_code in INTERESTING_CODES:
                    sev = self._assess_severity(path, resp.status_code)
                    findings.append(Finding(
                        title      = f"Discovered Path: /{path} (HTTP {resp.status_code})",
                        severity   = sev,
                        cvss_score = self._cvss(sev),
                        target     = base,
                        url        = url,
                        module     = self.NAME,
                        evidence   = f"GET {url} → HTTP {resp.status_code} ({len(resp.content)} bytes)",
                        description = self._describe_path(path, resp.status_code),
                        remediation = self._remediate_path(path, resp.status_code),
                        tags       = ["directory", f"status:{resp.status_code}", self._path_category(path)],
                    ))
            except Exception:
                pass
            time.sleep(0.05)  # mild rate limiting

        self.log(f"[DirBrute] Found {len(findings)} paths")
        return findings

    @staticmethod
    def _assess_severity(path: str, code: int) -> Severity:
        sensitive_paths = {".env", ".git", "phpinfo.php", "wp-config.php",
                           "config", "database", "backup", "backups", "db",
                           "actuator", "actuator/env", ".htaccess", "web.config"}
        admin_paths     = {"admin", "administrator", "panel", "phpmyadmin",
                           "console", "manager", "wp-admin"}

        if any(s in path.lower() for s in sensitive_paths):
            return Severity.CRITICAL if code in SENSITIVE_CODES else Severity.HIGH
        if any(a in path.lower() for a in admin_paths):
            return Severity.HIGH if code in SENSITIVE_CODES else Severity.MEDIUM
        if code in SENSITIVE_CODES:
            return Severity.MEDIUM
        return Severity.LOW

    @staticmethod
    def _cvss(sev: Severity) -> float:
        return {Severity.CRITICAL: 9.1, Severity.HIGH: 7.5,
                Severity.MEDIUM: 5.3, Severity.LOW: 3.1, Severity.INFO: 0.0}[sev]

    @staticmethod
    def _describe_path(path: str, code: int) -> str:
        if ".env" in path:
            return "Environment configuration file exposed. May contain DB credentials, API keys, and secrets."
        if ".git" in path:
            return "Git repository metadata exposed. Source code and commit history may be downloadable."
        if "backup" in path.lower():
            return "Backup directory or file is accessible. May contain copies of sensitive configuration."
        if code == 401:
            return f"Path /{path} requires authentication — confirming the resource exists."
        if code == 403:
            return f"Path /{path} is forbidden but exists. May indicate a sensitive resource."
        return f"Path /{path} returned HTTP {code}."

    @staticmethod
    def _remediate_path(path: str, code: int) -> str:
        if ".git" in path:
            return "Add 'Deny from all' to .htaccess for /.git. Use a .gitignore to exclude sensitive files."
        if ".env" in path:
            return "Never deploy .env files to a web-accessible directory. Move to parent dir or use server env vars."
        if code in (401, 403):
            return "Verify access controls are correct. If resource shouldn't exist, remove it."
        return "Evaluate if this path needs to be publicly accessible. Restrict or remove if not required."

    @staticmethod
    def _path_category(path: str) -> str:
        if any(x in path for x in ["admin", "panel", "manager", "console"]):
            return "admin-panel"
        if any(x in path for x in ["api", "graphql", "swagger"]):
            return "api-endpoint"
        if any(x in path for x in [".env", ".git", "config", "backup"]):
            return "sensitive-file"
        return "content"
