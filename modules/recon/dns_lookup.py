"""
VulnScanX - DNS Lookup Module
"""
import socket
import dns.resolver
from core.models import Finding
from core.config import Severity
from core.engine import BaseModule


class DNSLookup(BaseModule):
    name = "dns"
    description = "DNS record enumeration (A, MX, NS, TXT, CNAME, SOA)"
    category = "recon"

    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR"]

    def run(self):
        from utils.helpers import extract_domain
        domain = extract_domain(self.config.target)
        self.logger.info(f"DNS enumeration for: {domain}")

        records = {}
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        for rtype in self.RECORD_TYPES:
            try:
                answers = resolver.resolve(domain, rtype)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                pass

        # Create a comprehensive info finding
        if records:
            record_text = "\n".join(
                f"  {k}: {', '.join(v)}" for k, v in records.items()
            )
            finding = Finding(
                title=f"DNS Records Enumerated: {domain}",
                category="Recon",
                target=domain,
                url=f"https://{domain}",
                severity=Severity.INFO,
                cvss_score=0.0,
                owasp="A01:2025",
                description=f"DNS records discovered:\n{record_text}",
                proof_of_concept=record_text,
                remediation=(
                    "Review exposed TXT records for sensitive info. "
                    "Ensure SPF/DKIM/DMARC are properly configured."
                ),
                raw_data={"dns_records": records},
                tags=["recon", "dns"],
            )
            self.add_finding(finding)

        # Check for zone transfer vulnerability
        self._check_zone_transfer(domain, records.get("NS", []))

        # Check for missing DMARC
        self._check_email_security(domain, records)

        return self.findings

    def _check_zone_transfer(self, domain, nameservers):
        for ns in nameservers:
            try:
                import dns.zone
                z = dns.zone.from_xfr(
                    dns.query.xfr(ns.rstrip("."), domain, timeout=5)
                )
                if z:
                    finding = Finding(
                        title=f"DNS Zone Transfer Allowed: {ns}",
                        category="Misconfiguration",
                        target=domain,
                        url=f"https://{domain}",
                        severity=Severity.HIGH,
                        cvss_score=7.5,
                        cwe_id="CWE-200",
                        owasp="A02:2025",
                        description=(
                            f"Nameserver {ns} allows zone transfers (AXFR). "
                            "This exposes all DNS records to attackers."
                        ),
                        proof_of_concept=f"dig AXFR {domain} @{ns}",
                        remediation="Restrict zone transfers to authorized IPs only.",
                        tags=["dns", "zone-transfer", "misconfiguration"],
                    )
                    self.add_finding(finding)
            except Exception:
                pass

    def _check_email_security(self, domain, records):
        txt_records = records.get("TXT", [])
        has_spf = any("v=spf1" in r for r in txt_records)
        has_dmarc = False
        try:
            import dns.resolver
            dmarc_answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            has_dmarc = any("v=DMARC1" in str(r) for r in dmarc_answers)
        except Exception:
            pass

        if not has_spf:
            self.add_finding(Finding(
                title="Missing SPF Record",
                category="Email Security",
                target=domain,
                url=f"https://{domain}",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                owasp="A02:2025",
                description="No SPF record found. Domain vulnerable to email spoofing.",
                remediation='Add: v=spf1 include:_spf.example.com ~all',
                tags=["dns", "email", "spf"],
            ))

        if not has_dmarc:
            self.add_finding(Finding(
                title="Missing DMARC Record",
                category="Email Security",
                target=domain,
                url=f"https://{domain}",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                owasp="A02:2025",
                description="No DMARC policy found. Phishing attacks easier.",
                remediation='Add _dmarc TXT: v=DMARC1; p=reject; rua=mailto:dmarc@example.com',
                tags=["dns", "email", "dmarc"],
            ))
