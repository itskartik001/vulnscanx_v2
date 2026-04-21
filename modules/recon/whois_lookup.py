"""
VulnScanX - WHOIS Lookup Module
"""
import whois
from core.models import Finding
from core.config import Severity
from core.engine import BaseModule
from datetime import datetime, timezone


class WHOISLookup(BaseModule):
    name = "whois"
    description = "WHOIS domain registration and expiry analysis"
    category = "recon"

    def run(self):
        from utils.helpers import extract_domain
        domain = extract_domain(self.config.target)
        self.logger.info(f"WHOIS lookup for: {domain}")

        try:
            w = whois.whois(domain)
            info = {
                "registrar": str(w.registrar),
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "updated_date": str(w.updated_date),
                "name_servers": w.name_servers,
                "emails": w.emails,
                "org": str(w.org),
                "country": str(w.country),
            }

            self.add_finding(Finding(
                title=f"WHOIS Information: {domain}",
                category="Recon",
                target=domain,
                url=f"https://{domain}",
                severity=Severity.INFO,
                cvss_score=0.0,
                description=f"WHOIS data: Registrar={w.registrar}, Org={w.org}",
                proof_of_concept=str(info),
                remediation="Consider domain privacy protection (WHOIS guard).",
                raw_data=info,
                tags=["recon", "whois"],
            ))

            # Check for expiring domain
            exp = w.expiration_date
            if exp:
                if isinstance(exp, list):
                    exp = exp[0]
                try:
                    now = datetime.now(timezone.utc)
                    exp = exp.replace(tzinfo=timezone.utc) if exp.tzinfo is None else exp
                    days_left = (exp - now).days
                    if days_left < 30:
                        self.add_finding(Finding(
                            title=f"Domain Expiring Soon: {domain}",
                            category="Recon",
                            target=domain,
                            url=f"https://{domain}",
                            severity=Severity.HIGH,
                            cvss_score=7.0,
                            description=(
                                f"Domain expires in {days_left} days ({exp.date()}). "
                                "Expiry can cause complete service outage or domain takeover."
                            ),
                            remediation="Renew domain immediately.",
                            tags=["recon", "whois", "expiry"],
                        ))
                except Exception:
                    pass

        except Exception as e:
            self.logger.debug(f"WHOIS failed for {domain}: {e}")

        return self.findings
