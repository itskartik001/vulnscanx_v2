"""
VulnScanX - Directory Brute Forcer (stub referencing main file)
"""
# Full implementation is in dir_brute_force.py
import requests
import concurrent.futures
from core.models import Finding
from core.config import Severity
from core.engine import BaseModule
from utils.helpers import normalize_url

COMMON_PATHS = [
    "admin","wp-admin","login","api","swagger",".env",".git",
    "config.php","phpinfo.php","robots.txt","sitemap.xml",
    "phpmyadmin","adminer","actuator","backup","console",
    "server-status","wp-config.php","web.config","upload","uploads",
]

SENSITIVE = {
    ".env":(Severity.CRITICAL,9.5),".git":(Severity.CRITICAL,9.0),
    "phpinfo":(Severity.HIGH,7.5),"swagger":(Severity.MEDIUM,5.0),
    "actuator":(Severity.HIGH,8.0),"phpmyadmin":(Severity.HIGH,8.0),
    "config":(Severity.HIGH,8.5),"admin":(Severity.MEDIUM,5.0),
    "wp-config":(Severity.CRITICAL,9.8),"backup":(Severity.HIGH,7.8),
}


class DirectoryBruteforcer(BaseModule):
    name = "dirbrute"
    description = "HTTP directory and file brute-force enumeration"
    category = "recon"

    def run(self):
        base_url = normalize_url(self.config.target)
        session = requests.Session()
        session.headers["User-Agent"] = self.config.user_agent

        def check(path):
            try:
                self.rate_limiter.acquire()
                r = session.get(f"{base_url}/{path}", timeout=self.config.timeout,
                               allow_redirects=False, verify=False)
                if r.status_code in (200, 301, 302, 403):
                    return path, r.status_code, len(r.content)
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            futs = {ex.submit(check, p): p for p in COMMON_PATHS}
            for fut in concurrent.futures.as_completed(futs):
                res = fut.result()
                if res:
                    path, status, size = res
                    url = f"{base_url}/{path}"
                    sev, cvss = Severity.INFO, 0.0
                    for k, v in SENSITIVE.items():
                        if k in path.lower():
                            sev, cvss = v
                            break
                    self.add_finding(Finding(
                        title=f"Directory/File Found: /{path}",
                        category="Recon", target=base_url, url=url,
                        severity=sev, cvss_score=cvss, owasp="A01:2025",
                        description=f"Path /{path} accessible (HTTP {status})",
                        proof_of_concept=f"GET {url} -> {status} ({size} bytes)",
                        remediation="Remove sensitive files from web root.",
                        raw_data={"status_code": status, "size": size},
                        tags=["recon","dirbrute"],
                    ))
        return self.findings
