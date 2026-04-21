"""
VulnScanX - Port Scanner
"""
import socket
import concurrent.futures
from core.models import Finding
from core.config import Severity
from core.engine import BaseModule
from utils.helpers import extract_domain, resolve_ip


RISKY_PORTS = {
    21: ("FTP", "Insecure file transfer. Use SFTP instead.", Severity.HIGH, 7.5),
    22: ("SSH", "SSH exposed. Ensure key-based auth only.", Severity.INFO, 0.0),
    23: ("Telnet", "Telnet is unencrypted. Replace with SSH immediately.", Severity.CRITICAL, 9.0),
    25: ("SMTP", "SMTP open relay check recommended.", Severity.MEDIUM, 5.0),
    80: ("HTTP", "HTTP running. Ensure HTTPS redirect.", Severity.INFO, 0.0),
    110: ("POP3", "POP3 without TLS. Use POP3S (995).", Severity.MEDIUM, 5.3),
    135: ("RPC", "Windows RPC exposed. High risk.", Severity.HIGH, 8.0),
    139: ("NetBIOS", "NetBIOS/SMB exposed. Risk of lateral movement.", Severity.HIGH, 8.5),
    143: ("IMAP", "IMAP without TLS. Use IMAPS (993).", Severity.MEDIUM, 5.3),
    443: ("HTTPS", "HTTPS — check TLS version.", Severity.INFO, 0.0),
    445: ("SMB", "SMB exposed. Critical — WannaCry/EternalBlue attack vector.", Severity.CRITICAL, 9.8),
    1433: ("MSSQL", "MSSQL directly exposed to internet.", Severity.CRITICAL, 9.5),
    3306: ("MySQL", "MySQL directly exposed. Restrict to localhost.", Severity.HIGH, 8.8),
    3389: ("RDP", "RDP exposed. High-value target for ransomware.", Severity.CRITICAL, 9.5),
    5432: ("PostgreSQL", "PostgreSQL exposed. Restrict access.", Severity.HIGH, 8.5),
    5900: ("VNC", "VNC exposed. Often weakly protected.", Severity.CRITICAL, 9.0),
    6379: ("Redis", "Redis exposed without auth. Critical data exposure.", Severity.CRITICAL, 9.8),
    8080: ("HTTP Alt", "Alternative HTTP port. Check for admin interfaces.", Severity.MEDIUM, 5.0),
    8443: ("HTTPS Alt", "Alternative HTTPS port.", Severity.INFO, 0.0),
    27017: ("MongoDB", "MongoDB exposed. Often unauthenticated.", Severity.CRITICAL, 9.8),
}


class PortScanner(BaseModule):
    name = "ports"
    description = "TCP port scanning with service fingerprinting"
    category = "vuln"

    def run(self):
        domain = extract_domain(self.config.target)
        ip = resolve_ip(domain)
        if not ip:
            self.logger.warning(f"Cannot resolve IP for {domain}")
            return self.findings

        self.logger.info(f"Scanning {len(self.config.ports)} ports on {ip} ({domain})")
        open_ports = []

        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                sock.close()
                return port if result == 0 else None
            except Exception:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(scan_port, p): p for p in self.config.ports}
            for future in concurrent.futures.as_completed(futures):
                port = future.result()
                if port:
                    open_ports.append(port)

        for port in open_ports:
            info = RISKY_PORTS.get(port, ("Unknown", "Open port discovered.", Severity.LOW, 3.0))
            service, message, severity, cvss = info

            self.add_finding(Finding(
                title=f"Open Port {port}/{service}",
                category="Network Exposure",
                target=domain, url=f"{self.config.target}:{port}",
                severity=severity, cvss_score=cvss,
                owasp="A02:2025",
                description=f"Port {port} ({service}) is open on {ip}. {message}",
                proof_of_concept=f"TCP connect to {ip}:{port} — connection accepted",
                remediation=f"Firewall port {port} if not needed. {message}",
                raw_data={"ip": ip, "port": port, "service": service},
                tags=["ports", "network", service.lower()],
            ))

        return self.findings
