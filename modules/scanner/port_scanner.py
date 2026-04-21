"""
VulnScanX — Port Scanner
=========================
Custom async TCP port scanner with service fingerprinting.
Does NOT wrap nmap — implements raw socket scanning.

OWASP Top 10 2025: A02 – Security Misconfiguration
"""

import socket
import concurrent.futures
from typing import Dict, List, Optional, Tuple

from core import BaseModule, Finding, Severity

# Well-known service registry
SERVICES = {
    21:   ("FTP",            Severity.MEDIUM, 5.3),
    22:   ("SSH",            Severity.INFO,   0.0),
    23:   ("Telnet",         Severity.HIGH,   9.8),
    25:   ("SMTP",           Severity.MEDIUM, 5.0),
    53:   ("DNS",            Severity.INFO,   0.0),
    80:   ("HTTP",           Severity.INFO,   0.0),
    110:  ("POP3",           Severity.MEDIUM, 4.3),
    111:  ("RPC",            Severity.HIGH,   7.5),
    135:  ("RPC/MSRPC",      Severity.HIGH,   7.5),
    139:  ("NetBIOS",        Severity.HIGH,   7.5),
    143:  ("IMAP",           Severity.MEDIUM, 4.3),
    443:  ("HTTPS",          Severity.INFO,   0.0),
    445:  ("SMB",            Severity.CRITICAL, 9.8),
    993:  ("IMAPS",          Severity.INFO,   0.0),
    995:  ("POP3S",          Severity.INFO,   0.0),
    1433: ("MSSQL",          Severity.HIGH,   8.1),
    1521: ("Oracle DB",      Severity.HIGH,   8.1),
    2375: ("Docker API (unencrypted)", Severity.CRITICAL, 10.0),
    2376: ("Docker TLS",     Severity.MEDIUM, 5.0),
    3306: ("MySQL",          Severity.HIGH,   8.1),
    3389: ("RDP",            Severity.HIGH,   9.0),
    4444: ("Metasploit/Backdoor", Severity.CRITICAL, 10.0),
    5432: ("PostgreSQL",     Severity.HIGH,   8.1),
    5900: ("VNC",            Severity.HIGH,   9.8),
    6379: ("Redis (unauth)", Severity.CRITICAL, 10.0),
    8080: ("HTTP-Alt",       Severity.LOW,    3.1),
    8443: ("HTTPS-Alt",      Severity.INFO,   0.0),
    8888: ("HTTP Dev Server",Severity.MEDIUM, 5.3),
    9200: ("Elasticsearch",  Severity.CRITICAL, 9.8),
    27017:("MongoDB",        Severity.HIGH,   8.5),
}

HIGH_RISK_PORTS = {23, 111, 135, 139, 445, 1433, 1521, 2375, 3306,
                  3389, 4444, 5432, 5900, 6379, 9200, 27017}

COMMON_PORTS = sorted(SERVICES.keys())


class PortScanner(BaseModule):
    NAME        = "port_scanner"
    DESCRIPTION = "Async TCP port scanner with service fingerprinting"
    TAGS        = ["ports", "network", "owasp-a02"]

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.ports       = self.config.get("ports", COMMON_PORTS)
        self.max_workers = self.config.get("max_workers", 100)
        self.sock_timeout= self.config.get("sock_timeout", 1.0)

    def run(self, target: str) -> List[Finding]:
        host = self._resolve(target)
        self.log(f"[Ports] Scanning {host} ({len(self.ports)} ports)")

        open_ports = self._scan_ports(host)
        self.log(f"[Ports] Open: {open_ports}")

        findings = []
        for port, banner in open_ports:
            service_name, default_sev, default_cvss = SERVICES.get(
                port, (f"Unknown:{port}", Severity.INFO, 0.0)
            )

            # Escalate severity for dangerous services
            if port in HIGH_RISK_PORTS:
                finding = Finding(
                    title       = f"High-Risk Service Exposed: {service_name} (Port {port})",
                    severity    = default_sev,
                    cvss_score  = default_cvss,
                    target      = host,
                    url         = f"{host}:{port}",
                    module      = self.NAME,
                    evidence    = f"Port {port}/tcp OPEN — Banner: {banner or 'N/A'}",
                    description = self._describe(port, service_name),
                    remediation = self._remediate(port, service_name),
                    tags        = ["port-scan", f"port:{port}", f"service:{service_name}"],
                )
            else:
                finding = Finding(
                    title       = f"Open Port: {service_name} (Port {port})",
                    severity    = default_sev,
                    cvss_score  = default_cvss,
                    target      = host,
                    url         = f"{host}:{port}",
                    module      = self.NAME,
                    evidence    = f"Port {port}/tcp OPEN — Banner: {banner or 'N/A'}",
                    description = f"Port {port} ({service_name}) is open and reachable.",
                    remediation = f"Verify if port {port} needs to be publicly accessible. If not, restrict via firewall.",
                    tags        = ["port-scan", f"port:{port}"],
                )
            findings.append(finding)
        return findings

    def _scan_ports(self, host: str) -> List[Tuple[int, Optional[str]]]:
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self._check_port, host, port): port
                       for port in self.ports}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
        return sorted(open_ports, key=lambda x: x[0])

    def _check_port(self, host: str, port: int) -> Optional[Tuple[int, str]]:
        try:
            with socket.create_connection((host, port), timeout=self.sock_timeout) as sock:
                banner = ""
                try:
                    sock.settimeout(0.5)
                    banner = sock.recv(256).decode("utf-8", errors="ignore").strip()
                except Exception:
                    pass
                return (port, banner)
        except Exception:
            return None

    @staticmethod
    def _resolve(target: str) -> str:
        target = target.replace("https://", "").replace("http://", "").split("/")[0].split("?")[0]
        return target

    @staticmethod
    def _describe(port: int, service: str) -> str:
        descs = {
            23:    "Telnet transmits data in plaintext including credentials. Immediately deprecated.",
            445:   "SMB on port 445 is the attack vector for EternalBlue/WannaCry. Critical risk if internet-exposed.",
            3389:  "RDP exposed to the internet is a top vector for ransomware. Enforce NLA + MFA.",
            6379:  "Redis with no authentication exposed to the internet allows full data access and RCE via SLAVEOF.",
            2375:  "Unauthenticated Docker API gives full container/host control including root-level RCE.",
            9200:  "Elasticsearch with no auth leaks all data and allows deletion/modification.",
            27017: "MongoDB with no auth leaks all collections. Check authentication status.",
            4444:  "Port 4444 is the default Metasploit listener port — may indicate a backdoor.",
        }
        return descs.get(port, f"Service {service} on port {port} is externally reachable.")

    @staticmethod
    def _remediate(port: int, service: str) -> str:
        remeds = {
            23:    "Disable Telnet. Replace with SSH (port 22) with key-based authentication.",
            445:   "Block port 445 at the perimeter firewall. Patch MS17-010 (EternalBlue).",
            3389:  "Place RDP behind a VPN. Enable Network Level Authentication. Use MFA.",
            6379:  "Bind Redis to 127.0.0.1. Set requirepass. Use firewalls to block external access.",
            2375:  "Never expose Docker API without TLS. Use socket permissions. Enable --authorization-plugin.",
            9200:  "Enable Elasticsearch security features. Bind to localhost or use firewall rules.",
            27017: "Enable MongoDB authentication. Bind to localhost or use VPC/firewall.",
        }
        return remeds.get(port, f"Evaluate if {service} (port {port}) requires internet exposure. Use firewall if not.")
