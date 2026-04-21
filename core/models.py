"""
VulnScanX - Finding Model
==========================
Standardized data model for all vulnerability findings.
"""

import uuid
import json
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any


@dataclass
class Finding:
    """
    Represents a single vulnerability finding.
    All scanner modules produce Finding objects.
    """
    # Identity
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    title: str = ""
    category: str = ""                # e.g. XSS, SQLi, Recon, Misconfiguration

    # Target info
    target: str = ""
    url: str = ""
    parameter: Optional[str] = None
    method: str = "GET"

    # Risk classification
    severity: str = "INFO"            # CRITICAL / HIGH / MEDIUM / LOW / INFO
    cvss_score: float = 0.0
    cwe_id: Optional[str] = None      # e.g. CWE-79
    owasp: Optional[str] = None       # e.g. A03:2025

    # Evidence
    description: str = ""
    proof_of_concept: str = ""
    payload_used: Optional[str] = None
    request_snippet: Optional[str] = None
    response_snippet: Optional[str] = None

    # Remediation
    remediation: str = ""
    references: List[str] = field(default_factory=list)

    # AI analysis
    ai_explanation: Optional[str] = None
    ai_confidence: float = 0.0

    # Meta
    module: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    false_positive: bool = False
    verified: bool = False
    tags: List[str] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def __repr__(self):
        return (
            f"<Finding [{self.severity}] {self.title} "
            f"@ {self.url} | CVSS:{self.cvss_score}>"
        )


@dataclass
class ScanResult:
    """
    Aggregated result of a complete scan run.
    """
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target: str = ""
    start_time: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    end_time: Optional[str] = None
    duration_seconds: float = 0.0
    status: str = "running"           # running | completed | failed | aborted

    findings: List[Finding] = field(default_factory=list)
    modules_run: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Aggregated stats
    @property
    def stats(self) -> Dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        counts["total"] = len(self.findings)
        return counts

    @property
    def risk_score(self) -> float:
        """Compute an overall risk score (0–10) weighted by severity."""
        weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}
        if not self.findings:
            return 0.0
        total = sum(weights.get(f.severity, 0) for f in self.findings)
        # Normalize
        max_possible = len(self.findings) * 10
        return round((total / max_possible) * 10, 2) if max_possible else 0.0

    def add_finding(self, finding: Finding):
        # Deduplicate by title + URL + parameter
        key = (finding.title, finding.url, finding.parameter)
        existing_keys = {
            (f.title, f.url, f.parameter) for f in self.findings
        }
        if key not in existing_keys:
            self.findings.append(finding)

    def finalize(self):
        self.end_time = datetime.utcnow().isoformat()
        self.status = "completed"
        if self.start_time:
            start = datetime.fromisoformat(self.start_time)
            end = datetime.fromisoformat(self.end_time)
            self.duration_seconds = (end - start).total_seconds()

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": self.duration_seconds,
            "status": self.status,
            "stats": self.stats,
            "risk_score": self.risk_score,
            "modules_run": self.modules_run,
            "errors": self.errors,
            "metadata": self.metadata,
            "findings": [f.to_dict() for f in self.findings],
        }

    def sort_findings(self):
        """Sort findings by CVSS score descending."""
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        self.findings.sort(key=lambda f: (order.get(f.severity, 5), -f.cvss_score))
