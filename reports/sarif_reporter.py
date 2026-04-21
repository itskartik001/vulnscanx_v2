"""
VulnScanX - SARIF Reporter (GitHub Code Scanning compatible)
"""
import json
from pathlib import Path
from datetime import datetime
from core.models import ScanResult
from core.config import REPORTS_DIR, VERSION
from utils.helpers import sanitize_filename

SEVERITY_SARIF = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "none",
}


class SARIFReporter:
    def generate(self, result: ScanResult, output_path: Path = None) -> Path:
        if not output_path:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_safe = sanitize_filename(result.target)
            output_path = REPORTS_DIR / f"vulnscanx_{target_safe}_{ts}.sarif"

        rules = {}
        for f in result.findings:
            rule_id = f.title.replace(" ", "_").replace("—", "-")[:64]
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": f.title,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description},
                    "defaultConfiguration": {
                        "level": SEVERITY_SARIF.get(f.severity, "warning")
                    },
                    "properties": {
                        "tags": f.tags,
                        "security-severity": str(f.cvss_score),
                    },
                    "helpUri": (f.references[0] if f.references else
                                "https://owasp.org/www-project-top-ten/"),
                }

        results = []
        for f in result.findings:
            rule_id = f.title.replace(" ", "_").replace("—", "-")[:64]
            results.append({
                "ruleId": rule_id,
                "level": SEVERITY_SARIF.get(f.severity, "warning"),
                "message": {"text": f.description},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.url},
                        "region": {"startLine": 1}
                    }
                }],
                "properties": {
                    "cvss": f.cvss_score,
                    "cwe": f.cwe_id,
                    "owasp": f.owasp,
                    "payload": f.payload_used,
                    "remediation": f.remediation,
                }
            })

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "VulnScanX",
                        "version": VERSION,
                        "informationUri": "https://github.com/vulnscanx/vulnscanx",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "invocations": [{
                    "executionSuccessful": result.status == "completed",
                    "startTimeUtc": result.start_time,
                    "endTimeUtc": result.end_time,
                }],
            }]
        }

        with open(output_path, "w") as f:
            json.dump(sarif, f, indent=2, default=str)

        return output_path
