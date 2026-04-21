"""
VulnScanX - JSON Reporter
"""
import json
from pathlib import Path
from datetime import datetime
from core.models import ScanResult
from core.config import REPORTS_DIR
from utils.helpers import sanitize_filename


class JSONReporter:
    def generate(self, result: ScanResult, output_path: Path = None) -> Path:
        if not output_path:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_safe = sanitize_filename(result.target)
            output_path = REPORTS_DIR / f"vulnscanx_{target_safe}_{ts}.json"

        data = result.to_dict()
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2, default=str)

        return output_path
