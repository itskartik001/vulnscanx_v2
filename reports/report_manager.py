"""
VulnScanX - Report Manager
Facade to generate all report types from a scan result.
"""
from pathlib import Path
from typing import List
from core.models import ScanResult
from utils.logger import get_logger

logger = get_logger("reports")


class ReportManager:
    def __init__(self, formats: List[str] = None):
        self.formats = formats or ["json", "html"]

    def generate_all(self, result: ScanResult) -> dict:
        """Generate all configured report formats. Returns dict of format->path."""
        paths = {}
        for fmt in self.formats:
            try:
                path = self._generate(result, fmt)
                if path:
                    paths[fmt] = str(path)
                    logger.info(f"Report [{fmt.upper()}] saved: {path}")
            except Exception as e:
                logger.error(f"Report [{fmt}] failed: {e}")
        return paths

    def _generate(self, result: ScanResult, fmt: str) -> Path:
        if fmt == "json":
            from reports.json_reporter import JSONReporter
            return JSONReporter().generate(result)
        elif fmt == "html":
            from reports.html_reporter import HTMLReporter
            return HTMLReporter().generate(result)
        elif fmt == "pdf":
            from reports.pdf_reporter import PDFReporter
            return PDFReporter().generate(result)
        elif fmt == "sarif":
            from reports.sarif_reporter import SARIFReporter
            return SARIFReporter().generate(result)
        else:
            logger.warning(f"Unknown report format: {fmt}")
            return None
