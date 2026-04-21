"""
VulnScanX - PDF Reporter
Converts the HTML report to PDF using WeasyPrint.
"""
from pathlib import Path
from datetime import datetime
from core.models import ScanResult
from core.config import REPORTS_DIR
from utils.helpers import sanitize_filename
from utils.logger import get_logger

logger = get_logger("pdf_reporter")


class PDFReporter:
    def generate(self, result: ScanResult, output_path: Path = None) -> Path:
        from reports.html_reporter import HTMLReporter
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_safe = sanitize_filename(result.target)

        if not output_path:
            output_path = REPORTS_DIR / f"vulnscanx_{target_safe}_{ts}.pdf"

        # First generate HTML
        html_path = REPORTS_DIR / f"_tmp_{target_safe}_{ts}.html"
        HTMLReporter().generate(result, html_path)

        try:
            from weasyprint import HTML
            HTML(filename=str(html_path)).write_pdf(str(output_path))
            html_path.unlink(missing_ok=True)
            logger.info(f"PDF report saved: {output_path}")
        except ImportError:
            logger.warning("WeasyPrint not installed. Saving HTML instead.")
            html_path.rename(output_path.with_suffix(".html"))
            output_path = output_path.with_suffix(".html")
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            html_path.rename(output_path.with_suffix(".html"))
            output_path = output_path.with_suffix(".html")

        return output_path
