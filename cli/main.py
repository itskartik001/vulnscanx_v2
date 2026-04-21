#!/usr/bin/env python3
"""
VulnScanX - CLI Interface
===========================
Usage:
  vulnscanx scan <target> [options]
  vulnscanx templates [--list]
  vulnscanx report <scan_id>

Examples:
  vulnscanx scan https://example.com
  vulnscanx scan https://example.com --type full --threads 20 --output html,json,sarif
  vulnscanx scan https://example.com --type quick --no-ai
  vulnscanx scan https://example.com --proxy http://127.0.0.1:8080
"""

import sys
import argparse
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config import ScanConfig, BANNER, VERSION, TEMPLATES_DIR
from core.engine import VulnScanEngine
from reports.report_manager import ReportManager
from utils.logger import get_logger

logger = get_logger("cli")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnscanx",
        description="VulnScanX — Advanced Vulnerability Scanning Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  vulnscanx scan https://example.com
  vulnscanx scan https://example.com --type full --threads 20
  vulnscanx scan https://example.com --type quick --output html
  vulnscanx scan https://example.com --modules xss,sqli,headers
  vulnscanx scan https://example.com --proxy http://127.0.0.1:8080
  vulnscanx templates --list
        """
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # ── scan command ─────────────────────────────────
    scan = subparsers.add_parser("scan", help="Run vulnerability scan")
    scan.add_argument("target", help="Target URL (e.g. https://example.com)")
    scan.add_argument(
        "--type", "-t",
        choices=["full", "quick", "recon", "vuln"],
        default="full",
        help="Scan type preset (default: full)"
    )
    scan.add_argument(
        "--modules", "-m",
        default="",
        help="Comma-separated modules (e.g. xss,sqli,headers,ports)"
    )
    scan.add_argument(
        "--threads", "-T",
        type=int, default=10,
        help="Number of concurrent threads (default: 10)"
    )
    scan.add_argument(
        "--timeout",
        type=int, default=10,
        help="Request timeout in seconds (default: 10)"
    )
    scan.add_argument(
        "--rate-limit",
        type=int, default=50,
        help="Max requests per second (default: 50)"
    )
    scan.add_argument(
        "--output", "-o",
        default="json,html",
        help="Output formats: json,html,pdf,sarif (default: json,html)"
    )
    scan.add_argument(
        "--proxy",
        default=None,
        help="HTTP proxy (e.g. http://127.0.0.1:8080)"
    )
    scan.add_argument(
        "--no-ai",
        action="store_true",
        help="Disable AI analysis"
    )
    scan.add_argument(
        "--no-ssl-verify",
        action="store_true",
        help="Disable SSL certificate verification"
    )
    scan.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )
    scan.add_argument(
        "--cookie",
        default="",
        help='Cookies as key=value pairs: "session=abc; token=xyz"'
    )
    scan.add_argument(
        "--header",
        action="append",
        default=[],
        help='Custom headers: --header "Authorization: Bearer TOKEN"'
    )
    scan.add_argument(
        "--with-templates",
        action="store_true",
        help="Also run YAML template-based scanning"
    )

    # ── templates command ─────────────────────────────
    tmpl = subparsers.add_parser("templates", help="Manage scan templates")
    tmpl.add_argument("--list", action="store_true", help="List all templates")
    tmpl.add_argument("--validate", metavar="FILE", help="Validate a template file")

    # ── version command ───────────────────────────────
    subparsers.add_parser("version", help="Show version")

    return parser


def parse_cookies(cookie_str: str) -> dict:
    cookies = {}
    if not cookie_str:
        return cookies
    for pair in cookie_str.split(";"):
        pair = pair.strip()
        if "=" in pair:
            k, v = pair.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies


def parse_headers(header_list: list) -> dict:
    headers = {}
    for h in (header_list or []):
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers


def cmd_scan(args):
    print(BANNER)

    # Ethical use confirmation
    print("⚠️  IMPORTANT: Only use VulnScanX on systems you own or have written permission to test.")
    print("   Unauthorized scanning is illegal. By proceeding, you confirm authorization.\n")
    confirm = input(f"   Confirm scanning [{args.target}]? [y/N]: ").strip().lower()
    if confirm not in ("y", "yes"):
        print("   Scan aborted.")
        sys.exit(0)
    print()

    # Build config
    modules_list = [m.strip() for m in args.modules.split(",")] if args.modules else []

    config = ScanConfig(
        target=args.target,
        scan_type=args.type,
        threads=args.threads,
        timeout=args.timeout,
        rate_limit=args.rate_limit,
        verify_ssl=not args.no_ssl_verify,
        proxy=args.proxy,
        ai_analysis=not args.no_ai,
        verbose=args.verbose,
        output_formats=[f.strip() for f in args.output.split(",")],
        modules=modules_list if modules_list else list(
            {"full": ["subdomain","dns","whois","dirbrute","ports","headers","xss","sqli","traversal"],
             "quick": ["headers","ports","xss"],
             "recon": ["subdomain","dns","whois","dirbrute"],
             "vuln": ["headers","xss","sqli","traversal"]
             }.get(args.type, [])
        ),
        cookies=parse_cookies(args.cookie),
        headers=parse_headers(args.header),
    )

    # Initialize and run engine
    engine = VulnScanEngine(config)
    engine.load_default_modules()

    result = engine.run()

    # Optional: run template engine
    if args.with_templates:
        from core.template_engine import TemplateScanEngine
        print("Running YAML template engine...")
        tmpl_engine = TemplateScanEngine(config)
        tmpl_findings = tmpl_engine.run()
        for f in tmpl_findings:
            result.add_finding(f)
        print(f"Templates added {len(tmpl_findings)} additional findings.")

    # Generate reports
    report_manager = ReportManager(formats=config.output_formats)
    report_paths = report_manager.generate_all(result)

    print("\n📋 Reports generated:")
    for fmt, path in report_paths.items():
        print(f"   [{fmt.upper()}] {path}")

    return result


def cmd_templates(args):
    from core.template_engine import TemplateLoader
    templates = TemplateLoader.load_all()

    if args.list:
        print(f"\n{'ID':<30} {'NAME':<40} {'SEVERITY':<12} CATEGORY")
        print("-" * 100)
        for t in templates:
            print(
                f"{t['id']:<30} {t['name']:<40} "
                f"{t.get('severity','?').upper():<12} {t.get('category','?')}"
            )
        print(f"\nTotal: {len(templates)} templates in {TEMPLATES_DIR}")


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "templates":
        cmd_templates(args)
    elif args.command == "version":
        print(f"VulnScanX v{VERSION}")


if __name__ == "__main__":
    main()
