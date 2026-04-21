"""
VulnScanX - Core Scanning Engine
==================================
Orchestrates all scanning modules using async task scheduling,
thread pools, rate limiting, and result aggregation.
"""

import asyncio
import time
import threading
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Type, Optional, Callable
from datetime import datetime

from core.config import ScanConfig, Severity, BANNER
from core.models import Finding, ScanResult
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter

logger = get_logger("engine")


class BaseModule:
    """
    Every scanning module must inherit from BaseModule.
    Enforces a standard interface across all plugins.
    """
    name: str = "base"
    description: str = ""
    category: str = "generic"
    enabled: bool = True

    def __init__(self, config: ScanConfig, rate_limiter: RateLimiter):
        self.config = config
        self.rate_limiter = rate_limiter
        self.logger = get_logger(f"module.{self.name}")
        self.findings: List[Finding] = []

    def run(self) -> List[Finding]:
        """Override this method in each module."""
        raise NotImplementedError(f"Module {self.name} must implement run()")

    def add_finding(self, finding: Finding):
        finding.module = self.name
        self.findings.append(finding)
        self.logger.info(f"[{finding.severity}] {finding.title} -> {finding.url}")

    def _make_request(self, session, url: str, method: str = "GET",
                      data=None, params=None, headers=None):
        """Throttled HTTP request wrapper."""
        self.rate_limiter.acquire()
        try:
            req_headers = dict(self.config.headers)
            req_headers["User-Agent"] = self.config.user_agent
            if headers:
                req_headers.update(headers)

            response = session.request(
                method=method,
                url=url,
                data=data,
                params=params,
                headers=req_headers,
                timeout=self.config.timeout,
                verify=self.config.verify_ssl,
                allow_redirects=self.config.follow_redirects,
                proxies={"http": self.config.proxy, "https": self.config.proxy}
                if self.config.proxy else None,
            )
            return response
        except Exception as e:
            self.logger.debug(f"Request failed [{url}]: {e}")
            return None


class ProgressTracker:
    """Thread-safe progress tracking for live dashboard updates."""

    def __init__(self, total_tasks: int):
        self.total = total_tasks
        self.completed = 0
        self.current_module = ""
        self.lock = threading.Lock()
        self.callbacks: List[Callable] = []

    def update(self, module_name: str, increment: int = 1):
        with self.lock:
            self.completed = min(self.completed + increment, self.total)
            self.current_module = module_name
        for cb in self.callbacks:
            cb(self.to_dict())

    def register_callback(self, cb: Callable):
        self.callbacks.append(cb)

    @property
    def percentage(self) -> float:
        return round((self.completed / self.total) * 100, 1) if self.total else 0

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "completed": self.completed,
            "percentage": self.percentage,
            "current_module": self.current_module,
        }


class VulnScanEngine:
    """
    The heart of VulnScanX.
    Loads modules, schedules tasks, aggregates results, drives AI analysis.
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self.result = ScanResult(target=config.target)
        self.rate_limiter = RateLimiter(config.rate_limit)
        self._modules: List[BaseModule] = []
        self._progress: Optional[ProgressTracker] = None
        self._stop_event = threading.Event()

    def register_module(self, module_cls: Type[BaseModule]):
        instance = module_cls(self.config, self.rate_limiter)
        self._modules.append(instance)
        logger.debug(f"Registered module: {instance.name}")

    def load_default_modules(self):
        """Auto-load all built-in modules based on scan type."""
        from modules.recon.subdomain import SubdomainEnumerator
        from modules.recon.dns_lookup import DNSLookup
        from modules.recon.whois_lookup import WHOISLookup
        from modules.recon.dir_bruteforce import DirectoryBruteforcer
        from modules.vuln.port_scanner import PortScanner
        from modules.vuln.headers_check import SecurityHeadersChecker
        from modules.vuln.xss_scanner import XSSScanner
        from modules.vuln.sqli_scanner import SQLiScanner
        from modules.vuln.dir_traversal import DirectoryTraversalScanner

        module_map = {
            "subdomain": SubdomainEnumerator,
            "dns": DNSLookup,
            "whois": WHOISLookup,
            "dirbrute": DirectoryBruteforcer,
            "ports": PortScanner,
            "headers": SecurityHeadersChecker,
            "xss": XSSScanner,
            "sqli": SQLiScanner,
            "traversal": DirectoryTraversalScanner,
        }

        scan_presets = {
            "quick": ["headers", "ports", "xss"],
            "recon": ["subdomain", "dns", "whois", "dirbrute"],
            "vuln": ["headers", "xss", "sqli", "traversal"],
            "full": list(module_map.keys()),
        }

        active_modules = scan_presets.get(self.config.scan_type, list(module_map.keys()))
        if self.config.modules and self.config.modules != list(module_map.keys()):
            active_modules = self.config.modules

        for mod_name in active_modules:
            if mod_name in module_map:
                self.register_module(module_map[mod_name])

        logger.info(f"Loaded {len(self._modules)} modules for '{self.config.scan_type}' scan")

    def run(self) -> ScanResult:
        """Main scan orchestrator."""
        logger.info(f"VulnScanX scan starting -> target: {self.config.target}")
        self._progress = ProgressTracker(len(self._modules))
        self.result.modules_run = [m.name for m in self._modules]
        self._emit_ethical_warning()

        try:
            with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
                future_map = {
                    executor.submit(self._run_module, module): module
                    for module in self._modules
                }
                for future in as_completed(future_map):
                    module = future_map[future]
                    try:
                        findings = future.result()
                        for finding in findings:
                            self.result.add_finding(finding)
                        logger.info(f"Module [{module.name}] -> {len(findings)} findings")
                    except Exception as exc:
                        err = f"Module [{module.name}] raised: {exc}"
                        logger.error(err)
                        self.result.errors.append(err)
                    finally:
                        if self._progress:
                            self._progress.update(module.name)

        except KeyboardInterrupt:
            logger.warning("Scan interrupted by user")
            self.result.status = "aborted"
            self._stop_event.set()

        if self.config.ai_analysis and self.result.findings:
            self._apply_ai_analysis()

        self.result.finalize()
        self.result.sort_findings()
        self._print_summary()
        return self.result

    def _run_module(self, module: BaseModule) -> List[Finding]:
        if self._stop_event.is_set():
            return []
        try:
            return module.run()
        except Exception as e:
            logger.error(f"Module {module.name} failed: {e}")
            return []

    def _apply_ai_analysis(self):
        try:
            from ai.classifier import VulnClassifier
            from ai.explainer import VulnExplainer
            classifier = VulnClassifier()
            explainer = VulnExplainer()
            for finding in self.result.findings:
                predicted_severity, confidence = classifier.predict(finding)
                finding.ai_confidence = confidence
                if confidence > 0.75 and predicted_severity != finding.severity:
                    finding.severity = predicted_severity
                finding.ai_explanation = explainer.explain(finding)
            logger.info(f"AI analysis applied to {len(self.result.findings)} findings")
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")

    def _emit_ethical_warning(self):
        logger.warning(
            "LEGAL WARNING: Only use on systems you own or have explicit permission to test."
        )

    def _print_summary(self):
        stats = self.result.stats
        print("\n" + "=" * 60)
        print(f"  SCAN SUMMARY  |  Target: {self.config.target}")
        print("=" * 60)
        print(f"  CRITICAL : {stats.get('CRITICAL', 0)}")
        print(f"  HIGH     : {stats.get('HIGH', 0)}")
        print(f"  MEDIUM   : {stats.get('MEDIUM', 0)}")
        print(f"  LOW      : {stats.get('LOW', 0)}")
        print(f"  INFO     : {stats.get('INFO', 0)}")
        print("-" * 60)
        print(f"  TOTAL    : {stats.get('total', 0)} findings")
        print(f"  RISK     : {self.result.risk_score}/10")
        print(f"  DURATION : {self.result.duration_seconds:.1f}s")
        print("=" * 60 + "\n")

    def stop(self):
        self._stop_event.set()

    @property
    def progress(self) -> Optional[dict]:
        return self._progress.to_dict() if self._progress else None
