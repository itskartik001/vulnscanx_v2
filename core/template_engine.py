"""
VulnScanX - YAML Template Engine
===================================
Nuclei-inspired template parser and executor.
Load YAML templates, parse them, and fire HTTP probes dynamically.
"""
import re
import time
import yaml
import requests
from pathlib import Path
from typing import List, Optional
from core.models import Finding
from core.config import Severity, TEMPLATES_DIR
from utils.helpers import normalize_url, get_all_params, inject_payload
from utils.logger import get_logger

logger = get_logger("template_engine")


class TemplateLoader:
    """Loads and validates YAML template files."""

    REQUIRED_FIELDS = ["id", "name", "severity", "category"]

    @staticmethod
    def load(path: Path) -> Optional[dict]:
        try:
            with open(path) as f:
                template = yaml.safe_load(f)
            for field in TemplateLoader.REQUIRED_FIELDS:
                if field not in template:
                    logger.warning(f"Template {path.name} missing field: {field}")
                    return None
            return template
        except Exception as e:
            logger.error(f"Failed to load template {path}: {e}")
            return None

    @staticmethod
    def load_all(directory: Path = TEMPLATES_DIR) -> List[dict]:
        templates = []
        for yaml_file in directory.glob("*.yaml"):
            t = TemplateLoader.load(yaml_file)
            if t:
                templates.append(t)
        logger.info(f"Loaded {len(templates)} templates from {directory}")
        return templates


class TemplateExecutor:
    """Executes a single YAML template against a target."""

    def __init__(self, template: dict, target: str, config):
        self.template = template
        self.target = target
        self.config = config
        self.session = requests.Session()
        self.session.headers["User-Agent"] = config.user_agent

    def run(self) -> List[Finding]:
        findings = []
        match_config = self.template.get("match", {})
        match_type = match_config.get("type", "contains_any")

        # Header-check templates
        if "checks" in self.template:
            findings.extend(self._run_header_checks())
            return findings

        # Payload-based templates
        payloads = self.template.get("payloads", [])
        target_url = normalize_url(self.target)

        # Collect test URLs with parameters
        test_urls = self._collect_urls(target_url)
        for url in test_urls:
            params = get_all_params(url) or {"q": [""], "id": ["1"]}
            for param in params:
                for payload in payloads:
                    finding = self._probe(url, param, payload, match_config)
                    if finding:
                        findings.append(finding)
                        break  # One finding per param
        return findings

    def _probe(self, url, param, payload, match_config) -> Optional[Finding]:
        try:
            test_url = inject_payload(url, param, payload)
            match_type = match_config.get("type", "contains_any")

            if match_type == "response_time":
                return self._time_probe(url, param, payload, match_config)

            start = time.time()
            resp = self.session.get(test_url, timeout=self.config.timeout, verify=False)
            elapsed = time.time() - start

            if not resp or not resp.text:
                return None

            matched = False
            if match_type == "contains_any":
                values = match_config.get("values", [])
                matched = any(v.lower() in resp.text.lower() for v in values)
            elif match_type == "regex_any":
                patterns = match_config.get("values", [])
                matched = any(re.search(p, resp.text, re.I) for p in patterns)
            elif match_type == "response_header":
                header = match_config.get("header", "").lower()
                contains = match_config.get("contains", "")
                loc = resp.headers.get(header, "")
                matched = contains.lower() in loc.lower()

            if matched:
                return self._build_finding(url=test_url, param=param, payload=payload,
                                           resp=resp)
        except Exception as e:
            logger.debug(f"Template probe error: {e}")
        return None

    def _time_probe(self, url, param, payload, match_config) -> Optional[Finding]:
        threshold = match_config.get("threshold_seconds", 4.5)
        try:
            # Baseline
            t0 = time.time()
            self.session.get(url, timeout=self.config.timeout, verify=False)
            baseline = time.time() - t0

            test_url = inject_payload(url, param, payload)
            t1 = time.time()
            resp = self.session.get(test_url, timeout=15, verify=False)
            elapsed = time.time() - t1

            if elapsed >= threshold and elapsed > baseline + 3.0:
                return self._build_finding(url=test_url, param=param, payload=payload,
                                           resp=resp, extra=f"Delay: {elapsed:.2f}s")
        except Exception:
            pass
        return None

    def _run_header_checks(self) -> List[Finding]:
        findings = []
        try:
            resp = self.session.get(normalize_url(self.target),
                                    timeout=self.config.timeout, verify=False)
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            for check in self.template.get("checks", []):
                hdr = check["header"].lower()
                if hdr not in headers_lower:
                    sev = check.get("severity", "medium").upper()
                    cvss = check.get("cvss", 5.3)
                    findings.append(Finding(
                        title=f"Missing Header: {check['header']}",
                        category=self.template["category"],
                        target=self.target,
                        url=normalize_url(self.target),
                        severity=sev,
                        cvss_score=cvss,
                        cwe_id=self.template.get("cwe"),
                        owasp=self.template.get("owasp"),
                        description=f"Security header `{check['header']}` is absent.",
                        proof_of_concept=f"Header not found in response from {self.target}",
                        remediation=check.get("remediation", ""),
                        module=f"template:{self.template['id']}",
                        tags=self.template.get("tags", []),
                    ))
        except Exception as e:
            logger.debug(f"Header check failed: {e}")
        return findings

    def _build_finding(self, url, param, payload, resp, extra="") -> Finding:
        t = self.template
        severity = t.get("severity", "medium").upper()
        snippet = (resp.text or "")[:300] if resp else ""
        return Finding(
            title=f"{t['name']} — {param}",
            category=t["category"],
            target=self.target,
            url=url,
            parameter=param,
            severity=severity,
            cvss_score=float(t.get("cvss", 5.0)),
            cwe_id=t.get("cwe"),
            owasp=t.get("owasp"),
            description=t.get("description", ""),
            proof_of_concept=(
                f"Template: {t['id']}\nURL: {url}\n"
                f"Param: {param}\nPayload: {payload}\n{extra}"
            ),
            payload_used=payload,
            response_snippet=snippet,
            remediation=t.get("remediation", ""),
            references=t.get("references", []),
            module=f"template:{t['id']}",
            tags=t.get("tags", []),
        )

    def _collect_urls(self, base_url) -> List[str]:
        urls = [base_url]
        try:
            resp = self.session.get(base_url, timeout=self.config.timeout, verify=False)
            links = re.findall(r'href=["\']([^"\']*\?[^"\']+)["\']', resp.text or "", re.I)
            for link in links[:10]:
                if link.startswith("/"):
                    link = base_url + link
                if base_url in link:
                    urls.append(link)
        except Exception:
            pass
        return list(set(urls))[:8]


class TemplateScanEngine:
    """Orchestrates template-based scanning across all loaded templates."""

    def __init__(self, config):
        self.config = config
        self.templates = TemplateLoader.load_all()

    def run(self) -> List[Finding]:
        all_findings = []
        for template in self.templates:
            try:
                executor = TemplateExecutor(template, self.config.target, self.config)
                findings = executor.run()
                all_findings.extend(findings)
                if findings:
                    logger.info(f"Template [{template['id']}]: {len(findings)} findings")
            except Exception as e:
                logger.error(f"Template {template.get('id', '?')} failed: {e}")
        return all_findings
