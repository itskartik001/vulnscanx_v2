"""
VulnScanX — YAML Template Engine
===================================
Nuclei-inspired template-based scanning engine.
Parses YAML templates and executes them dynamically against targets.

Template schema:
  id, name, description, severity, tags,
  requests[]{method, path, headers, body, payloads, matchers, extractors}
"""

import os
import re
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
import yaml

from core import Finding, Severity

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ---------------------------------------------------------------------------
# Template data model
# ---------------------------------------------------------------------------

@dataclass
class Matcher:
    type:   str       # "word", "regex", "status", "binary"
    values: List[str] = field(default_factory=list)
    part:   str       = "body"     # "body", "headers", "all"
    condition: str    = "or"       # "or" | "and"
    negative: bool    = False

    def match(self, response: requests.Response) -> bool:
        part = self._get_part(response)
        if self.type == "word":
            results = [v.lower() in part.lower() for v in self.values]
        elif self.type == "regex":
            results = [bool(re.search(v, part, re.I)) for v in self.values]
        elif self.type == "status":
            results = [str(response.status_code) in self.values]
        elif self.type == "binary":
            results = [v.encode() in response.content for v in self.values]
        else:
            results = [False]

        if self.condition == "and":
            matched = all(results)
        else:
            matched = any(results)

        return not matched if self.negative else matched

    def _get_part(self, resp: requests.Response) -> str:
        if self.part == "headers":
            return str(dict(resp.headers))
        elif self.part == "all":
            return str(dict(resp.headers)) + resp.text
        return resp.text


@dataclass
class Extractor:
    type:  str         # "regex", "kval", "xpath", "json"
    name:  str
    values: List[str]  = field(default_factory=list)
    group: int         = 0

    def extract(self, response: requests.Response) -> Optional[str]:
        body = response.text
        if self.type == "regex":
            for pattern in self.values:
                m = re.search(pattern, body, re.I)
                if m:
                    try:
                        return m.group(self.group)
                    except IndexError:
                        return m.group(0)
        elif self.type == "kval":
            for key in self.values:
                val = response.headers.get(key)
                if val:
                    return val
        return None


@dataclass
class TemplateRequest:
    method:    str              = "GET"
    path:      str              = "/"
    headers:   Dict[str, str]   = field(default_factory=dict)
    body:      str              = ""
    payloads:  Dict[str, List]  = field(default_factory=dict)
    matchers:  List[Matcher]    = field(default_factory=list)
    extractors: List[Extractor] = field(default_factory=list)
    stop_at_first_match: bool   = True


@dataclass
class Template:
    id:          str
    name:        str
    description: str
    severity:    Severity
    cvss_score:  float
    tags:        List[str]
    requests:    List[TemplateRequest]
    remediation: str              = ""
    references:  List[str]        = field(default_factory=list)
    author:      str              = "vulnscanx"
    raw:         Dict             = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Template parser
# ---------------------------------------------------------------------------

SEVERITY_MAP = {
    "info":     Severity.INFO,
    "low":      Severity.LOW,
    "medium":   Severity.MEDIUM,
    "high":     Severity.HIGH,
    "critical": Severity.CRITICAL,
}

CVSS_MAP = {
    Severity.INFO:     0.0,
    Severity.LOW:      3.9,
    Severity.MEDIUM:   6.5,
    Severity.HIGH:     8.1,
    Severity.CRITICAL: 9.5,
}


class TemplateParser:
    @staticmethod
    def load_file(path: str) -> Optional[Template]:
        try:
            with open(path, "r") as f:
                data = yaml.safe_load(f)
            return TemplateParser.parse(data)
        except Exception as e:
            print(f"[TemplateEngine] Failed to parse {path}: {e}")
            return None

    @staticmethod
    def parse(data: Dict) -> Template:
        sev_str = data.get("severity", "info").lower()
        sev     = SEVERITY_MAP.get(sev_str, Severity.INFO)

        template_requests = []
        for req_data in data.get("requests", []):
            matchers = [
                Matcher(
                    type      = m.get("type", "word"),
                    values    = m.get("words", m.get("regex", m.get("values", []))),
                    part      = m.get("part", "body"),
                    condition = m.get("condition", "or"),
                    negative  = m.get("negative", False),
                )
                for m in req_data.get("matchers", [])
            ]
            extractors = [
                Extractor(
                    type   = e.get("type", "regex"),
                    name   = e.get("name", "extracted"),
                    values = e.get("regex", e.get("words", [])),
                    group  = e.get("group", 0),
                )
                for e in req_data.get("extractors", [])
            ]
            template_requests.append(TemplateRequest(
                method    = req_data.get("method", "GET").upper(),
                path      = req_data.get("path", "/"),
                headers   = req_data.get("headers", {}),
                body      = req_data.get("body", ""),
                payloads  = req_data.get("payloads", {}),
                matchers  = matchers,
                extractors = extractors,
            ))

        return Template(
            id          = data.get("id", str(uuid.uuid4())[:8]),
            name        = data.get("name", data.get("id", "Unknown")),
            description = data.get("description", ""),
            severity    = sev,
            cvss_score  = data.get("cvss_score", CVSS_MAP[sev]),
            tags        = data.get("tags", []),
            requests    = template_requests,
            remediation = data.get("remediation", ""),
            references  = data.get("references", []),
            author      = data.get("author", "vulnscanx"),
            raw         = data,
        )


# ---------------------------------------------------------------------------
# Template executor
# ---------------------------------------------------------------------------

class TemplateEngine:
    """
    Loads all YAML templates from the templates/ directory and
    executes them against a target, yielding Finding objects.
    """

    def __init__(self, templates_dir: str = None, config: dict = None):
        self.config        = config or {}
        self.timeout       = self.config.get("timeout", 10)
        self.templates_dir = templates_dir or str(
            Path(__file__).parent.parent / "templates"
        )
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "VulnScanX/1.0 Template Engine"
        self.session.verify = False

    def load_templates(self) -> List[Template]:
        templates = []
        path      = Path(self.templates_dir)
        if not path.exists():
            return templates
        for f in path.rglob("*.yaml"):
            tmpl = TemplateParser.load_file(str(f))
            if tmpl:
                templates.append(tmpl)
        return templates

    def run(self, target: str) -> List[Finding]:
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        target = target.rstrip("/")

        templates = self.load_templates()
        findings  = []
        print(f"[TemplateEngine] Running {len(templates)} templates against {target}")

        for tmpl in templates:
            for req in tmpl.requests:
                results = self._execute_request(target, tmpl, req)
                findings.extend(results)

        return findings

    def _execute_request(
        self,
        target: str,
        tmpl: Template,
        req: TemplateRequest,
    ) -> List[Finding]:
        findings = []

        # Expand payloads (simple product expansion)
        payload_combos = self._expand_payloads(req.payloads)
        if not payload_combos:
            payload_combos = [{}]

        for combo in payload_combos:
            url     = self._interpolate(target + req.path, combo)
            headers = {k: self._interpolate(v, combo) for k, v in req.headers.items()}
            body    = self._interpolate(req.body, combo)

            try:
                if req.method == "GET":
                    resp = self.session.get(url, headers=headers, timeout=self.timeout)
                elif req.method == "POST":
                    resp = self.session.post(url, data=body, headers=headers, timeout=self.timeout)
                else:
                    resp = self.session.request(req.method, url, headers=headers,
                                                data=body, timeout=self.timeout)
            except Exception as e:
                continue

            # Run matchers
            matched = all(m.match(resp) for m in req.matchers) if req.matchers else False
            if not matched:
                continue

            # Run extractors
            extracted = {}
            for ext in req.extractors:
                val = ext.extract(resp)
                if val:
                    extracted[ext.name] = val

            findings.append(Finding(
                title       = f"[Template] {tmpl.name}",
                severity    = tmpl.severity,
                cvss_score  = tmpl.cvss_score,
                target      = target,
                url         = url,
                payload     = str(combo),
                module      = f"template:{tmpl.id}",
                evidence    = f"HTTP {resp.status_code} — Matched: {tmpl.name}" + (
                    f" | Extracted: {extracted}" if extracted else ""
                ),
                description = tmpl.description,
                remediation = tmpl.remediation,
                tags        = tmpl.tags,
                references  = tmpl.references,
            ))

            if req.stop_at_first_match:
                break

        return findings

    @staticmethod
    def _interpolate(template_str: str, values: Dict) -> str:
        for k, v in values.items():
            template_str = template_str.replace(f"{{{{{k}}}}}", str(v))
        return template_str

    @staticmethod
    def _expand_payloads(payloads: Dict) -> List[Dict]:
        """Expand payload dict into all combinations (simple product)."""
        if not payloads:
            return []
        import itertools
        keys   = list(payloads.keys())
        values = [payloads[k] if isinstance(payloads[k], list) else [payloads[k]]
                  for k in keys]
        return [dict(zip(keys, combo)) for combo in itertools.product(*values)]
