"""
VulnScanX — Report Generators
================================
Generates JSON, HTML, and PDF reports from scan results.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# JSON Report
# ---------------------------------------------------------------------------

class JSONReporter:
    def __init__(self, output_dir: str = "reports/output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, scan_result: Dict, filename: Optional[str] = None) -> str:
        if not filename:
            ts       = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            target   = scan_result.get("target", "unknown").replace("://", "_").replace("/", "_")
            filename = f"vulnscanx_{target}_{ts}.json"

        path = self.output_dir / filename
        with open(path, "w") as f:
            json.dump(scan_result, f, indent=2, default=str)

        return str(path)


# ---------------------------------------------------------------------------
# SARIF Report (GitHub/CI-CD compatible)
# ---------------------------------------------------------------------------

class SARIFReporter:
    """Generates SARIF 2.1.0 format for GitHub Advanced Security / CI integration."""

    SARIF_SCHEMA = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json"

    def generate(self, scan_result: Dict) -> Dict:
        runs = [{
            "tool": {
                "driver": {
                    "name":            "VulnScanX",
                    "version":         "1.0.0",
                    "informationUri":  "https://github.com/vulnscanx",
                    "rules":           self._build_rules(scan_result),
                }
            },
            "results": [self._finding_to_result(f) for f in scan_result.get("findings", [])],
        }]
        return {
            "$schema": self.SARIF_SCHEMA,
            "version": "2.1.0",
            "runs":    runs,
        }

    @staticmethod
    def _build_rules(scan_result: Dict) -> List[Dict]:
        seen  = set()
        rules = []
        for finding in scan_result.get("findings", []):
            rule_id = finding.get("module", "unknown")
            if rule_id not in seen:
                seen.add(rule_id)
                rules.append({
                    "id":   rule_id,
                    "name": finding.get("title", rule_id),
                    "shortDescription": {"text": finding.get("title", "")},
                    "fullDescription":  {"text": finding.get("description", "")},
                    "helpUri": finding.get("references", [""])[0] if finding.get("references") else "",
                    "properties": {
                        "tags": finding.get("tags", []),
                        "cvss": finding.get("cvss_score", 0),
                    },
                })
        return rules

    @staticmethod
    def _finding_to_result(f: Dict) -> Dict:
        level_map = {
            "CRITICAL": "error",
            "HIGH":     "error",
            "MEDIUM":   "warning",
            "LOW":      "note",
            "INFO":     "none",
        }
        return {
            "ruleId":  f.get("module", "unknown"),
            "level":   level_map.get(f.get("severity", "INFO"), "note"),
            "message": {"text": f.get("description", f.get("title", ""))},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.get("url", f.get("target", ""))},
                }
            }],
            "properties": {
                "payload":   f.get("payload", ""),
                "evidence":  f.get("evidence", ""),
                "parameter": f.get("parameter", ""),
            },
        }


# ---------------------------------------------------------------------------
# HTML Report
# ---------------------------------------------------------------------------

SEVERITY_COLORS = {
    "CRITICAL": "#ff2d55",
    "HIGH":     "#ff6b35",
    "MEDIUM":   "#ffcc00",
    "LOW":      "#34c759",
    "INFO":     "#636e72",
}


class HTMLReporter:
    def __init__(self, output_dir: str = "reports/output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, scan_result: Dict, filename: Optional[str] = None) -> str:
        if not filename:
            ts       = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            target   = scan_result.get("target", "unknown").replace("://", "_").replace("/", "_")
            filename = f"vulnscanx_{target}_{ts}.html"

        html = self._render(scan_result)
        path = self.output_dir / filename
        with open(path, "w") as f:
            f.write(html)
        return str(path)

    def _render(self, data: Dict) -> str:
        findings  = data.get("findings", [])
        summary   = data.get("by_severity", {})
        generated = datetime.utcnow().strftime("%Y-%m-%d %Human:%M UTC").replace("Human:", "%H:")
        generated = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

        severity_bars = ""
        for sev, count in summary.items():
            if count > 0:
                color = SEVERITY_COLORS.get(sev, "#636e72")
                severity_bars += f"""
                <div class="sev-bar">
                  <span class="sev-label" style="color:{color}">{sev}</span>
                  <div class="bar-track">
                    <div class="bar-fill" style="background:{color};width:{min(count*8, 100)}%;"></div>
                  </div>
                  <span class="sev-count">{count}</span>
                </div>"""

        findings_html = ""
        for i, f in enumerate(findings):
            color    = SEVERITY_COLORS.get(f.get("severity", "INFO"), "#636e72")
            refs     = "".join(f'<a href="{r}" target="_blank">{r}</a><br>' for r in f.get("references", []))
            tags     = "".join(f'<span class="tag">{t}</span>' for t in f.get("tags", []))
            ai_block = ""
            if f.get("ai_analysis"):
                ai = f["ai_analysis"]
                ai_block = f"""
                <div class="ai-block">
                  <div class="ai-header">🤖 AI Analysis</div>
                  <div class="ai-severity">AI Severity: <b>{ai.get('ai_severity','N/A')}</b>
                    (Confidence: {ai.get('ai_confidence',0)*100:.0f}%)</div>
                  <div class="ai-narrative">{ai.get('human_narrative','').replace(chr(10),'<br>')}</div>
                </div>"""

            findings_html += f"""
            <div class="finding" id="f{i}">
              <div class="finding-header" onclick="toggle('fb{i}')">
                <span class="sev-badge" style="background:{color}">{f.get('severity','INFO')}</span>
                <span class="finding-title">{f.get('title','N/A')}</span>
                <span class="cvss-badge">CVSS {f.get('cvss_score',0):.1f}</span>
                <span class="toggle-icon" id="ti{i}">▼</span>
              </div>
              <div class="finding-body" id="fb{i}">
                <table class="meta-table">
                  <tr><td>URL</td><td><code>{f.get('url','N/A')}</code></td></tr>
                  <tr><td>Parameter</td><td><code>{f.get('parameter') or 'N/A'}</code></td></tr>
                  <tr><td>Module</td><td>{f.get('module','N/A')}</td></tr>
                  <tr><td>Timestamp</td><td>{f.get('timestamp','N/A')}</td></tr>
                </table>
                <div class="section-label">Description</div>
                <p>{f.get('description','')}</p>
                <div class="section-label">Payload / Evidence</div>
                <pre class="code-block">{f.get('payload') or ''}\n{f.get('evidence') or ''}</pre>
                <div class="section-label">Remediation</div>
                <p class="remediation">{f.get('remediation','')}</p>
                <div class="tags-row">{tags}</div>
                {ai_block}
                {"<div class='section-label'>References</div>" + refs if refs else ""}
              </div>
            </div>"""

        total = len(findings)
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VulnScanX Report — {data.get('target','')}</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;700;800&display=swap');

    :root {{
      --bg:      #0a0a0f;
      --surface: #12121a;
      --border:  #1e1e2e;
      --text:    #e2e2e8;
      --muted:   #6e6e8a;
      --accent:  #7c3aed;
    }}

    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

    body {{
      font-family: 'Syne', sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      padding: 0;
    }}

    .header {{
      background: linear-gradient(135deg, #0a0a0f 0%, #12082a 50%, #0a0a0f 100%);
      border-bottom: 1px solid var(--border);
      padding: 40px 60px;
      position: relative;
      overflow: hidden;
    }}

    .header::before {{
      content: '';
      position: absolute;
      top: -50%; left: -10%;
      width: 400px; height: 400px;
      background: radial-gradient(circle, rgba(124,58,237,0.15) 0%, transparent 70%);
      pointer-events: none;
    }}

    .header-top {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 20px;
    }}

    .logo {{
      font-size: 28px;
      font-weight: 800;
      letter-spacing: -1px;
      background: linear-gradient(135deg, #7c3aed, #db2777);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }}

    .logo span {{ color: #ff2d55; -webkit-text-fill-color: #ff2d55; }}

    .report-meta {{ text-align: right; color: var(--muted); font-size: 13px; }}
    .report-meta strong {{ color: var(--text); display: block; margin-bottom: 4px; }}

    .target-line {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 15px;
      color: var(--muted);
      margin-bottom: 8px;
    }}

    .target-line b {{ color: #7c3aed; }}

    .main {{ padding: 40px 60px; max-width: 1400px; margin: 0 auto; }}

    .summary-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 16px;
      margin-bottom: 40px;
    }}

    .stat-card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
      text-align: center;
      transition: transform 0.2s, border-color 0.2s;
    }}

    .stat-card:hover {{ transform: translateY(-2px); border-color: var(--accent); }}

    .stat-num {{
      font-size: 40px;
      font-weight: 800;
      line-height: 1;
      margin-bottom: 6px;
    }}

    .stat-label {{ font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; }}

    .section-title {{
      font-size: 18px;
      font-weight: 700;
      margin-bottom: 20px;
      padding-bottom: 10px;
      border-bottom: 1px solid var(--border);
    }}

    .severity-chart {{ margin-bottom: 40px; }}

    .sev-bar {{
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 10px;
    }}

    .sev-label {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      font-weight: 700;
      width: 70px;
      text-transform: uppercase;
    }}

    .bar-track {{ flex: 1; height: 8px; background: var(--border); border-radius: 99px; overflow: hidden; }}
    .bar-fill   {{ height: 100%; border-radius: 99px; transition: width 1s ease; }}
    .sev-count  {{ font-family: 'JetBrains Mono', monospace; font-size: 13px; width: 30px; text-align: right; }}

    .finding {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      margin-bottom: 12px;
      overflow: hidden;
      transition: border-color 0.2s;
    }}

    .finding:hover {{ border-color: #2d2d3e; }}

    .finding-header {{
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 16px 20px;
      cursor: pointer;
      user-select: none;
    }}

    .sev-badge {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 10px;
      font-weight: 700;
      padding: 3px 8px;
      border-radius: 4px;
      color: #fff;
      min-width: 72px;
      text-align: center;
    }}

    .finding-title {{ flex: 1; font-weight: 600; font-size: 15px; }}
    .cvss-badge {{ font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--muted); }}
    .toggle-icon {{ color: var(--muted); transition: transform 0.2s; }}

    .finding-body {{ display: none; padding: 0 20px 20px; border-top: 1px solid var(--border); }}

    .meta-table {{ width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 13px; }}
    .meta-table td {{ padding: 6px 12px 6px 0; vertical-align: top; }}
    .meta-table td:first-child {{ color: var(--muted); width: 100px; white-space: nowrap; }}
    .meta-table code {{ font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #a78bfa; word-break: break-all; }}

    .section-label {{
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 1.5px;
      color: var(--muted);
      margin: 16px 0 6px;
    }}

    p {{ font-size: 14px; line-height: 1.6; color: #b0b0c8; }}

    pre.code-block {{
      background: #0d0d14;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      color: #ff6b9d;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }}

    .remediation {{ color: #86efac !important; }}

    .tags-row {{ display: flex; flex-wrap: wrap; gap: 6px; margin-top: 12px; }}

    .tag {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      padding: 2px 8px;
      background: #1e1e32;
      border: 1px solid #2d2d4e;
      border-radius: 4px;
      color: #7c6aed;
    }}

    .ai-block {{
      margin-top: 16px;
      background: #0d0818;
      border: 1px solid #2d1f4e;
      border-radius: 8px;
      padding: 14px;
    }}

    .ai-header {{ font-size: 12px; font-weight: 700; color: #a78bfa; margin-bottom: 8px; }}
    .ai-severity {{ font-size: 13px; color: var(--muted); margin-bottom: 8px; }}
    .ai-narrative {{ font-size: 13px; line-height: 1.7; color: #b0b0c8; }}

    a {{ color: #7c3aed; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}

    .footer {{
      text-align: center;
      padding: 30px;
      color: var(--muted);
      font-size: 12px;
      border-top: 1px solid var(--border);
      margin-top: 60px;
    }}

    @media (max-width: 768px) {{
      .header {{ padding: 20px; }}
      .main   {{ padding: 20px; }}
    }}
  </style>
</head>
<body>

<div class="header">
  <div class="header-top">
    <div>
      <div class="logo">Vuln<span>Scan</span>X</div>
      <div class="target-line" style="margin-top:8px">
        Target: <b>{data.get('target','N/A')}</b>
      </div>
    </div>
    <div class="report-meta">
      <strong>Security Assessment Report</strong>
      Generated: {generated}<br>
      Scan ID: {data.get('scan_id','N/A')}<br>
      Duration: {data.get('duration',0):.2f}s
    </div>
  </div>
</div>

<div class="main">
  <div class="summary-grid">
    <div class="stat-card">
      <div class="stat-num" style="color:#e2e2e8">{total}</div>
      <div class="stat-label">Total Findings</div>
    </div>
    <div class="stat-card">
      <div class="stat-num" style="color:#ff2d55">{summary.get('CRITICAL',0)}</div>
      <div class="stat-label">Critical</div>
    </div>
    <div class="stat-card">
      <div class="stat-num" style="color:#ff6b35">{summary.get('HIGH',0)}</div>
      <div class="stat-label">High</div>
    </div>
    <div class="stat-card">
      <div class="stat-num" style="color:#ffcc00">{summary.get('MEDIUM',0)}</div>
      <div class="stat-label">Medium</div>
    </div>
    <div class="stat-card">
      <div class="stat-num" style="color:#34c759">{summary.get('LOW',0)}</div>
      <div class="stat-label">Low</div>
    </div>
    <div class="stat-card">
      <div class="stat-num" style="color:#636e72">{summary.get('INFO',0)}</div>
      <div class="stat-label">Info</div>
    </div>
  </div>

  <div class="severity-chart">
    <div class="section-title">Severity Distribution</div>
    {severity_bars}
  </div>

  <div class="section-title">Vulnerability Findings ({total})</div>
  {findings_html if findings_html else '<p style="color:var(--muted)">No findings for this scan.</p>'}

</div>

<div class="footer">
  VulnScanX v1.0.0 — For authorized security testing only.
  Report generated {generated}.
</div>

<script>
  function toggle(id) {{
    const el = document.getElementById(id);
    const idx = id.replace('fb','');
    const icon = document.getElementById('ti' + idx);
    if (el.style.display === 'block') {{
      el.style.display = 'none';
      icon.textContent = '▼';
    }} else {{
      el.style.display = 'block';
      icon.textContent = '▲';
    }}
  }}

  // Auto-open CRITICAL findings
  document.querySelectorAll('.sev-badge').forEach((badge, i) => {{
    if (badge.textContent.trim() === 'CRITICAL') {{
      document.getElementById('fb' + i)?.style && (document.getElementById('fb' + i).style.display = 'block');
    }}
  }});
</script>
</body>
</html>"""
