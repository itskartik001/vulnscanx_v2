"""
VulnScanX - HTML Reporter
Generates a self-contained, styled HTML report.
"""
from pathlib import Path
from datetime import datetime
from core.models import ScanResult
from core.config import REPORTS_DIR
from utils.helpers import sanitize_filename


class HTMLReporter:
    SEV_COLORS = {
        "CRITICAL": "#dc2626", "HIGH": "#ea580c",
        "MEDIUM": "#d97706", "LOW": "#2563eb", "INFO": "#6b7280",
    }

    def generate(self, result: ScanResult, output_path: Path = None) -> Path:
        if not output_path:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_safe = sanitize_filename(result.target)
            output_path = REPORTS_DIR / f"vulnscanx_{target_safe}_{ts}.html"

        stats = result.stats
        findings_html = "".join(self._render_finding(f, i)
                                for i, f in enumerate(result.findings))

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VulnScanX Report — {result.target}</title>
<style>
  :root {{
    --bg: #0f172a; --surface: #1e293b; --surface2: #334155;
    --text: #f1f5f9; --text-muted: #94a3b8; --accent: #38bdf8;
    --border: #475569;
    --critical: #dc2626; --high: #ea580c; --medium: #d97706;
    --low: #2563eb; --info: #6b7280;
  }}
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ background:var(--bg); color:var(--text); font-family:'Segoe UI',sans-serif; line-height:1.6; }}
  .header {{ background:linear-gradient(135deg,#0f172a 0%,#1e3a5f 100%); padding:3rem 2rem; border-bottom:2px solid var(--accent); }}
  .header h1 {{ font-size:2.5rem; color:var(--accent); font-weight:800; letter-spacing:-1px; }}
  .header .subtitle {{ color:var(--text-muted); margin-top:.5rem; font-size:1.1rem; }}
  .warning-banner {{ background:#7f1d1d; border:1px solid #dc2626; padding:1rem 2rem; color:#fca5a5; font-weight:600; text-align:center; }}
  .container {{ max-width:1200px; margin:0 auto; padding:2rem; }}
  .stats-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:1rem; margin:2rem 0; }}
  .stat-card {{ background:var(--surface); border-radius:12px; padding:1.5rem; text-align:center; border:1px solid var(--border); }}
  .stat-card .count {{ font-size:2.5rem; font-weight:900; }}
  .stat-card .label {{ color:var(--text-muted); font-size:.85rem; text-transform:uppercase; letter-spacing:1px; }}
  .stat-card.critical .count {{ color:var(--critical); }}
  .stat-card.high .count {{ color:var(--high); }}
  .stat-card.medium .count {{ color:var(--medium); }}
  .stat-card.low .count {{ color:var(--low); }}
  .stat-card.total .count {{ color:var(--accent); }}
  .meta-bar {{ background:var(--surface); border-radius:12px; padding:1.5rem; margin:1rem 0; display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:1rem; border:1px solid var(--border); }}
  .meta-item {{ display:flex; flex-direction:column; }}
  .meta-item .key {{ font-size:.75rem; text-transform:uppercase; color:var(--text-muted); letter-spacing:1px; }}
  .meta-item .val {{ font-weight:600; color:var(--accent); margin-top:.2rem; }}
  .risk-bar {{ background:var(--surface); border-radius:12px; padding:1.5rem; margin:1rem 0; border:1px solid var(--border); }}
  .risk-label {{ display:flex; justify-content:space-between; margin-bottom:.75rem; }}
  .risk-track {{ background:var(--surface2); border-radius:999px; height:12px; overflow:hidden; }}
  .risk-fill {{ height:100%; border-radius:999px; background:linear-gradient(90deg,#16a34a,#d97706,#dc2626); transition:width .8s; }}
  .section-title {{ font-size:1.4rem; font-weight:700; margin:2rem 0 1rem; padding-bottom:.5rem; border-bottom:2px solid var(--border); color:var(--accent); }}
  .finding-card {{ background:var(--surface); border-radius:12px; margin:.75rem 0; border:1px solid var(--border); overflow:hidden; }}
  .finding-header {{ display:flex; align-items:center; gap:1rem; padding:1rem 1.5rem; cursor:pointer; }}
  .finding-header:hover {{ background:var(--surface2); }}
  .sev-badge {{ padding:.25rem .75rem; border-radius:999px; font-size:.75rem; font-weight:700; text-transform:uppercase; letter-spacing:1px; color:#fff; flex-shrink:0; }}
  .finding-title {{ font-weight:600; flex:1; }}
  .finding-meta {{ color:var(--text-muted); font-size:.85rem; }}
  .finding-body {{ padding:1.5rem; border-top:1px solid var(--border); display:none; }}
  .finding-body.active {{ display:block; }}
  .field-grid {{ display:grid; grid-template-columns:1fr 1fr; gap:1rem; margin-bottom:1rem; }}
  @media(max-width:600px){{.field-grid{{grid-template-columns:1fr;}}}}
  .field {{ background:var(--bg); border-radius:8px; padding:1rem; border:1px solid var(--border); }}
  .field .field-label {{ font-size:.7rem; text-transform:uppercase; color:var(--text-muted); letter-spacing:1px; margin-bottom:.4rem; }}
  .field .field-val {{ font-size:.9rem; word-break:break-all; }}
  .code-block {{ background:#0a0f1e; border:1px solid var(--border); border-radius:8px; padding:1rem; font-family:'Courier New',monospace; font-size:.82rem; overflow-x:auto; white-space:pre-wrap; word-break:break-all; color:#7dd3fc; margin:.5rem 0; }}
  .remediation {{ background:#052e16; border:1px solid #16a34a; border-radius:8px; padding:1rem; color:#86efac; margin:.5rem 0; white-space:pre-wrap; font-size:.9rem; }}
  .tag {{ display:inline-block; background:var(--surface2); border-radius:4px; padding:.15rem .5rem; font-size:.72rem; color:var(--text-muted); margin:.15rem; }}
  .ai-block {{ background:#1a1033; border:1px solid #7c3aed; border-radius:8px; padding:1rem; color:#c4b5fd; margin:.5rem 0; font-size:.88rem; white-space:pre-wrap; }}
  .footer {{ text-align:center; padding:2rem; color:var(--text-muted); font-size:.85rem; border-top:1px solid var(--border); margin-top:3rem; }}
  .chart-container {{ background:var(--surface); border-radius:12px; padding:1.5rem; border:1px solid var(--border); margin:1rem 0; }}
  .bar-chart {{ display:flex; flex-direction:column; gap:.5rem; }}
  .bar-row {{ display:flex; align-items:center; gap:1rem; }}
  .bar-name {{ width:80px; font-size:.85rem; text-align:right; color:var(--text-muted); flex-shrink:0; }}
  .bar-track {{ flex:1; background:var(--surface2); border-radius:999px; height:20px; overflow:hidden; }}
  .bar-fill {{ height:100%; border-radius:999px; min-width:4px; }}
  .bar-count {{ width:30px; font-weight:700; font-size:.9rem; }}
</style>
</head>
<body>
<div class="header">
  <h1>⚡ VulnScanX</h1>
  <div class="subtitle">Advanced Vulnerability Scan Report &mdash; {result.target}</div>
  <div style="margin-top:.5rem;color:#94a3b8;font-size:.9rem">Scan ID: {result.scan_id} &nbsp;|&nbsp; {result.start_time[:19].replace('T',' ')} UTC</div>
</div>
<div class="warning-banner">
  ⚠️ CONFIDENTIAL SECURITY REPORT — FOR AUTHORIZED PERSONNEL ONLY — DO NOT DISTRIBUTE
</div>
<div class="container">
  <div class="stats-grid">
    <div class="stat-card critical"><div class="count">{stats.get('CRITICAL',0)}</div><div class="label">Critical</div></div>
    <div class="stat-card high"><div class="count">{stats.get('HIGH',0)}</div><div class="label">High</div></div>
    <div class="stat-card medium"><div class="count">{stats.get('MEDIUM',0)}</div><div class="label">Medium</div></div>
    <div class="stat-card low"><div class="count">{stats.get('LOW',0)}</div><div class="label">Low</div></div>
    <div class="stat-card total"><div class="count">{stats.get('total',0)}</div><div class="label">Total</div></div>
  </div>

  <div class="meta-bar">
    <div class="meta-item"><div class="key">Target</div><div class="val">{result.target}</div></div>
    <div class="meta-item"><div class="key">Risk Score</div><div class="val">{result.risk_score}/10</div></div>
    <div class="meta-item"><div class="key">Duration</div><div class="val">{result.duration_seconds:.1f}s</div></div>
    <div class="meta-item"><div class="key">Status</div><div class="val">{result.status.upper()}</div></div>
    <div class="meta-item"><div class="key">Modules</div><div class="val">{len(result.modules_run)}</div></div>
  </div>

  <div class="risk-bar">
    <div class="risk-label"><span style="font-weight:700">Overall Risk Score</span><span style="color:var(--accent);font-size:1.5rem;font-weight:900">{result.risk_score}/10</span></div>
    <div class="risk-track"><div class="risk-fill" style="width:{result.risk_score*10}%"></div></div>
  </div>

  <div class="chart-container">
    <div class="section-title" style="margin-top:0">Findings Distribution</div>
    <div class="bar-chart">
      {self._render_bar("CRITICAL", stats.get('CRITICAL',0), stats.get('total',1), "#dc2626")}
      {self._render_bar("HIGH", stats.get('HIGH',0), stats.get('total',1), "#ea580c")}
      {self._render_bar("MEDIUM", stats.get('MEDIUM',0), stats.get('total',1), "#d97706")}
      {self._render_bar("LOW", stats.get('LOW',0), stats.get('total',1), "#2563eb")}
      {self._render_bar("INFO", stats.get('INFO',0), stats.get('total',1), "#6b7280")}
    </div>
  </div>

  <div class="section-title">Vulnerability Findings</div>
  {findings_html if findings_html else '<p style="color:var(--text-muted);padding:2rem;text-align:center">No vulnerabilities found.</p>'}

  <div class="footer">
    Generated by VulnScanX v2.0 &nbsp;&bull;&nbsp; {datetime.now().strftime('%Y-%m-%d %H:%M')} UTC<br>
    <span style="color:#dc2626;font-weight:600">FOR AUTHORIZED USE ONLY</span>
  </div>
</div>
<script>
document.querySelectorAll('.finding-header').forEach(h => {{
  h.addEventListener('click', () => {{
    const body = h.nextElementSibling;
    body.classList.toggle('active');
  }});
}});
</script>
</body>
</html>"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        return output_path

    def _render_bar(self, label, count, total, color):
        pct = (count / total * 100) if total > 0 else 0
        return f'''<div class="bar-row">
      <div class="bar-name">{label}</div>
      <div class="bar-track"><div class="bar-fill" style="width:{pct}%;background:{color}"></div></div>
      <div class="bar-count" style="color:{color}">{count}</div>
    </div>'''

    def _render_finding(self, finding, index):
        sev_color = self.SEV_COLORS.get(finding.severity, "#6b7280")
        tags_html = "".join(f'<span class="tag">{t}</span>' for t in finding.tags)
        poc = (finding.proof_of_concept or "").replace("<", "&lt;").replace(">", "&gt;")
        rem = (finding.remediation or "").replace("<", "&lt;").replace(">", "&gt;")
        ai_block = ""
        if finding.ai_explanation:
            ai_exp = finding.ai_explanation.replace("<","&lt;").replace(">","&gt;")
            ai_block = f'<div class="field-label">🤖 AI ANALYSIS</div><div class="ai-block">{ai_exp}</div>'

        return f'''
<div class="finding-card">
  <div class="finding-header">
    <span class="sev-badge" style="background:{sev_color}">{finding.severity}</span>
    <div class="finding-title">{finding.title}</div>
    <div class="finding-meta">CVSS {finding.cvss_score} &nbsp;|&nbsp; {finding.category}</div>
  </div>
  <div class="finding-body">
    <div class="field-grid">
      <div class="field"><div class="field-label">URL</div><div class="field-val">{finding.url}</div></div>
      <div class="field"><div class="field-label">Parameter</div><div class="field-val">{finding.parameter or "N/A"}</div></div>
      <div class="field"><div class="field-label">CWE</div><div class="field-val">{finding.cwe_id or "N/A"}</div></div>
      <div class="field"><div class="field-label">OWASP</div><div class="field-val">{finding.owasp or "N/A"}</div></div>
    </div>
    <div class="field-label" style="margin:.5rem 0 .3rem">DESCRIPTION</div>
    <p style="font-size:.9rem;color:var(--text-muted)">{finding.description}</p>
    <div class="field-label" style="margin:.75rem 0 .3rem">PROOF OF CONCEPT</div>
    <div class="code-block">{poc}</div>
    <div class="field-label" style="margin:.75rem 0 .3rem">REMEDIATION</div>
    <div class="remediation">{rem}</div>
    {ai_block}
    <div style="margin-top:.75rem">{tags_html}</div>
  </div>
</div>'''
