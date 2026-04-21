"""
VulnScanX - Production Flask Web App
"""
import sys, os, json, threading, uuid
from pathlib import Path
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core.config import ScanConfig
from core.engine import VulnScanEngine
from reports.report_manager import ReportManager
from utils.logger import get_logger

logger = get_logger("web")
app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.environ.get("SECRET_KEY", "vulnscanx-dev-secret")
CORS(app)

_scans = {}
_lock  = threading.Lock()

PRESETS = {
    "full":  ["subdomain","dns","whois","dirbrute","ports","headers","xss","sqli","traversal"],
    "quick": ["headers","ports","xss"],
    "recon": ["subdomain","dns","whois","dirbrute"],
    "vuln":  ["headers","xss","sqli","traversal"],
}

def _run(scan_id, config):
    with _lock: _scans[scan_id]["status"] = "running"
    try:
        engine = VulnScanEngine(config)
        engine.load_default_modules()
        with _lock: _scans[scan_id]["engine"] = engine
        result = engine.run()
        paths = ReportManager(["json","html"]).generate_all(result)
        with _lock:
            _scans[scan_id].update({
                "result": result, "status": "completed",
                "stats": result.stats, "risk_score": result.risk_score,
                "findings": [f.to_dict() for f in result.findings],
                "report_paths": paths,
                "duration_seconds": result.duration_seconds,
            })
    except Exception as e:
        logger.error(f"Scan {scan_id} error: {e}")
        with _lock: _scans[scan_id].update({"status":"failed","error":str(e)})

@app.route("/")
def index(): return render_template("dashboard.html")

@app.route("/api/scan", methods=["POST"])
def start_scan():
    d = request.get_json() or {}
    target = d.get("target","").strip()
    if not target: return jsonify({"error":"Target required"}), 400
    scan_type = d.get("scan_type","full")
    modules = d.get("modules") or PRESETS.get(scan_type, PRESETS["full"])
    config = ScanConfig(
        target=target, scan_type=scan_type,
        threads=int(d.get("threads",10)),
        ai_analysis=bool(d.get("ai_analysis",True)),
        modules=modules,
    )
    scan_id = str(uuid.uuid4())[:8]
    with _lock:
        _scans[scan_id] = {
            "scan_id":scan_id,"target":target,"config":config,
            "engine":None,"result":None,"status":"queued",
            "started_at":datetime.utcnow().isoformat(),
            "stats":{},"findings":[],"risk_score":0,
            "report_paths":{},"duration_seconds":0,
        }
    threading.Thread(target=_run, args=(scan_id,config), daemon=True).start()
    return jsonify({"scan_id":scan_id,"status":"queued","target":target})

@app.route("/api/scan/<sid>/status")
def scan_status(sid):
    with _lock: s = _scans.get(sid)
    if not s: return jsonify({"error":"Not found"}), 404
    engine = s.get("engine")
    return jsonify({
        "scan_id":sid, "target":s["target"], "status":s["status"],
        "started_at":s["started_at"], "stats":s.get("stats",{}),
        "risk_score":s.get("risk_score",0),
        "finding_count":len(s.get("findings",[])),
        "duration_seconds":s.get("duration_seconds",0),
        "progress":engine.progress if engine else None,
        "error":s.get("error"),
    })

@app.route("/api/scan/<sid>/findings")
def scan_findings(sid):
    with _lock: s = _scans.get(sid)
    if not s: return jsonify({"error":"Not found"}), 404
    sev = request.args.get("severity","").upper()
    findings = s.get("findings",[])
    if sev: findings = [f for f in findings if f["severity"]==sev]
    return jsonify({"findings":findings,"total":len(findings)})

@app.route("/api/scans")
def list_scans():
    with _lock:
        out = [{"scan_id":s["scan_id"],"target":s["target"],"status":s["status"],
                "started_at":s["started_at"],"stats":s.get("stats",{}),
                "risk_score":s.get("risk_score",0)}
               for s in _scans.values()]
    return jsonify({"scans":sorted(out,key=lambda x:x["started_at"],reverse=True)})

@app.route("/api/scan/<sid>/stop", methods=["POST"])
def stop_scan(sid):
    with _lock: s = _scans.get(sid)
    if not s: return jsonify({"error":"Not found"}), 404
    if s.get("engine"): s["engine"].stop()
    with _lock: _scans[sid]["status"] = "aborted"
    return jsonify({"status":"aborted"})

@app.route("/api/scan/<sid>/report/<fmt>")
def download_report(sid, fmt):
    with _lock: s = _scans.get(sid)
    if not s: return jsonify({"error":"Not found"}), 404
    result = s.get("result")
    if not result: return jsonify({"error":"Scan not completed"}), 400
    paths = ReportManager([fmt]).generate_all(result)
    if fmt not in paths: return jsonify({"error":f"Cannot generate {fmt}"}), 500
    path = Path(paths[fmt])
    mime = {"json":"application/json","html":"text/html","pdf":"application/pdf","sarif":"application/json"}.get(fmt,"application/octet-stream")
    return send_file(path, mimetype=mime, as_attachment=True, download_name=path.name)

@app.route("/api/health")
def health():
    return jsonify({"status":"ok","version":"2.0.0","scans":len(_scans)})

if __name__ == "__main__":
    host = os.environ.get("HOST","0.0.0.0")
    port = int(os.environ.get("PORT",10000))
    print(f"\n🌐 VulnScanX Dashboard → http://{host}:{port}\n")
    app.run(host=host, port=port, debug=False, threaded=True)
