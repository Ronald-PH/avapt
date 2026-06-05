import io
import json
import threading
import uuid
from datetime import datetime
from pathlib import Path
import os


from flask import (
    Flask, render_template, request, jsonify,
    send_file,
)

from core.config        import (
    VERSION, DEFAULT_MODEL, DEFAULT_OLLAMA, MAX_AI_WORKERS,
    SCAN_PROFILES, DEFAULT_SCAN_PROFILE,
)
from core.ollama_client import OllamaClient
from core.scanner       import run_scan
from core.report_html   import build_html
from core.report_pdf    import build_pdf, HAS_REPORTLAB
from core.report_sarif  import build_sarif

# Get the directory where app.py is located
APP_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = APP_DIR / 'templates'
STATIC_DIR = APP_DIR / 'static'

app = Flask(__name__, 
            template_folder=str(TEMPLATE_DIR),
            static_folder=str(STATIC_DIR))
app.secret_key = os.environ.get("AVAPT_SECRET_KEY", "avapt-dev-secret")

# Add custom Jinja2 filters
@app.template_filter('basename')
def basename_filter(path):
    """Return the last component of a path (filename)"""
    if not path:
        return ''
    # Handle both Windows and Unix paths
    return path.replace('\\', '/').split('/')[-1]

@app.template_filter('split')
def split_filter(value, delimiter='/', index=-1):
    """Split a string and return a specific index (default last)"""
    if not value:
        return ''
    parts = value.replace('\\', '/').split(delimiter)
    if index == -1:
        return parts[-1] if parts else ''
    return parts[index] if 0 <= index < len(parts) else ''

# ── in-memory job store ───────────────────────────────────────────────────────
# { job_id: { status, progress, result, error } }
JOBS: dict[str, dict] = {}
JOBS_LOCK = threading.Lock()
# =============================================================================
# ROUTES — UI
# =============================================================================

@app.route("/")
def index():
    ollama_url = request.args.get("ollama_url", DEFAULT_OLLAMA)
    client = OllamaClient(base_url=ollama_url)
    models = client.list_models() if client.is_available() else []
    return render_template(
        "index.html",
        version      = VERSION,
        default_model= DEFAULT_MODEL,
        default_url  = DEFAULT_OLLAMA,
        models       = models,
        has_pdf      = True,
        profiles     = SCAN_PROFILES,
        default_profile = DEFAULT_SCAN_PROFILE,
    )


@app.route("/scan", methods=["POST"])
def start_scan():
    """Start a background scan and return a job_id."""
    prompt     = request.form.get("prompt", "").strip()
    target     = request.form.get("target", "").strip()
    model      = request.form.get("model",  DEFAULT_MODEL).strip()
    ollama_url = request.form.get("ollama_url", DEFAULT_OLLAMA).strip()
    profile    = request.form.get("profile", DEFAULT_SCAN_PROFILE).strip()
    baseline_path = request.form.get("baseline", "").strip()
    workers_raw = request.form.get("workers", str(MAX_AI_WORKERS)).strip()
    try:
        workers = int(workers_raw)
    except ValueError:
        return jsonify({"error": "Workers must be a number"}), 400
    workers = max(1, min(workers, MAX_AI_WORKERS))

    if not target:
        return jsonify({"error": "No target path provided"}), 400

    job_id = str(uuid.uuid4())
    with JOBS_LOCK:
        JOBS[job_id] = {
            "status":   "running",
            "progress": {"done": 0, "total": 0, "current_file": ""},
            "result":   None,
            "error":    None,
            "started":  datetime.utcnow().isoformat(),
        }

    def _run():
        try:
            ollama = OllamaClient(base_url=ollama_url, model=model)

            def _cb(done, total, filename, count):
                with JOBS_LOCK:
                    JOBS[job_id]["progress"] = {
                        "done":         done,
                        "total":        total,
                        "current_file": filename,
                    }

            result = run_scan(
                target,
                prompt,
                ollama,
                workers=workers,
                profile=profile,
                baseline_path=baseline_path,
                progress_cb=_cb,
            )
            with JOBS_LOCK:
                JOBS[job_id]["status"] = "done"
                JOBS[job_id]["result"] = result
            print(f"Job {job_id} completed: {len(result)} findings")
        except Exception as exc:
            with JOBS_LOCK:
                JOBS[job_id]["status"] = "error"
                JOBS[job_id]["error"]  = str(exc)

    t = threading.Thread(target=_run, daemon=True)
    t.start()

    return jsonify({"job_id": job_id})


@app.route("/job/<job_id>")
def job_status(job_id: str):
    """Poll job status + progress."""
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify({
        "status":   job["status"],
        "progress": job["progress"],
        "error":    job["error"],
        "has_result": job["result"] is not None,
    })


@app.route("/report/<job_id>")
def view_report(job_id: str):
    """Render the HTML report for a completed scan."""
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job or not job["result"]:
        return "Scan not found or not complete", 404
    return render_template(
        "report.html",
        job_id  = job_id,
        result  = job["result"],
        version = VERSION,
        has_pdf = True,
    )


# =============================================================================
# ROUTES — DOWNLOADS
# =============================================================================

@app.route("/download/html/<job_id>")
def download_html(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job or not job["result"]:
        return "Not found", 404
    html_bytes = build_html(job["result"]).encode("utf-8")
    return send_file(
        io.BytesIO(html_bytes),
        mimetype             = "text/html",
        as_attachment        = True,
        download_name        = f"avapt_report_{job_id[:8]}.html",
    )


@app.route("/download/json/<job_id>")
def download_json(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job or not job["result"]:
        return "Not found", 404
    json_bytes = json.dumps(job["result"], indent=2).encode("utf-8")
    return send_file(
        io.BytesIO(json_bytes),
        mimetype             = "application/json",
        as_attachment        = True,
        download_name        = f"avapt_report_{job_id[:8]}.json",
    )


@app.route("/download/pdf/<job_id>")
def download_pdf(job_id: str):
    if not HAS_REPORTLAB:
        return "reportlab not installed. Run: pip install reportlab", 500
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job or not job["result"]:
        return "Not found", 404

    buf = io.BytesIO()
    # build_pdf writes to a path, so use a temp file approach
    import tempfile, os
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        build_pdf(job["result"], tmp_path)
        with open(tmp_path, "rb") as fh:
            pdf_bytes = fh.read()
    finally:
        os.unlink(tmp_path)

    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype             = "application/pdf",
        as_attachment        = True,
        download_name        = f"avapt_report_{job_id[:8]}.pdf",
    )


@app.route("/download/sarif/<job_id>")
def download_sarif(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job or not job["result"]:
        return "Not found", 404
    sarif_bytes = build_sarif(job["result"]).encode("utf-8")
    return send_file(
        io.BytesIO(sarif_bytes),
        mimetype             = "application/sarif+json",
        as_attachment        = True,
        download_name        = f"avapt_report_{job_id[:8]}.sarif",
    )


@app.route("/download/baseline/<job_id>")
def download_baseline(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job or not job["result"]:
        return "Not found", 404
    baseline = {
        "tool": "avapt",
        "created_from": job_id,
        "fingerprints": [
            f.get("fingerprint")
            for f in job["result"].get("findings", [])
            if f.get("fingerprint")
        ],
    }
    baseline_bytes = json.dumps(baseline, indent=2).encode("utf-8")
    return send_file(
        io.BytesIO(baseline_bytes),
        mimetype             = "application/json",
        as_attachment        = True,
        download_name        = f"avapt_baseline_{job_id[:8]}.json",
    )


# =============================================================================
# ROUTES — API
# =============================================================================

@app.route("/api/models")
def api_models():
    """Return available Ollama models for the given URL."""
    url    = request.args.get("url", DEFAULT_OLLAMA)
    client = OllamaClient(base_url=url)
    if not client.is_available():
        return jsonify({"available": False, "models": []}), 200
    return jsonify({"available": True, "models": client.list_models()})


@app.route("/api/jobs")
def api_jobs():
    """List all jobs (summary)."""
    with JOBS_LOCK:
        jobs = {
            jid: {
                "status":  j["status"],
                "started": j["started"],
                "findings": len(j["result"]["findings"]) if j["result"] else 0,
            }
            for jid, j in JOBS.items()
        }
    return jsonify(jobs)


if __name__ == "__main__":
    import sys, io as _io
    if sys.platform == "win32":
        sys.stdout = _io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
        sys.stderr = _io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
    app.run(debug=True, host="0.0.0.0", port=5000)
