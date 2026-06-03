from pathlib import Path
from core.config import VERSION


# ── helpers ───────────────────────────────────────────────────────────────────

def _esc(s) -> str:
    return (str(s)
            .replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _sev_badge(sev: str) -> str:
    c = {"critical": "#ff2d55", "high": "#ff6b35",
         "medium": "#ffd60a",   "low":  "#30d158"}
    return (f'<span class="badge" style="background:{c.get(sev, "#888")}">'
            f'{sev.upper()}</span>')


def _src_badge(src: str) -> str:
    labels = {"ai": "AI", "dependency": "DEP"}
    colors = {"ai": "#bf5fff", "dependency": "#ffd60a"}
    return (f'<span class="src-badge" style="color:{colors.get(src, "#aaa")}">'
            f'{labels.get(src, src.upper())}</span>')


def _bar(label: str, count: int, total: int, cls: str) -> str:
    pct = round(count / total * 100) if total else 0
    return f"""<div class="bar-row">
      <span class="bar-label">{label}</span>
      <div class="bar-track">
        <div class="bar-fill bc-{cls}" style="width:{pct}%"></div>
      </div>
      <span class="bar-count bc-{cls}">{count}</span>
    </div>"""


# ── main builder ──────────────────────────────────────────────────────────────

def build_html(result: dict) -> str:
    meta       = result["meta"]
    summary    = result["summary"]
    src_counts = result.get("source_counts", {})
    findings   = result["findings"]      # already sorted by severity
    total      = len(findings)
    risk       = ("CRITICAL" if summary["critical"] > 0 else
                  "HIGH"     if summary["high"]     > 0 else
                  "MEDIUM"   if summary["medium"]   > 0 else "LOW")

    # ── finding rows ──────────────────────────────────────────────────────────
    rows = ""
    for i, f in enumerate(findings):
        uid     = f"v{i}"
        prereqs = "".join(
            f"<li>{_esc(p)}</li>"
            for p in f.get("attack_path", {}).get("prerequisites", [])
        )
        ap = f.get("attack_path", {})
        rows += f"""
        <tr onclick="toggle('{uid}')" class="vuln-row sev-{f['severity']}">
          <td>{_esc(f['type'])}</td>
          <td>{_sev_badge(f['severity'])}</td>
          <td class="score">{f['severity_score']}</td>
          <td class="filepath" title="{_esc(f['file'])}">{_esc(Path(f['file']).name)}</td>
          <td class="mono">{_esc(f.get('cwe', ''))}</td>
          <td class="mono">{_esc(f.get('cve_id') or '-')}</td>
          <td class="conf">{_esc(f.get('confidence', ''))}</td>
          <td>{_src_badge(f.get('source', 'ai'))}</td>
        </tr>
        <tr id="{uid}" class="detail-row">
          <td colspan="8"><div class="detail-inner">
            <div class="detail-grid">
              <div class="detail-section">
                <h4>Location</h4>
                <p><strong>File:</strong><br><code>{_esc(f['file'])}</code></p>
                <p><strong>Lines:</strong> {f['location']['from_line']} - {f['location']['to_line']}</p>
                <p><strong>Language:</strong> {_esc(f['code'].get('language', ''))}</p>
              </div>
              <div class="detail-section">
                <h4>Explanation</h4>
                <p>{_esc(f.get('explanation', ''))}</p>
              </div>
              <div class="detail-section">
                <h4>Attack Path</h4>
                <p><strong>Entry:</strong> {_esc(ap.get('entry_point', ''))}</p>
                <p><strong>Impact:</strong> {_esc(ap.get('impact', ''))}</p>
                <p><strong>Likelihood:</strong> {_esc(ap.get('likelihood', ''))}</p>
                {"<ul>" + prereqs + "</ul>" if prereqs else ""}
              </div>
              <div class="detail-section">
                <h4>Remediation</h4>
                <p>{_esc(f.get('remediation', ''))}</p>
              </div>
            </div>
            <div class="code-block">
              <div class="code-header">
                <span>{_esc(f['code'].get('language', ''))}</span>
                <span>Line {f['location']['from_line']}</span>
              </div>
              <pre><code>{_esc(f['code'].get('snippet', ''))}</code></pre>
            </div>
          </div></td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AVAPT Report — {_esc(meta['scan_root'])}</title>
<style>
{_CSS}
</style>
</head>
<body>
<header>
  <div class="logo">
    <div class="logo-icon">A</div>
    <div class="logo-text">av<em>apt</em></div>
  </div>
  <div class="hdr-right">
    <span class="model-tag">{_esc(meta['ai_model'])}</span>
    <span class="risk-pill risk-{risk}">{risk}</span>
  </div>
</header>

<main>
  <div class="meta-strip">
    {_meta_item("Target",        meta['scan_root'])}
    {_meta_item("Timestamp",     meta['timestamp'])}
    {_meta_item("Files Scanned", meta['files_scanned'])}
    {_meta_item("Code Files",    meta['code_files'])}
    {_meta_item("Languages",     ', '.join(meta['languages']) or 'N/A')}
    {_meta_item("AI Model",      meta['ai_model'])}
    {_meta_item("Ollama URL",    meta['ollama_url'])}
    {_meta_item("Total Findings",total)}
  </div>

  <div class="cards">
    <div class="card cc"><div class="card-n">{summary['critical']}</div><div class="card-l">Critical</div></div>
    <div class="card ch"><div class="card-n">{summary['high']}</div><div class="card-l">High</div></div>
    <div class="card cm"><div class="card-n">{summary['medium']}</div><div class="card-l">Medium</div></div>
    <div class="card cl"><div class="card-n">{summary['low']}</div><div class="card-l">Low</div></div>
  </div>

  <div class="src-strip">
    <div class="ss"><span class="ss-n ss-ai">{src_counts.get('ai', 0)}</span>
      <span class="ss-lbl">AI Findings</span></div>
    <div class="ss"><span class="ss-n ss-dep">{src_counts.get('dependency', 0)}</span>
      <span class="ss-lbl">Dependency CVEs</span></div>
  </div>

  <section>
    <h2>Severity Distribution</h2>
    <div class="bar-chart">
      {_bar("Critical", summary['critical'], total, "crit")}
      {_bar("High",     summary['high'],     total, "high")}
      {_bar("Medium",   summary['medium'],   total, "med")}
      {_bar("Low",      summary['low'],      total, "low")}
    </div>
  </section>

  <section>
    <h2>Executive Summary</h2>
    <div class="summary-box">
      <p>Security assessment of <strong style="color:var(--accent)">{_esc(meta['scan_root'])}</strong>
      completed using <strong style="color:var(--ai)">{_esc(meta['ai_model'])}</strong> via Ollama.
      <strong>{meta['code_files']}</strong> code file(s)
      ({_esc(', '.join(meta['languages']) or 'unknown')}) were sent in full to the AI
      for semantic analysis — no regex patterns, pure AI reasoning.</p>
      <br>
      <p>Overall risk: <strong class="risk-pill risk-{risk}">{risk}</strong> &mdash;
      <strong>{total}</strong> findings
      (<span style="color:var(--c-crit)">{summary['critical']} critical</span>,
       <span style="color:var(--c-high)">{summary['high']} high</span>,
       <span style="color:var(--c-med)">{summary['medium']} medium</span>,
       <span style="color:var(--c-low)">{summary['low']} low</span>).
      {"Immediate remediation required before deployment." if risk in ("CRITICAL","HIGH")
       else "Review and address findings in priority order."}</p>
    </div>
  </section>

  <section>
    <h2>Detailed Findings</h2>
    <div class="filters">
      <button class="fb active" onclick="filterSev('all',this)">All ({total})</button>
      <button class="fb" onclick="filterSev('critical',this)">Critical ({summary['critical']})</button>
      <button class="fb" onclick="filterSev('high',this)">High ({summary['high']})</button>
      <button class="fb" onclick="filterSev('medium',this)">Medium ({summary['medium']})</button>
      <button class="fb" onclick="filterSev('low',this)">Low ({summary['low']})</button>
      <button class="fb fb-ai" onclick="filterSrc('ai',this)">AI Only</button>
      <button class="fb"       onclick="filterSrc('dependency',this)">Deps Only</button>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr>
          <th>Vulnerability</th><th>Severity</th><th>Score</th>
          <th>File</th><th>CWE</th><th>CVE</th>
          <th>Confidence</th><th>Source</th>
        </tr></thead>
        <tbody id="tbl">{rows}</tbody>
      </table>
    </div>
  </section>
</main>

<footer>
  <span>avapt v{_esc(VERSION)} &mdash; {_esc(meta['ai_model'])}</span>
  <span>{_esc(meta['timestamp'])}</span>
</footer>

<script>
{_JS}
</script>
</body>
</html>"""


def _meta_item(label: str, value) -> str:
    return (f'<div class="mi">'
            f'<span class="mi-l">{_esc(label)}</span>'
            f'<span class="mi-v">{_esc(value)}</span>'
            f'</div>')


# ── embedded CSS ──────────────────────────────────────────────────────────────
_CSS = """
:root {
  --bg:#0a0c10; --bg2:#0f1219; --bg3:#161b24;
  --border:#1e2533; --text:#c9d1e0; --muted:#5a6478;
  --accent:#00d4ff; --ai:#bf5fff;
  --c-crit:#ff2d55; --c-high:#ff6b35; --c-med:#ffd60a; --c-low:#30d158;
  --mono:'JetBrains Mono','Fira Code','Consolas',monospace;
  --ui: -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
}
* { box-sizing:border-box; margin:0; padding:0 }
body { background:var(--bg); color:var(--text); font-family:var(--ui);
       font-size:14px; line-height:1.6 }
header { background:var(--bg2); border-bottom:1px solid var(--border);
         padding:16px 36px; display:flex; align-items:center;
         justify-content:space-between; position:sticky; top:0; z-index:100 }
.logo { display:flex; align-items:center; gap:10px }
.logo-icon { width:34px; height:34px; background:var(--accent); border-radius:8px;
             display:flex; align-items:center; justify-content:center;
             font-size:17px; font-weight:800; color:#000; font-family:var(--mono) }
.logo-text { font-size:19px; font-weight:800; letter-spacing:-.5px }
.logo-text em { color:var(--accent); font-style:normal }
.hdr-right { display:flex; align-items:center; gap:14px; font-size:12px }
.model-tag { background:rgba(191,95,255,.12); border:1px solid rgba(191,95,255,.3);
             color:var(--ai); padding:4px 12px; border-radius:20px;
             font-family:var(--mono) }
.risk-pill { padding:5px 14px; border-radius:20px; font-size:11px;
             font-weight:700; letter-spacing:1px }
.risk-CRITICAL { background:rgba(255,45,85,.15);  color:var(--c-crit); border:1px solid var(--c-crit) }
.risk-HIGH     { background:rgba(255,107,53,.15); color:var(--c-high); border:1px solid var(--c-high) }
.risk-MEDIUM   { background:rgba(255,214,10,.15); color:var(--c-med);  border:1px solid var(--c-med)  }
.risk-LOW      { background:rgba(48,209,88,.15);  color:var(--c-low);  border:1px solid var(--c-low)  }
main { max-width:1380px; margin:0 auto; padding:36px }
h2 { font-size:18px; font-weight:700; margin-bottom:18px;
     border-left:3px solid var(--accent); padding-left:10px }
section { margin-bottom:44px }
.meta-strip { background:var(--bg2); border:1px solid var(--border);
              border-radius:10px; padding:18px 24px; display:flex;
              flex-wrap:wrap; gap:28px; margin-bottom:32px }
.mi { display:flex; flex-direction:column; gap:2px }
.mi-l { font-size:10px; color:var(--muted); text-transform:uppercase;
        letter-spacing:1px; font-weight:700 }
.mi-v { font-size:12px; font-family:var(--mono); color:var(--accent) }
.cards { display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin-bottom:32px }
.card { background:var(--bg2); border:1px solid var(--border);
        border-radius:10px; padding:22px 20px; position:relative; overflow:hidden }
.card::before { content:''; position:absolute; top:0; left:0; right:0; height:3px }
.cc::before{background:var(--c-crit)} .ch::before{background:var(--c-high)}
.cm::before{background:var(--c-med)}  .cl::before{background:var(--c-low)}
.card-n { font-size:44px; font-weight:800; line-height:1;
          margin-bottom:4px; font-family:var(--mono) }
.cc .card-n{color:var(--c-crit)} .ch .card-n{color:var(--c-high)}
.cm .card-n{color:var(--c-med)}  .cl .card-n{color:var(--c-low)}
.card-l { font-size:10px; font-weight:700; letter-spacing:1.5px;
          color:var(--muted); text-transform:uppercase }
.src-strip { display:flex; gap:16px; flex-wrap:wrap; margin-bottom:32px }
.ss { background:var(--bg2); border:1px solid var(--border); border-radius:8px;
      padding:10px 18px; display:flex; align-items:center; gap:10px }
.ss-n { font-size:22px; font-weight:800; font-family:var(--mono) }
.ss-ai{color:var(--ai)} .ss-dep{color:var(--c-med)}
.ss-lbl { font-size:11px; color:var(--muted) }
.bar-chart { display:flex; flex-direction:column; gap:10px }
.bar-row { display:flex; align-items:center; gap:10px }
.bar-label { width:72px; font-size:11px; font-weight:700; text-transform:uppercase;
             letter-spacing:1px; color:var(--muted) }
.bar-track { flex:1; height:18px; background:var(--bg3); border-radius:4px; overflow:hidden }
.bar-fill { height:100%; border-radius:4px }
.bar-count { width:28px; text-align:right; font-family:var(--mono);
             font-weight:700; font-size:12px }
.bc-crit{background:var(--c-crit);color:var(--c-crit)}
.bc-high{background:var(--c-high);color:var(--c-high)}
.bc-med{background:var(--c-med);color:var(--c-med)}
.bc-low{background:var(--c-low);color:var(--c-low)}
.filters { display:flex; gap:8px; flex-wrap:wrap; margin-bottom:16px }
.fb { padding:5px 14px; border-radius:20px; cursor:pointer; font-size:11px;
      font-weight:700; letter-spacing:1px; text-transform:uppercase;
      border:1px solid var(--border); background:var(--bg2); color:var(--muted);
      transition:all .15s }
.fb:hover { border-color:var(--accent); color:var(--accent) }
.fb.active { background:var(--accent); color:#000; border-color:var(--accent) }
.fb-ai { border-color:rgba(191,95,255,.35); color:var(--ai) }
.fb-ai.active { background:var(--ai); color:#000; border-color:var(--ai) }
.table-wrap { overflow-x:auto }
table { width:100%; border-collapse:collapse; font-size:13px }
thead tr { background:var(--bg3) }
th { padding:10px 14px; text-align:left; font-size:10px; font-weight:700;
     letter-spacing:1px; text-transform:uppercase; color:var(--muted);
     border-bottom:1px solid var(--border); white-space:nowrap }
.vuln-row { background:var(--bg2); cursor:pointer; transition:background .12s;
            border-bottom:1px solid var(--border) }
.vuln-row:hover { background:var(--bg3) }
td { padding:10px 14px; vertical-align:middle }
.filepath { font-family:var(--mono); font-size:11px; color:var(--accent);
            max-width:170px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap }
.mono { font-family:var(--mono); font-size:11px }
.score { font-family:var(--mono); font-weight:700 }
.conf { font-size:11px; text-transform:uppercase; letter-spacing:1px }
.sev-critical .score{color:var(--c-crit)} .sev-high .score{color:var(--c-high)}
.sev-medium   .score{color:var(--c-med)}  .sev-low  .score{color:var(--c-low)}
.badge { display:inline-block; padding:2px 9px; border-radius:12px;
         font-size:10px; font-weight:800; letter-spacing:1px; color:#000 }
.src-badge { font-size:11px; font-weight:700; font-family:var(--mono) }
.detail-row { display:none }
.detail-row.open { display:table-row }
.detail-inner { background:var(--bg3); border-bottom:1px solid var(--border); padding:22px }
.detail-grid { display:grid; grid-template-columns:1fr 1fr; gap:18px; margin-bottom:18px }
.detail-section h4 { font-size:10px; font-weight:700; letter-spacing:1.2px;
                     text-transform:uppercase; color:var(--accent); margin-bottom:8px;
                     padding-bottom:4px; border-bottom:1px solid var(--border) }
.detail-section p { font-size:13px; color:var(--text); margin-bottom:6px; line-height:1.6 }
.detail-section ul { padding-left:16px; margin-top:4px }
.detail-section li { font-size:12px; color:var(--muted); margin-bottom:2px }
.detail-section code { font-family:var(--mono); font-size:11px; background:var(--bg);
                       padding:1px 5px; border-radius:3px; border:1px solid var(--border);
                       display:inline-block; max-width:100%; overflow-wrap:break-word }
.code-block { background:#0d1117; border:1px solid var(--border);
              border-radius:8px; overflow:hidden; font-family:var(--mono); font-size:12px }
.code-header { background:var(--bg3); border-bottom:1px solid var(--border);
               padding:7px 14px; display:flex; justify-content:space-between;
               font-size:10px; color:var(--muted) }
pre { overflow-x:auto; padding:14px; line-height:1.75 }
code { color:#e2b96e; white-space:pre }
.summary-box { background:var(--bg2); border:1px solid var(--border);
               border-radius:10px; padding:22px 26px; line-height:1.8 }
footer { border-top:1px solid var(--border); padding:20px 36px;
         color:var(--muted); font-size:11px; display:flex; justify-content:space-between }
@media(max-width:768px){
  .cards{grid-template-columns:1fr 1fr}
  .detail-grid{grid-template-columns:1fr}
  main{padding:18px} header{padding:14px 18px}
}
"""

# ── embedded JS ───────────────────────────────────────────────────────────────
_JS = """
function toggle(id) {
  document.getElementById(id).classList.toggle('open');
}
function filterSev(sev, btn) {
  document.querySelectorAll('.fb').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.vuln-row').forEach(row => {
    const show = sev === 'all' || row.classList.contains('sev-' + sev);
    _setVisible(row, show);
  });
}
function filterSrc(src, btn) {
  document.querySelectorAll('.fb').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.vuln-row').forEach(row => {
    const badge = row.querySelector('.src-badge');
    const txt   = badge ? badge.textContent.trim().toLowerCase() : '';
    const show  = (src === 'ai' && txt === 'ai') ||
                  (src === 'dependency' && txt === 'dep');
    _setVisible(row, show);
  });
}
function _setVisible(row, show) {
  row.style.display = show ? '' : 'none';
  const detail = row.nextElementSibling;
  if (detail) {
    if (!show) { detail.classList.remove('open'); detail.style.display = 'none'; }
    else       { detail.style.display = ''; }
  }
}
"""
