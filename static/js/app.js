let currentJobId = null;
let pollTimer    = null;
let modelTimer   = null;

// ── scan ─────────────────────────────────────────────────────────────────────
async function startScan() {
  const target     = document.getElementById('target').value.trim();
  const prompt     = document.getElementById('prompt').value.trim();
  const model      = document.getElementById('model').value;
  const ollama_url = document.getElementById('ollama_url').value.trim();
  const workers    = document.getElementById('workers').value;

  if (!target) {
    alert('Please enter a target path.');
    return;
  }

  if (!prompt) {
    alert('Please enter a prompt.');
    return;
  }

  setScanning(true);
  showProgress('Starting scan…', 0, 0);

  const body = new FormData();
  body.append('prompt',     prompt);
  body.append('target',     target);
  body.append('model',      model);
  body.append('ollama_url', ollama_url);
  body.append('workers',    workers);

  try {
    const res  = await fetch('/scan', { method:'POST', body });
    const data = await res.json();
    if (data.error) {
      showError(data.error);
      setScanning(false);
      return;
    }
    currentJobId = data.job_id;
    pollTimer = setInterval(pollJob, 1200);
  } catch (e) {
    showError('Failed to start scan: ' + e.message);
    setScanning(false);
  }
}

async function pollJob() {
  if (!currentJobId) return;
  try {
    const res  = await fetch(`/job/${currentJobId}`);
    const data = await res.json();
    const p    = data.progress;

    if (p.total > 0) {
      const pct = Math.round(p.done / p.total * 100);
      updateProgress(p.done, p.total, p.current_file, pct);
    }

    if (data.status === 'done') {
      clearInterval(pollTimer);
      window.location.href = `/report/${currentJobId}`;
    } else if (data.status === 'error') {
      clearInterval(pollTimer);
      showError(data.error || 'Scan failed.');
      setScanning(false);
    }
  } catch (e) {
    console.error('Poll error:', e);
  }
}

// ── progress UI ───────────────────────────────────────────────────────────────
function showProgress(title, done, total) {
  document.getElementById('progress-card').classList.remove('hidden');
  document.getElementById('progress-title').textContent = title;
  document.getElementById('progress-counts').textContent =
    total > 0 ? `${done} / ${total}` : '';
  document.getElementById('progress-file').textContent = '';
  document.getElementById('progress-fill').style.width = '0%';
}

function updateProgress(done, total, filename, pct) {
  document.getElementById('progress-title').textContent = 'Scanning…';
  document.getElementById('progress-counts').textContent = `${done} / ${total} files`;
  document.getElementById('progress-file').textContent  = filename || '';
  document.getElementById('progress-fill').style.width  = pct + '%';
}

function showError(msg) {
  document.getElementById('progress-title').textContent = 'Error';
  document.getElementById('progress-file').textContent  = msg;
  document.getElementById('progress-fill').style.width  = '100%';
  document.getElementById('progress-fill').style.background = 'var(--c-crit)';
}

function setScanning(active) {
  document.getElementById('btn-scan').disabled = active;
  document.getElementById('btn-label').textContent = active ? 'Scanning…' : 'Run AI Scan';
}

// ── model loader ──────────────────────────────────────────────────────────────
function debounceLoadModels() {
  clearTimeout(modelTimer);
  modelTimer = setTimeout(loadModels, 800);
}

async function loadModels() {
  const url  = document.getElementById('ollama_url').value.trim();
  const sel  = document.getElementById('model');
  const stat = document.getElementById('model-status');
  stat.textContent = 'Loading…';
  try {
    const res  = await fetch(`/api/models?url=${encodeURIComponent(url)}`);
    const data = await res.json();
    if (!data.available || !data.models.length) {
      stat.textContent = 'Ollama not reachable at this URL';
      return;
    }
    const prev = sel.value;
    sel.innerHTML = data.models
      .map(m => `<option value="${m}" ${m===prev?'selected':''}>${m}</option>`)
      .join('');
    stat.textContent = `${data.models.length} model(s) available`;
  } catch (e) {
    stat.textContent = 'Could not load models';
  }
}

// ── jobs list ─────────────────────────────────────────────────────────────────
async function loadJobs() {
  try {
    const res  = await fetch('/api/jobs');
    const data = await res.json();
    const ids  = Object.keys(data);
    if (!ids.length) return;

    document.getElementById('jobs-card').style.display = '';
    const tbody = document.getElementById('jobs-body');
    tbody.innerHTML = ids.map(id => {
      const j   = data[id];
      const cls = `status-${j.status}`;
      return `<tr>
        <td class="mono" style="font-size:11px">${id.slice(0,8)}…</td>
        <td class="${cls}">${j.status}</td>
        <td>${j.findings}</td>
        <td style="font-size:11px;color:var(--muted)">${j.started.slice(0,19).replace('T',' ')}</td>
        <td>
          ${j.status==='done'
            ? `<a href="/report/${id}" class="btn-sm">View</a>`
            : `<span class="btn-sm">—</span>`}
        </td>
      </tr>`;
    }).join('');
  } catch(_) {}
}

document.addEventListener('DOMContentLoaded', () => {
  loadJobs();
  setInterval(loadJobs, 8000);
});
