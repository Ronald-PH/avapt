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
    const show  = (src === 'ai'  && txt === 'ai') ||
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
