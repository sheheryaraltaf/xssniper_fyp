// XSSniper Frontend JS — v3

/* ═══════════════════════════════════
   THEME  (Light / Dark)
═══════════════════════════════════ */
(function initTheme() {
  var saved = localStorage.getItem('xss-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', saved);
})();

function setTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  localStorage.setItem('xss-theme', t);
}
function toggleTheme() {
  setTheme(document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
}

/* ═══════════════════════════════════
   API Helper
═══════════════════════════════════ */
async function api(method, url, data = null) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (data) opts.body = JSON.stringify(data);
  const res = await fetch(url, opts);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Unknown error' }));
    throw new Error(err.detail || 'Request failed');
  }
  return res.json();
}

/* ═══════════════════════════════════
   Toast Notifications
═══════════════════════════════════ */
function toast(msg, type = 'info') {
  const palette = {
    success: { border: '#00ff88', color: '#00ff88', bg: '#020d07' },
    error:   { border: '#f43f5e', color: '#f43f5e', bg: '#0d0208' },
    info:    { border: '#22d3ee', color: '#22d3ee', bg: '#020a0d' },
    warning: { border: '#f59e0b', color: '#f59e0b', bg: '#0d0900' },
  };
  const p = palette[type] || palette.info;
  const icons = { success: '✓', error: '✗', info: 'ℹ', warning: '⚠' };
  const t = document.createElement('div');
  t.style.cssText = `position:fixed;bottom:24px;right:24px;z-index:9999;background:${p.bg};border:1px solid ${p.border};color:${p.color};padding:12px 20px;border-radius:10px;font-family:'JetBrains Mono',monospace;font-size:13px;box-shadow:0 8px 32px rgba(0,0,0,0.5),0 0 20px ${p.border}22;animation:slideUp 0.3s ease;max-width:360px;display:flex;align-items:center;gap:10px;`;
  t.innerHTML = `<span style="font-size:16px">${icons[type]}</span><span>${msg}</span>`;
  document.body.appendChild(t);
  setTimeout(() => { t.style.cssText += 'opacity:0;transform:translateY(8px);transition:all 0.3s;'; setTimeout(() => t.remove(), 300); }, 3500);
}

/* ═══════════════════════════════════
   Toggle Switches
═══════════════════════════════════ */
function initToggles() {
  document.querySelectorAll('.toggle').forEach(t => {
    t.addEventListener('click', () => {
      t.classList.toggle('on');
      const inp = document.getElementById(t.dataset.for);
      if (inp) inp.value = t.classList.contains('on') ? 'true' : 'false';
    });
  });
}

/* ═══════════════════════════════════
   Tabs
═══════════════════════════════════ */
function initTabs() {
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const g = btn.dataset.group;
      document.querySelectorAll(`.tab-btn[data-group="${g}"]`).forEach(b => b.classList.remove('active'));
      document.querySelectorAll(`.tab-panel[data-group="${g}"]`).forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById(btn.dataset.target)?.classList.add('active');
    });
  });
}

/* ═══════════════════════════════════
   Modal
═══════════════════════════════════ */
function openModal(id)  { document.getElementById(id)?.classList.add('open'); }
function closeModal(id) { document.getElementById(id)?.classList.remove('open'); }
document.addEventListener('click', e => {
  if (e.target.classList.contains('modal-overlay')) e.target.classList.remove('open');
});

/* ═══════════════════════════════════
   Password Show/Hide Toggle
═══════════════════════════════════ */
function togglePassword(inputId) {
  const inp  = document.getElementById(inputId);
  const icon = document.querySelector(`[data-eye="${inputId}"], [onclick*="togglePassword('${inputId}')"]`);
  if (!inp) return;
  if (inp.type === 'password') { inp.type = 'text';     if (icon) icon.textContent = '🙈'; }
  else                         { inp.type = 'password'; if (icon) icon.textContent = '👁'; }
}

/* ═══════════════════════════════════
   PASSWORD STRENGTH  (register page)
   Rules:
   1. Min 8 characters
   2. At least one uppercase letter
   3. At least one lowercase letter
   4. At least one number
   5. At least one special character
═══════════════════════════════════ */
function updateStrength(val) {
  const wrap = document.getElementById('pw-strength-wrap');
  if (!wrap) return;
  wrap.style.display = val.length > 0 ? 'block' : 'none';

  const rules = {
    len:     val.length >= 8,
    upper:   /[A-Z]/.test(val),
    lower:   /[a-z]/.test(val),
    num:     /[0-9]/.test(val),
    special: /[^A-Za-z0-9]/.test(val),
  };

  // Update rule indicators
  Object.entries(rules).forEach(([key, met]) => {
    const el = document.getElementById('rule-' + key);
    if (el) el.classList.toggle('met', met);
  });

  const score = Object.values(rules).filter(Boolean).length;
  const segs  = [document.getElementById('ps1'), document.getElementById('ps2'),
                 document.getElementById('ps3'), document.getElementById('ps4')];
  const label = document.getElementById('pw-label');

  const levels = [
    { cls: 's-weak',   text: 'Weak — too easy to guess',    color: '#f43f5e' },
    { cls: 's-weak',   text: 'Weak — add more variety',     color: '#f43f5e' },
    { cls: 's-fair',   text: 'Fair — getting better',       color: '#f59e0b' },
    { cls: 's-good',   text: 'Good — almost there',         color: '#22d3ee' },
    { cls: 's-strong', text: 'Strong — great password! ✓',  color: '#00ff88' },
  ];

  const lvl = levels[score] || levels[0];
  segs.forEach((s, i) => {
    if (!s) return;
    s.className = 'pw-seg';
    if (i < score) s.classList.add(lvl.cls);
  });
  if (label) { label.textContent = lvl.text; label.style.color = lvl.color; }

  // Also update input border
  const inp = document.getElementById('reg-pass');
  if (inp) {
    inp.classList.remove('input-error', 'input-ok');
    if (score >= 4) inp.classList.add('input-ok');
    else if (val.length > 0) inp.classList.add('input-error');
  }
}

/* ── Field validators for register form ── */
function validateUsername(inp) {
  const v   = inp.value.trim();
  const err = document.getElementById('err-username');
  const ok  = /^[a-zA-Z0-9_]{3,20}$/.test(v);
  inp.classList.toggle('input-ok',    ok && v.length > 0);
  inp.classList.toggle('input-error', !ok && v.length > 0);
  if (err) {
    if (v.length === 0)      { err.style.display = 'none'; }
    else if (v.length < 3)   { showErr(err, 'At least 3 characters required'); }
    else if (v.length > 20)  { showErr(err, 'Maximum 20 characters'); }
    else if (!/^[a-zA-Z0-9_]+$/.test(v)) { showErr(err, 'Only letters, numbers and underscores'); }
    else                     { err.style.display = 'none'; }
  }
}

function validateEmail(inp) {
  const v   = inp.value.trim();
  const err = document.getElementById('err-email');
  const ok  = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
  inp.classList.toggle('input-ok',    ok);
  inp.classList.toggle('input-error', !ok && v.length > 0);
  if (err) {
    if (!ok && v.length > 0) showErr(err, 'Enter a valid email address');
    else                     err.style.display = 'none';
  }
}

function validateConfirm(inp) {
  const pass = document.getElementById('reg-pass')?.value || '';
  const err  = document.getElementById('err-confirm');
  const ok   = inp.value === pass && inp.value.length > 0;
  inp.classList.toggle('input-ok',    ok);
  inp.classList.toggle('input-error', !ok && inp.value.length > 0);
  if (err) {
    if (inp.value.length > 0 && inp.value !== pass) showErr(err, 'Passwords do not match');
    else err.style.display = 'none';
  }
}

function showErr(el, msg) {
  el.textContent = '⚠ ' + msg;
  el.style.display = 'block';
}

/* ═══════════════════════════════════
   LOGIN
═══════════════════════════════════ */
async function doLogin(event) {
  event.preventDefault();
  const login    = document.getElementById('login-input').value.trim();
  const password = document.getElementById('login-pass').value;
  const errEl    = document.getElementById('login-error');
  const btn      = document.getElementById('login-btn');

  if (!login)    { showAuthErr(errEl, 'Please enter your email or username'); return; }
  if (!password) { showAuthErr(errEl, 'Please enter your password'); return; }

  errEl.style.display = 'none';
  btn.textContent = 'AUTHENTICATING...';
  btn.disabled = true;

  try {
    await api('POST', '/api/login', { login, password });
    btn.textContent = '✓ ACCESS GRANTED';
    btn.style.background = 'var(--g)';
    btn.style.color      = '#040e08';
    setTimeout(() => window.location.href = '/', 800);
  } catch (err) {
    showAuthErr(errEl, err.message);
    btn.textContent = 'LOGIN';
    btn.disabled = false;
    shakCard();
  }
}

/* ═══════════════════════════════════
   REGISTER
   Full client-side validation before sending to server
═══════════════════════════════════ */
async function doRegister(event) {
  event.preventDefault();
  const username = document.getElementById('reg-username').value.trim();
  const email    = document.getElementById('reg-email').value.trim();
  const password = document.getElementById('reg-pass').value;
  const confirm  = document.getElementById('reg-confirm').value;
  const errEl    = document.getElementById('reg-error');
  const sucEl    = document.getElementById('reg-success');
  const btn      = document.getElementById('reg-btn');

  errEl.style.display = 'none';
  sucEl.style.display = 'none';

  // ── Client-side validation ──────────────────────────────
  if (!username || username.length < 3)
    return showAuthErr(errEl, 'Username must be at least 3 characters');
  if (!/^[a-zA-Z0-9_]+$/.test(username))
    return showAuthErr(errEl, 'Username: only letters, numbers and underscores allowed');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return showAuthErr(errEl, 'Please enter a valid email address');

  // Password rules
  if (password.length < 8)
    return showAuthErr(errEl, 'Password must be at least 8 characters');
  if (!/[A-Z]/.test(password))
    return showAuthErr(errEl, 'Password needs at least one uppercase letter (A–Z)');
  if (!/[a-z]/.test(password))
    return showAuthErr(errEl, 'Password needs at least one lowercase letter (a–z)');
  if (!/[0-9]/.test(password))
    return showAuthErr(errEl, 'Password needs at least one number (0–9)');
  if (!/[^A-Za-z0-9]/.test(password))
    return showAuthErr(errEl, 'Password needs at least one special character (!@#$…)');
  if (password !== confirm)
    return showAuthErr(errEl, 'Passwords do not match');
  // ── End validation ──────────────────────────────────────

  btn.textContent = 'CREATING ACCOUNT...';
  btn.disabled = true;

  try {
    await api('POST', '/api/register', { username, email, password, confirm });
    sucEl.textContent  = '✓ Account created! Redirecting to login…';
    sucEl.style.display = 'block';
    setTimeout(() => window.location.href = '/login', 1500);
  } catch (err) {
    showAuthErr(errEl, err.message);
    btn.textContent = 'CREATE ACCOUNT';
    btn.disabled = false;
  }
}

function showAuthErr(el, msg) {
  el.textContent = '⚠ ' + msg;
  el.style.display = 'block';
  shakCard();
}

function shakCard() {
  const card = document.querySelector('.auth-card');
  if (!card) return;
  card.style.animation = 'none';
  requestAnimationFrame(() => { card.style.animation = 'shake 0.4s ease'; });
  setTimeout(() => card.style.animation = '', 400);
}

/* ═══════════════════════════════════
   SCANNER
═══════════════════════════════════ */
let currentScanId = null;
let scanEventSource = null;

async function startScan() {
  const url = document.getElementById('scan-url').value.trim();
  if (!url || !/^https?:\/\//i.test(url)) {
    toast('Enter a valid URL starting with http:// or https://', 'error'); return;
  }
  const config = {
    url,
    data:         document.getElementById('scan-data')?.value.trim() || '',
    json_mode:    document.getElementById('h-json')?.value === 'true',
    crawl:        document.getElementById('h-crawl')?.value === 'true',
    level:        parseInt(document.getElementById('scan-level')?.value || 2),
    threads:      parseInt(document.getElementById('scan-threads')?.value || 2),
    timeout:      parseInt(document.getElementById('scan-timeout')?.value || 5),
    delay:        parseFloat(document.getElementById('scan-delay')?.value || 0),
    fuzzer:       document.getElementById('h-fuzzer')?.value === 'true',
    encode:       document.getElementById('h-encode')?.value === 'true',
    path:         document.getElementById('h-path')?.value === 'true',
    file:         document.getElementById('scan-file')?.value.trim() || '',
    skip_dom:     document.getElementById('h-skipdom')?.value === 'true',
    headers:      document.getElementById('scan-headers')?.value.trim() || '',
    proxy:        document.getElementById('scan-proxy')?.value.trim() || '',
    ml_prefilter: document.getElementById('h-ml')?.value === 'true',
  };
  const terminal = document.getElementById('terminal-output');
  terminal.innerHTML = '';
  document.getElementById('start-btn').disabled  = true;
  document.getElementById('stop-btn').disabled   = false;
  document.getElementById('scan-url').disabled   = true;
  addLog(`[*] XSSniper Initialized`, 'dim');
  addLog(`[*] Target: ${url}`, 'dim');
  addLog(`[*] ${new Date().toLocaleString()}`, 'dim');
  addLog('[*] ' + '─'.repeat(60), 'dim');
  try {
    const { scan_id } = await api('POST', '/api/scan/start', config);
    currentScanId = scan_id;
    scanEventSource = new EventSource(`/api/scan/${scan_id}/stream`);
    scanEventSource.onmessage = e => {
      if (e.data.startsWith('__DONE__')) {
        const result = JSON.parse(e.data.replace('__DONE__', ''));
        scanEventSource.close();
        onScanDone(result);
      } else { addLog(e.data); }
    };
    scanEventSource.onerror = () => { scanEventSource.close(); addLog('[ERROR] Connection lost', 'red'); resetScanUI(); };
  } catch (err) { addLog(`[ERROR] ${err.message}`, 'red'); resetScanUI(); }
}

function addLog(msg, forceColor = null) {
  const terminal = document.getElementById('terminal-output');
  if (!terminal) return;
  const line = document.createElement('div');
  let cls = forceColor || 'default';
  if (!forceColor) {
    if (msg.includes('[ERROR]') || msg.toLowerCase().includes('failed')) cls = 'red';
    else if (msg.includes('[+]') || msg.includes('VULNERABILITY') || msg.includes('FOUND')) cls = 'green';
    else if (msg.includes('[ML]')) cls = 'cyan';
    else if (msg.includes('[WARN]')) cls = 'orange';
    else if (msg.includes('[*]')) cls = 'dim';
  }
  const colorMap = { green:'var(--green)',red:'var(--red)',cyan:'var(--cyan)',orange:'var(--o)',dim:'var(--td)',default:'#8fbc8f' };
  line.style.color = colorMap[cls] || colorMap.default;
  line.textContent = msg;
  terminal.appendChild(line);
  terminal.scrollTop = terminal.scrollHeight;
}

function onScanDone(result) {
  addLog('', 'dim');
  addLog('─'.repeat(60), 'dim');
  if (result.status === 'success') {
    addLog(`[✓] Scan completed! Vulnerabilities: ${result.vulnerabilities}`, 'green');
    addLog(`[✓] Duration: ${result.duration?.toFixed(2)}s`, 'green');
    toast(`Scan complete! Found ${result.vulnerabilities} vulnerabilities`, 'success');
  } else { addLog('[ERROR] Scan failed', 'red'); toast('Scan failed', 'error'); }
  resetScanUI();
}

function resetScanUI() {
  document.getElementById('start-btn').disabled  = false;
  document.getElementById('stop-btn').disabled   = true;
  document.getElementById('scan-url').disabled   = false;
}

async function stopScan() {
  if (scanEventSource) scanEventSource.close();
  try { await api('POST', '/api/scan/stop'); addLog('[!] Scan stopped by user', 'orange'); toast('Scan stopped', 'warning'); } catch(e) {}
  resetScanUI();
}

function updateSliderLabel(id, labelId) {
  const v = document.getElementById(id)?.value;
  const l = document.getElementById(labelId);
  if (l) l.textContent = v;
}

/* ═══════════════════════════════════
   HISTORY
═══════════════════════════════════ */
async function viewReport(scanId) {
  try {
    const d = await api('GET', `/api/scan-detail/${scanId}`);
    document.getElementById('modal-url').textContent      = d.url;
    document.getElementById('modal-date').textContent     = d.date;
    document.getElementById('modal-status').innerHTML     = `<span class="badge badge-${d.status==='Completed'?'green':'red'}">${d.status}</span>`;
    document.getElementById('modal-vulns').textContent    = d.vulnerabilities;
    document.getElementById('modal-duration').textContent = d.duration ? d.duration.toFixed(2)+'s' : 'N/A';
    const logEl = document.getElementById('modal-log');
    logEl.innerHTML = '';
    (d.log_output || 'No log available').split('\n').forEach(line => {
      if (!line.trim()) return;
      const el = document.createElement('div');
      let c = '#8fbc8f';
      if (line.includes('[+]') || line.includes('VULNERABILITY')) c = 'var(--green)';
      else if (line.includes('[ERROR]')) c = 'var(--red)';
      else if (line.includes('[ML]'))   c = 'var(--cyan)';
      else if (line.includes('[WARN]')) c = 'var(--o)';
      else if (line.includes('[*]'))    c = 'var(--td)';
      el.style.color = c; el.textContent = line;
      logEl.appendChild(el);
    });
    document.getElementById('export-csv-btn').onclick = () => exportCSV(scanId);
    openModal('report-modal');
  } catch (err) { toast('Failed to load report', 'error'); }
}

function exportCSV(scanId) { window.location.href = `/api/export/csv/${scanId}`; toast('Downloading CSV…', 'success'); }

/* ═══════════════════════════════════
   ADMIN
═══════════════════════════════════ */
async function deleteUser(userId, username) {
  if (!confirm(`Delete user "${username}"? This cannot be undone.`)) return;
  try {
    await api('DELETE', `/api/admin/users/${userId}`);
    toast(`User ${username} deleted`, 'success');
    document.getElementById(`user-row-${userId}`)?.remove();
  } catch (err) { toast(err.message, 'error'); }
}

/* ═══════════════════════════════════
   SIDEBAR (desktop collapse + mobile drawer)
═══════════════════════════════════ */
var _isMobile = () => window.innerWidth <= 768;
var _sbCollapsed = false;
var _sbDrawerOpen = false;

function _initSidebar() {
  if (localStorage.getItem('sbCollapsed') === '1') {
    _sbCollapsed = true;
    document.getElementById('app-shell')?.classList.add('sb-collapsed');
    document.getElementById('sidebar-toggle-btn')?.classList.add('is-open');
  }
}

function toggleSidebar() {
  _isMobile() ? (_sbDrawerOpen ? _closeMobileDrawer() : _openMobileDrawer()) : _toggleDesktopCollapse();
}

function _toggleDesktopCollapse() {
  _sbCollapsed = !_sbCollapsed;
  document.getElementById('app-shell')?.classList.toggle('sb-collapsed', _sbCollapsed);
  document.getElementById('sidebar-toggle-btn')?.classList.toggle('is-open', _sbCollapsed);
  localStorage.setItem('sbCollapsed', _sbCollapsed ? '1' : '0');
}

function _openMobileDrawer() {
  document.getElementById('sidebar')?.classList.add('sidebar-open');
  document.getElementById('sidebar-overlay')?.classList.add('overlay-open');
  document.body.style.overflow = 'hidden';
  _sbDrawerOpen = true;
}

function closeSidebar() { _closeMobileDrawer(); }
function _closeMobileDrawer() {
  document.getElementById('sidebar')?.classList.remove('sidebar-open');
  document.getElementById('sidebar-overlay')?.classList.remove('overlay-open');
  document.body.style.overflow = '';
  _sbDrawerOpen = false;
}

function onNavClick() { if (_isMobile()) _closeMobileDrawer(); }
window.addEventListener('resize', () => { if (!_isMobile()) _closeMobileDrawer(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape') _closeMobileDrawer(); });

/* ═══════════════════════════════════
   CLOCK
═══════════════════════════════════ */
function _startClock() {
  const tick = () => {
    const el = document.getElementById('topbar-time');
    if (el) el.textContent = new Date().toLocaleTimeString('en-US', { hour12: false });
    setTimeout(tick, 1000);
  };
  tick();
}

/* ═══════════════════════════════════
   DOMContentLoaded
═══════════════════════════════════ */
document.addEventListener('DOMContentLoaded', () => {
  initToggles();
  initTabs();
  _initSidebar();
  _startClock();

  // Add keyframes
  const style = document.createElement('style');
  style.textContent = `
    @keyframes shake { 0%,100%{transform:translateX(0)} 20%{transform:translateX(-8px)} 40%{transform:translateX(8px)} 60%{transform:translateX(-5px)} 80%{transform:translateX(5px)} }
    @keyframes slideUp { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:translateY(0)} }
  `;
  document.head.appendChild(style);

  // Enter key on login password field
  document.getElementById('login-pass')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') doLogin(e);
  });
});
