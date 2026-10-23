/**
 * CyberGuard Firewall Lab — Phase 2 Frontend
 * All state is loaded from the Flask REST API.
 * In-memory APP_STATE is used as a local cache.
 */

// ==========================================
// 1. State Cache
// ==========================================
const APP_STATE = {
  firewallActive: true,
  labMode: true,
  policies: { INPUT: 'DROP', OUTPUT: 'ACCEPT', FORWARD: 'DROP' },
  rules: [],
  logs: [],
  liveCounters: {},
  firewallLive: false,
};

const API_BASE = '';   // Same origin when served via Flask
const API_TOKEN = window.CYBERGUARD_API_TOKEN || '';

// ==========================================
// 2. Init
// ==========================================
document.addEventListener('DOMContentLoaded', async () => {
  initNav();
  initAddRuleModal();
  initDeleteModal();
  initTestSimulator();
  initActivityLog();
  initFilters();
  initFirewallToggle();
  document.getElementById('btn-confirm-firewall')?.addEventListener('click', confirmFirewallRules);
  initRefreshBtn();
  await loadAll();
  refreshLiveCounters();
  window.setInterval(refreshLiveCounters, 3000);
});

// ==========================================
// 3. API helpers
// ==========================================
async function apiFetch(path, options = {}) {
  const mergedOptions = {
    method: options.method || 'GET',
    headers: { 'Content-Type': 'application/json', 'X-API-Token': API_TOKEN, ...(options.headers || {}) },
  };
  if (options.body) mergedOptions.body = options.body;

  try {
    const res = await fetch(API_BASE + path, mergedOptions);
    const json = await res.json().catch(() => ({ success: false, error: 'Invalid JSON response' }));
    return { ok: res.ok, status: res.status, data: json };
  } catch (err) {
    return { ok: false, status: 0, data: { success: false, error: 'Network error: ' + err.message } };
  }
}

// ==========================================
// 4. Load everything from API
// ==========================================
async function loadAll() {
  await Promise.all([loadStatus(), loadRules(), loadLogs()]);
  renderMetrics();
  renderRulesTable();
  renderLogs();
}

async function loadStatus() {
  const { ok, data } = await apiFetch('/api/firewall/status');
  if (ok && data.success) {
    APP_STATE.firewallActive = data.firewall_active;
    APP_STATE.labMode        = data.lab_mode;
    APP_STATE.firewallLive   = Boolean(data.live);
    APP_STATE.policies       = data.policies;
    updateFirewallToggleUI();
    updateLabModeBadge(data.lab_mode, data.dry_run);
    setRollbackBanner(Boolean(data.rollback_pending));
  }
}

async function loadRules() {
  const { ok, data } = await apiFetch('/api/rules');
  if (ok && data.success) {
    APP_STATE.rules = data.rules;
  }
}

async function loadLogs() {
  const { ok, data } = await apiFetch('/api/logs?limit=100');
  if (ok && data.success) {
    APP_STATE.logs = data.logs;
  }
}

async function refreshLiveCounters() {
  if (!APP_STATE.firewallLive) return;
  const { ok, data } = await apiFetch('/api/live/counters');
  if (!ok || !data || typeof data !== 'object') return;
  APP_STATE.liveCounters = data;
  renderRulesTable();
}

function formatBytes(bytes) {
  const value = Number(bytes) || 0;
  if (value < 1024) return `${value} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let size = value / 1024;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit += 1; }
  return `${size.toFixed(1)} ${units[unit]}`;
}

function setRollbackBanner(visible) {
  const banner = document.getElementById('rollback-banner');
  if (banner) banner.hidden = !visible;
}

// ==========================================
// 5. Render
// ==========================================
function renderMetrics() {
  const active = APP_STATE.firewallActive;
  const rules  = APP_STATE.rules.filter(r => r.status === 'ACTIVE');

  const statusEl = document.getElementById('metric-status');
  if (statusEl) {
    statusEl.textContent = active ? 'ACTIVE' : 'INACTIVE';
    statusEl.style.color = active ? 'var(--green)' : 'var(--red)';
  }
  const headerStatus = document.getElementById('firewall-status-text') ||
                       document.getElementById('header-status-badge');
  if (headerStatus) {
    headerStatus.textContent = active ? '● ACTIVE' : '○ INACTIVE';
    headerStatus.style.color = active ? 'var(--green,#15803d)' : 'var(--red,#dc2626)';
  }

  setEl('metric-total-rules',     rules.length);
  setEl('metric-blocked-sources', rules.filter(r =>
    (r.action === 'DROP' || r.action === 'REJECT') && r.src_ip !== '0.0.0.0/0').length);
  setEl('metric-allowed-ports',   rules.filter(r =>
    r.action === 'ACCEPT' && r.dst_port !== 'any').length);
  setEl('sidebar-rule-count',     rules.length);

  const setPolicy = (id, val) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = val;
    el.className = el.className.replace(/target-\w+|tag-\w+/g, '').trim();
    el.classList.add(val === 'ACCEPT' ? 'target-accept' : 'target-drop');
    el.classList.add(val === 'ACCEPT' ? 'tag-accept'    : 'tag-drop');
  };
  setPolicy('pol-input',   APP_STATE.policies.INPUT);
  setPolicy('pol-output',  APP_STATE.policies.OUTPUT);
  setPolicy('pol-forward', APP_STATE.policies.FORWARD);

  // Pulse dot colour
  const dot = document.getElementById('header-pulse-dot');
  if (dot) dot.style.background = active ? 'var(--accent-green, #16a34a)' : 'var(--accent-red, #dc2626)';
}

function buildRuleRows(filtered) {
  if (filtered.length === 0) {
    return '<tr><td colspan="12" style="text-align:center;color:var(--text-muted);padding:24px 0;font-size:0.85rem;">No rules match the current filter.</td></tr>';
  }
  return filtered.map(r => {
    const counters = APP_STATE.liveCounters[String(r.id)];
    const actionClass = 'action-' + r.action.toLowerCase();
    const statusDot   = r.status === 'ACTIVE' ? '●' : '○';
    const statusColor = r.status === 'ACTIVE' ? 'var(--accent-green)' : 'var(--text-muted)';
    return `<tr>
      <td style="color:var(--text-muted);font-size:0.75rem;">#${r.id}</td>
      <td><span class="chain-badge chain-${r.chain.toLowerCase()}">${esc(r.chain)}</span></td>
      <td>${esc(r.protocol)}</td>
      <td>${esc(r.src_ip)}</td>
      <td>${esc(r.dst_ip)}</td>
      <td>${esc(r.src_port)}</td>
      <td>${esc(r.dst_port)}</td>
      <td class="${actionClass}">${esc(r.action)}</td>
      <td>${Number(counters ? counters.packets : r.packets).toLocaleString()}</td>
      <td>${esc(counters ? formatBytes(counters.bytes) : r.bytes)}</td>
      <td style="color:${statusColor};font-family:monospace;">${statusDot} ${esc(r.status)}</td>
      <td>
        <button class="btn btn-sm btn-icon" onclick="prefillTest(${r.id})" title="Prefill Packet Tester">▶</button>
        <button class="btn btn-sm btn-icon btn-icon-danger" onclick="confirmDelete(${r.id})" title="Delete Rule">✕</button>
      </td>
    </tr>`;
  }).join('');
}

function renderRulesTable() {
  const chainFilter  = document.getElementById('rule-chain-filter')?.value  || 'ALL';
  const actionFilter = document.getElementById('rule-action-filter')?.value || 'ALL';
  const searchTerm   = (document.getElementById('rule-search-input')?.value || '').toLowerCase();

  const filtered = APP_STATE.rules.filter(r => {
    if (chainFilter  !== 'ALL' && r.chain  !== chainFilter)  return false;
    if (actionFilter !== 'ALL' && r.action !== actionFilter) return false;
    if (searchTerm) {
      const blob = `${r.src_ip} ${r.dst_ip} ${r.chain} ${r.protocol} ${r.dst_port} ${r.src_port} ${r.action}`.toLowerCase();
      if (!blob.includes(searchTerm)) return false;
    }
    return true;
  });

  const html = buildRuleRows(filtered);

  // Populate dashboard quick-view table
  const tbody = document.getElementById('rules-table-body');
  if (tbody) tbody.innerHTML = html;

  // Populate the dedicated Firewall Rules section table
  const tbodyFull = document.getElementById('rules-table-body-full');
  if (tbodyFull) tbodyFull.innerHTML = html;
}

function renderLogs() {
  const container = document.getElementById('activity-log-stream');
  if (!container) return;
  if (APP_STATE.logs.length === 0) {
    container.innerHTML = '<div style="color:var(--text-muted);text-align:center;padding:20px;font-size:0.85rem;">No activity logs yet.</div>';
    return;
  }
  const tagColors = {
    RULE_ADD:    '#16a34a',
    RULE_DELETE: '#dc2626',
    TEST:        '#2563eb',
    STATUS:      '#d97706',
    SYNC:        '#0891b2',
    DELETE:      '#dc2626',
  };
  container.innerHTML = APP_STATE.logs.map(l => {
    const tagColor = tagColors[l.tag] || '#4f46e5';
    const resultBg =
      (l.result === 'SUCCESS' || l.result === 'ALLOW')   ? 'rgba(22,163,74,0.1)'  :
      (l.result === 'BLOCK'   || l.result === 'BLOCKED') ? 'rgba(220,38,38,0.1)'  :
      'rgba(0,0,0,0.04)';
    const resultColor =
      (l.result === 'SUCCESS' || l.result === 'ALLOW')   ? '#16a34a' :
      (l.result === 'BLOCK'   || l.result === 'BLOCKED') ? '#dc2626' :
      '#94a3b8';
    return `<div class="log-item">
      <span class="log-ts">[${esc(l.created_at || '')}]</span>
      <span class="log-tag" style="color:${tagColor};">${esc(l.tag)}</span>
      <span class="log-msg">${esc(l.message)}</span>
      <span class="log-result" style="background:${resultBg};color:${resultColor};">${esc(l.result)}</span>
    </div>`;
  }).join('');
  container.scrollTop = 0;
}

// ==========================================
// 6. Add Rule Modal
// ==========================================
// --- Client-side validation helpers ---
function isValidIpOrCidr(s) {
  if (!s || s === 'any' || s === '0.0.0.0/0') return true;
  if (s.includes('/')) {
    const [ip, prefix] = s.split('/');
    const pfx = parseInt(prefix, 10);
    return isValidIp(ip) && !isNaN(pfx) && pfx >= 0 && pfx <= 32;
  }
  return isValidIp(s);
}
function isValidIp(s) {
  const parts = s.split('.');
  if (parts.length !== 4) return false;
  return parts.every(p => /^\d{1,3}$/.test(p) && parseInt(p, 10) >= 0 && parseInt(p, 10) <= 255);
}
function isValidPort(s) {
  if (!s || s === 'any') return true;
  return /^\d+$/.test(s) && parseInt(s, 10) >= 1 && parseInt(s, 10) <= 65535;
}

function setFieldError(id, msg) {
  const el = document.getElementById(id);
  if (!el) return;
  el.style.borderColor = msg ? '#dc2626' : '';
  el.style.boxShadow   = msg ? '0 0 0 3px rgba(220,38,38,0.12)' : '';
  let hint = el.parentElement.querySelector('.field-error-hint');
  if (msg) {
    if (!hint) { hint = document.createElement('div'); hint.className = 'field-error-hint'; el.parentElement.appendChild(hint); }
    hint.textContent = msg;
    hint.style.cssText = 'color:#dc2626;font-size:0.72rem;margin-top:3px;';
  } else {
    hint?.remove();
  }
}

function clearFieldErrors() {
  ['rule-src','rule-dst','rule-sport','rule-dport'].forEach(id => setFieldError(id, ''));
}

function validateRuleForm(payload) {
  let valid = true;
  clearFieldErrors();

  if (!isValidIpOrCidr(payload.src_ip)) {
    setFieldError('rule-src', `Invalid IP/CIDR: "${payload.src_ip}". Use format 192.168.1.0 or 10.0.0.0/24`);
    valid = false;
  }
  if (!isValidIpOrCidr(payload.dst_ip)) {
    setFieldError('rule-dst', `Invalid IP/CIDR: "${payload.dst_ip}". Use format 192.168.1.0 or 0.0.0.0/0`);
    valid = false;
  }
  if (!isValidPort(payload.src_port)) {
    setFieldError('rule-sport', `Invalid port "${payload.src_port}". Must be 1-65535 or blank.`);
    valid = false;
  }
  if (!isValidPort(payload.dst_port)) {
    setFieldError('rule-dport', `Invalid port "${payload.dst_port}". Must be 1-65535 or blank.`);
    valid = false;
  }
  return valid;
}

function initAddRuleModal() {
  const modal     = document.getElementById('modal-add-rule');
  const openBtn   = document.getElementById('btn-open-add-modal');
  const closeBtn  = document.getElementById('modal-add-close');
  const cancelBtn = document.getElementById('modal-add-cancel');
  const form      = document.getElementById('form-add-rule');
  if (!modal || !form) return;

  const open = () => {
    modal.style.display = 'flex';
    clearFieldErrors();
    updateCmdPreview();
  };
  const close = () => {
    modal.style.display = 'none';
    form.reset();
    clearFieldErrors();
    updateCmdPreview();
  };

  openBtn?.addEventListener('click', open);
  closeBtn?.addEventListener('click', close);
  cancelBtn?.addEventListener('click', close);
  modal.addEventListener('click', e => { if (e.target === modal) close(); });

  ['rule-chain','rule-proto','rule-src','rule-dst','rule-sport','rule-dport','rule-action'].forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.addEventListener('input',  updateCmdPreview);
      el.addEventListener('change', updateCmdPreview);
      el.addEventListener('input',  () => setFieldError(id, '')); // clear error on type
    }
  });

  const submitBtn = form.querySelector('[type=submit]');
  const submitOrigHTML = submitBtn ? submitBtn.innerHTML : '';

  form.addEventListener('submit', async e => {
    e.preventDefault();
    const payload = {
      chain:    document.getElementById('rule-chain').value,
      protocol: document.getElementById('rule-proto').value,
      src_ip:   (document.getElementById('rule-src').value.trim()   || '0.0.0.0/0'),
      dst_ip:   (document.getElementById('rule-dst').value.trim()   || '0.0.0.0/0'),
      src_port: (document.getElementById('rule-sport').value.trim() || 'any'),
      dst_port: (document.getElementById('rule-dport').value.trim() || 'any'),
      action:   document.getElementById('rule-action').value,
    };

    // Client-side validation first
    if (!validateRuleForm(payload)) {
      showAlert('✕ Please fix the highlighted fields before saving.', 'danger');
      return;
    }

    if (submitBtn) { submitBtn.disabled = true; submitBtn.innerHTML = '<span style="opacity:.7">⏳ Saving…</span>'; }

    const { ok, data } = await apiFetch('/api/rules', {
      method: 'POST',
      body: JSON.stringify(payload),
    });

    if (submitBtn) { submitBtn.disabled = false; submitBtn.innerHTML = submitOrigHTML; }

    if (ok && data.success) {
      // Reload from DB so IDs and all fields are correct
      await loadRules();
      await loadLogs();
      close();
      renderMetrics();
      renderRulesTable();
      renderLogs();
      showAlert(`✓ Rule #${data.rule.id} added — ${data.rule.chain} ${data.rule.protocol} → ${data.rule.action}`, 'success');
    } else {
      const errMsg = data.error || 'Could not add rule';
      showAlert('✕ ' + errMsg, 'danger');
      // Try to highlight the relevant field
      if (errMsg.toLowerCase().includes('source ip') || errMsg.toLowerCase().includes('src_ip')) setFieldError('rule-src', errMsg);
      else if (errMsg.toLowerCase().includes('destination ip') || errMsg.toLowerCase().includes('dst_ip')) setFieldError('rule-dst', errMsg);
      else if (errMsg.toLowerCase().includes('source port')) setFieldError('rule-sport', errMsg);
      else if (errMsg.toLowerCase().includes('destination port')) setFieldError('rule-dport', errMsg);
    }
  });
}

function updateCmdPreview() {
  const chain  = document.getElementById('rule-chain')?.value  || 'INPUT';
  const proto  = document.getElementById('rule-proto')?.value  || 'TCP';
  const src    = document.getElementById('rule-src')?.value.trim()   || '';
  const dst    = document.getElementById('rule-dst')?.value.trim()   || '';
  const sport  = document.getElementById('rule-sport')?.value.trim() || '';
  const dport  = document.getElementById('rule-dport')?.value.trim() || '';
  const action = document.getElementById('rule-action')?.value || 'DROP';

  const parts = ['iptables', '-A', chain];
  if (proto !== 'ALL') parts.push('-p', proto.toLowerCase());
  if (src && src !== '0.0.0.0/0') parts.push('-s', src);
  if (dst && dst !== '0.0.0.0/0') parts.push('-d', dst);
  if (sport && (proto === 'TCP' || proto === 'UDP')) parts.push('--sport', sport);
  if (dport && (proto === 'TCP' || proto === 'UDP')) parts.push('--dport', dport);
  parts.push('-j', action);

  const el = document.getElementById('iptables-cmd-preview');
  if (el) el.textContent = parts.join(' ');
}

// ==========================================
// 7. Delete Modal
// ==========================================
let deleteTarget = null;

window.confirmDelete = function(id) {
  const rule = APP_STATE.rules.find(r => r.id === id);
  if (!rule) return;
  deleteTarget = id;
  const details = document.getElementById('delete-rule-details');
  if (details) details.textContent =
    `Rule #${rule.id} [${rule.chain} ${rule.protocol} ${rule.src_ip} → ${rule.dst_ip}:${rule.dst_port} (${rule.action})]`;
  const modal = document.getElementById('modal-delete-confirm');
  if (modal) modal.style.display = 'flex';
};

function initDeleteModal() {
  const modal   = document.getElementById('modal-delete-confirm');
  const cancel  = document.getElementById('btn-cancel-delete');
  const confirm = document.getElementById('btn-confirm-delete');
  if (!modal) return;

  const close = () => { modal.style.display = 'none'; deleteTarget = null; };
  cancel?.addEventListener('click', close);
  confirm?.addEventListener('click', async () => {
    if (deleteTarget === null) return;
    const origHTML = confirm.innerHTML;
    confirm.disabled = true; confirm.innerHTML = '⏳ Deleting…';

    const { ok, data } = await apiFetch(`/api/rules/${deleteTarget}`, { method: 'DELETE' });

    confirm.disabled = false; confirm.innerHTML = origHTML;
    if (ok && data.success) {
      APP_STATE.rules = APP_STATE.rules.filter(r => r.id !== deleteTarget);
      close();
      await loadLogs();
      renderMetrics();
      renderRulesTable();
      renderLogs();
      showAlert(`🗑 Rule #${data.deleted_id} deleted successfully`, 'danger');
    } else {
      showAlert('✕ Error deleting rule: ' + (data.error || 'Unknown error'), 'danger');
      close();
    }
  });
}

// ==========================================
// 8. Firewall Toggle
// ==========================================
function initFirewallToggle() {
  const toggleBtn    = document.getElementById('btn-toggle-firewall');
  const disableModal = document.getElementById('modal-disable-confirm');
  const cancelBtn    = document.getElementById('btn-cancel-disable');
  const confirmBtn   = document.getElementById('btn-confirm-disable');
  if (!toggleBtn) return;

  toggleBtn.addEventListener('click', () => {
    if (APP_STATE.firewallActive) {
      if (disableModal) { disableModal.style.display = 'flex'; }
      else { performFirewallToggle(false); }
    } else {
      performFirewallToggle(true);
    }
  });

  cancelBtn?.addEventListener('click', () => { if (disableModal) disableModal.style.display = 'none'; });
  confirmBtn?.addEventListener('click', () => {
    if (disableModal) disableModal.style.display = 'none';
    performFirewallToggle(false);
  });
}

async function performFirewallToggle(newState) {
  const { ok, data } = await apiFetch('/api/firewall/toggle', {
    method: 'POST',
    body: JSON.stringify({ active: newState }),
  });
  if (ok && data.success) {
    APP_STATE.firewallActive = data.firewall_active;
    updateFirewallToggleUI();
    renderMetrics();
    await loadLogs();
    renderLogs();
      if (data.firewall_active && data.rollback_seconds) setRollbackBanner(true);
      else setRollbackBanner(false);
    showAlert(
      data.firewall_active ? '🟢 Firewall ACTIVATED — kernel filtering enforced' : '🔴 Firewall DISABLED — all traffic passing',
      data.firewall_active ? 'success' : 'danger'
    );
  } else {
    showAlert('✕ Firewall update failed: ' + (data.error || 'Unknown error'), 'danger');
  }
}

async function confirmFirewallRules() {
  const { ok, data } = await apiFetch('/api/firewall/confirm', { method: 'POST', body: '{}' });
  if (ok && data.success) {
    setRollbackBanner(false);
    showAlert(data.confirmed ? '✓ Firewall rules confirmed' : 'No pending rollback to confirm', 'success');
    await loadStatus();
  } else {
    showAlert('✕ Could not confirm firewall rules: ' + (data.error || 'Unknown error'), 'danger');
  }
}

function updateFirewallToggleUI() {
  const toggleBtn = document.getElementById('btn-toggle-firewall');
  if (!toggleBtn) return;
  if (APP_STATE.firewallActive) {
    toggleBtn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18.36 6.64a9 9 0 1 1-12.73 0"></path><line x1="12" y1="2" x2="12" y2="12"></line></svg> Disable Firewall`;
    toggleBtn.className = toggleBtn.className.replace('btn-success', 'btn-danger').replace(/\s+/g, ' ').trim();
    if (!toggleBtn.className.includes('btn-danger')) toggleBtn.className += ' btn-danger';
  } else {
    toggleBtn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18.36 6.64a9 9 0 1 1-12.73 0"></path><line x1="12" y1="2" x2="12" y2="12"></line></svg> Enable Firewall`;
    toggleBtn.className = toggleBtn.className.replace('btn-danger', 'btn-success').replace(/\s+/g, ' ').trim();
    if (!toggleBtn.className.includes('btn-success')) toggleBtn.className += ' btn-success';
  }
}

function updateLabModeBadge(labMode, dryRun) {
  const labTag = document.querySelector('.lab-tag');
  const sysTag = document.querySelector('.system-tag');
  if (labTag) labTag.textContent = labMode ? 'LAB MODE' : 'LIVE MODE';
  if (sysTag) sysTag.textContent = dryRun ? 'DRY-RUN' : 'KERNEL EXEC';
}

// ==========================================
// 9. Refresh Button
// ==========================================
function initRefreshBtn() {
  const btn = document.getElementById('btn-refresh-rules');
  if (!btn) return;
  const origHTML = btn.innerHTML;
  btn.addEventListener('click', async () => {
    btn.disabled = true; btn.innerHTML = '⏳ Syncing…';
    await loadAll();
    btn.disabled = false; btn.innerHTML = origHTML;
    showAlert('✓ Synced from database', 'success');
  });
}

// ==========================================
// 10. Packet Tester — calls /api/simulate
// ==========================================
function initTestSimulator() {
  const form = document.getElementById('form-packet-test');
  if (!form) return;

  form.addEventListener('submit', async e => {
    e.preventDefault();
    const srcIp  = document.getElementById('test-src-ip')?.value.trim()   || '';
    const dstIp  = document.getElementById('test-dst-ip')?.value.trim()   || '';
    const proto  = document.getElementById('test-protocol')?.value         || 'TCP';
    const dport  = document.getElementById('test-dst-port')?.value.trim() || 'any';
    const chain  = document.getElementById('test-chain')?.value            || 'INPUT';

    if (!isValidIp(srcIp)) { showAlert('✕ Invalid Source IP address', 'danger'); return; }
    if (!isValidIp(dstIp)) { showAlert('✕ Invalid Destination IP address', 'danger'); return; }
    if (!isValidPort(dport) && dport !== 'any') { showAlert('✕ Invalid destination port', 'danger'); return; }

    const submitBtn = form.querySelector('[type=submit]');
    const origHTML  = submitBtn ? submitBtn.innerHTML : '';
    if (submitBtn) { submitBtn.disabled = true; submitBtn.innerHTML = '⏳ Simulating…'; }

    const { ok, data } = await apiFetch('/api/simulate', {
      method: 'POST',
      body: JSON.stringify({ src_ip: srcIp, dst_ip: dstIp, protocol: proto, dst_port: dport, chain }),
    });

    if (submitBtn) { submitBtn.disabled = false; submitBtn.innerHTML = origHTML; }

    if (ok && data.success) {
      displayResult(data);
      await loadLogs();
      renderLogs();
    } else {
      showAlert('✕ Simulation error: ' + (data.error || 'Unknown error'), 'danger');
    }
  });
}

function displayResult(result) {
  const box         = document.getElementById('test-verdict-box');
  const text        = document.getElementById('test-verdict-text');
  const explanation = document.getElementById('test-explanation-text');
  const matchCard   = document.getElementById('test-matched-rule-card');
  const matchSpecs  = document.getElementById('test-matched-rule-specs');
  if (!box) return;

  if (result.verdict === 'ALLOW') {
    box.className = 'verdict-display verdict-allow';
    if (text) text.textContent = '✓ ALLOW';
  } else {
    box.className = 'verdict-display verdict-block';
    if (text) text.textContent = '✕ BLOCK';
  }
  if (explanation) explanation.textContent = result.explanation || '';
  if (matchCard) {
    matchCard.style.display = 'block';
    if (matchSpecs) {
      if (result.matched_rule) {
        const r = result.matched_rule;
        matchSpecs.textContent = `Rule #${r.id} | ${r.chain} | ${r.protocol} | ${r.src_ip} → ${r.dst_ip}:${r.dst_port} | ${r.action}`;
      } else {
        matchSpecs.textContent = 'No rule matched — default chain policy applied.';
      }
    }
  }
}

window.prefillTest = function(id) {
  const rule = APP_STATE.rules.find(r => r.id === id);
  if (!rule) return;

  // Navigate to tester section first
  document.querySelectorAll('.nav-item[data-target]').forEach(n => n.classList.remove('active'));
  document.querySelectorAll('.dashboard-section').forEach(s => s.classList.remove('active'));
  const testerNav = document.querySelector('.nav-item[data-target="sec-tester"]');
  if (testerNav) testerNav.classList.add('active');
  document.getElementById('sec-tester')?.classList.add('active');
  const titleEl = document.getElementById('header-title');
  if (titleEl) titleEl.textContent = 'Packet Tester';

  // Fill in form fields
  const src   = document.getElementById('test-src-ip');
  const proto = document.getElementById('test-protocol');
  const dport = document.getElementById('test-dst-port');
  const chain = document.getElementById('test-chain');

  if (src) {
    if (rule.src_ip === '0.0.0.0/0') src.value = '192.168.1.50';
    else if (rule.src_ip.includes('/')) src.value = rule.src_ip.split('/')[0].replace(/\.0$/, '.10');
    else src.value = rule.src_ip;
  }
  if (proto && rule.protocol !== 'ALL') proto.value = rule.protocol;
  if (dport) dport.value = rule.dst_port !== 'any' ? rule.dst_port : '80';
  if (chain) chain.value = rule.chain;

  document.getElementById('form-packet-test')?.scrollIntoView({ behavior: 'smooth' });
};

// ==========================================
// 11. Activity Log
// ==========================================
function initActivityLog() {
  document.getElementById('btn-clear-logs')?.addEventListener('click', async () => {
    const { ok } = await apiFetch('/api/logs', { method: 'DELETE' });
    if (ok) {
      APP_STATE.logs = [];
      renderLogs();
      showAlert('✓ Logs cleared', 'success');
    }
  });

  document.getElementById('btn-export-logs')?.addEventListener('click', () => {
    window.open(API_BASE + '/api/logs/export', '_blank');
  });
}

// ==========================================
// 12. Filters & Search
// ==========================================
function initFilters() {
  document.getElementById('rule-chain-filter')?.addEventListener('change',  renderRulesTable);
  document.getElementById('rule-action-filter')?.addEventListener('change', renderRulesTable);
  document.getElementById('rule-search-input')?.addEventListener('input',   renderRulesTable);
}

// ==========================================
// 13. Sidebar navigation
// ==========================================
function initNav() {
  const navItems = document.querySelectorAll('.nav-item[data-target]');
  const sections = document.querySelectorAll('.dashboard-section');
  const titleEl  = document.getElementById('header-title');
  const titleMap = {
    'sec-dashboard': 'Firewall Lab Dashboard',
    'sec-rules':     'Firewall Rules',
    'sec-tester':    'Packet Tester',
    'sec-logs':      'Activity Log',
    'sec-topology':  'Lab Topology',
  };
  navItems.forEach(item => {
    item.addEventListener('click', () => {
      const target = item.dataset.target;
      navItems.forEach(n => n.classList.remove('active'));
      item.classList.add('active');
      sections.forEach(s => s.classList.remove('active'));
      document.getElementById(target)?.classList.add('active');
      if (titleEl && titleMap[target]) titleEl.textContent = titleMap[target];
    });
  });
}

// ==========================================
// 14. Toast / Alert
// ==========================================
function showAlert(msg, type) {
  const el = document.getElementById('alert-box');
  if (!el) return;
  el.textContent = msg;
  el.className = 'alert alert-' + (type === 'danger' ? 'danger' : 'success');
  el.style.display = 'block';
  // Auto-hide after 4 seconds
  clearTimeout(el._timer);
  el._timer = setTimeout(() => { el.style.display = 'none'; }, 4000);
}

// ==========================================
// 15. Helpers
// ==========================================
function setEl(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function esc(s) {
  if (typeof s !== 'string') return String(s ?? '');
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// Preset chip helpers (called from inline onclick in templates/index.html)
window.setSourcePreset = function(val) {
  const el = document.getElementById('rule-src');
  if (el) { el.value = val; setFieldError('rule-src', ''); updateCmdPreview(); }
};
window.setDestPreset = function(val) {
  const el = document.getElementById('rule-dst');
  if (el) { el.value = val; setFieldError('rule-dst', ''); updateCmdPreview(); }
};
window.setDportPreset = function(val) {
  const el = document.getElementById('rule-dport');
  if (el) { el.value = val; setFieldError('rule-dport', ''); updateCmdPreview(); }
};
