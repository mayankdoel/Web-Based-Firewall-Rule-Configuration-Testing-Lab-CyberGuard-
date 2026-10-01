/**
 * CyberGuard Firewall Lab — Phase 2 Frontend
 * All state is now loaded from the Flask REST API.
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
};

const API_BASE = '';   // Same origin when served via Flask

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
  initRefreshBtn();
  await loadAll();
});

// ==========================================
// 3. API helpers
// ==========================================
async function apiFetch(path, options = {}) {
  const defaults = { headers: { 'Content-Type': 'application/json' } };
  const res = await fetch(API_BASE + path, { ...defaults, ...options });
  const json = await res.json().catch(() => ({ success: false, error: 'Invalid response' }));
  return { ok: res.ok, status: res.status, data: json };
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
    APP_STATE.policies       = data.policies;
    updateFirewallToggleUI();
    updateLabModeBadge(data.lab_mode, data.dry_run);
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

  setEl('metric-total-rules',    rules.length);
  setEl('metric-blocked-sources', rules.filter(r =>
    (r.action === 'DROP' || r.action === 'REJECT') && r.src_ip !== '0.0.0.0/0').length);
  setEl('metric-allowed-ports',   rules.filter(r =>
    r.action === 'ACCEPT' && r.dst_port !== 'any').length);
  setEl('sidebar-rule-count',    rules.length);

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

  // Pulse dot
  const dot = document.getElementById('header-pulse-dot');
  if (dot) dot.style.background = active ? 'var(--accent-green, #22c55e)' : 'var(--accent-red, #ef4444)';
}

function renderRulesTable() {
  const tbody       = document.getElementById('rules-table-body');
  if (!tbody) return;
  const chainFilter  = document.getElementById('rule-chain-filter')?.value  || 'ALL';
  const actionFilter = document.getElementById('rule-action-filter')?.value || 'ALL';
  const searchTerm   = (document.getElementById('rule-search-input')?.value || '').toLowerCase();

  let filtered = APP_STATE.rules.filter(r => {
    if (chainFilter  !== 'ALL' && r.chain  !== chainFilter)  return false;
    if (actionFilter !== 'ALL' && r.action !== actionFilter) return false;
    if (searchTerm) {
      const blob = `${r.src_ip} ${r.dst_ip} ${r.chain} ${r.protocol} ${r.dst_port} ${r.action}`.toLowerCase();
      if (!blob.includes(searchTerm)) return false;
    }
    return true;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = '<tr><td colspan="12" style="text-align:center;color:var(--text-muted,#6b7280);padding:24px;">No rules match the current filter.</td></tr>';
    return;
  }

  tbody.innerHTML = filtered.map(r => {
    const actionClass = 'action-' + r.action.toLowerCase();
    const statusDot   = r.status === 'ACTIVE' ? '●' : '○';
    // Handle both simple index.html and advanced templates/index.html table column counts
    const statusCol = document.querySelector('th:nth-child(11)')
      ? `<td style="color: var(--accent-green, #22c55e); font-family: monospace;">${statusDot} ${esc(r.status)}</td>`
      : '';
    return `<tr>
      <td>#${r.id}</td>
      <td>${esc(r.chain)}</td>
      <td>${esc(r.protocol)}</td>
      <td>${esc(r.src_ip)}</td>
      <td>${esc(r.dst_ip)}</td>
      <td>${esc(r.src_port)}</td>
      <td>${esc(r.dst_port)}</td>
      <td class="${actionClass}">${esc(r.action)}</td>
      <td>${Number(r.packets).toLocaleString()}</td>
      <td>${r.bytes}</td>
      ${statusCol}
      <td>
        <button class="btn btn-sm" onclick="prefillTest(${r.id})" title="Prefill Packet Tester">▶</button>
        <button class="btn btn-sm" onclick="confirmDelete(${r.id})" title="Delete Rule" style="color:var(--red,#dc2626);">✕</button>
      </td>
    </tr>`;
  }).join('');
}

function renderLogs() {
  const container = document.getElementById('activity-log-stream');
  if (!container) return;
  if (APP_STATE.logs.length === 0) {
    container.innerHTML = '<div style="color:var(--text-muted,#6b7280);text-align:center;padding:12px;">No logs yet.</div>';
    return;
  }
  container.innerHTML = APP_STATE.logs.map(l =>
    `<div class="log-item"><span style="color:var(--blue,#2563eb);">[${esc(l.created_at || '')}]</span> <strong>${esc(l.tag)}</strong> ${esc(l.message)}</div>`
  ).join('');
}

// ==========================================
// 6. Add Rule Modal
// ==========================================
function initAddRuleModal() {
  const modal     = document.getElementById('modal-add-rule');
  const openBtn   = document.getElementById('btn-open-add-modal');
  const closeBtn  = document.getElementById('modal-add-close');
  const cancelBtn = document.getElementById('modal-add-cancel');
  const form      = document.getElementById('form-add-rule');
  if (!modal || !form) return;

  const open  = () => { modal.style.display = 'flex'; updateCmdPreview(); };
  const close = () => { modal.style.display = 'none'; form.reset(); };

  openBtn?.addEventListener('click', open);
  closeBtn?.addEventListener('click', close);
  cancelBtn?.addEventListener('click', close);
  modal.addEventListener('click', e => { if (e.target === modal) close(); });

  ['rule-chain','rule-proto','rule-src','rule-dst','rule-sport','rule-dport','rule-action'].forEach(id => {
    const el = document.getElementById(id);
    if (el) { el.addEventListener('input', updateCmdPreview); el.addEventListener('change', updateCmdPreview); }
  });

  form.addEventListener('submit', async e => {
    e.preventDefault();
    const payload = {
      chain:    document.getElementById('rule-chain').value,
      protocol: document.getElementById('rule-proto').value,
      src_ip:   document.getElementById('rule-src').value.trim()   || '0.0.0.0/0',
      dst_ip:   document.getElementById('rule-dst').value.trim()   || '0.0.0.0/0',
      src_port: document.getElementById('rule-sport').value.trim() || 'any',
      dst_port: document.getElementById('rule-dport').value.trim() || 'any',
      action:   document.getElementById('rule-action').value,
    };

    const submitBtn = form.querySelector('[type=submit]');
    if (submitBtn) { submitBtn.disabled = true; submitBtn.textContent = 'Saving…'; }

    const { ok, data } = await apiFetch('/api/rules', {
      method: 'POST', body: JSON.stringify(payload)
    });

    if (submitBtn) { submitBtn.disabled = false; submitBtn.textContent = 'Add Rule'; }

    if (ok && data.success) {
      APP_STATE.rules.push(data.rule);
      close();
      renderMetrics();
      renderRulesTable();
      await loadLogs();
      renderLogs();
      showAlert(`✓ Rule #${data.rule.id} added successfully!`, 'success');
    } else {
      showAlert('✕ Error: ' + (data.error || 'Could not add rule'), 'danger');
    }
  });
}

function updateCmdPreview() {
  const chain  = document.getElementById('rule-chain')?.value  || 'INPUT';
  const proto  = document.getElementById('rule-proto')?.value  || 'TCP';
  const src    = document.getElementById('rule-src')?.value.trim();
  const dst    = document.getElementById('rule-dst')?.value.trim();
  const sport  = document.getElementById('rule-sport')?.value.trim();
  const dport  = document.getElementById('rule-dport')?.value.trim();
  const action = document.getElementById('rule-action')?.value || 'DROP';

  let parts = ['iptables', '-A', chain];
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
    confirm.disabled = true; confirm.textContent = 'Deleting…';

    const { ok, data } = await apiFetch(`/api/rules/${deleteTarget}`, { method: 'DELETE' });

    confirm.disabled = false; confirm.textContent = 'Delete';
    if (ok && data.success) {
      APP_STATE.rules = APP_STATE.rules.filter(r => r.id !== deleteTarget);
      close();
      renderMetrics();
      renderRulesTable();
      await loadLogs();
      renderLogs();
      showAlert(`Rule #${data.deleted_id} deleted`, 'danger');
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
  const toggleBtn   = document.getElementById('btn-toggle-firewall');
  const disableModal = document.getElementById('modal-disable-confirm');
  const cancelBtn   = document.getElementById('btn-cancel-disable');
  const confirmBtn  = document.getElementById('btn-confirm-disable');
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
    body: JSON.stringify({ active: newState })
  });
  if (ok && data.success) {
    APP_STATE.firewallActive = data.firewall_active;
    updateFirewallToggleUI();
    renderMetrics();
    await loadLogs();
    renderLogs();
    showAlert(
      data.firewall_active ? '🟢 Firewall ACTIVATED' : '🔴 Firewall DISABLED — all traffic passing',
      data.firewall_active ? 'success' : 'danger'
    );
  }
}

function updateFirewallToggleUI() {
  const toggleBtn = document.getElementById('btn-toggle-firewall');
  if (!toggleBtn) return;
  if (APP_STATE.firewallActive) {
    toggleBtn.textContent = 'Disable Firewall';
    toggleBtn.className = toggleBtn.className.replace('btn-success', '').trim();
  } else {
    toggleBtn.textContent = 'Enable Firewall';
    if (!toggleBtn.className.includes('btn-success')) toggleBtn.className += ' btn-success';
  }
}

function updateLabModeBadge(labMode, dryRun) {
  const labTag    = document.querySelector('.lab-tag');
  const sysTag    = document.querySelector('.system-tag');
  if (labTag) labTag.textContent = labMode ? 'LAB MODE' : 'LIVE MODE';
  if (sysTag) sysTag.textContent = dryRun ? 'DRY-RUN' : 'KERNEL EXEC';
}

// ==========================================
// 9. Refresh Button
// ==========================================
function initRefreshBtn() {
  const btn = document.getElementById('btn-refresh-rules');
  if (!btn) return;
  btn.addEventListener('click', async () => {
    btn.disabled = true;
    await loadAll();
    btn.disabled = false;
    showAlert('✓ Synced from database', 'success');
  });
}

// ==========================================
// 10. Packet Tester — now calls /api/simulate
// ==========================================
function initTestSimulator() {
  const form = document.getElementById('form-packet-test');
  if (!form) return;

  form.addEventListener('submit', async e => {
    e.preventDefault();
    const srcIp  = document.getElementById('test-src-ip').value.trim();
    const dstIp  = document.getElementById('test-dst-ip').value.trim();
    const proto  = document.getElementById('test-protocol').value;
    const dport  = document.getElementById('test-dst-port').value.trim();
    const chain  = document.getElementById('test-chain').value;

    const submitBtn = form.querySelector('[type=submit]');
    if (submitBtn) { submitBtn.disabled = true; submitBtn.textContent = '⏳ Simulating…'; }

    const { ok, data } = await apiFetch('/api/simulate', {
      method: 'POST',
      body: JSON.stringify({ src_ip: srcIp, dst_ip: dstIp, protocol: proto, dst_port: dport || 'any', chain })
    });

    if (submitBtn) { submitBtn.disabled = false; submitBtn.textContent = '▶ Run Simulation'; }

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
    text.textContent = '✓ ALLOW';
  } else {
    box.className = 'verdict-display verdict-block';
    text.textContent = '✕ BLOCK';
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
  const src   = document.getElementById('test-src-ip');
  const proto = document.getElementById('test-protocol');
  const dport = document.getElementById('test-dst-port');
  const chain = document.getElementById('test-chain');

  if (rule.src_ip === '0.0.0.0/0') src.value = '192.168.1.50';
  else if (rule.src_ip.includes('/')) src.value = rule.src_ip.split('/')[0].replace(/\.0$/, '.10');
  else src.value = rule.src_ip;

  if (rule.protocol !== 'ALL') proto.value = rule.protocol;
  dport.value = rule.dst_port !== 'any' ? rule.dst_port : '80';
  if (chain) chain.value = rule.chain;

  document.getElementById('form-packet-test')?.scrollIntoView({ behavior: 'smooth' });
};

// ==========================================
// 11. Activity Log
// ==========================================
function initActivityLog() {
  document.getElementById('btn-clear-logs')?.addEventListener('click', async () => {
    await apiFetch('/api/logs', { method: 'DELETE' });
    APP_STATE.logs = [];
    renderLogs();
    showAlert('Logs cleared', 'success');
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
// 13. Sidebar navigation (advanced template)
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
// 14. Alert
// ==========================================
function showAlert(msg, type) {
  const el = document.getElementById('alert-box');
  if (!el) return;
  el.textContent = msg;
  el.className = 'alert alert-' + (type === 'danger' ? 'danger' : 'success');
  el.style.display = 'block';
  setTimeout(() => { el.style.display = 'none'; }, 3500);
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
  if (el) { el.value = val; updateCmdPreview(); }
};
window.setDestPreset = function(val) {
  const el = document.getElementById('rule-dst');
  if (el) { el.value = val; updateCmdPreview(); }
};
window.setDportPreset = function(val) {
  const el = document.getElementById('rule-dport');
  if (el) { el.value = val; updateCmdPreview(); }
};

