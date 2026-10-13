function formatIST(dateString) {
  if (!dateString) return '—';
  try {
    let str = String(dateString).trim();
    if (/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?$/.test(str)) {
      str = str.replace(' ', 'T') + 'Z';
    }
    const d = new Date(str);
    if (isNaN(d.getTime())) return dateString;
    return d.toLocaleString('en-IN', {
      timeZone: 'Asia/Kolkata',
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      hour12: true
    });
  } catch (e) {
    return dateString;
  }
}

if (!requireAdmin()) {
  // requireAdmin redirects unauthorized users to the login page.
} else {
  initAdmin();
}

let globalStats = null;
let currentScansPage = 1;

async function initAdmin() {
  const user = getUserData();
  if (user.name) {
    document.getElementById('sidebar-name').textContent = user.name;
    document.getElementById('user-name-nav').textContent = `Admin: ${user.name.split(' ')[0]}`;
    document.getElementById('avatar-initials').textContent = user.name[0].toUpperCase();
  }
  await loadOverview();
}

function showSection(name) {
  ['overview', 'users', 'scans', 'analytics'].forEach(section => {
    document.getElementById('section-' + section).classList.toggle('hidden', section !== name);
  });
  document.querySelectorAll('.sidebar-link').forEach((btn, index) => {
    btn.classList.remove('active');
    if (['overview', 'users', 'scans', 'analytics'][index] === name) btn.classList.add('active');
  });
  if (name === 'users') loadUsers();
  if (name === 'scans') loadScans(1);
  if (name === 'analytics') renderAnalytics();
}

async function loadOverview() {
  try {
    const [dashRes, statsRes] = await Promise.all([
      API.get('/api/admin/dashboard'),
      API.get('/api/admin/stats')
    ]);
    const dash = await dashRes.json();
    const stats = await statsRes.json();
    if (dash.success && stats.success) {
      globalStats = stats.stats;
      renderOverview(dash.dashboard, stats.stats);
    }
  } catch (e) {
    showToast('Cannot connect to backend server', 'error');
  }
}

function renderOverview(dash, stats) {
  document.getElementById('stat-users').textContent = dash.total_users || 0;
  document.getElementById('stat-total-scans').textContent = dash.total_scans || 0;
  document.getElementById('stat-today').textContent = stats.scans_today || 0;
  document.getElementById('stat-threats-today').textContent = stats.threats_blocked_today || 0;

  const vd = stats.verdict_distribution || {};
  const dangerCount = (vd.DANGEROUS || 0) + (vd.PHISHING || 0) + (vd.SPAM || 0) + (vd.FAKE || 0);
  const warnCount = vd.SUSPICIOUS || 0;
  const safeCount = (vd.SAFE || 0) + (vd.LEGITIMATE || 0) + (vd.HAM || 0) + (vd.VALID || 0);
  

  const knownCount = dangerCount + warnCount + safeCount;
  const unknownCount = Math.max(0, (dash.total_scans || 0) - knownCount);
  
  renderDonut('chart-global-verdicts', {
    labels: ['Dangerous/Spam', 'Suspicious', 'Safe/Legitimate', 'Unknown'],
    data: [dangerCount, warnCount, safeCount, unknownCount],
    colors: ['#FF4757', '#FFA502', '#2ED573', '#94A3B8']
  });

  const td = stats.type_distribution || {};
  const sumTypes = (td.sms || 0) + (td.email_address || 0) + (td.email_comprehensive || 0) + (td.url || 0);
  const unknownType = Math.max(0, (dash.total_scans || 0) - sumTypes);
  
  renderDonut('chart-global-types', {
    labels: ['SMS', 'Email', 'Body', 'URL', 'Unknown'],
    data: [td.sms || 0, td.email_address || 0, td.email_comprehensive || 0, td.url || 0, unknownType],
    colors: ['#00D4FF', '#7B5EA7', '#FFA502', '#FF4757', '#94A3B8']
  });

  const daily = stats.daily_activity || {};
  const last30 = [];
  for (let i = 29; i >= 0; i--) {
    const date = new Date();
    date.setDate(date.getDate() - i);
    const key = date.toISOString().split('T')[0];
    last30.push({ label: date.toLocaleDateString('en', { month: 'short', day: 'numeric' }), val: daily[key] || 0 });
  }
  renderLine('chart-global-activity', { labels: last30.map(x => x.label), data: last30.map(x => x.val), label: 'Platform Scans' });

  renderHourlyBar('chart-hourly', stats.hourly_activity || {});

  const topUsers = stats.top_users || [];
  renderBar('chart-top-users', {
    labels: topUsers.map(user => ((user.name || 'User').split(' ')[0])),
    data: topUsers.map(user => user.scans),
    label: 'Scans',
    color: ['#00D4FF', '#7B5EA7', '#FFA502', '#FF4757', '#2ED573']
  });

  const domains = stats.top_flagged_domains || [];
  const domainsElement = document.getElementById('flagged-domains-list');
  if (domains.length) {
    domainsElement.innerHTML = domains.map((domain, index) => `
      <div class="evidence-item admin-domain-item">
        <span class="admin-domain-url">${index + 1}. ${domain.url.slice(0, 60)}${domain.url.length > 60 ? '...' : ''}</span>
        <span class="badge badge-dangerous">${domain.count} flag${domain.count > 1 ? 's' : ''}</span>
      </div>`).join('');
  } else {
    domainsElement.innerHTML = `<div class="empty-state"><p>No flagged domains yet</p></div>`;
  }

  renderAdminRecentTable(dash.recent_scans || []);
}

function renderAdminRecentTable(scans) {
  const wrap = document.getElementById('admin-recent-table');
  if (!scans.length) {
    wrap.innerHTML = `<div class="empty-state"><p>No scans yet</p></div>`;
    return;
  }
  const iconMap = { sms: 'SMS', email_address: 'EMAIL', email_comprehensive: 'BODY', url: 'URL' };
  const rows = scans.map(scan => {
    const verdict = scan.verdict || '';
    const className = ['DANGEROUS', 'PHISHING', 'SPAM'].includes(verdict) ? 'badge-dangerous' : verdict === 'SUSPICIOUS' ? 'badge-suspicious' : 'badge-safe';
    const date = formatIST(scan.created_at);
    return `<tr>
      <td data-label="Type"><span style="text-transform: uppercase; font-weight: bold;">${(iconMap[scan.scan_type] || scan.scan_type).replace('_', ' ')}</span></td>
      <td class="admin-table-content" data-label="Input"><span class="mobile-table-value">${scan.input_text}</span></td>
      <td data-label="Verdict"><span class="badge ${className}">${verdict}</span></td>
      <td class="admin-table-risk" data-label="Risk">${scan.risk_score || 0}/100</td>
      <td class="admin-table-date" data-label="Time">${date}</td>
      <td class="admin-table-user" data-label="User">${scan.user_id || 'Anonymous'}</td>
    </tr>`;
  }).join('');
  wrap.innerHTML = `<table class="admin-recent-scans-table"><thead><tr><th>Type</th><th>Input</th><th>Verdict</th><th>Risk</th><th>Time</th><th>User</th></tr></thead><tbody>${rows}</tbody></table>`;
}

async function loadUsers() {
  const wrap = document.getElementById('users-table');
  wrap.innerHTML = `<div class="empty-state"><p>Loading users...</p></div>`;
  try {
    const res = await API.get('/api/admin/users');
    const data = await res.json();
    if (!data.success) throw new Error(data.message);
    const users = data.users;
    if (!users.length) {
      wrap.innerHTML = `<div class="empty-state"><p>No users registered</p></div>`;
      return;
    }
    const rows = users.map(user => {
      const isDeleted = user.is_deleted;
      const roleBadge = user.role === 'admin'
        ? `<span class="badge admin-role-badge">Admin</span>`
        : `<span class="badge badge-safe">User</span>`;
      let status = user.is_active
        ? `<span class="badge badge-safe">Active</span>`
        : `<span class="badge badge-suspicious">Inactive</span>`;
      
      if (isDeleted) {
          status = `<span class="badge badge-dangerous">Deleted</span>`;
      }

      const joined = formatIST(user.created_at);
      const rowStyle = isDeleted ? 'style="opacity: 0.6; background-color: #f3f4f6;"' : '';
      
      let actionBtn = '<span class="text-muted admin-protected-label">Protected</span>';
      if (user.role !== 'admin') {
          if (isDeleted) {
              actionBtn = `<div class="user-actions">
                <button class="btn btn-success btn-sm" onclick="restoreUser('${user.id}', '${(user.name || 'User').replace(/'/g, "\\'")}')" title="Restore user account"><i class="fas fa-undo"></i> Restore</button>
              </div>`;
          } else {
              actionBtn = `<div class="user-actions">
                <button class="btn btn-outline btn-sm" onclick="toggleUser('${user.id}')">${user.is_active ? 'Deactivate' : 'Activate'}</button>
                <button class="btn btn-danger btn-sm" onclick="deleteUser('${user.id}', '${(user.name || 'User').replace(/'/g, "\\'")}')" title="Delete user account"><i class="fas fa-trash"></i></button>
              </div>`;
          }
      }

      return `<tr ${rowStyle}>
        <td data-label="Name"><strong style="${isDeleted ? 'text-decoration: line-through;' : ''}">${user.name}</strong></td>
        <td class="admin-table-email" data-label="Email">${user.email}</td>
        <td data-label="Role">${roleBadge}</td>
        <td data-label="Status">${status}</td>
        <td class="admin-table-number" data-label="Scans">${user.total_scans || 0}</td>
        <td class="admin-table-date" data-label="Joined">${joined}</td>
        <td data-label="Actions">${actionBtn}</td>
      </tr>`;
    }).join('');
    wrap.innerHTML = `<table class="admin-users-table"><thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Scans</th><th>Joined</th><th>Actions</th></tr></thead><tbody>${rows}</tbody></table>`;
  } catch (e) {
    wrap.innerHTML = `<div class="empty-state"><p>Error: ${e.message}</p></div>`;
  }
}

async function toggleUser(userId) {
  try {
    const res = await API.post(`/api/admin/user/${userId}/toggle`, {});
    const data = await res.json();
    if (data.success) {
      showToast(data.message, 'success');
      loadUsers();
    } else showToast(data.message, 'error');
  } catch {
    showToast('Failed to toggle user', 'error');
  }
}

async function deleteUser(userId, name) {
  if (!confirm(`Delete user "${name}"? You can restore this account later.`)) return;
  try {
    const res = await API.del(`/api/admin/user/${userId}`);
    const data = await res.json();
    if (data.success) {
      showToast('User deleted', 'success');
      loadUsers();
    } else showToast(data.message, 'error');
  } catch {
    showToast('Failed to delete user', 'error');
  }
}

async function restoreUser(userId, name) {
  if (!confirm(`Restore account for user "${name}"?`)) return;
  try {
    const res = await API.post(`/api/admin/user/${userId}/restore`, {});
    const data = await res.json();
    if (data.success) {
      showToast('User account restored successfully', 'success');
      loadUsers();
    } else showToast(data.message || 'Failed to restore user', 'error');
  } catch {
    showToast('Failed to restore user', 'error');
  }
}

async function loadScans(page = 1) {
  currentScansPage = page;
  const wrap = document.getElementById('all-scans-table');
  wrap.innerHTML = `<div class="empty-state"><p>Loading scans...</p></div>`;
  
  const search = document.getElementById('adminSearchUser') ? document.getElementById('adminSearchUser').value : '';
  const scanType = document.getElementById('adminScanType') ? document.getElementById('adminScanType').value : 'all';
  const start = document.getElementById('adminStartDate')?.value || '';
  const end = document.getElementById('adminEndDate')?.value || '';
  const params = new URLSearchParams({
    page: String(page),
    search,
    scan_type: scanType
  });
  if (start) params.set('start', start);
  if (end) params.set('end', end);
  
  try {
    const res = await API.get(`/api/admin/scans?${params.toString()}`);
    const data = await res.json();
    if (!data.success) throw new Error(data.message);
    const iconMap = { sms: 'SMS', email_address: 'EMAIL', email_comprehensive: 'BODY', url: 'URL' };
    const rows = data.scans.map((scan, index) => {
      const verdict = scan.verdict || '';
      const className = ['DANGEROUS', 'PHISHING', 'SPAM'].includes(verdict)
        ? 'badge-dangerous'
        : verdict === 'SUSPICIOUS' ? 'badge-suspicious' : 'badge-safe';
      const date = formatIST(scan.created_at);
      return `<tr>
        <td class="admin-table-index" data-label="#">${((page - 1) * 10) + index + 1}</td>
        <td data-label="Type"><span style="text-transform: uppercase; font-weight: bold;">${(iconMap[scan.scan_type] || scan.scan_type).replace('_', ' ')}</span></td>
        <td class="admin-table-content-small" data-label="Input" style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${(scan.input_text||'').replace(/""/g, '&quot;')}"><span class="mobile-table-value">${scan.input_text}</span></td>
        <td data-label="Verdict"><span class="badge ${className}">${verdict}</span></td>
        <td class="admin-table-risk" data-label="Risk">${scan.risk_score || 0}/100</td>
        <td class="admin-table-time" data-label="Time">${date}</td>
        <td class="admin-table-user" data-label="User">${scan.user_id || 'Anonymous'}</td>
      </tr>`;
    }).join('');

    wrap.innerHTML = `<table class="admin-scans-table"><thead><tr><th>Sr.No</th><th>Type</th><th>Input</th><th>Verdict</th><th>Risk</th><th>Time</th><th>User</th></tr></thead><tbody>${rows}</tbody></table>`;

    const pagination = document.getElementById('scans-pagination');
    pagination.style.display = 'block'; pagination.style.textAlign = 'center'; pagination.style.lineHeight = '2.5'; pagination.innerHTML = '';
    for (let i = 1; i <= data.pages; i++) {
      const button = document.createElement('button');
      button.className = `btn btn-sm ${i === page ? 'btn-primary' : 'btn-outline'}`;
      button.textContent = i;
      button.onclick = () => loadScans(i);
      button.style.margin = '4px'; pagination.appendChild(button); if (i % 10 === 0) { pagination.appendChild(document.createElement('br')); }
    }
  } catch (e) {
    wrap.innerHTML = `<div class="empty-state"><p>Error: ${e.message}</p></div>`;
  }
}

function renderAnalytics() {
  if (!globalStats) return;
  const daily = globalStats.daily_activity || {};
  const last30 = [];
  for (let i = 29; i >= 0; i--) {
    const date = new Date();
    date.setDate(date.getDate() - i);
    const key = date.toISOString().split('T')[0];
    last30.push({ label: date.toLocaleDateString('en', { month: 'short', day: 'numeric' }), val: daily[key] || 0 });
  }
  renderLine('chart-analytics-compare', { labels: last30.map(x => x.label), data: last30.map(x => x.val), label: 'Total Scans', color: '#00D4FF' });

  const dailyByType = globalStats.daily_by_type || {};
  const typeDistribution = globalStats.type_distribution || {};
  const scanTypes = [
    { key: 'sms', label: 'SMS', color: '#00D4FF' },
    { key: 'email_address', label: 'Email Address', color: '#7B5EA7' },
    { key: 'email_comprehensive', label: 'Email Comprehensive', color: '#FFA502' },
    { key: 'url', label: 'URL', color: '#FF4757' }
  ];
  renderMultiBar('chart-analytics-types', {
    labels: last30.map(x => x.label),
    datasets: scanTypes.map(type => ({
      label: type.label,
      color: type.color,
      data: last30.map((day, index) => {
        const date = new Date();
        date.setDate(date.getDate() - (29 - index));
        const key = date.toISOString().split('T')[0];
        const valuesForDay = dailyByType[key] || {};
        return valuesForDay[type.key]
          || valuesForDay[type.key.toUpperCase()]
          || valuesForDay[type.key.replace('_', '')]
          || 0;
      })
    }))
  });

  const trendChart = window.Chart && Chart.getChart('chart-analytics-types');
  const hasDailyTypeData = trendChart?.data.datasets.some(dataset => dataset.data.some(value => value > 0));
  if (!hasDailyTypeData && Object.keys(typeDistribution).length) {
    const fallbackData = scanTypes.map(type => (
      typeDistribution[type.key]
      || typeDistribution[type.key.toUpperCase()]
      || typeDistribution[type.key.replace('_', '')]
      || (type.key === 'sms' ? typeDistribution.message : 0)
      || 0
    ));
    trendChart.data.datasets.forEach((dataset, index) => {
      dataset.data = dataset.data.map((value, dayIndex) => dayIndex === dataset.data.length - 1 ? fallbackData[index] : value);
    });
    trendChart.update();
  }
}

// ── CSV Download ──
function adminDownloadCSV() {
  const token    = (typeof getToken === 'function' ? getToken() : null) || sessionStorage.getItem('Atoken') || localStorage.getItem('Atoken') || '';
  const scanType = document.getElementById('adminScanType')?.value || 'all';
  const search   = document.getElementById('adminSearchUser')?.value.trim() || '';
  const start    = document.getElementById('adminStartDate')?.value || '';
  const end      = document.getElementById('adminEndDate')?.value   || '';

  const params = new URLSearchParams();
  if (scanType && scanType !== 'all') params.set('scan_type', scanType);
  if (search)  params.set('search', search);
  if (start)   params.set('start', start);
  if (end)     params.set('end', end);

  const baseUrl = typeof API_BASE !== 'undefined' ? API_BASE : 'http://127.0.0.1:5000';

  fetch(`${baseUrl}/api/admin/export/csv?${params.toString()}`, {
    method: 'GET',
    headers: { 'Authorization': `Bearer ${token}` }
  })
  .then(res => {
    if (res.status === 401) {
      showToast('Session expired or unauthorized. Please log in again.', 'error');
      return;
    }
    if (!res.ok) { showToast('Export failed — please try again', 'error'); return; }
    const disposition = res.headers.get('Content-Disposition') || '';
    const match = disposition.match(/filename="?([^"]+)"?/);
    const filename = match ? match[1] : 'cybersentinel_admin_scans.csv';
    return res.blob().then(blob => ({ blob, filename }));
  })
  .then(data => {
    if (!data) return;
    const { blob, filename } = data;
    const url = URL.createObjectURL(blob);
    const a   = document.createElement('a');
    a.href     = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    showToast('CSV downloaded!', 'success');
  })
  .catch(() => showToast('Export failed — is the server running?', 'error'));
}
