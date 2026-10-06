/**
 * Cyber Sentinel - Dashboard Operations & Visualizations
 */

const DashboardView = {
  trendChartInstance: null,
  severityChartInstance: null,

  async loadData() {
    try {
      const analytics = await App.apiRequest('/api/analytics');
      this.updateKPIs(analytics);
      this.renderTrendChart(analytics.daily_trends || []);
      this.renderSeverityChart(analytics.risk_level_distribution || {});
      this.renderRecentTable(analytics.recent_activity || []);
    } catch (err) {
      console.error('Failed to load dashboard data:', err);
    }
  },

  updateKPIs(data) {
    document.getElementById('kpiTotalScans').innerText = data.total_scans || 0;
    document.getElementById('kpiSafeScans').innerText = data.safe_scans || 0;
    document.getElementById('kpiSuspiciousScans').innerText = data.suspicious_scans || 0;
    document.getElementById('kpiMaliciousScans').innerText = data.malicious_scans || 0;
  },

  renderTrendChart(dailyTrends) {
    const ctx = document.getElementById('dashboardTrendChart');
    if (!ctx) return;

    if (this.trendChartInstance) {
      this.trendChartInstance.destroy();
    }

    const labels = dailyTrends.map(d => d.date);
    const safeData = dailyTrends.map(d => d.safe);
    const susData = dailyTrends.map(d => d.suspicious);
    const malData = dailyTrends.map(d => d.malicious);

    this.trendChartInstance = new Chart(ctx, {
      type: 'line',
      data: {
        labels: labels.length ? labels : ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
        datasets: [
          {
            label: 'Safe',
            data: safeData.length ? safeData : [0, 0, 0, 0, 0, 0, 0],
            borderColor: '#10b981',
            backgroundColor: 'rgba(16, 185, 129, 0.1)',
            tension: 0.35,
            fill: true
          },
          {
            label: 'Suspicious',
            data: susData.length ? susData : [0, 0, 0, 0, 0, 0, 0],
            borderColor: '#f59e0b',
            backgroundColor: 'rgba(245, 158, 11, 0.1)',
            tension: 0.35,
            fill: true
          },
          {
            label: 'Malicious',
            data: malData.length ? malData : [0, 0, 0, 0, 0, 0, 0],
            borderColor: '#ef4444',
            backgroundColor: 'rgba(239, 68, 68, 0.15)',
            tension: 0.35,
            fill: true
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {legend: {position: 'top',labels: { color: '#9ca3af', font: { family: 'Inter', size: 11 } }}},
        scales: {
          x: {grid: { color: 'rgba(255, 255, 255, 0.05)' },ticks: { color: '#6b7280' }},
          y: {beginAtZero: true,grid: { color: 'rgba(255, 255, 255, 0.05)' },ticks: { color: '#6b7280', stepSize: 1 }}
        }
      }
    });
  },

  renderSeverityChart(riskDist) {
    const ctx = document.getElementById('dashboardSeverityChart');
    if (!ctx) return;
    if (this.severityChartInstance) {this.severityChartInstance.destroy();}
    const low = riskDist.LOW || 0;
    const med = riskDist.MEDIUM || 0;
    const high = riskDist.HIGH || 0;
    const crit = riskDist.CRITICAL || 0;
    const hasData = (low + med + high + crit) > 0;
    this.severityChartInstance = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['Low Risk', 'Medium Risk', 'High Risk', 'Critical Risk'],
        datasets: [{
          data: hasData ? [low, med, high, crit] : [1, 0, 0, 0],
          backgroundColor: ['#10b981', '#f59e0b', '#ef4444', '#ec4899'],
          borderColor: '#111827',
          borderWidth: 3
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom',
            labels: { color: '#9ca3af', font: { family: 'Inter', size: 11 } }
          }
        },
        cutout: '70%'
      }
    });
  },

  renderRecentTable(scans) {
    const tbody = document.getElementById('dashboardRecentActivityTable');
    if (!tbody) return;
    if (!scans || scans.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="6" style="text-align: center; color: var(--text-dim); padding: 24px;">
            No threat scans recorded yet. Try running a scan or loading demo presets!
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = scans.map(s => {
      const isSafe = s.prediction.includes('Safe') || s.prediction.includes('Real');
      const isSuspicious = s.prediction.includes('Suspicious');
      const tagClass = isSafe ? 'risk-tag-safe' : (isSuspicious ? 'risk-tag-medium' : 'risk-tag-high');
      const typeIcon = s.scan_type === 'url' ? 'URL' : (s.scan_type === 'email' ? 'EMAIL' : (s.scan_type === 'message' ? 'SMS' : 'SCAN'));
      return `
        <tr style="cursor: pointer;" onclick="HistoryView.openDetailModal('${s.id}')">
          <td><span style="font-size: 1.1rem; font-weight: bold; margin-right: 5px;">${typeIcon}</span></td>
          <td class="input-mono" style="font-size: 0.85rem; max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
            ${s.input_preview}
          </td>
          <td><span class="risk-tag ${tagClass}">${s.prediction}</span></td>
          <td style="font-weight: 600;">${s.confidence.toFixed(1)}%</td>
          <td style="font-weight: 800; font-family: var(--font-mono); color: ${isSafe ? 'var(--color-safe)' : (isSuspicious ? 'var(--color-suspicious)' : 'var(--color-malicious)')};">
            ${s.risk_score}
          </td>
          <td style="font-size: 0.78rem; color: var(--text-dim);">${s.created_at || 'Just now'}</td>
        </tr>
      `;
    }).join('');
  }
};

if (!requireAuth()) {
  // No user token: requireAuth redirects to the login page.
} else {
  loadDashboard();
}

async function loadDashboard() {
  const user = getUserData();
  if (user.name) {
    document.getElementById('sidebar-name').textContent = user.name;
    document.getElementById('user-name-nav').textContent = `Hi, ${user.name.split(' ')[0]}`;
    document.getElementById('avatar-initials').textContent = user.name.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2);
  }

  try {
    const [dashRes, statsRes] = await Promise.all([
      API.get('/api/user/dashboard'),
      API.get('/api/user/stats')
    ]);
    const dashData = await dashRes.json();
    const statsData = await statsRes.json();

    if (dashData.success) renderDashboard(dashData.dashboard, statsData.stats);
    else showToast('Failed to load dashboard data', 'error');
  } catch (e) {
    showToast('Cannot reach server. Is the backend running?', 'error');
  }
}

function renderDashboard(dash, stats) {
  document.getElementById('stat-total').textContent = dash.total_scans || 0;
  document.getElementById('stat-threats').textContent = dash.threats_found || 0;
  document.getElementById('stat-safe').textContent = (dash.total_scans || 0) - (dash.threats_found || 0);
  document.getElementById('stat-score').textContent = (dash.safety_score || 100) + '%';

  const types = stats ? stats.by_type : {};
  renderDonut('chart-types', {
    labels: ['SMS', 'Email Address', 'Email Body', 'URL'],
    data: [types.sms || 0, types.email_address || 0, types.email_body || types.email_comprehensive || 0, types.url || 0],
    colors: ['#00D4FF', '#7B5EA7', '#FFA502', '#FF4757']
  });

  const vd = stats ? stats.by_verdict : {};
  renderDonut('chart-verdicts', {
    labels: ['Dangerous', 'Phishing', 'Spam', 'Safe'],
    data: [vd.dangerous || 0, vd.phishing || 0, vd.spam || 0, vd.safe || 0],
    colors: ['#FF4757', '#FF6B35', '#FFA502', '#2ED573']
  });

  const daily = stats ? stats.daily_activity : {};
  const last30 = [];
  for (let i = 29; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    const key = d.toISOString().split('T')[0];
    last30.push({ label: d.toLocaleDateString('en', { month: 'short', day: 'numeric' }), val: daily[key] || 0 });
  }
  renderLine('chart-activity', {
    labels: last30.map(x => x.label),
    data: last30.map(x => x.val),
    label: 'Scans per Day'
  });

  renderRecentTable(dash.recent_scans || []);
}

function renderRecentTable(scans) {
  const wrap = document.getElementById('recent-table');
  if (!scans.length) {
    wrap.innerHTML = `<div class="empty-state"><div class="empty-icon">📭</div><p>No scans yet. <a href="scan.html" class="dashboard-first-scan-link">Run your first scan →</a></p></div>`;
    return;
  }
  const iconMap = { sms: 'SMS', email_address: 'EMAIL', email_comprehensive: 'EMAIL COMPREHENSIVE', url: 'URL' };
  const rows = scans.map(s => {
    const v = s.verdict || '';
    const cls = ['DANGEROUS', 'PHISHING', 'SPAM', 'FAKE', 'DISPOSABLE'].includes(v) ? 'badge-dangerous' : v === 'SUSPICIOUS' ? 'badge-suspicious' : 'badge-safe';
    const date = new Date(s.created_at).toLocaleDateString('en', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    return `<tr class="dashboard-scan-row">
        <td><span class="dashboard-scan-type-label" style="text-transform: uppercase; font-weight: bold;">${(iconMap[s.scan_type] || s.scan_type).replace('_', ' ')}</span></td>
        <td class="dashboard-table-content" title="${s.input_text}">${s.input_text}</td>
        <td><span class="badge ${cls}">${v}</span></td>
        <td class="dashboard-risk-value">${s.risk_score || 0}/100</td>
        <td class="dashboard-scan-date">${date}</td>
      </tr>`;
  }).join('');
  wrap.innerHTML = `<table><thead><tr><th>Type</th><th>Input</th><th>Verdict</th><th>Risk</th><th>Time</th></tr></thead><tbody>${rows}</tbody></table>`;
}
