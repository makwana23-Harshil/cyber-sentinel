
const HistoryView = {currentPage: 1,pageSize: 12,searchTimer: null,
  debounceFetch() {
    clearTimeout(this.searchTimer);
    this.searchTimer = setTimeout(() => {this.fetchHistory(1);}, 300);
  },

  async fetchHistory(page = 1) {
    this.currentPage = page;
    const search = document.getElementById('historySearchInput')?.value.trim() || '';
    const scanType = document.getElementById('filterType')?.value || 'all';
    const prediction = document.getElementById('filterVerdict')?.value || 'all';
    const riskLevel = document.getElementById('filterRisk')?.value || 'all';

    let url = `/api/history?page=${page}&page_size=${this.pageSize}`;
    if (search) url += `&search=${encodeURIComponent(search)}`;
    if (scanType !== 'all') url += `&scan_type=${encodeURIComponent(scanType)}`;
    if (prediction !== 'all') url += `&prediction=${encodeURIComponent(prediction)}`;
    if (riskLevel !== 'all') url += `&risk_level=${encodeURIComponent(riskLevel)}`;

    try {
      const data = await App.apiRequest(url);
      this.renderHistoryTable(data);
      this.updatePagination(data);
    } catch (err) {
      console.error('Failed to fetch history:', err);
    }
  },

  renderHistoryTable(data) {
    const tbody = document.getElementById('historyTableBody');
    if (!tbody) return;
    if (!data.scans || data.scans.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="7" style="text-align: center; color: var(--text-dim); padding: 32px;">
            No scan logs match your search or filter criteria.
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = data.scans.map(s => {
      const isSafe = s.prediction.includes('Safe') || s.prediction.includes('Real');
      const isSuspicious = s.prediction.includes('Suspicious');
      const tagClass = isSafe ? 'risk-tag-safe' : (isSuspicious ? 'risk-tag-medium' : 'risk-tag-high');
      const typeIcon = s.scan_type === 'url' ? 'URL' : (s.scan_type === 'email' ? 'EMAIL' : (s.scan_type === 'message' ? 'SMS' : 'SCAN'));

      return `
        <tr>
          <td><span style="font-size: 1.1rem; font-weight: bold; margin-right: 5px;">${typeIcon}</span></td>
          <td class="input-mono" style="font-size: 0.85rem; max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
            ${s.input_preview}
          </td>
          <td><span class="risk-tag ${tagClass}">${s.prediction}</span></td>
          <td style="font-weight: 600;">${s.confidence.toFixed(1)}%</td>
          <td style="font-weight: 800; font-family: var(--font-mono); color: ${isSafe ? 'var(--color-safe)' : (isSuspicious ? 'var(--color-suspicious)' : 'var(--color-malicious)')};">
            ${s.risk_score}
          </td>
          <td style="font-size: 0.78rem; color: var(--text-dim);">${s.created_at}</td>
          <td>
            <div style="display: flex; gap: 6px;">
              <button class="btn-cyber btn-secondary btn-sm" onclick="HistoryView.openDetailModal('${s.id}')">Inspect</button>
              <button class="btn-cyber btn-danger btn-sm" onclick="HistoryView.deleteRecord('${s.id}')">✕</button>
            </div>
          </td>
        </tr>
      `;
    }).join('');
  },

  updatePagination(data) {
    const total = data.total || 0;
    const page = data.page || 1;
    const totalPages = Math.ceil(total / this.pageSize) || 1;

    const infoEl = document.getElementById('historyPaginationInfo');
    if (infoEl) {
      infoEl.innerText = `Showing Page ${page} of ${totalPages} (${total} total records)`;
    }

    const btnPrev = document.getElementById('btnPrevPage');
    const btnNext = document.getElementById('btnNextPage');

    if (btnPrev) btnPrev.disabled = page <= 1;
    if (btnNext) btnNext.disabled = page >= totalPages;
  },

  prevPage() {
    if (this.currentPage > 1) {this.fetchHistory(this.currentPage - 1);}
  },

  nextPage() {this.fetchHistory(this.currentPage + 1);},
  async deleteRecord(scanId) {
    if (!confirm('Are you sure you want to delete this scan record?')) return;

    try {
      await App.apiRequest(`/api/history/${scanId}`, { method: 'DELETE' });
      App.showToast('Record deleted successfully', 'info');
      this.fetchHistory(this.currentPage);
    } catch (err) {
    }
  },

  async confirmClearHistory() {
    if (!confirm('WARNING: This will permanently wipe all threat scan history records from the database. Proceed?')) return;

    try {
      await App.apiRequest('/api/history/clear', { method: 'POST' });
      App.showToast('Threat history wiped clean', 'info');
      this.fetchHistory(1);
      DashboardView.loadData();
    } catch (err) {
      // Handled in apiRequest
    }
  },

  async openDetailModal(scanId) {
    const modal = document.getElementById('scanDetailModal');
    const modalBody = document.getElementById('modalScanBody');
    const modalTitle = document.getElementById('modalScanTitle');

    modal.classList.add('active');
    modalBody.innerHTML = '<div style="text-align: center; padding: 32px;"><div class="cyber-spinner"></div> Loading audit record...</div>';

    try {
      const scan = await App.apiRequest(`/api/history/${scanId}`);
      modalTitle.innerText = `Threat Audit Log: ${scan.scan_type.toUpperCase()} (#${scan.id.substring(0, 8)})`;

      const isSafe = scan.prediction.includes('Safe') || scan.prediction.includes('Real');
      const isSuspicious = scan.prediction.includes('Suspicious');
      const scoreColor = isSafe ? 'var(--color-safe)' : (isSuspicious ? 'var(--color-suspicious)' : 'var(--color-malicious)');

      let indicatorsHtml = '';
      if (scan.indicators && scan.indicators.length > 0) {
        indicatorsHtml = `
          <div style="margin-top: 18px;">
            <h4 style="font-size: 0.95rem; font-weight: 700; margin-bottom: 10px;">Detected Threat Indicators</h4>
            <div style="background: var(--bg-surface-elevated); border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 14px;">
              ${scan.indicators.map(i => `<div style="padding: 4px 0; font-size: 0.85rem;">${i}</div>`).join('')}
            </div>
          </div>
        `;
      }

      let xaiHtml = '';
      if (scan.xai_data?.highlighted_html) {
        xaiHtml = `
          <div style="margin-top: 18px;">
            <h4 style="font-size: 0.95rem; font-weight: 700; margin-bottom: 8px;">Explainable AI: Target Content Visualizer</h4>
            <div class="xai-preview-box">${scan.xai_data.highlighted_html}</div>
          </div>
        `;
      }

      modalBody.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; background: var(--bg-surface-elevated); padding: 16px; border-radius: var(--radius-md); border: 1px solid var(--border-color); margin-bottom: 18px;">
          <div>
            <div style="font-size: 1.2rem; font-weight: 800; color: ${scoreColor};">${scan.prediction}</div>
            <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 2px;">
              Risk Level: <b>${scan.risk_level}</b> • Confidence: <b>${scan.confidence.toFixed(1)}%</b> • ${scan.created_at}
            </div>
          </div>
          <div style="text-align: right;">
            <div style="font-size: 1.8rem; font-weight: 900; font-family: var(--font-mono); color: ${scoreColor};">${scan.risk_score}</div>
            <div style="font-size: 0.7rem; color: var(--text-dim); text-transform: uppercase;">Cyber Risk Score</div>
          </div>
        </div>

        <div>
          <h4 style="font-size: 0.95rem; font-weight: 700; margin-bottom: 8px;">Raw Target Payload</h4>
          <div style="background: #0b0f17; border: 1px solid var(--border-color); padding: 12px; border-radius: var(--radius-md); font-family: var(--font-mono); font-size: 0.82rem; max-height: 180px; overflow-y: auto; white-space: pre-wrap; word-break: break-all;">
            ${scan.raw_input}
          </div>
        </div>

        ${indicatorsHtml}
        ${xaiHtml}
      `;
    } catch (err) {
      modalBody.innerHTML = `<div style="color: var(--color-malicious); padding: 20px;">Failed to load record details.</div>`;
    }
  },

  closeModal() {
    const modal = document.getElementById('scanDetailModal');
    if (modal) modal.classList.remove('active');
  }
};

if (!requireAuth()) {
} else {
  loadHistory();
}

let allScans = [];
let currentFilter = 'all';
let currentScansPage = 1;
const scansPerPage = 10;

async function loadHistory() {
  const user = getUserData();
  if (user.name) document.getElementById('user-name-nav').textContent = `Hi, ${user.name.split(' ')[0]}`;
  
  const startDate = document.getElementById('startDate') ? document.getElementById('startDate').value : '';
  const endDate = document.getElementById('endDate') ? document.getElementById('endDate').value : '';
  let url = `/api/user/history?limit=all`;
  if (startDate) url += `&start=${startDate}`;
  if (endDate) url += `&end=${endDate}`;
  
  try {
    const res = await API.get(url);
    const data = await res.json();
    if (!data.success) throw new Error(data.message);
    allScans = data.scans;
    filterScans();
  } catch (e) {
    document.getElementById('history-table').innerHTML = `<div class="empty-state"><p>Error: ${e.message}</p></div>`;
  }
}

const iconMap = { sms: 'SMS', email_address: 'EMAIL', email_comprehensive: 'EMAIL COMPREHENSIVE', url: 'URL' };
const threatVerdicts = ['DANGEROUS', 'PHISHING', 'SPAM', 'FAKE', 'DISPOSABLE', 'INVALID'];

function setFilter(filter, btn) {
  currentFilter = filter;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  filterScans();
}

function filterScans() {
  const q = document.getElementById('search-input').value.toLowerCase();
  let filtered = allScans;
  if (currentFilter === 'threats') filtered = filtered.filter(s => threatVerdicts.includes(s.verdict));
  else if (currentFilter !== 'all') filtered = filtered.filter(s => s.scan_type === currentFilter);
  if (q) filtered = filtered.filter(s => s.input_text.toLowerCase().includes(q) || (s.verdict || '').toLowerCase().includes(q));
  currentScansPage = 1;
    renderTable(filtered);
}

function renderTable(scans) {
    const wrap = document.getElementById('history-table');
    const noRes = document.getElementById('no-results');
    const pagination = document.getElementById('user-scans-pagination');
    if (!scans.length) {
      wrap.innerHTML = '';
      noRes.classList.remove('hidden');
      if (pagination) pagination.innerHTML = '';
      return;
    }
    noRes.classList.add('hidden');
    
    const totalPages = Math.ceil(scans.length / scansPerPage);
    if (currentScansPage > totalPages) currentScansPage = totalPages || 1;
    const startIndex = (currentScansPage - 1) * scansPerPage;
    const paginatedScans = scans.slice(startIndex, startIndex + scansPerPage);

    const rows = paginatedScans.map((s, index) => {
      const v = s.verdict || '';
      const details = s.details || {};
      let badge = 'badge-safe';
      if (['DANGEROUS', 'PHISHING', 'SPAM'].includes(v)) badge = 'badge-dangerous';
      else if (v === 'SUSPICIOUS') badge = 'badge-suspicious';
      
      const date = new Date(s.created_at).toLocaleDateString('en', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' });
      
      const iconMap = { sms: 'SMS', email_address: 'EMAIL', email_comprehensive: 'BODY', url: 'URL' };
      const iconText = iconMap[s.scan_type] || 'SCAN';

      return `
        <tr onclick="toggleDetail('${s.id}', this)" style="cursor: pointer;">
          <td>${startIndex + index + 1}</td>
          <td>${iconText}</td>
          <td class="history-content-preview">${s.input_text}</td>
          <td><span class="badge ${badge}">${v || 'LEGITIMATE'}</span></td>
          <td>
            <div class="risk-bar-bg"><div class="risk-bar-fill ${badge.replace('badge', 'risk')}" style="width: ${s.risk_score || 0}%"></div></div>
          </td>
          <td class="history-date">${date}</td>
        </tr>
        <tr id="detail-${s.id}" class="detail-row hidden">
          <td colspan="6">
            <div class="history-detail-metadata" style="margin-top: 15px; display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 15px;">
              ${Object.entries(details).filter(([k]) => !['verdict', 'confidence', 'risk_score', 'extracted_urls', 'link_inspections'].includes(k)).map(([k, v]) => {
                let isMlPred = k.toLowerCase().includes('ml_prediction') || k.toLowerCase() === 'ml prediction' || k.toLowerCase().includes('prediction');
                let displayValue = v;
                if (k === 'sender_analysis' && v && typeof v === 'object' && Array.isArray(v.risk_factors) &&
                    Array.isArray(details.risk_evidence) && JSON.stringify(v.risk_factors) === JSON.stringify(details.risk_evidence)) {
                  displayValue = { ...v };
                  delete displayValue.risk_factors;
                }
                let vStr = typeof displayValue === 'object' ? JSON.stringify(displayValue, null, 2) : String(displayValue);
                
                let boxBg = '#f8f9fa';
                let boxColor = '#000000';
                let boxBorder = '1px solid #ced4da';
                let headingColor = '#d97706';
                
                if (isMlPred) {
                  let vUpper = vStr.toUpperCase();
                  if (vUpper.includes('SAFE') || vUpper.includes('LEGITIMATE') || vUpper.includes('HAM')) {
                      boxBg = '#d1e7dd';
                      boxColor = '#0f5132';
                      boxBorder = '1px solid #badbcc';
                  } else if (vUpper.includes('DANGEROUS') || vUpper.includes('FAKE') || vUpper.includes('PHISHING') || vUpper.includes('SPAM')) {
                      boxBg = '#f8d7da';
                      boxColor = '#842029';
                      boxBorder = '1px solid #f5c2c7';
                  } else if (vUpper.includes('SUSPICIOUS')) {
                      boxBg = '#fff3cd';
                      boxColor = '#664d03';
                      boxBorder = '1px solid #ffecb5';
                  }
                }
                
                if (typeof v === 'number' && (k.toLowerCase().includes('probability') || k.toLowerCase().includes('confidence') || k.toLowerCase().includes('score'))) {
                  vStr = (v <= 1 ? (v * 100).toFixed(1) : v.toFixed(1)) + '%';
                }

                return `<div class="history-detail-item" style="display: flex; flex-direction: column; background: transparent; border: none; padding: 0;">
                  <strong style="color: ${headingColor}; text-transform: uppercase; font-size: 0.85rem; margin-bottom: 6px;">${k.replace(/_/g, ' ')}:</strong>
                  <div style="flex-grow: 1; padding: 12px; background: ${boxBg}; border: ${boxBorder}; border-radius: 6px; white-space: pre-wrap; word-wrap: break-word; font-family: monospace; line-height: 1.4; color: ${boxColor}; max-height: 400px; overflow-y: auto;">${vStr}</div>
                </div>`;
              }).join('')}
            </div>
          </td>
        </tr>`;
    }).join('');
    
    wrap.innerHTML = `<table><thead><tr><th>Sr.No</th><th>Type</th><th>Content</th><th>Verdict</th><th>Risk</th><th>Scanned</th></tr></thead><tbody>${rows}</tbody></table>`;
    
    if (pagination) {
      pagination.style.display = 'block';
      pagination.style.textAlign = 'center';
      pagination.style.lineHeight = '2.5';
      pagination.style.marginTop = '15px';
      pagination.innerHTML = '';
      for (let i = 1; i <= totalPages; i++) {
        const button = document.createElement('button');
        button.className = `btn btn-sm ${i === currentScansPage ? 'btn-primary' : 'btn-outline'}`;
        button.textContent = i;
        button.style.margin = '4px';
        button.onclick = () => {
            currentScansPage = i;
            renderTable(scans);
        };
        pagination.appendChild(button);
        if (i % 10 === 0) {
            pagination.appendChild(document.createElement('br'));
        }
      }
    }
}

function toggleDetail(id, row) {
  const det = document.getElementById('detail-' + id);
  det.classList.toggle('hidden');
}

function escHtml(str) {
  return (str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}




