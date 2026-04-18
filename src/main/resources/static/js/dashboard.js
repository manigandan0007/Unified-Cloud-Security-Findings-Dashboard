(function () {
    const form      = document.getElementById('credsForm');
    const goBtn     = document.getElementById('goBtn');
    const statusEl  = document.getElementById('hubStatus');
    const summaryEl = document.getElementById('hubSummary');
    const chartsEl  = document.getElementById('hubCharts');
    const tablesEl  = document.getElementById('hubTables');
    const filtersEl = document.getElementById('hubFilters');
    const findingsEl= document.getElementById('hubFindings');
    const emptyEl   = document.getElementById('hubEmpty');
    const searchEl  = document.getElementById('hubSearch');
    const sevFilterEl = document.getElementById('sevFilter');
    const countEl   = document.getElementById('hubCount');

    const SEV_COLORS = {
        CRITICAL: '#a4262c',
        HIGH: '#d13438',
        MEDIUM: '#f7630c',
        LOW: '#0078d4',
        INFORMATIONAL: '#8a8886',
        UNKNOWN: '#bfbfbf'
    };
    const chartInstances = {};

    let lastFindings = [];

    function setStatus(kind, msg) {
        if (!msg) { statusEl.hidden = true; return; }
        statusEl.hidden = false;
        statusEl.className = 'hub-status ' + kind;
        statusEl.textContent = msg;
    }

    function escapeHtml(s) {
        if (s == null) return '';
        return String(s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    function fmtDate(iso) {
        if (!iso) return '—';
        try { return new Date(iso).toLocaleString(); } catch (e) { return iso; }
    }

    function renderSummary(counts, total) {
        const order = ['CRITICAL','HIGH','MEDIUM','LOW','INFORMATIONAL'];
        let html = `<div class="sev-tile TOTAL"><div class="num">${total}</div><div class="lbl">Total</div></div>`;
        order.forEach(s => {
            const n = counts[s] || 0;
            html += `<div class="sev-tile ${s}"><div class="num">${n}</div><div class="lbl">${s}</div></div>`;
        });
        summaryEl.innerHTML = html;
        summaryEl.hidden = false;
    }

    function renderFindings(findings) {
        if (!findings.length) {
            findingsEl.innerHTML = '';
            emptyEl.hidden = false;
            countEl.textContent = '0 shown';
            return;
        }
        emptyEl.hidden = true;
        countEl.textContent = findings.length + ' shown';

        findingsEl.innerHTML = findings.map(f => {
            const sev = (f.severity || 'INFORMATIONAL').toUpperCase();
            const resources = (f.resources || []).slice(0, 3).map(r =>
                `<div class="fx-res"><b>${escapeHtml(r.type || '')}</b> ${escapeHtml(r.id || '')}${r.region ? ' <span style="opacity:.6">(' + escapeHtml(r.region) + ')</span>' : ''}</div>`
            ).join('');
            const more = (f.resources && f.resources.length > 3)
                ? `<div class="fx-res" style="opacity:.7">+ ${f.resources.length - 3} more resource(s)</div>` : '';
            return `
              <div class="fx" data-sev="${sev}">
                <div class="fx-head">
                  <div class="fx-title">${escapeHtml(f.title || '(no title)')}</div>
                  <span class="sev-badge ${sev}">${sev}</span>
                </div>
                ${f.description ? `<div class="fx-desc">${escapeHtml(f.description)}</div>` : ''}
                <div class="fx-meta">
                  <span><b>Product:</b>${escapeHtml(f.productName || '—')}</span>
                  <span><b>Account:</b>${escapeHtml(f.awsAccountId || f.subscriptionId || '—')}</span>
                  <span><b>Region:</b>${escapeHtml(f.region || '—')}</span>
                  ${f.workflowStatus ? `<span><b>Status:</b>${escapeHtml(f.workflowStatus)}</span>` : ''}
                  ${f.complianceStatus ? `<span><b>Compliance:</b>${escapeHtml(f.complianceStatus)}</span>` : ''}
                  <span><b>Updated:</b>${escapeHtml(fmtDate(f.updatedAt))}</span>
                </div>
                ${resources}${more}
              </div>`;
        }).join('');
    }

    function applyFilters() {
        const q = (searchEl.value || '').trim().toLowerCase();
        const sev = sevFilterEl.value;
        const filtered = lastFindings.filter(f => {
            const sv = (f.severity || 'INFORMATIONAL').toUpperCase();
            if (sev && sv !== sev) return false;
            if (!q) return true;
            const hay = ((f.title||'') + ' ' + (f.productName||'') + ' ' + (f.description||'') + ' ' +
                (f.resources||[]).map(r => (r.id||'') + ' ' + (r.type||'')).join(' ')).toLowerCase();
            return hay.includes(q);
        });
        renderFindings(filtered);
    }

    searchEl && searchEl.addEventListener('input', applyFilters);
    sevFilterEl && sevFilterEl.addEventListener('change', applyFilters);

    function destroyCharts() {
        Object.keys(chartInstances).forEach(k => {
            try { chartInstances[k].destroy(); } catch (e) {}
            delete chartInstances[k];
        });
    }

    function mapToLabels(obj) {
        const entries = Object.entries(obj || {}).filter(([, v]) => v > 0);
        return { labels: entries.map(e => e[0]), values: entries.map(e => e[1]) };
    }

    function topN(obj, n) {
        return Object.entries(obj || {}).sort((a, b) => b[1] - a[1]).slice(0, n);
    }

    function baseOpts(extra) {
        return Object.assign({
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { position: 'bottom', labels: { boxWidth: 10, font: { size: 11 } } } }
        }, extra || {});
    }

    function renderCharts(data) {
        if (typeof Chart === 'undefined') return;
        destroyCharts();
        chartsEl.hidden = false;

        const sevOrder = ['CRITICAL','HIGH','MEDIUM','LOW','INFORMATIONAL'];
        const sevVals = sevOrder.map(s => (data.severityCounts || {})[s] || 0);
        chartInstances.sev = new Chart(document.getElementById('chartSeverity'), {
            type: 'doughnut',
            data: {
                labels: sevOrder,
                datasets: [{ data: sevVals, backgroundColor: sevOrder.map(s => SEV_COLORS[s]), borderWidth: 1, borderColor: '#fff' }]
            },
            options: baseOpts({ cutout: '62%' })
        });

        const wf = mapToLabels(data.workflowStatusCounts);
        chartInstances.wf = new Chart(document.getElementById('chartWorkflow'), {
            type: 'bar',
            data: { labels: wf.labels, datasets: [{ label: 'Findings', data: wf.values, backgroundColor: '#0078d4' }] },
            options: baseOpts({ plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } })
        });

        const comp = mapToLabels(data.complianceStatusCounts);
        const compColors = comp.labels.map(l => {
            const up = String(l).toUpperCase();
            if (up.includes('PASS')) return '#107c10';
            if (up.includes('FAIL')) return '#a4262c';
            if (up.includes('WARN')) return '#f7630c';
            return '#8a8886';
        });
        chartInstances.comp = new Chart(document.getElementById('chartCompliance'), {
            type: 'pie',
            data: { labels: comp.labels, datasets: [{ data: comp.values, backgroundColor: compColors, borderColor: '#fff', borderWidth: 1 }] },
            options: baseOpts()
        });

        const topProds = topN(data.productCounts, 8);
        chartInstances.prod = new Chart(document.getElementById('chartProducts'), {
            type: 'bar',
            data: { labels: topProds.map(e => e[0]), datasets: [{ label: 'Findings', data: topProds.map(e => e[1]), backgroundColor: '#4fa3e2' }] },
            options: baseOpts({ indexAxis: 'y', plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, ticks: { precision: 0 } } } })
        });

        const topTypes = topN(data.resourceTypeCounts, 8);
        chartInstances.rtype = new Chart(document.getElementById('chartResourceTypes'), {
            type: 'bar',
            data: { labels: topTypes.map(e => e[0]), datasets: [{ label: 'Findings', data: topTypes.map(e => e[1]), backgroundColor: '#6a3aa3' }] },
            options: baseOpts({ indexAxis: 'y', plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, ticks: { precision: 0 } } } })
        });

        const ageKeys = ['lt_7d', '7_30d', '30_90d', 'gt_90d'];
        const ageLabels = ['< 7 days', '7 – 30 days', '30 – 90 days', '> 90 days'];
        const ageVals = ageKeys.map(k => (data.ageBuckets || {})[k] || 0);
        chartInstances.age = new Chart(document.getElementById('chartAge'), {
            type: 'bar',
            data: { labels: ageLabels, datasets: [{ label: 'Findings', data: ageVals, backgroundColor: ['#107c10', '#0078d4', '#f7630c', '#a4262c'] }] },
            options: baseOpts({ plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } })
        });
    }

    function renderTopResources(rows) {
        const tbody = document.querySelector('#tblTopResources tbody');
        if (!rows || !rows.length) {
            tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:#605e5c;padding:14px">No resource data.</td></tr>';
            return;
        }
        tbody.innerHTML = rows.map((r, i) => {
            const s = r.bySeverity || {};
            const cell = (k) => {
                const v = s[k] || 0;
                return `<td class="t-right"><span class="mini-sev ${v ? k : 'zero'}">${v}</span></td>`;
            };
            return `<tr>
                <td>${i + 1}</td>
                <td><div class="res-id">${escapeHtml(r.id)}</div></td>
                <td class="res-type">${escapeHtml(r.type || '—')}</td>
                ${cell('CRITICAL')}${cell('HIGH')}${cell('MEDIUM')}${cell('LOW')}
                <td class="t-right"><b>${r.count}</b></td>
            </tr>`;
        }).join('');
    }

    function renderAgeTable(ageBuckets, total) {
        const tbody = document.querySelector('#tblAge tbody');
        const rows = [
            ['< 7 days',     ageBuckets.lt_7d  || 0],
            ['7 – 30 days',  ageBuckets['7_30d'] || 0],
            ['30 – 90 days', ageBuckets['30_90d'] || 0],
            ['> 90 days',    ageBuckets.gt_90d || 0]
        ];
        tbody.innerHTML = rows.map(([label, count]) => {
            const pct = total > 0 ? Math.round((count / total) * 100) : 0;
            return `<tr>
                <td>${label}</td>
                <td class="t-right">${count}</td>
                <td class="t-right">
                    <div class="bar-cell">
                        <div class="bar"><span style="width:${pct}%"></span></div>
                        <span style="min-width:34px;text-align:right">${pct}%</span>
                    </div>
                </td>
            </tr>`;
        }).join('');
    }

    function resetDashboard() {
        summaryEl.hidden = true;
        chartsEl.hidden = true;
        tablesEl.hidden = true;
        filtersEl.hidden = true;
        emptyEl.hidden = true;
        findingsEl.innerHTML = '';
        destroyCharts();
    }

    async function runFetch(url, payload, loadingMsg, buttonEl, scopeLabel) {
        buttonEl.disabled = true;
        resetDashboard();
        setStatus('loading', loadingMsg);

        try {
            const resp = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'same-origin',
                body: JSON.stringify(payload)
            });
            const data = await resp.json().catch(() => ({ error: 'Invalid response' }));
            if (!resp.ok || data.error) {
                setStatus('err', data.error || ('Request failed: HTTP ' + resp.status));
                return;
            }

            lastFindings = data.findings || [];
            const truncNote = data.truncated
                ? ' (capped at ' + data.count + ' — more are available; raise Max Results).'
                : '.';
            setStatus('info', `Loaded ${data.count} finding(s) across ${data.pages} page(s) from ${scopeLabel}${truncNote}`);

            renderSummary(data.severityCounts || {}, data.count || 0);
            renderCharts(data);
            renderTopResources(data.topResources || []);
            renderAgeTable(data.ageBuckets || {}, data.count || 0);
            tablesEl.hidden = false;
            filtersEl.hidden = false;
            applyFilters();
        } catch (err) {
            setStatus('err', 'Network error: ' + err.message);
        } finally {
            buttonEl.disabled = false;
        }
    }

    form.addEventListener('submit', (e) => {
        e.preventDefault();
        const payload = {
            accessKey:    document.getElementById('accessKey').value.trim(),
            secretKey:    document.getElementById('secretKey').value.trim(),
            sessionToken: document.getElementById('sessionToken').value.trim() || null,
            region:       document.getElementById('region').value,
            maxResults:   parseInt(document.getElementById('maxResults').value, 10) || 200
        };
        if (!payload.accessKey || !payload.secretKey) {
            setStatus('err', 'Access key and secret key are required.');
            return;
        }
        runFetch('/api/securityhub/findings', payload,
            'Fetching findings from AWS Security Hub (paginating)...',
            goBtn, 'AWS ' + payload.region);
    });

    const azForm  = document.getElementById('azureForm');
    const azGoBtn = document.getElementById('azGoBtn');
    if (azForm) {
        azForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const payload = {
                tenantId:       document.getElementById('azTenantId').value.trim(),
                clientId:       document.getElementById('azClientId').value.trim(),
                clientSecret:   document.getElementById('azClientSecret').value.trim(),
                subscriptionId: document.getElementById('azSubscriptionId').value.trim(),
                maxResults:     parseInt(document.getElementById('azMaxResults').value, 10) || 200
            };
            if (!payload.tenantId || !payload.clientId || !payload.clientSecret || !payload.subscriptionId) {
                setStatus('err', 'Tenant ID, Client ID, Client Secret and Subscription ID are required.');
                return;
            }
            runFetch('/api/defender/alerts', payload,
                'Fetching alerts from Microsoft Defender for Cloud (paginating)...',
                azGoBtn, 'Azure subscription ' + payload.subscriptionId.substring(0, 8) + '…');
        });
    }

    const tabButtons = document.querySelectorAll('.tab');
    const panels = {
        aws:   document.getElementById('panelAws'),
        azure: document.getElementById('panelAzure')
    };
    const titleEl    = document.getElementById('hubTitle');
    const subtitleEl = document.getElementById('hubSubtitle');
    const HEADINGS = {
        aws:   { title: 'AWS Security Hub',             subtitle: 'Enter AWS credentials to pull live findings from Amazon Security Hub.' },
        azure: { title: 'Microsoft Defender for Cloud', subtitle: 'Enter Azure service principal credentials to pull security alerts.' }
    };

    function switchTab(name) {
        tabButtons.forEach(b => {
            const isActive = b.dataset.tab === name;
            b.classList.toggle('active', isActive);
            b.setAttribute('aria-selected', isActive ? 'true' : 'false');
        });
        Object.keys(panels).forEach(k => { panels[k].hidden = (k !== name); });
        const h = HEADINGS[name];
        if (titleEl && h)    titleEl.innerHTML = escapeHtml(h.title) + ' <span class="muted-h1">&middot; Findings Dashboard</span>';
        if (subtitleEl && h) subtitleEl.textContent = h.subtitle;
        resetDashboard();
        setStatus(null);
    }

    tabButtons.forEach(b => b.addEventListener('click', () => switchTab(b.dataset.tab)));
    switchTab('aws');
})();