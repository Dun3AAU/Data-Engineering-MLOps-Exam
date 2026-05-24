const SUMMARY_URL = 'public/reasoning/latest_summary.json';
const RAW_SUMMARY_URL = 'public/reasoning/latest_raw_summary.json';
const REPORT_URL = 'public/reasoning/latest_reasoning.json';

const byId = (id) => document.getElementById(id);

function formatNumber(value) {
  return new Intl.NumberFormat('en-US').format(Number(value || 0));
}

function formatDate(value) {
  if (!value) return 'Unknown';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Unknown' : date.toLocaleString();
}

function renderBarList(container, entries, accentClass = '') {
  const root = byId(container);
  root.innerHTML = '';
  const values = Object.entries(entries || {});
  const max = Math.max(1, ...values.map(([, count]) => Number(count || 0)));

  values.forEach(([label, count]) => {
    const row = document.createElement('div');
    row.className = 'bar-row';
    row.innerHTML = `
      <div>${label}</div>
      <div class="bar-track"><div class="bar-fill ${accentClass}" style="width: ${Math.max(6, (count / max) * 100)}%"></div></div>
      <div>${formatNumber(count)}</div>
    `;
    root.appendChild(row);
  });

  if (!values.length) {
    root.innerHTML = '<div class="stack-item">No data available yet.</div>';
  }
}

function renderAssets(assets) {
  const root = byId('topAssets');
  root.innerHTML = '';

  (assets || []).forEach((asset) => {
    const el = document.createElement('div');
    el.className = 'stack-item';
    el.innerHTML = `
      <div class="stack-item-top">
        <strong>${asset.asset_id}</strong>
        <span>${formatNumber(asset.finding_count)} findings</span>
      </div>
      <div class="stack-item-top">
        <span>Criticality: ${asset.criticality}</span>
        <span>${asset.internet_exposed ? 'Internet-exposed' : 'Internal only'}</span>
      </div>
      <span>Highest priority: ${asset.highest_priority}</span>
    `;
    root.appendChild(el);
  });

  if (!(assets || []).length) {
    root.innerHTML = '<div class="stack-item">No assets available yet.</div>';
  }
}

function renderFindings(records) {
  const tbody = byId('findingsTable');
  tbody.innerHTML = '';

  (records || []).forEach((record) => {
    const row = document.createElement('tr');
    const priority = record.expert?.priority || 'P5';
    const risk = record.expert?.risk_level || 'unknown';
    const decision = record.expert?.decision || 'monitor';
    const confidence = Math.round((record.expert?.confidence ?? record.input?.match_confidence ?? 0) * 100);

    row.innerHTML = `
      <td>
        <div><strong>${record.input.asset.asset_id}</strong></div>
        <div class="muted">${record.input.asset.asset_type}${record.input.asset.internet_exposed ? ' • exposed' : ''}</div>
        <div class="muted">${record.input.asset.site || 'Unknown site'}${record.input.asset.role ? ` • ${record.input.asset.role}` : ''}</div>
      </td>
      <td>
        <div><strong>${record.input.cve.cve_id}</strong></div>
        <div class="muted">CVSS ${record.input.cve.cvss_v3_score ?? 'n/a'}</div>
      </td>
      <td><span class="badge ${priority.toLowerCase()}">${priority}</span></td>
      <td><span class="badge ${risk}">${risk}</span></td>
      <td>${decision}</td>
      <td>${confidence}%</td>
    `;
    tbody.appendChild(row);
  });

  if (!(records || []).length) {
    tbody.innerHTML = '<tr><td colspan="6">No findings available yet.</td></tr>';
  }
}

function setText(id, value) {
  const el = byId(id);
  if (el) el.textContent = value;
}

async function loadDashboard() {
  const [summaryResp, reportResp] = await Promise.all([
    fetch(SUMMARY_URL, { cache: 'no-store' }),
    fetch(REPORT_URL, { cache: 'no-store' }),
  ]);

  if (!summaryResp.ok || !reportResp.ok) {
    throw new Error('Dashboard data not available yet. Run the reasoning pipeline first.');
  }

  const summary = await summaryResp.json();
  const report = await reportResp.json();

  setText('providerChip', `Provider: ${report.provider}`);
  setText('modelChip', `Model: ${report.model}`);
  setText('timestampChip', `Generated: ${formatDate(report.generated_at)}`);

  setText('totalFindings', formatNumber(summary.total_findings));
  // raw summary may be available with matching-only counts
  try {
    const rawResp = await fetch(RAW_SUMMARY_URL, { cache: 'no-store' });
    if (rawResp.ok) {
      const raw = await rawResp.json();
      setText('rawMatches', formatNumber(raw.total_findings));
    } else {
      setText('rawMatches', '—');
    }
  } catch (e) {
    setText('rawMatches', '—');
  }
  setText('processedFindings', `${formatNumber(summary.processed_findings)} processed in this run`);
  setText('internetExposed', formatNumber(summary.internet_exposed_count));

  const topPriority = Object.keys(summary.by_priority || {})[0] || 'P5';
  const topDecision = Object.keys(summary.by_decision || {})[0] || 'monitor';
  setText('topPriority', topPriority);
  setText('topDecision', topDecision);

  renderBarList('decisionBars', summary.by_decision, 'decision');
  renderBarList('priorityBars', summary.by_priority, 'priority');
  renderBarList('criticalityBars', summary.by_criticality, 'criticality');
  renderAssets(summary.top_assets);
  renderFindings(report.records);
}

loadDashboard().catch((error) => {
  console.error(error);
  setText('providerChip', 'Provider unavailable');
  setText('modelChip', 'Model unavailable');
  setText('timestampChip', error.message);
  byId('findingsTable').innerHTML = `<tr><td colspan="6">${error.message}</td></tr>`;
});
