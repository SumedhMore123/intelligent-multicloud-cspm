(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
  const dateValue = (value) => { const n = Date.parse(value || ''); return Number.isFinite(n) ? n : null; };
  const reportTypes = [
    { id: 'executive', title: 'Executive Security Summary', description: 'High-level posture, priority risks, visibility, and evidence-based actions.', icon: 'executive', detail: 'Posture and priority risks' },
    { id: 'findings', title: 'Security Findings Report', description: 'Scoped finding records, risk severity, status, and cloud distribution.', icon: 'findings', detail: 'Findings and risk exposure' },
    { id: 'cloud', title: 'Cloud Security Posture', description: 'Per-provider findings, open exposure, risk severity, and resources.', icon: 'cloudSecurity', detail: 'Provider posture from scan data' },
    { id: 'compliance', title: 'Compliance Summary', description: 'Generic evaluated-check posture and framework mapping availability.', icon: 'compliance', detail: 'Generic posture; mappings unavailable' },
    { id: 'inventory', title: 'Inventory Report', description: 'Observed resources, resource types, risk, and last observation.', icon: 'inventory', detail: 'Finding-backed resource inventory' },
    { id: 'policies', title: 'Policy Evaluation Report', description: 'Observed policy IDs and associated finding evaluations.', icon: 'policies', detail: 'Observed policies; not a full catalog' },
  ];
  const state = { type: 'executive', cloud: 'all', domain: 'all', severity: 'all', status: 'all', dateRange: 'all', dateFrom: '', dateTo: '', generatedAt: null, generatedSnapshot: null, busy: false };
  let shared = null;
  let allFindings = [];

  function domainLabel(finding) {
    const value = String(shared.normalizeDomain(finding) || '').trim();
    if (!value) return 'Unspecified';
    const upper = value.toUpperCase();
    if (upper.includes('IAM') || upper.includes('IDENTITY')) return 'IAM';
    if (upper.includes('NETWORK')) return 'Network';
    if (upper.includes('DATA')) return 'Data';
    if (upper.includes('COMPLIANCE')) return 'Compliance';
    if (upper.includes('AI')) return 'AI';
    return value.toLocaleLowerCase().replace(/\b\w/g, (letter) => letter.toUpperCase());
  }
  function getReportTypes() { return reportTypes; }
  function buildReportScope(findings, filters = state) {
    const now = Date.now();
    let from = null, to = null;
    if (filters.dateRange === '7') from = now - 7 * 86400000;
    if (filters.dateRange === '30') from = now - 30 * 86400000;
    if (filters.dateRange === 'custom') {
      from = filters.dateFrom ? Date.parse(`${filters.dateFrom}T00:00:00`) : null;
      to = filters.dateTo ? Date.parse(`${filters.dateTo}T23:59:59.999`) : null;
    }
    const validCustom = filters.dateRange !== 'custom' || (Number.isFinite(from) && Number.isFinite(to) && from <= to);
    if (!validCustom) return { records: [], valid: false, range: null };
    const records = findings.filter((finding) => {
      if (filters.cloud !== 'all' && shared.normalizeCloud(finding.cloud) !== filters.cloud) return false;
      if (filters.domain !== 'all' && domainLabel(finding) !== filters.domain) return false;
      if (['findings', 'cloud', 'inventory', 'policies'].includes(filters.type) && filters.severity !== 'all' && shared.normalizeSeverity(finding.severity) !== filters.severity) return false;
      if (['findings', 'inventory', 'policies'].includes(filters.type) && filters.status !== 'all' && shared.normalizeStatus(finding.status) !== filters.status) return false;
      if (filters.dateRange !== 'all') {
        const timestamp = dateValue(finding.detected_at);
        if (timestamp == null || timestamp < from || (to != null && timestamp > to)) return false;
      }
      return true;
    });
    return { records, valid: true, range: filters.dateRange === 'all' ? null : { from, to } };
  }
  function cloudDistribution(records) {
    const counts = shared.getFindingsByCloud(records);
    const names = ['AWS', 'Azure', 'GCP', ...(counts.Other ? ['Other'] : [])];
    return names.map((cloud) => ({ cloud, findingCount: counts[cloud] || 0, available: (counts[cloud] || 0) > 0 }));
  }
  function severityName(value) { return value ? value.charAt(0) + value.slice(1).toLowerCase() : 'Not recorded'; }
  function makeMetric(label, value, note = '') { return { label, value, note }; }
  function inventoryFor(records) { return window.CSPMInventoryAdapter.getInventoryResources(records); }
  function policiesFor(records) { return window.CSPMPolicyAdapter.getObservedPolicies(records); }
  function executiveFor(records) {
    const adapter = window.CSPMExecutiveSummary;
    const metrics = adapter.calculateExecutiveMetrics(records);
    const risks = adapter.getPriorityRisks(records);
    const recommendations = adapter.getExecutiveRecommendations(records, risks);
    return { metrics, risks, recommendations, summary: adapter.generateExecutivePostureSummary(records, metrics) };
  }
  function buildReportData(type, records, filters = state) {
    const generatedAt = state.generatedAt || null;
    const scope = {
      cloud: filters.cloud === 'all' ? 'All clouds' : filters.cloud,
      domain: filters.domain === 'all' ? 'All domains' : filters.domain,
      severity: !['findings', 'cloud', 'inventory', 'policies'].includes(type) || filters.severity === 'all' ? 'All severities' : severityName(filters.severity),
      status: !['findings', 'inventory', 'policies'].includes(type) || filters.status === 'all' ? 'All finding statuses' : filters.status,
      dateRange: dateLabel(filters),
    };
    const title = reportTypes.find((item) => item.id === type)?.title || reportTypes[0].title;
    const resources = inventoryFor(records);
    const dist = shared.getSeverityDistribution(records);
    const clouds = cloudDistribution(records);
    const risk = { critical: dist.critical || 0, high: dist.high || 0, medium: dist.medium || 0, low: dist.low || 0 };
    const policyRecords = type === 'policies' ? policiesFor(records) : null;
    let metrics = [], sections = [], rows = [], limitation = '';

    if (type === 'executive') {
      const exec = executiveFor(records);
      const m = exec.metrics;
      metrics = [makeMetric('Overall scan posture', `${m.compliance.score}%`, `${m.compliance.passed} passed of ${m.compliance.evaluated} evaluated checks`), makeMetric('Findings', m.total), makeMetric('Open findings', m.open), makeMetric('High open', m.highOpen), makeMetric('Critical', m.critical), makeMetric('Resources', resources.length)];
      sections.push({ title: 'Executive summary', text: exec.summary });
      sections.push({ title: 'Risk distribution', rows: [['Critical', risk.critical], ['High', risk.high], ['Medium', risk.medium], ['Low', risk.low]] });
      sections.push({ title: 'Cloud visibility', rows: clouds.map((cloud) => [cloud.cloud, cloud.available ? `${cloud.findingCount} findings` : 'No scan data available']) });
      const domains = [...new Set(records.map(domainLabel))].sort();
      sections.push({ title: 'Observed security domains', rows: domains.length ? domains.map((domain) => [domain, records.filter((finding) => domainLabel(finding) === domain).length + ' findings']) : [['Domains', 'No scan data available']] });
      sections.push({ title: 'Priority risks', items: exec.risks.map((item) => `${item.severity} · ${item.title} · ${item.findings.length} findings across ${item.resourceCount} resources`) });
      sections.push({ title: 'Recommended actions', items: exec.recommendations.map((item) => `${item.title} — ${item.reason}`) });
      rows = exec.risks.map((item) => ({ severity: item.severity, finding: item.title, domain: item.domain, findings: item.findings.length, resources: item.resourceCount }));
    } else if (type === 'findings') {
      metrics = [makeMetric('Total findings', shared.calcTotalFindings(records)), makeMetric('Open findings', shared.calcOpenFindings(records)), makeMetric('Critical', risk.critical), makeMetric('High', risk.high), makeMetric('Medium', risk.medium), makeMetric('Low', risk.low), makeMetric('Resources', resources.length)];
      sections.push({ title: 'Severity distribution', rows: [['Critical', risk.critical], ['High', risk.high], ['Medium', risk.medium], ['Low', risk.low]] });
      sections.push({ title: 'Findings by cloud', rows: clouds.map((cloud) => [cloud.cloud, cloud.available ? `${cloud.findingCount} findings` : 'No scan data available']) });
      rows = records.map((f) => ({ finding_id: f.finding_id || '', finding: f.finding || '', cloud: shared.normalizeCloud(f.cloud), domain: domainLabel(f), severity: shared.normalizeSeverity(f.severity), status: shared.normalizeStatus(f.status), resource_type: f.resource_type || '', resource_id: f.resource_id || '', risk_score: f.risk_score ?? '', detected_at: f.detected_at || '' }));
    } else if (type === 'cloud') {
      const providerAvailability = new Map(cloudDistribution(allFindings).map((cloud) => [cloud.cloud, cloud.available]));
      const selectedClouds = (filters.cloud === 'all' ? clouds : clouds.filter((cloud) => cloud.cloud === filters.cloud)).map((cloud) => ({ ...cloud, available: providerAvailability.get(cloud.cloud) || false }));
      metrics = [makeMetric('Clouds with data', selectedClouds.filter((cloud) => cloud.available).length), makeMetric('Findings in scope', records.length), makeMetric('Open findings', shared.calcOpenFindings(records)), makeMetric('Resources', resources.length)];
      sections.push({ title: 'Provider posture', rows: selectedClouds.map((cloud) => {
        if (!cloud.available) return [cloud.cloud, 'No scan data available'];
        const scoped = records.filter((f) => shared.normalizeCloud(f.cloud) === cloud.cloud);
        if (!scoped.length) return [cloud.cloud, 'No findings match the selected filters'];
        const providerResources = inventoryFor(scoped);
        const providerRisk = shared.getSeverityDistribution(scoped);
        return [cloud.cloud, `${scoped.length} findings · ${shared.calcOpenFindings(scoped)} open · ${providerResources.length} resources · Critical ${providerRisk.critical} / High ${providerRisk.high} / Medium ${providerRisk.medium} / Low ${providerRisk.low}`];
      }) });
      rows = selectedClouds.map((cloud) => {
        const scoped = records.filter((f) => shared.normalizeCloud(f.cloud) === cloud.cloud);
        const providerRisk = shared.getSeverityDistribution(scoped);
        if (!cloud.available) return { cloud: cloud.cloud, data_available: false, status: 'No scan data available' };
        if (!scoped.length) return { cloud: cloud.cloud, data_available: true, findings: 0, open: 0, resources: 0, critical: 0, high: 0, medium: 0, low: 0, status: 'No findings match the selected filters' };
        return { cloud: cloud.cloud, data_available: true, findings: scoped.length, open: shared.calcOpenFindings(scoped), resources: inventoryFor(scoped).length, ...providerRisk };
      });
    } else if (type === 'compliance') {
      const generic = shared.getComplianceData(records).generic;
      metrics = [makeMetric('Generic scan posture', `${generic.score}%`, 'Not a framework compliance score'), makeMetric('Passed', generic.passed), makeMetric('Evaluated', generic.evaluated), makeMetric('Attention', generic.evaluated - generic.passed)];
      sections.push({ title: 'Framework mapping status', text: 'Framework mappings unavailable. CIS, ISO 27001, SOC 2, and NIST are Not Mapped in the current findings data.' });
      sections.push({ title: 'Posture definition', text: 'Generic posture is calculated by CSPMShared from evaluated findings. INFO records are excluded by the shared calculation.' });
      rows = [['CIS', 'Not Mapped'], ['ISO 27001', 'Not Mapped'], ['SOC 2', 'Not Mapped'], ['NIST', 'Not Mapped']].map(([framework, status]) => ({ framework, status }));
      limitation = 'This report does not indicate certification or regulatory compliance.';
    } else if (type === 'inventory') {
      const count = (key) => resources.reduce((sum, resource) => sum + (Number(resource[key]) || 0), 0);
      metrics = [makeMetric('Resources', resources.length), makeMetric('Resource types', new Set(resources.map((r) => r.resource_type)).size), makeMetric('Open findings', count('open_findings')), makeMetric('High-risk resources', resources.filter((r) => ['Critical Risk', 'High Risk'].includes(r.status)).length)];
      const resourceClouds = new Map(); resources.forEach((r) => r.clouds.forEach((cloud) => resourceClouds.set(cloud, (resourceClouds.get(cloud) || 0) + 1)));
      const types = new Map(); resources.forEach((r) => types.set(r.resource_type, (types.get(r.resource_type) || 0) + 1));
      sections.push({ title: 'Resources by cloud', rows: [...resourceClouds] });
      sections.push({ title: 'Resource types', rows: [...types].sort((a, b) => b[1] - a[1]) });
      sections.push({ title: 'Resources', table: { headers: ['Resource', 'Type', 'Cloud', 'Open', 'Highest severity', 'Status', 'Last seen'], rows: resources.map((r) => [r.resource_id, r.resource_type, r.clouds.join(', '), r.open_findings, r.highest_severity || 'Not recorded', r.status, r.last_seen || 'Not recorded']) } });
      rows = resources.map((r) => ({ resource_id: r.resource_id, resource_type: r.resource_type, clouds: r.clouds, domains: r.domains, findings: r.finding_count, open: r.open_findings, highest_severity: r.highest_severity, status: r.status, last_seen: r.last_seen }));
    } else if (type === 'policies') {
      metrics = [makeMetric('Observed policies', policyRecords.length), makeMetric('With open findings', policyRecords.filter((p) => p.openCount > 0).length), makeMetric('Open findings', policyRecords.reduce((sum, p) => sum + p.openCount, 0)), makeMetric('Resources affected', new Set(policyRecords.flatMap((p) => [...p.resourceKeys])).size)];
      sections.push({ title: 'Policy data source', text: 'Observed Policies derived from current finding IDs. The full scanner policy catalog is not connected to dashboard evaluations.' });
      sections.push({ title: 'Observed policies', table: { headers: ['Policy', 'Observed ID', 'Cloud', 'Domain', 'Severity', 'Findings', 'Open', 'Resources', 'Last observed'], rows: policyRecords.map((p) => [p.name, p.id || 'Not recorded', p.clouds.join(', '), p.domains.join(', '), p.severity, p.findingCount, p.openCount, p.resources, p.lastObserved == null ? 'Not recorded' : new Date(p.lastObserved).toISOString()]) } });
      rows = policyRecords.map((p) => ({ name: p.name, observed_id: p.id, clouds: p.clouds, domains: p.domains, severity: p.severity, findings: p.findingCount, open: p.openCount, resources: p.resources, status: 'Observed', last_observed: p.lastObserved == null ? null : new Date(p.lastObserved).toISOString() }));
      limitation = 'Policy metadata, enablement state, and a complete policy catalog are unavailable.';
    }
    return { title, type, generatedAt, source: 'CSPM current data', scope, frameworkMappings: 'Unavailable', totalRecords: records.length, metrics, sections, rows, rawFindings: records, limitation };
  }
  function dateLabel(filters) {
    if (filters.dateRange === '7') return 'Last 7 days';
    if (filters.dateRange === '30') return 'Last 30 days';
    if (filters.dateRange === 'custom') return `${filters.dateFrom || 'Start'} to ${filters.dateTo || 'End'}`;
    return 'All available data';
  }
  function reportAvailability(type, records) {
    if (type === 'policies') return policiesFor(records).length > 0;
    return records.length > 0;
  }
  function currentReport() {
    const scoped = buildReportScope(allFindings, state);
    if (!scoped.valid) return { scope: scoped, data: null };
    return { scope: scoped, data: scoped.records.length ? buildReportData(state.type, scoped.records) : null };
  }
  function renderCoverage() {
    const clouds = cloudDistribution(allFindings);
    const resources = inventoryFor(allFindings);
    const domains = [...new Set(allFindings.map(domainLabel))].sort();
    const knownDomains = ['IAM', 'Network', 'Data', 'Compliance', 'AI'];
    $('reportsCoverageBadges').innerHTML = `<span class="report-coverage-chip"><strong>${allFindings.length}</strong> findings</span><span class="report-coverage-chip"><strong>${resources.length}</strong> monitored resources</span>${clouds.map((cloud) => `<span class="report-coverage-chip ${cloud.available ? 'is-available' : 'is-awaiting'}"><span aria-hidden="true">${window.CSPM_ICONS[cloud.cloud.toLowerCase()] || window.CSPM_ICONS.cloud}</span><strong>${esc(cloud.cloud)}</strong> ${cloud.available ? `${cloud.findingCount} findings` : 'Awaiting scan data'}</span>`).join('')}<span class="report-coverage-domains"><strong>Available domains:</strong> ${domains.length ? domains.map(esc).join(', ') : 'None'}</span><span class="report-coverage-domains"><strong>Awaiting:</strong> ${knownDomains.filter((domain) => !domains.includes(domain)).map(esc).join(', ') || 'None'}</span>`;
    const cloudsInData = [...new Set(allFindings.map((finding) => shared.normalizeCloud(finding.cloud)))];
    fillSelect('reportCloud', [{ value: 'all', label: 'All clouds' }, ...['AWS', 'Azure', 'GCP'].map((cloud) => ({ value: cloud, label: cloud })), ...cloudsInData.filter((cloud) => !['AWS', 'Azure', 'GCP'].includes(cloud)).map((cloud) => ({ value: cloud, label: cloud }))], state.cloud);
    fillSelect('reportDomain', [{ value: 'all', label: 'All domains' }, ...domains.map((domain) => ({ value: domain, label: domain }))], state.domain);
    const severities = [...new Set(allFindings.map((finding) => shared.normalizeSeverity(finding.severity)))].sort((a, b) => ({ CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1, PASS: 0 }[b] - ({ CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1, PASS: 0 }[a])));
    fillSelect('reportSeverity', [{ value: 'all', label: 'All severities' }, ...severities.map((value) => ({ value, label: severityName(value) }))], state.severity);
    const statuses = [...new Set(allFindings.map((finding) => shared.normalizeStatus(finding.status)))].sort();
    fillSelect('reportStatus', [{ value: 'all', label: 'All statuses' }, ...statuses.map((value) => ({ value, label: value }))], state.status);
  }
  function fillSelect(id, options, selected) {
    $(id).innerHTML = options.map((option) => `<option value="${esc(option.value)}">${esc(option.label)}</option>`).join('');
    $(id).value = selected;
  }
  function renderCards() {
    $('reportTypeGrid').innerHTML = reportTypes.map((type, index) => {
      const selected = type.id === state.type;
      const available = reportAvailability(type.id, allFindings);
      return `<button class="report-type-card ${type.id === 'executive' ? 'is-primary' : ''} ${selected ? 'is-selected' : ''}" type="button" data-report-type="${type.id}" aria-pressed="${selected}" style="--report-delay:${index * 35}ms"><span class="report-type-icon" data-cspm-icon="${type.icon}" aria-hidden="true">${window.CSPM_ICONS[type.icon] || ''}</span><span class="report-type-copy"><strong>${esc(type.title)}</strong><small>${esc(type.description)}</small></span><span class="report-type-availability" data-available="${available}">${available ? 'Available' : 'No source data'}</span><span class="report-type-select" aria-hidden="true">${selected ? window.CSPM_ICONS.activity : window.CSPM_ICONS.chevronDown}</span></button>`;
    }).join('');
  }
  function renderSummaryMetrics(data) {
    return data.metrics.map((metric, index) => `<div class="report-summary-metric" style="--metric-delay:${index * 25}ms"><span>${esc(metric.label)}</span><strong>${esc(metric.value)}</strong>${metric.note ? `<small>${esc(metric.note)}</small>` : ''}</div>`).join('');
  }
  function renderSection(section) {
    let content = '';
    if (section.text) content = `<p>${esc(section.text)}</p>`;
    if (section.rows) content = `<dl class="report-detail-list">${section.rows.map(([label, value]) => `<div><dt>${esc(label)}</dt><dd>${esc(value)}</dd></div>`).join('')}</dl>`;
    if (section.items) content = section.items.length ? `<ul class="report-detail-bullets">${section.items.map((item) => `<li>${esc(item)}</li>`).join('')}</ul>` : '<p>No items available in this scope.</p>';
    if (section.table) content = renderTable(section.table);
    return `<section class="report-detail-section"><h3>${esc(section.title)}</h3>${content}</section>`;
  }
  function renderTable(table) {
    return `<div class="report-data-table-scroll" tabindex="0" aria-label="Scrollable ${esc(table.headers.join(' '))} table"><table class="report-data-table"><thead><tr>${table.headers.map((header) => `<th scope="col">${esc(header)}</th>`).join('')}</tr></thead><tbody>${table.rows.length ? table.rows.map((row) => `<tr>${row.map((cell) => `<td>${esc(cell == null || cell === '' ? 'Not recorded' : cell)}</td>`).join('')}</tr>`).join('') : `<tr><td colspan="${table.headers.length}">No records in this scope.</td></tr>`}</tbody></table></div>`;
  }
  function findingsTable(records) {
    return renderTable({ headers: ['ID', 'Finding', 'Cloud', 'Domain', 'Severity', 'Status', 'Resource', 'Detected'], rows: records.map((f) => [f.finding_id || 'Not recorded', f.finding || 'Untitled finding', shared.normalizeCloud(f.cloud), domainLabel(f), severityName(shared.normalizeSeverity(f.severity)), shared.normalizeStatus(f.status), [f.resource_type, f.resource_id].filter(Boolean).join(' · ') || 'Not recorded', f.detected_at || 'Not recorded']) });
  }
  function renderPreview() {
    const type = reportTypes.find((item) => item.id === state.type) || reportTypes[0];
    let scope, data, previewFailed = false;
    try { ({ scope, data } = currentReport()); }
    catch (_) { scope = { valid: false, records: [] }; data = null; previewFailed = true; }
    $('reportPreviewTitle').textContent = type.title;
    $('reportPreviewDescription').textContent = type.description;
    $('reportScopeLabel').textContent = `${scopeLabel()} · ${dateLabel(state)}`;
    $('reportCustomDates').hidden = state.dateRange !== 'custom';
    $('reportSeverityWrap').hidden = !['findings', 'cloud', 'inventory', 'policies'].includes(state.type);
    $('reportStatusWrap').hidden = !['findings', 'inventory', 'policies'].includes(state.type);
    const invalidDate = !scope.valid;
    const empty = !data || !reportAvailability(state.type, scope.records);
    $('reportEmptyState').hidden = !(invalidDate || empty);
    $('reportEmptyState').textContent = previewFailed ? 'Report preview is unavailable. Retry report generation.' : invalidDate ? 'Select a valid custom date range to preview this report.' : 'No CSPM data available for this report scope.';
    $('reportPreviewBody').innerHTML = data ? `${renderSummaryMetrics(data)}${data.sections.map(renderSection).join('')}${state.type === 'findings' ? `<section class="report-detail-section"><h3>Finding records (${scope.records.length})</h3>${findingsTable(scope.records)}</section>` : ''}${data.limitation ? `<p class="report-limitation">${esc(data.limitation)}</p>` : ''}` : '';
    if (!state.generatedAt) $('reportGeneratedAt').textContent = 'Not generated — preview only';
    $('reportPreviewStatus').textContent = state.generatedAt ? 'Generated' : 'Preview';
    $('reportPreviewStatus').dataset.state = state.generatedAt ? 'generated' : 'preview';
    $('reportGenerate').disabled = !allFindings.length || !scope.valid || !scope.records.length || state.busy;
    $('reportDownloadJson').disabled = !state.generatedSnapshot || state.busy;
    $('reportDownloadCsv').disabled = !state.generatedSnapshot || state.busy;
    $('reportPrint').disabled = !state.generatedSnapshot || state.busy;
    $('reportPreviewPanel').classList.toggle('has-generated-report', Boolean(state.generatedSnapshot));
  }
  function scopeLabel() {
    const bits = [state.cloud === 'all' ? 'All clouds' : state.cloud, state.domain === 'all' ? 'All domains' : state.domain];
    if (state.severity !== 'all' && !['executive', 'compliance'].includes(state.type)) bits.push(severityName(state.severity));
    if (state.status !== 'all' && ['findings', 'inventory', 'policies'].includes(state.type)) bits.push(state.status);
    return bits.join(' · ');
  }
  function invalidateGenerated() {
    state.generatedAt = null; state.generatedSnapshot = null; $('reportGeneratedAt').textContent = 'Not generated — preview only'; $('reportStatusMessage').textContent = '';
    renderPreview();
  }
  function renderAll() { renderCards(); renderPreview(); }
  function csvCell(value) { return `"${String(value ?? '').replace(/"/g, '""')}"`; }
  function csvFor(snapshot) {
    const report = snapshot.data;
    let headers, rows;
    if (snapshot.type === 'findings') {
      headers = ['finding_id', 'finding', 'cloud', 'domain', 'severity', 'status', 'resource_type', 'resource_id', 'risk_score', 'detected_at'];
      rows = report.rows.map((row) => headers.map((header) => row[header] ?? ''));
    } else if (snapshot.type === 'inventory') {
      headers = ['resource_id', 'resource_type', 'clouds', 'domains', 'findings', 'open', 'highest_severity', 'status', 'last_seen'];
      rows = report.rows.map((row) => headers.map((header) => Array.isArray(row[header]) ? row[header].join('; ') : row[header] ?? ''));
    } else if (snapshot.type === 'policies') {
      headers = ['name', 'observed_id', 'clouds', 'domains', 'severity', 'findings', 'open', 'resources', 'status', 'last_observed'];
      rows = report.rows.map((row) => headers.map((header) => Array.isArray(row[header]) ? row[header].join('; ') : row[header] ?? ''));
    } else if (snapshot.type === 'cloud') {
      headers = ['cloud', 'data_available', 'findings', 'open', 'resources', 'critical', 'high', 'medium', 'low', 'status'];
      rows = report.rows.map((row) => headers.map((header) => row[header] ?? ''));
    } else {
      headers = ['section', 'value'];
      rows = report.metrics.map((metric) => [metric.label, metric.value]);
      if (snapshot.type === 'compliance') rows.push(...report.rows.map((row) => [row.framework, row.status]));
    }
    return [headers, ...rows].map((row) => row.map(csvCell).join(',')).join('\r\n');
  }
  function download(filename, content, mime) {
    const url = URL.createObjectURL(new Blob([content], { type: `${mime};charset=utf-8` }));
    const link = document.createElement('a'); link.href = url; link.download = filename; document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1200);
  }
  function buildSnapshot() {
    const scoped = buildReportScope(allFindings, state);
    if (!scoped.valid) throw new Error('Select a valid custom date range.');
    if (!scoped.records.length || !reportAvailability(state.type, scoped.records)) throw new Error('No CSPM data available for this report scope.');
    state.generatedAt = new Date().toISOString();
    const filters = {
      type: state.type, cloud: state.cloud, domain: state.domain,
      severity: ['findings', 'cloud', 'inventory', 'policies'].includes(state.type) ? state.severity : 'all',
      status: ['findings', 'inventory', 'policies'].includes(state.type) ? state.status : 'all',
      dateRange: state.dateRange, dateFrom: $('reportDateFrom').value, dateTo: $('reportDateTo').value,
    };
    const data = buildReportData(state.type, scoped.records, filters);
    data.generatedAt = state.generatedAt;
    data.scope = { ...data.scope, generatedDateRange: dateLabel(filters) };
    state.generatedSnapshot = { type: state.type, filters, data };
    return state.generatedSnapshot;
  }
  async function generateReport() {
    if (state.busy) return;
    state.busy = true; $('reportGenerate').setAttribute('aria-busy', 'true'); $('reportGenerate').innerHTML = '<span class="report-spinner" aria-hidden="true"></span> Generating report…'; $('reportStatusMessage').textContent = 'Generating report…'; renderPreview();
    await new Promise((resolve) => setTimeout(resolve, 140));
    try {
      const snapshot = buildSnapshot();
      $('reportGeneratedAt').textContent = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(snapshot.data.generatedAt));
      $('reportPreviewStatus').textContent = 'Generated'; $('reportStatusMessage').textContent = `${snapshot.data.title} generated from ${snapshot.data.totalRecords} current CSPM findings.`;
    } catch (_) {
      state.generatedSnapshot = null; state.generatedAt = null;
      $('reportStatusMessage').innerHTML = 'Unable to generate report. Check the selected scope and retry. <button id="reportRetryGeneration" class="btn btn-quiet" type="button">Retry</button>';
    } finally {
      state.busy = false; $('reportGenerate').removeAttribute('aria-busy'); $('reportGenerate').innerHTML = `<span data-cspm-icon="reports" aria-hidden="true">${window.CSPM_ICONS.reports}</span> Generate report`; renderPreview();
    }
  }
  function downloadJson() {
    if (!state.generatedSnapshot) return;
    const { data, type, filters } = state.generatedSnapshot;
    const payload = { report: data.title, generated: data.generatedAt, dataSource: data.source, scope: data.scope, filters, frameworkMappings: data.frameworkMappings, metrics: data.metrics, results: data.rows, findings: data.rawFindings };
    download(`cspm-${type}-report-${data.generatedAt.slice(0, 10)}.json`, JSON.stringify(payload, null, 2), 'application/json');
    $('reportStatusMessage').textContent = 'Downloaded scoped report data as JSON.';
  }
  function downloadCsv() {
    if (!state.generatedSnapshot) return;
    const snapshot = state.generatedSnapshot;
    download(`cspm-${snapshot.type}-report-${snapshot.data.generatedAt.slice(0, 10)}.csv`, csvFor(snapshot), 'text/csv');
    $('reportStatusMessage').textContent = 'Downloaded scoped report data as CSV.';
  }
  function refreshData() {
    shared = window.CSPMShared;
    if (!shared || !shared.hasDataSource() || typeof shared.getFindings !== 'function') throw new Error('CSPM data is unavailable');
    const source = shared.getFindings(); if (!Array.isArray(source)) throw new Error('CSPM data is invalid');
    allFindings = source.filter((finding) => finding && typeof finding === 'object');
    state.generatedAt = null; state.generatedSnapshot = null;
    renderCoverage(); renderAll(); $('reportsError').hidden = true; $('reportsContent').setAttribute('aria-busy', 'false');
    document.querySelectorAll('.reports-coverage,.reports-types-section,.reports-workspace,.reports-backend-notes').forEach((section) => { section.hidden = false; });
  }
  function showError() {
    $('reportsContent').setAttribute('aria-busy', 'false'); $('reportsError').hidden = false;
    document.querySelectorAll('.reports-coverage,.reports-types-section,.reports-workspace,.reports-backend-notes').forEach((section) => { section.hidden = true; });
  }
  function init() {
    try { refreshData(); } catch (error) { console.error('Reports could not load current CSPM data:', error); showError(); }
    $('reportTypeGrid').addEventListener('click', (event) => {
      const card = event.target.closest('[data-report-type]'); if (!card) return;
      state.type = card.dataset.reportType; invalidateGenerated(); renderCards();
    });
    ['reportCloud', 'reportDomain', 'reportSeverity', 'reportStatus', 'reportDateRange', 'reportDateFrom', 'reportDateTo'].forEach((id) => $(id).addEventListener('change', () => {
      state.cloud = $('reportCloud').value; state.domain = $('reportDomain').value; state.severity = $('reportSeverity').value; state.status = $('reportStatus').value; state.dateRange = $('reportDateRange').value; state.dateFrom = $('reportDateFrom').value; state.dateTo = $('reportDateTo').value; invalidateGenerated();
    }));
    $('reportGenerate').addEventListener('click', generateReport);
    $('reportStatusMessage').addEventListener('click', (event) => { if (event.target.closest('#reportRetryGeneration')) generateReport(); });
    $('reportDownloadJson').addEventListener('click', downloadJson);
    $('reportDownloadCsv').addEventListener('click', downloadCsv);
    $('reportPrint').addEventListener('click', () => { if (state.generatedSnapshot) window.print(); });
    $('reportsRefresh').addEventListener('click', () => { try { refreshData(); $('reportStatusMessage').textContent = 'Report data refreshed from the shared CSPM source.'; } catch (_) { showError(); } });
    $('reportsRetry').addEventListener('click', () => { try { refreshData(); } catch (_) { showError(); } });
    document.addEventListener('keydown', (event) => { if (event.key === '/' && !/INPUT|TEXTAREA|SELECT/.test(document.activeElement?.tagName || '')) { event.preventDefault(); $('reportCloud').focus(); } });
    $('reportDateFrom').addEventListener('change', () => { $('reportDateTo').min = $('reportDateFrom').value; });
    $('reportDateTo').addEventListener('change', () => { $('reportDateFrom').max = $('reportDateTo').value; });
  }
  window.CSPMReports = Object.freeze({ getReportTypes, buildReportScope, buildReportData });
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init, { once: true }); else init();
})();
