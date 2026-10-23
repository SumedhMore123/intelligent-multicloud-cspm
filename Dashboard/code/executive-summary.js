/* Executive Summary calculations and rendering. All source metrics come from CSPMShared. */
(function () {
  'use strict';

  const THRESHOLDS = Object.freeze({ healthy: 70, attention: 50 });
  const SEVERITY_ORDER = Object.freeze({ CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 });
  const SEVERITY_NAMES = Object.freeze({ CRITICAL: 'Critical', HIGH: 'High', MEDIUM: 'Medium', LOW: 'Low' });
  const ICONS = window.CSPM_ICONS || {};

  function escapeHTML(value) {
    return String(value ?? '').replace(/[&<>"']/g, (character) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    })[character]);
  }

  function getPostureState(score) {
    if (score >= THRESHOLDS.healthy) return { key: 'healthy', label: 'Healthy' };
    if (score >= THRESHOLDS.attention) return { key: 'attention', label: 'Needs Attention' };
    return { key: 'high-risk', label: 'High Risk' };
  }

  function calculateExecutiveMetrics(findings) {
    const shared = window.CSPMShared;
    const compliance = shared.getComplianceData(findings);
    const postureScore = shared.calcComplianceScore(findings);
    const severity = shared.getSeverityDistribution(findings);
    const cloud = shared.getFindingsByCloud(findings);
    return {
      total: shared.calcTotalFindings(findings),
      open: shared.calcOpenFindings(findings),
      critical: shared.calcCriticalFindings(findings),
      highOpen: shared.calcHighFindings(findings),
      resources: shared.calcMonitoredResources(findings),
      risk: severity,
      compliance: { ...compliance.generic, score: postureScore },
      hasFrameworkMappings: compliance.frameworks.length > 0,
      cloud,
      domains: {
        iam: shared.getModuleStats(findings, 'IAM'),
        network: shared.getModuleStats(findings, 'NETWORK'),
        data: shared.getModuleStats(findings, 'DATA'),
      },
    };
  }

  function generateExecutivePostureSummary(findings, metrics = calculateExecutiveMetrics(findings)) {
    if (!findings.length) return 'No security findings are available in the current dataset. Awaiting scan data.';
    const leadingDomain = [
      ['IAM Security', metrics.domains.iam.openCount],
      ['Network Security', metrics.domains.network.openCount],
      ['Data Security', metrics.domains.data.openCount],
    ].sort((a, b) => b[1] - a[1])[0];
    if (metrics.critical > 0) {
      return `${metrics.critical} critical findings are present; ${metrics.open} findings are open, including ${metrics.highOpen} high-severity findings. Review the highest-priority items below${leadingDomain[1] ? `; open findings are concentrated in ${leadingDomain[0]}` : ''}.`;
    }
    if (metrics.highOpen > 0) {
      return `${metrics.open} open findings were identified, including ${metrics.highOpen} high-severity findings.${leadingDomain[1] ? ` Current open findings are concentrated in ${leadingDomain[0]}.` : ''}`;
    }
    if (metrics.open > 0) return `${metrics.open} findings remain open in the current dataset; no open high or critical findings were identified.`;
    return 'No findings are currently marked open in the available scan data.';
  }

  function getPriorityRisks(findings) {
    const shared = window.CSPMShared;
    const groups = new Map();
    findings.filter((finding) => shared.isOpenFinding(finding) && ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(shared.normalizeSeverity(finding.severity))).forEach((finding) => {
      const domain = shared.normalizeDomain(finding) || 'Unspecified domain';
      const title = String(finding.finding || finding.rule_name || 'Finding details unavailable').trim();
      const key = `${domain.toLowerCase()}\u0000${title.toLowerCase()}`;
      if (!groups.has(key)) groups.set(key, { title, domain, findings: [], resources: new Set(), severity: 'LOW', maxRisk: 0 });
      const group = groups.get(key);
      group.findings.push(finding);
      const resource = finding.resource_id ? `${finding.resource_type || ''}::${finding.resource_id}` : `finding::${finding.finding_id || group.findings.length}`;
      group.resources.add(resource);
      const severity = shared.normalizeSeverity(finding.severity);
      if (SEVERITY_ORDER[severity] > SEVERITY_ORDER[group.severity]) group.severity = severity;
      group.maxRisk = Math.max(group.maxRisk, Number(finding.risk_score) || 0);
    });
    return [...groups.values()].map((group) => ({ ...group, resourceCount: group.resources.size }))
      .sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] || b.maxRisk - a.maxRisk || b.findings.length - a.findings.length)
      .slice(0, 4);
  }

  function getDomainPosture(metrics) {
    const complianceState = metrics.compliance.evaluated ? getPostureState(metrics.compliance.score).key : 'awaiting';
    return [
      { name: 'IAM Security', stats: metrics.domains.iam, state: metrics.domains.iam.findingCount ? 'attention' : 'awaiting', detail: `${metrics.domains.iam.findingCount} findings in current data`, open: metrics.domains.iam.openCount, href: 'iam.html' },
      { name: 'Network Security', stats: metrics.domains.network, state: metrics.domains.network.findingCount ? 'attention' : 'awaiting', detail: metrics.domains.network.findingCount ? `${metrics.domains.network.findingCount} findings in current data` : 'No network scan records available', open: metrics.domains.network.openCount },
      { name: 'Data Security', stats: metrics.domains.data, state: metrics.domains.data.findingCount ? 'attention' : 'awaiting', detail: metrics.domains.data.findingCount ? `${metrics.domains.data.findingCount} findings in current data` : 'No data scan records available', open: metrics.domains.data.openCount },
      { name: 'Compliance', state: complianceState, detail: metrics.compliance.evaluated ? `${metrics.compliance.score}% overall scan-result posture` : 'Awaiting evaluated scan data', open: null, value: metrics.compliance.evaluated ? `${metrics.compliance.score}%` : '—' },
      { name: 'AI Intelligence', state: 'coming', detail: 'Analysis capability is not available yet', open: null, value: '—' },
    ];
  }

  function getCloudPosture(metrics) {
    return ['AWS', 'Azure', 'GCP'].map((name) => ({
      name,
      count: metrics.cloud[name] || 0,
      state: metrics.cloud[name] ? 'Available' : 'No scan records',
      icon: ICONS[name.toLowerCase()] || ICONS.cloud,
    }));
  }

  function getExecutiveRecommendations(findings, priorityRisks) {
    const open = findings.filter((finding) => window.CSPMShared.isOpenFinding(finding));
    const recommendations = [
      {
        test: (finding) => /wildcard permissions|excessive permissions/i.test(finding.finding || ''),
        title: 'Review broad IAM permissions',
        area: 'IAM Security',
      },
      {
        test: (finding) => /trusts an external|trust policy allows any aws account/i.test(finding.finding || ''),
        title: 'Review external account trust policies',
        area: 'IAM Security',
      },
      {
        test: (finding) => /mfa is not enabled|without mfa/i.test(finding.finding || ''),
        title: 'Enable MFA for affected identities',
        area: 'IAM Security',
      },
      {
        test: (finding) => /multiple active access keys|90-day rotation|90 day rotation/i.test(finding.finding || ''),
        title: 'Review access-key rotation and use',
        area: 'IAM Security',
      },
    ];
    const generated = recommendations.map((recommendation) => {
      const related = open.filter(recommendation.test);
      if (!related.length) return null;
      const resources = new Set(related.map((finding) => `${finding.resource_type || ''}::${finding.resource_id || finding.finding_id || ''}`));
      const severity = related.reduce((top, finding) => SEVERITY_ORDER[window.CSPMShared.normalizeSeverity(finding.severity)] > SEVERITY_ORDER[top] ? window.CSPMShared.normalizeSeverity(finding.severity) : top, 'LOW');
      const sourceRules = [...new Set(related.map((finding) => finding.finding).filter(Boolean))];
      return {
        ...recommendation,
        count: related.length,
        resourceCount: resources.size,
        severity,
        reason: `${related.length} open finding${related.length === 1 ? '' : 's'} across ${resources.size} resource${resources.size === 1 ? '' : 's'} report ${sourceRules.slice(0, 2).join(' and ').toLowerCase()}.`,
        href: related.some((finding) => /iam|identity/i.test(window.CSPMShared.normalizeDomain(finding))) ? 'iam.html' : 'index.html#latestFindingsPanel',
      };
    }).filter(Boolean);
    if (generated.length) return generated.slice(0, 4);
    return priorityRisks.slice(0, 3).map((risk) => ({
      title: `Review ${risk.title.charAt(0).toLowerCase()}${risk.title.slice(1)}`,
      area: risk.domain,
      count: risk.findings.length,
      resourceCount: risk.resourceCount,
      severity: risk.severity,
      reason: `${risk.findings.length} open finding${risk.findings.length === 1 ? '' : 's'} affect ${risk.resourceCount} resource${risk.resourceCount === 1 ? '' : 's'}.`,
      href: /iam|identity/i.test(risk.domain) ? 'iam.html' : 'index.html#latestFindingsPanel',
    }));
  }

  function getTrendPeriods(findings) {
    const keyFor = (finding) => finding.scan_id || finding.scan_date || finding.scan_timestamp || finding.scan_period || '';
    const periods = new Map();
    findings.forEach((finding) => {
      const key = keyFor(finding);
      if (key) {
        if (!periods.has(String(key))) periods.set(String(key), []);
        periods.get(String(key)).push(finding);
      }
    });
    return [...periods.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }

  function renderRiskRows(distribution) {
    const entries = [
      ['CRITICAL', distribution.critical],
      ['HIGH', distribution.high],
      ['MEDIUM', distribution.medium],
      ['LOW', distribution.low],
    ];
    const max = Math.max(1, ...entries.map(([, count]) => count));
    if (!distribution.total) return '<div class="exec-empty-note">No risk-severity findings are available in the current dataset.</div>';
    return `<div class="exec-risk-list" role="list">${entries.map(([severity, count]) => `<div class="exec-risk-row" role="listitem"><div class="exec-risk-label"><span>${SEVERITY_NAMES[severity]}</span><strong>${count}</strong></div><div class="exec-risk-track" aria-hidden="true"><div class="exec-risk-fill" data-severity="${severity.toLowerCase()}" style="width:${count / max * 100}%"></div></div></div>`).join('')}</div><p class="exec-priority-meta">PASS and INFO records are excluded from risk severity.</p>`;
  }

  function renderPriorities(risks) {
    if (!risks.length) return '<div class="exec-empty-note">No open risk findings require prioritization in the current data.</div>';
    return `<div class="exec-priority-list">${risks.map((risk, index) => {
      const href = /iam|identity/i.test(risk.domain) ? 'iam.html' : 'index.html#latestFindingsPanel';
      return `<article class="exec-priority-item"><span class="exec-priority-number">${String(index + 1).padStart(2, '0')}</span><div><div class="exec-priority-title">${escapeHTML(risk.title)}</div><div class="exec-priority-meta">${escapeHTML(risk.domain)} · ${risk.findings.length} open finding${risk.findings.length === 1 ? '' : 's'} across ${risk.resourceCount} affected resource${risk.resourceCount === 1 ? '' : 's'}</div><a class="exec-priority-link" href="${href}">Review in ${href === 'iam.html' ? 'IAM Security' : 'Dashboard'}</a></div><span class="exec-severity-pill" data-severity="${risk.severity.toLowerCase()}">${SEVERITY_NAMES[risk.severity]}</span></article>`;
    }).join('')}</div>`;
  }

  function renderDomainCards(domains) {
    return `<div class="exec-domain-grid">${domains.map((domain) => {
      const body = `<div class="exec-domain-name">${domain.name}</div>${domain.open === null ? `<div class="exec-domain-count">${escapeHTML(domain.value || '—')}</div>` : `<div class="exec-domain-count">${domain.open}</div>`}<div class="exec-domain-detail">${escapeHTML(domain.open === null ? domain.detail : `${domain.open} open · ${domain.detail}`)}</div><span class="exec-status-pill" data-state="${domain.state}">${domain.state === 'coming' ? 'Coming Soon' : domain.state === 'awaiting' ? 'Awaiting Data' : domain.state === 'attention' ? 'Monitoring' : 'Healthy'}</span>`;
      return domain.href ? `<a class="exec-domain-card" href="${domain.href}">${body}</a>` : `<div class="exec-domain-card">${body}</div>`;
    }).join('')}</div>`;
  }

  function renderCloudCards(clouds) {
    const max = Math.max(1, ...clouds.map((cloud) => cloud.count));
    return `<div class="exec-cloud-list">${clouds.map((cloud) => `<div class="exec-cloud-row" data-provider="${cloud.name}"><span class="exec-cloud-icon" aria-hidden="true">${cloud.icon}</span><div class="exec-cloud-info"><div class="exec-cloud-name">${cloud.name}</div><div class="exec-cloud-status">${cloud.count ? 'Scan records available' : 'No scan records in current data'}</div></div><span class="exec-cloud-count">${cloud.count}</span><div class="exec-cloud-track" aria-hidden="true"><div class="exec-cloud-fill" data-provider="${cloud.name}" style="width:${cloud.count / max * 100}%"></div></div></div>`).join('')}</div><p class="exec-priority-meta">Zero records do not establish that a provider is secure; scan coverage is not included in this dataset.</p>`;
  }

  function renderCompliance(metrics) {
    if (!metrics.compliance.evaluated) return '<div class="exec-empty-note">Awaiting evaluated scan data. No posture percentage is shown.</div>';
    const state = getPostureState(metrics.compliance.score);
    return `<div class="exec-compliance-score"><div class="exec-compliance-value" data-state="${state.key}">${metrics.compliance.score}%</div><div class="exec-compliance-copy"><strong>Overall scan-result posture</strong><span>${metrics.compliance.passed} passed of ${metrics.compliance.evaluated} evaluated records</span></div></div><div class="exec-framework-state"><strong>${metrics.hasFrameworkMappings ? 'Framework mappings available' : 'No framework control mappings configured'}</strong><span>${metrics.hasFrameworkMappings ? 'Framework-specific scores are not calculated by the current shared data layer.' : 'CIS, ISO 27001, SOC 2, and NIST scores are unavailable.'}</span></div>`;
  }

  function renderRecommendations(recommendations) {
    if (!recommendations.length) return '<div class="exec-empty-note">No findings-based recommendations are available for the current dataset.</div>';
    return `<div class="exec-recommendations">${recommendations.map((recommendation, index) => `<article class="exec-recommendation"><span class="exec-rec-index">${String(index + 1).padStart(2, '0')}</span><div><div class="exec-rec-title-row"><div class="exec-rec-title">${escapeHTML(recommendation.title)}</div><span class="exec-severity-pill" data-severity="${recommendation.severity.toLowerCase()}">${SEVERITY_NAMES[recommendation.severity]} Priority</span></div><div class="exec-rec-reason">${escapeHTML(recommendation.reason)}</div><div class="exec-rec-area">${escapeHTML(recommendation.area)}</div></div><a class="exec-rec-action" href="${recommendation.href}">View ${recommendation.href === 'iam.html' ? 'IAM' : 'findings'}</a></article>`).join('')}</div>`;
  }

  function getExecutiveSignals(metrics) {
    const signals = [];
    if (metrics.critical) signals.push({ tone: 'high', title: 'Critical findings', copy: `${metrics.critical} critical finding${metrics.critical === 1 ? '' : 's'} are present in the current dataset.` });
    else if (metrics.highOpen) signals.push({ tone: 'attention', title: 'High-severity exposure', copy: `${metrics.highOpen} high-severity findings are currently open.` });
    if (metrics.compliance.evaluated && metrics.compliance.score < THRESHOLDS.healthy) signals.push({ tone: 'attention', title: 'Posture needs attention', copy: `The current scan-result posture is ${metrics.compliance.score}%, below the ${THRESHOLDS.healthy}% healthy threshold used on this page.` });
    if (!metrics.domains.network.findingCount || !metrics.domains.data.findingCount) {
      const missing = [];
      if (!metrics.domains.network.findingCount) missing.push('network');
      if (!metrics.domains.data.findingCount) missing.push('data security');
      signals.push({ tone: 'neutral', title: 'Visibility gap', copy: `No ${missing.join(' or ')} scan records are available in the current dataset.` });
    }
    if (!metrics.hasFrameworkMappings) signals.push({ tone: 'neutral', title: 'Framework mappings unavailable', copy: 'Framework-specific control posture cannot be reported from the available data.' });
    return signals.slice(0, 4);
  }

  function renderTrend(findings) {
    const periods = getTrendPeriods(findings);
    if (periods.length < 2) return '<div class="exec-trend-empty">A posture trend will appear after multiple scan periods are available. Historical values are not present in the current dataset.</div>';
    const scores = periods.map(([label, periodFindings]) => ({ label, score: window.CSPMShared.getComplianceData(periodFindings).generic.score }));
    const points = scores.map((point, index) => `${30 + index * (540 / (scores.length - 1))},${120 - point.score}`).join(' ');
    return `<svg class="exec-trend-chart" viewBox="0 0 600 150" role="img" aria-label="Scan-result posture trend across ${scores.length} recorded scan periods"><line x1="30" y1="20" x2="570" y2="20" stroke="var(--border)"/><line x1="30" y1="70" x2="570" y2="70" stroke="var(--border)"/><line x1="30" y1="120" x2="570" y2="120" stroke="var(--border)"/><polyline class="exec-trend-line" points="${points}"/>${scores.map((point, index) => `<circle class="exec-trend-dot" cx="${30 + index * (540 / (scores.length - 1))}" cy="${120 - point.score}" r="4"><title>${escapeHTML(point.label)}: ${point.score}%</title></circle>`).join('')}<text x="0" y="24">100%</text><text x="4" y="124">0%</text></svg>`;
  }

  function renderExecutiveSummary() {
    const shared = window.CSPMShared;
    const content = document.getElementById('execContent');
    const loading = document.querySelector('.exec-loading');
    const summary = document.getElementById('execSummary');
    const error = document.getElementById('execError');
    if (!content || !loading || !summary || !error) return;
    try {
      if (!shared || typeof shared.getFindings !== 'function' || !shared.hasDataSource()) throw new Error('Shared CSPM findings are unavailable.');
      const findings = shared.getFindings();
      if (!Array.isArray(findings)) throw new Error('CSPM findings are not available as a list.');
      const metrics = calculateExecutiveMetrics(findings);
      const state = metrics.total ? getPostureState(metrics.compliance.score) : { key: 'awaiting', label: 'Awaiting Scan Data' };
      const risks = getPriorityRisks(findings);
      const domains = getDomainPosture(metrics);
      const clouds = getCloudPosture(metrics);
      const recommendations = getExecutiveRecommendations(findings, risks);
      const signals = getExecutiveSignals(metrics);
      const gauge = metrics.total ? `<div class="exec-gauge" data-state="${state.key}" style="--exec-angle:${metrics.compliance.score * 3.6}deg"><div class="exec-gauge-inner"><div class="exec-gauge-number">${metrics.compliance.score}<small>%</small></div><div class="exec-gauge-caption">Scan posture</div></div></div>` : '<div class="exec-gauge" data-state="awaiting"><div class="exec-gauge-inner"><div class="exec-gauge-number">—</div><div class="exec-gauge-caption">Awaiting data</div></div></div>';
      const metricsHTML = [
        ['Open Findings', metrics.open, ''],
        ['Critical Findings', metrics.critical, 'critical'],
        ['High Open', metrics.highOpen, 'high'],
        ['Monitored Resources', metrics.resources, ''],
      ].map(([label, value, tone]) => `<div class="exec-metric" ${tone ? `data-tone="${tone}"` : ''}><div class="exec-metric-label">${label}</div><strong class="exec-metric-value">${value}</strong></div>`).join('');
      const signalsHTML = signals.length ? `<div class="exec-signals">${signals.map((signal) => `<div class="exec-signal" data-tone="${signal.tone}"><span class="exec-signal-dot" aria-hidden="true"></span><div><div class="exec-signal-title">${escapeHTML(signal.title)}</div><div class="exec-signal-copy">${escapeHTML(signal.copy)}</div></div></div>`).join('')}</div>` : '<div class="exec-empty-note">No current executive signals.</div>';
      const html = `<div class="exec-overview">
        <section class="exec-hero" aria-labelledby="execHeroTitle"><div class="exec-gauge-wrap"><div class="exec-eyebrow">Overall Security Posture</div>${gauge}</div><div class="exec-hero-copy"><div class="exec-hero-heading"><h2 id="execHeroTitle">${state.label}</h2><span class="exec-status-pill" data-state="${state.key}">${state.label}</span></div><p class="exec-hero-summary">${escapeHTML(generateExecutivePostureSummary(findings, metrics))}</p><p class="exec-hero-footnote">${metrics.total ? `${metrics.total} total records · ${metrics.risk.total} risk-severity findings · ${metrics.compliance.passed} passed of ${metrics.compliance.evaluated} evaluated` : 'No security findings available · Awaiting scan data'}</p><div class="exec-hero-metrics">${metricsHTML}</div></div></section>
        <div class="exec-main-grid"><section class="exec-panel" aria-labelledby="execPriorityTitle"><div class="exec-section-heading"><div><h2 id="execPriorityTitle">Priority Risks</h2><p>Open risks grouped only by matching finding text and domain.</p></div></div>${renderPriorities(risks)}</section><section class="exec-panel" aria-labelledby="execRiskTitle"><div class="exec-section-heading"><div><h2 id="execRiskTitle">Risk Breakdown</h2><p>Current risk findings by severity</p></div></div>${renderRiskRows(metrics.risk)}</section></div>
        <section class="exec-section-spacer" aria-labelledby="execDomainsTitle"><div class="exec-section-heading"><div><h2 id="execDomainsTitle">Security Domain Posture</h2><p>Coverage and open findings from the shared scan records.</p></div></div>${renderDomainCards(domains)}</section>
        <div class="exec-support-grid"><section class="exec-panel" aria-labelledby="execCloudTitle"><div class="exec-section-heading"><div><h2 id="execCloudTitle">Cloud Security Posture</h2><p>Scan-record counts; zero records do not imply a secure provider.</p></div></div>${renderCloudCards(clouds)}</section><section class="exec-panel" aria-labelledby="execComplianceTitle"><div class="exec-section-heading"><div><h2 id="execComplianceTitle">Compliance Overview</h2><p>Canonical overall scan-result calculation.</p></div></div>${renderCompliance(metrics)}</section></div>
        <div class="exec-bottom-grid"><section class="exec-panel" aria-labelledby="execActionsTitle"><div class="exec-section-heading"><div><h2 id="execActionsTitle">Recommended Actions</h2><p>Actions derived from open finding patterns in the current data.</p></div></div>${renderRecommendations(recommendations)}</section><div class="exec-overview"><section class="exec-panel" aria-labelledby="execTrendTitle"><div class="exec-section-heading"><div><h2 id="execTrendTitle">Posture Trend</h2><p>Historical comparison requires scan-period data.</p></div></div><div class="exec-trend-wrap">${renderTrend(findings)}</div></section><section class="exec-panel" aria-labelledby="execSignalsTitle"><div class="exec-section-heading"><div><h2 id="execSignalsTitle">Executive Signals</h2><p>Current-state observations only; no historical change is inferred.</p></div></div>${signalsHTML}</section></div></div>
      </div>`;
      summary.innerHTML = html;
      summary.hidden = false;
      loading.hidden = true;
      error.hidden = true;
      content.setAttribute('aria-busy', 'false');
      animateMetricValues(summary);
      const status = document.getElementById('execStatus');
      if (status) status.textContent = `Executive summary updated. ${metrics.total} records, ${metrics.open} open findings, ${metrics.compliance.score}% scan-result posture.`;
    } catch (caught) {
      loading.hidden = true;
      summary.hidden = true;
      error.hidden = false;
      content.setAttribute('aria-busy', 'false');
      const status = document.getElementById('execStatus');
      if (status) status.textContent = 'Security posture data unavailable. Refresh to retry.';
      console.error('Executive Summary render failed:', caught);
    }
  }

  function animateMetricValues(root) {
    if (window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) return;
    const duration = 420;
    root.querySelectorAll('.exec-metric-value').forEach((element) => {
      const target = Number(element.textContent);
      if (!Number.isFinite(target) || target <= 0) return;
      const start = performance.now();
      const tick = (now) => {
        const progress = Math.min(1, (now - start) / duration);
        element.textContent = String(Math.round(target * (1 - Math.pow(1 - progress, 3))));
        if (progress < 1) requestAnimationFrame(tick);
      };
      element.textContent = '0';
      requestAnimationFrame(tick);
    });
  }

  window.CSPMExecutiveSummary = Object.freeze({
    calculateExecutiveMetrics,
    generateExecutivePostureSummary,
    getPriorityRisks,
    getDomainPosture,
    getCloudPosture,
    getExecutiveRecommendations,
    getTrendPeriods,
    renderExecutiveSummary,
  });

  const retryExecutiveSummary = () => {
    if (!window.CSPMShared || typeof window.CSPMShared.hasDataSource !== 'function' || !window.CSPMShared.hasDataSource()) window.location.reload();
    else renderExecutiveSummary();
  };
  document.getElementById('refreshBtn')?.addEventListener('click', retryExecutiveSummary);
  document.getElementById('execRetry')?.addEventListener('click', retryExecutiveSummary);
  renderExecutiveSummary();
})();
