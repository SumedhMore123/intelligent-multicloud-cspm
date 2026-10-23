// Cloud Security workspace, aggregated from the shared CSPM finding records.
(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const providers = [
    { name: 'AWS', icon: 'aws', tone: 'aws', environmentLabel: 'Account', environmentKeys: ['account_id', 'accountId', 'account', 'cloud_account_id'] },
    { name: 'Azure', icon: 'azure', tone: 'azure', environmentLabel: 'Subscription', environmentKeys: ['subscription_id', 'subscriptionId', 'subscription'] },
    { name: 'GCP', icon: 'gcp', tone: 'gcp', environmentLabel: 'Project', environmentKeys: ['project_id', 'projectId', 'project'] },
  ];
  const severityKeys = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const domainCatalog = [
    ['IAM', ['IAM', 'IDENTITY']], ['Network', ['NETWORK']], ['Data', ['DATA']],
    ['Compliance', ['COMPLIANCE']], ['AI', ['AI']],
  ];
  const state = { provider: 'all', query: '', severity: '', domain: '', status: '', page: 1, pageSize: window.CSPMSettings?.getCSPMSettings?.().tablePageSize || 20, cloudDrawer: null, drawerReturnFocus: null };
  let data = null;
  let scopedFindings = [];

  const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
  function getProvider(name) { return providers.find((provider) => provider.name === name) || { name, icon: 'cloud', tone: 'other', environmentLabel: 'Environments', environmentKeys: [] }; }
  function displayDomain(finding, shared) {
    const value = shared.normalizeDomain(finding).trim();
    if (!value) return 'Unspecified';
    const match = domainCatalog.find(([, terms]) => terms.some((term) => value.includes(term)));
    if (match) return match[0];
    return value.toLocaleLowerCase().replace(/\b\w/g, (letter) => letter.toUpperCase());
  }
  function resourcePairs(findings) {
    const pairs = new Map();
    findings.forEach((finding) => {
      const type = String(finding.resource_type || '').trim();
      const id = String(finding.resource_id || '').trim();
      if (!type || !id) return;
      const key = JSON.stringify([type, id]);
      if (!pairs.has(key)) pairs.set(key, { type, id });
    });
    return pairs;
  }
  function environmentStats(findings, cloud) {
    const provider = getProvider(cloud);
    const keys = new Set();
    const regions = new Set();
    findings.forEach((finding) => {
      provider.environmentKeys.forEach((key) => {
        const value = finding[key];
        if (value != null && String(value).trim()) keys.add(String(value).trim());
      });
      const region = finding.region ?? finding.region_name ?? finding.regionName;
      if (region != null && String(region).trim()) regions.add(String(region).trim());
    });
    return { environmentLabel: provider.environmentLabel, environments: [...keys], regions: [...regions] };
  }
  function postureFor(cloudStats) {
    if (!cloudStats.hasData) return { key: 'awaiting', label: 'Awaiting Data' };
    if (cloudStats.openCritical > 0) return { key: 'critical', label: 'Critical Risk' };
    if (cloudStats.openHigh > 0) return { key: 'high', label: 'High Risk' };
    if (cloudStats.openRisk > 0) return { key: 'attention', label: 'Attention' };
    if (cloudStats.evaluatedChecks > 0) return { key: 'healthy', label: 'Healthy' };
    return { key: 'awaiting', label: 'Awaiting Data' };
  }

  // Aggregate the shared records once. Child views use these normalized cloud
  // buckets so totals, charts, recommendations and tables stay consistent.
  function getCloudSecurityData(findings) {
    const shared = window.CSPMShared;
    const buckets = new Map(['AWS', 'Azure', 'GCP', 'Other'].map((name) => [name, []]));
    findings.forEach((finding) => {
      const cloud = shared.normalizeCloud(finding.cloud);
      if (!buckets.has(cloud)) buckets.set(cloud, []);
      buckets.get(cloud).push(finding);
    });
    const clouds = [...buckets.entries()].map(([name, records]) => {
      const open = records.filter((finding) => shared.isOpenFinding(finding));
      const openRisk = open.filter((finding) => shared.isRiskFinding(finding));
      const severity = shared.getSeverityDistribution(records);
      const openHigh = openRisk.filter((finding) => shared.normalizeSeverity(finding.severity) === 'HIGH').length;
      const openCritical = openRisk.filter((finding) => shared.normalizeSeverity(finding.severity) === 'CRITICAL').length;
      const riskScores = openRisk.filter((finding) => finding.risk_score !== '' && finding.risk_score != null && Number.isFinite(Number(finding.risk_score))).map((finding) => Number(finding.risk_score));
      const domainCounts = new Map();
      records.forEach((finding) => {
        const domain = displayDomain(finding, shared);
        domainCounts.set(domain, (domainCounts.get(domain) || 0) + 1);
      });
      const resources = resourcePairs(records);
      const resourceTypes = new Map();
      resources.forEach((resource) => resourceTypes.set(resource.type, (resourceTypes.get(resource.type) || 0) + 1));
      const generic = shared.getComplianceData(records).generic;
      const cloud = {
        name, icon: getProvider(name).icon, records, hasData: records.length > 0, totalFindings: records.length,
        openFindings: shared.calcOpenFindings(records), severity, openRiskSeverity: shared.getSeverityDistribution(openRisk), openHigh, openCritical, openRisk: openRisk.length,
        resources: [...resources.values()], resourceCount: resources.size, resourceTypes: [...resourceTypes.entries()].map(([type, count]) => ({ type, count })).sort((a, b) => b.count - a.count || a.type.localeCompare(b.type)),
        domains: [...domainCounts.entries()].map(([domain, count]) => ({ domain, count })).sort((a, b) => a.domain.localeCompare(b.domain)),
        evaluatedChecks: generic.evaluated,
        riskScoreTotal: riskScores.length ? riskScores.reduce((sum, score) => sum + score, 0) : null,
        ...environmentStats(records, name),
      };
      cloud.posture = postureFor(cloud);
      return cloud;
    });
    const findingsByCloud = shared.getFindingsByCloud(findings);
    const overall = {
      totalFindings: shared.calcTotalFindings(findings),
      openFindings: shared.calcOpenFindings(findings),
      severity: shared.getSeverityDistribution(findings),
      resources: resourcePairs(findings).size,
      cloudsWithData: clouds.filter((cloud) => ['AWS', 'Azure', 'GCP'].includes(cloud.name) && cloud.hasData).length,
      findingsByCloud,
    };
    return { clouds, overall };
  }

  function getCloudPosture(cloudStats) { return cloudStats.posture; }
  function getCloudResourceStats(cloudStats) { return { total: cloudStats.resourceCount, types: cloudStats.resourceTypes }; }
  function getCloudRiskDistribution(cloudStats) { return { critical: cloudStats.openRiskSeverity.critical || 0, high: cloudStats.openRiskSeverity.high || 0, medium: cloudStats.openRiskSeverity.medium || 0, low: cloudStats.openRiskSeverity.low || 0, openCritical: cloudStats.openCritical, openHigh: cloudStats.openHigh, openRisk: cloudStats.openRisk, riskScoreTotal: cloudStats.riskScoreTotal }; }
  function getCloudDomainStats(cloudStats) { return cloudStats.domains; }
  function getCloudResourceTypeStats(cloudStats) { return cloudStats.resourceTypes; }
  function currentFindings() {
    const shared = window.CSPMShared;
    const recordIds = new Map();
    shared.getFindings().forEach((finding, index) => recordIds.set(finding, index));
    const cloudStats = data.clouds.find((cloud) => cloud.name === state.provider);
    scopedFindings = state.provider === 'all' ? shared.getFindings() : cloudStats?.records || [];
    return scopedFindings.map((finding) => ({ finding, index: recordIds.get(finding) ?? -1 }));
  }
  function findingHref(finding, index) {
    const params = new URLSearchParams();
    if (finding.finding_id) params.set('id', finding.finding_id);
    if (Number.isInteger(index) && index >= 0) params.set('record', String(index));
    return params.size ? `findings.html?${params.toString()}` : 'findings.html';
  }
  function formatDate(value) {
    if (!value) return '—';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    return date.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  }
  function providerMark(cloud, css = '') {
    return `<span class="cloud-provider-mark cloud-provider-${esc(getProvider(cloud).tone)} ${css}" role="img" aria-label="${esc(cloud)} logo">${window.CSPM_ICONS[getProvider(cloud).icon] || window.CSPM_ICONS.cloud}</span>`;
  }
  function metric(label, value, icon, tone = '') {
    const countAttribute = typeof value === 'number' ? ` data-cloud-count="${value}"` : '';
    return `<div class="cloud-summary-metric ${tone ? `metric-${tone}` : ''}"><span class="cloud-summary-icon" data-cspm-icon="${icon}" aria-hidden="true">${window.CSPM_ICONS[icon] || ''}</span><div><span>${esc(label)}</span><strong${countAttribute}>${value === null ? '—' : esc(value)}</strong></div></div>`;
  }
  function renderSummary() {
    const shared = window.CSPMShared;
    const findings = state.provider === 'all' ? shared.getFindings() : data.clouds.find((cloud) => cloud.name === state.provider)?.records || [];
    const cloud = data.clouds.find((item) => item.name === state.provider);
    const noScan = state.provider !== 'all' && !cloud?.hasData;
    const high = shared.getSeverityDistribution(findings);
    const resourceCount = noScan ? null : (cloud ? cloud.resourceCount : resourcePairs(findings).size);
    $('cloudSummary').innerHTML = [
      metric('Total Findings', noScan ? null : shared.calcTotalFindings(findings), 'findings'),
      metric('Open Findings', noScan ? null : shared.calcOpenFindings(findings), 'alerts'),
      metric('High / Critical', noScan ? null : `${(high.high || 0) + (high.critical || 0)}`, 'high', 'risk'),
      metric('Monitored Resources', resourceCount, 'resources'),
      metric('Clouds with Data', data.overall.cloudsWithData, 'cloud'),
    ].join('');
    $('cloudsWithDataBadge').textContent = `${data.overall.cloudsWithData} of 3 providers with data`;
  }
  function renderProviderCards() {
    $('cloudProviderCards').innerHTML = providers.map((provider, index) => {
      const cloud = data.clouds.find((item) => item.name === provider.name);
      const active = state.provider === provider.name;
      const metrics = cloud.hasData ? `<span><strong data-cloud-count="${cloud.totalFindings}">${cloud.totalFindings}</strong> findings</span><span><strong data-cloud-count="${cloud.openFindings}">${cloud.openFindings}</strong> open</span><span><strong data-cloud-count="${cloud.openHigh}">${cloud.openHigh}</strong> high</span><span><strong data-cloud-count="${cloud.openCritical}">${cloud.openCritical}</strong> critical</span><span><strong data-cloud-count="${cloud.resourceCount}">${cloud.resourceCount}</strong> resources</span>` : '<span class="provider-no-metrics">No scan data. Connect a scan to establish posture visibility.</span>';
      return `<button type="button" class="cloud-provider-card cloud-provider-card-${provider.tone} ${active ? 'is-selected' : ''} ${cloud.hasData ? 'has-data' : 'no-data'}" data-provider="${provider.name}" aria-pressed="${active}" aria-haspopup="dialog" aria-label="${provider.name}, ${cloud.hasData ? `${cloud.posture.label}, ${cloud.totalFindings} findings, ${cloud.openFindings} open, ${cloud.resourceCount} resources` : 'Awaiting scan data'}. Select provider and open details." style="--cloud-order:${index}">
        <span class="provider-card-head">${providerMark(provider.name)}<span class="provider-data-state" data-state="${cloud.hasData ? 'available' : 'awaiting'}">${cloud.hasData ? 'Data Available' : 'Awaiting Scan Data'}</span></span>
        <strong class="provider-card-name">${provider.name}</strong>
        <span class="provider-posture" data-posture="${cloud.posture.key}">${cloud.posture.label}</span>
        <span class="provider-card-metrics">${metrics}</span><span class="provider-card-action">View cloud details <span aria-hidden="true">→</span></span>
      </button>`;
    }).join('');
  }
  function renderFindingsByCloud() {
    const maxTotal = Math.max(1, ...data.clouds.map((cloud) => cloud.totalFindings));
    $('findingsByCloud').innerHTML = data.clouds.map((cloud) => {
      if (!cloud.hasData) return `<div class="cloud-breakdown-row is-unscanned">${providerMark(cloud.name)}<div class="cloud-breakdown-main"><div class="cloud-breakdown-label"><strong>${esc(cloud.name)}</strong><span>No scan data</span></div><div class="cloud-breakdown-track" aria-hidden="true"></div></div><span class="cloud-breakdown-total">—</span></div>`;
      const counts = cloud.severity;
      const parts = severityKeys.map((key) => ({ key, value: counts[key.toLowerCase()] || 0 }));
      const known = parts.reduce((sum, part) => sum + part.value, 0);
      parts.push({ key: 'OTHER', value: Math.max(0, cloud.totalFindings - known) });
      const bar = parts.filter((part) => part.value).map((part) => `<span class="breakdown-segment segment-${part.key.toLowerCase()}" style="--segment:${part.value / maxTotal * 100}%" title="${part.key} ${part.value}"></span>`).join('');
      return `<button type="button" class="cloud-breakdown-row ${state.provider === cloud.name ? 'is-selected' : ''}" data-select-cloud="${esc(cloud.name)}" aria-label="Select ${esc(cloud.name)} context, ${cloud.totalFindings} findings, ${cloud.openFindings} open"><span>${providerMark(cloud.name)}</span><span class="cloud-breakdown-main"><span class="cloud-breakdown-label"><strong>${esc(cloud.name)}</strong><span>${cloud.openFindings} open of ${cloud.totalFindings}</span></span><span class="cloud-breakdown-track" role="img" aria-label="${parts.map((part) => `${part.key}: ${part.value}`).join(', ')}">${bar}</span><span class="cloud-breakdown-sub">${cloud.openHigh} open high · ${cloud.openCritical} open critical</span></span><strong class="cloud-breakdown-total">${cloud.totalFindings}</strong></button>`;
    }).join('');
  }
  function renderRisk() {
    const cloudRows = data.clouds.filter((cloud) => cloud.name !== 'Other' || cloud.hasData);
    const maxSeverity = Math.max(1, ...cloudRows.flatMap((cloud) => {
      const counts = getCloudRiskDistribution(cloud);
      return [counts.critical, counts.high, counts.medium, counts.low];
    }));
    $('riskByCloud').innerHTML = cloudRows.map((cloud) => {
      if (!cloud.hasData) return `<div class="risk-cloud-row risk-cloud-unscanned">${providerMark(cloud.name)}<strong>${esc(cloud.name)}</strong><span>No scan data</span></div>`;
      const counts = getCloudRiskDistribution(cloud);
      const blocks = severityKeys.map((key) => {
        const value = counts[key.toLowerCase()];
        return `<div class="risk-severity-row"><span>${key.charAt(0) + key.slice(1).toLowerCase()}</span><span class="risk-severity-track"><i class="risk-severity-fill risk-fill-${key.toLowerCase()}" style="--bar-width:${value / maxSeverity * 100}%"></i></span><strong>${value}</strong></div>`;
      }).join('');
      return `<div class="risk-cloud-row ${state.provider === cloud.name ? 'is-selected' : ''}">${providerMark(cloud.name)}<strong>${esc(cloud.name)}</strong><div class="risk-severity-grid">${blocks}</div><span class="risk-open-count">${counts.openRisk} open risk</span></div>`;
    }).join('');
    const ranked = data.clouds.filter((cloud) => cloud.openRisk > 0).sort((a, b) => b.openCritical - a.openCritical || b.openHigh - a.openHigh || b.openRisk - a.openRisk || (b.riskScoreTotal || 0) - (a.riskScoreTotal || 0));
    const lead = ranked[0];
    $('riskConcentration').innerHTML = lead ? `<span class="risk-concentration-icon" data-cspm-icon="activity" aria-hidden="true">${window.CSPM_ICONS.activity}</span><span><strong>Risk concentration: ${esc(lead.name)}</strong><small>${lead.openRisk} open risk findings${lead.riskScoreTotal === null ? '' : ` · combined recorded risk score ${lead.riskScoreTotal}`}</small></span>` : '<span class="risk-concentration-icon" data-cspm-icon="activity" aria-hidden="true">' + window.CSPM_ICONS.activity + '</span><span><strong>No open risk findings in scanned cloud data</strong><small>Risk concentration uses open risk severities and recorded risk scores; it is not a percentage.</small></span>';
  }
  function renderResources() {
    const resourceClouds = data.clouds.filter((cloud) => cloud.hasData || ['AWS', 'Azure', 'GCP'].includes(cloud.name));
    const max = Math.max(1, ...resourceClouds.map((cloud) => cloud.resourceCount));
    $('resourcesByCloud').innerHTML = resourceClouds.map((cloud, index) => {
      if (!cloud.hasData) return `<div class="resource-cloud-row is-unscanned">${providerMark(cloud.name)}<span class="resource-cloud-name">${esc(cloud.name)}</span><span class="resource-cloud-no-data">Awaiting cloud data</span></div>`;
      return `<div class="resource-cloud-row ${state.provider === cloud.name ? 'is-selected' : ''}" style="--cloud-order:${index}">${providerMark(cloud.name)}<span class="resource-cloud-name">${esc(cloud.name)}</span><span class="resource-cloud-track"><i style="--bar-width:${cloud.resourceCount / max * 100}%"></i></span><strong data-cloud-count="${cloud.resourceCount}">${cloud.resourceCount}</strong></div>`;
    }).join('');
    const typed = data.clouds.filter((cloud) => cloud.hasData && cloud.resourceTypes.length);
    $('resourceTypesByCloud').innerHTML = typed.length ? typed.map((cloud) => `<section class="resource-types-cloud"><h3>${providerMark(cloud.name)}<span>${esc(cloud.name)}</span></h3><div>${cloud.resourceTypes.map((item) => `<div class="resource-type-row"><span>${esc(item.type)}</span><i></i><strong data-cloud-count="${item.count}">${item.count}</strong></div>`).join('')}</div></section>`).join('') : '<div class="cloud-panel-empty">No resource type data is available.</div>';
    if (!typed.length) return;
  }
  function renderDomains() {
    $('domainsByCloud').innerHTML = data.clouds.filter((cloud) => cloud.hasData || ['AWS', 'Azure', 'GCP'].includes(cloud.name)).map((cloud) => {
      if (!cloud.hasData) return `<div class="domain-cloud-row is-unscanned">${providerMark(cloud.name)}<strong>${esc(cloud.name)}</strong><span>Awaiting cloud data</span></div>`;
      return `<div class="domain-cloud-row ${state.provider === cloud.name ? 'is-selected' : ''}"><div class="domain-cloud-head">${providerMark(cloud.name)}<strong>${esc(cloud.name)}</strong><span>${cloud.totalFindings} findings</span></div><div class="domain-chip-list">${cloud.domains.map((item) => `<span class="domain-chip">${esc(item.domain)}<strong>${item.count}</strong></span>`).join('')}</div></div>`;
    }).join('');
  }
  function renderVisibility() {
    $('cloudVisibility').innerHTML = providers.map((provider) => {
      const cloud = data.clouds.find((item) => item.name === provider.name);
      const status = cloud.hasData ? 'Data Available' : 'Awaiting Data';
      const detail = cloud.hasData && cloud.environments.length ? `${cloud.environments.length} ${provider.environmentLabel}` : cloud.hasData ? 'Provider findings observed' : `No ${provider.name} scan data available`;
      return `<button type="button" class="visibility-provider-row ${state.provider === provider.name ? 'is-selected' : ''}" data-select-cloud="${provider.name}" aria-label="Select ${provider.name}. ${status}.">${providerMark(provider.name)}<strong>${provider.name}</strong><span class="visibility-state" data-state="${cloud.hasData ? 'available' : 'awaiting'}">${status}</span><small>${esc(detail)}</small></button>`;
    }).join('');
    const accountClouds = providers.map((provider) => ({ provider, cloud: data.clouds.find((item) => item.name === provider.name) })).filter(({ cloud }) => cloud.environments.length);
    $('accountVisibility').textContent = accountClouds.length ? accountClouds.map(({ provider, cloud }) => `${provider.name}: ${cloud.environments.length} ${provider.environmentLabel}${cloud.environments.length === 1 ? '' : 's'}`).join(' · ') : 'Account-level visibility unavailable';
    const regionCount = data.clouds.reduce((sum, cloud) => sum + cloud.regions.length, 0);
    $('regionVisibility').textContent = regionCount ? `${regionCount} observed region${regionCount === 1 ? '' : 's'}` : 'Regional inventory data unavailable';
  }
  function renderComparison() {
    $('cloudComparisonBody').innerHTML = data.clouds.filter((cloud) => cloud.name !== 'Other' || cloud.hasData).map((cloud) => `<tr class="${state.provider === cloud.name ? 'is-selected' : ''}"><th scope="row">${providerMark(cloud.name)}${esc(cloud.name)}</th><td><span class="comparison-state" data-state="${cloud.hasData ? 'available' : 'awaiting'}">${cloud.hasData ? 'Data Available' : 'No scan data'}</span></td><td>${cloud.hasData ? cloud.totalFindings : '—'}</td><td>${cloud.hasData ? cloud.openFindings : '—'}</td><td>${cloud.hasData ? cloud.severity.high || 0 : '—'}</td><td>${cloud.hasData ? cloud.severity.critical || 0 : '—'}</td><td>${cloud.hasData ? cloud.resourceCount : '—'}</td></tr>`).join('');
  }
  function getCloudRecommendations(clouds) {
    const output = [];
    clouds.forEach((cloud) => {
      if (!cloud.hasData) {
        if (providers.some((provider) => provider.name === cloud.name)) output.push({ cloud: cloud.name, icon: cloud.icon, type: 'awaiting', title: `Connect ${cloud.name === 'Azure' ? 'an' : 'a'} ${cloud.name} scan`, detail: `No ${cloud.name} scan data is available; posture cannot yet be assessed.`, href: 'findings.html' });
        return;
      }
      if (cloud.openCritical || cloud.openHigh) {
        const highCritical = cloud.openCritical + cloud.openHigh;
        output.push({ cloud: cloud.name, icon: cloud.icon, type: 'risk', title: `Review ${highCritical} open high or critical finding${highCritical === 1 ? '' : 's'} in ${cloud.name}`, detail: `${cloud.openCritical} critical and ${cloud.openHigh} high-severity open records are in the current findings data.`, href: 'findings.html' });
      } else if (cloud.openRisk) {
        output.push({ cloud: cloud.name, icon: cloud.icon, type: 'attention', title: `Review ${cloud.openRisk} open risk finding${cloud.openRisk === 1 ? '' : 's'} in ${cloud.name}`, detail: 'Open findings remain in the current cloud scan data.', href: 'findings.html' });
      } else {
        output.push({ cloud: cloud.name, icon: cloud.icon, type: 'healthy', title: `No open risk findings in ${cloud.name}`, detail: 'Keep provider scan coverage current to maintain visibility.', href: 'findings.html' });
      }
    });
    return output;
  }
  function renderRecommendations() {
    const clouds = state.provider === 'all' ? data.clouds.filter((cloud) => ['AWS', 'Azure', 'GCP'].includes(cloud.name)) : data.clouds.filter((cloud) => cloud.name === state.provider);
    const actions = getCloudRecommendations(clouds);
    $('cloudRecommendations').innerHTML = actions.length ? actions.map((action) => `<a class="cloud-recommendation" data-kind="${action.type}" href="${esc(action.href)}"><span class="recommendation-provider">${providerMark(action.cloud)}</span><span class="recommendation-copy"><strong>${esc(action.title)}</strong><small>${esc(action.detail)}</small></span><span class="recommendation-arrow" aria-hidden="true">→</span></a>`).join('') : '<p class="cloud-panel-empty">No provider recommendations are available.</p>';
  }
  function buildFilters() {
    const shared = window.CSPMShared;
    const findings = shared.getFindings();
    const values = {
      cloudSeverityFilter: [...new Set(findings.map((finding) => shared.normalizeSeverity(finding.severity)))].sort(),
      cloudDomainFilter: [...new Set(findings.map((finding) => displayDomain(finding, shared)))].sort(),
      cloudStatusFilter: [...new Set(findings.map((finding) => shared.normalizeStatus(finding.status)))].sort(),
    };
    const defs = [
      ['cloudSeverityFilter', 'All severities', values.cloudSeverityFilter],
      ['cloudDomainFilter', 'All domains', values.cloudDomainFilter],
      ['cloudStatusFilter', 'All statuses', values.cloudStatusFilter],
    ];
    defs.forEach(([id, allLabel, options]) => {
      const selected = $(id).value;
      $(id).innerHTML = `<option value="">${allLabel}</option>${options.map((value) => `<option value="${esc(value)}">${esc(value.charAt(0) + value.slice(1).toLocaleLowerCase())}</option>`).join('')}`;
      $(id).value = options.includes(selected) ? selected : '';
    });
  }
  function renderFindingsTable() {
    const shared = window.CSPMShared;
    const rows = currentFindings().filter(({ finding }) => {
      if (state.severity && shared.normalizeSeverity(finding.severity) !== state.severity) return false;
      if (state.domain && displayDomain(finding, shared) !== state.domain) return false;
      if (state.status && shared.normalizeStatus(finding.status) !== state.status) return false;
      const query = state.query.trim().toLocaleLowerCase();
      if (query) {
        const resource = [finding.resource_type, finding.resource_id].filter(Boolean).join(' ');
        const text = [finding.finding, resource, shared.normalizeDomain(finding), finding.category, finding.finding_id].filter(Boolean).join(' ').toLocaleLowerCase();
        if (!text.includes(query)) return false;
      }
      return true;
    });
    $('cloudFindingsDescription').textContent = state.provider === 'all' ? 'Search and filter operational findings across all cloud providers.' : `Search and filter operational findings in the ${state.provider} context.`;
    const pages = Math.max(1, Math.ceil(rows.length / state.pageSize));
    state.page = Math.min(Math.max(1, state.page), pages);
    const start = (state.page - 1) * state.pageSize;
    const visible = rows.slice(start, start + state.pageSize);
    $('cloudFindingsResult').textContent = rows.length ? `Showing ${start + 1}–${Math.min(start + visible.length, rows.length)} of ${rows.length} findings${state.provider === 'all' ? ' across all clouds' : ` in ${state.provider}`}` : `0 findings${state.provider === 'all' ? ' across all clouds' : ` in ${state.provider}`}`;
    $('cloudFindingsBody').innerHTML = visible.map(({ finding, index }, rowIndex) => {
      const cloud = shared.normalizeCloud(finding.cloud);
      const severity = shared.normalizeSeverity(finding.severity);
      const status = shared.normalizeStatus(finding.status);
      const href = findingHref(finding, index);
      return `<tr tabindex="0" aria-label="Open finding ${esc(finding.finding_id || finding.finding || 'details')}. Press Enter to view." data-finding-href="${esc(href)}" style="--row-order:${Math.min(rowIndex, 24)}"><td>${providerMark(cloud, 'table-provider-mark')}<span class="table-cloud-name">${esc(cloud)}</span></td><td><a class="cloud-finding-link" href="${esc(href)}"><strong>${esc(finding.finding || finding.finding_id || 'Untitled finding')}</strong><small>${esc(finding.finding_id || 'No finding ID')}</small></a></td><td>${esc(displayDomain(finding, shared))}</td><td><span class="cloud-resource-type">${esc(finding.resource_type || 'Unknown resource')}</span><small class="cloud-resource-id">${esc(finding.resource_id || 'Not recorded')}</small></td><td><span class="cloud-severity-pill" data-severity="${severity.toLowerCase()}">${esc(severity)}</span></td><td>${finding.risk_score === '' || finding.risk_score == null || !Number.isFinite(Number(finding.risk_score)) ? '—' : esc(finding.risk_score)}</td><td><span class="cloud-status-pill" data-status="${status.toLowerCase()}">${esc(status)}</span></td><td>${esc(formatDate(finding.detected_at))}</td></tr>`;
    }).join('');
    const noData = state.provider !== 'all' && !data.clouds.find((cloud) => cloud.name === state.provider)?.hasData;
    $('cloudFindingsEmpty').hidden = rows.length > 0;
    if (!rows.length) $('cloudFindingsEmpty').innerHTML = noData ? `<strong>No ${esc(state.provider)} scan data available.</strong><span>Finding and resource metrics will appear after a scan produces records.</span>` : `<strong>${scopedFindings.length ? 'No findings match these filters.' : 'No cloud findings are available.'}</strong><span>Change the search or filters to see matching records.</span>`;
    $('clearCloudFindingFilters').hidden = !state.query && !state.severity && !state.domain && !state.status;
    $('cloudFindingsPagination').hidden = rows.length <= state.pageSize;
    $('cloudFindingsPageLabel').textContent = rows.length ? `Showing ${start + 1}–${Math.min(start + visible.length, rows.length)} of ${rows.length}` : 'Showing 0 of 0';
    $('cloudFindingsPageNumber').textContent = `${state.page} / ${pages}`;
    $('cloudFindingsPrev').disabled = state.page <= 1;
    $('cloudFindingsNext').disabled = state.page >= pages;
  }
  function renderWorkspace() {
    renderProviderCards(); renderSummary(); renderFindingsByCloud(); renderRisk(); renderResources(); renderDomains(); renderVisibility(); renderComparison(); renderRecommendations(); buildFilters(); renderFindingsTable();
    animateCounts();
  }
  function animateCounts() {
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches || document.visibilityState === 'hidden';
    document.querySelectorAll('[data-cloud-count]').forEach((element) => {
      const target = Number(element.dataset.cloudCount);
      if (!Number.isFinite(target)) return;
      if (reduced) { element.textContent = String(target); return; }
      const started = performance.now();
      const tick = (now) => {
        const progress = Math.min(1, (now - started) / 420);
        element.textContent = String(Math.round(target * (1 - Math.pow(1 - progress, 3))));
        if (progress < 1) requestAnimationFrame(tick);
      };
      element.textContent = '0'; requestAnimationFrame(tick);
    });
  }
  function setData() {
    const shared = window.CSPMShared;
    if (!shared || !shared.hasDataSource()) throw new Error('Shared CSPM finding data is unavailable');
    data = getCloudSecurityData(shared.getFindings());
    renderWorkspace();
  }
  function showError() {
    $('cloudSecurityLoading').hidden = true; $('cloudSecurityWorkspace').hidden = true; $('cloudSecurityError').hidden = false;
    $('cloudSecurityContent').setAttribute('aria-busy', 'false');
  }
  function setProvider(value) {
    state.provider = value;
    state.query = ''; state.severity = ''; state.domain = ''; state.status = ''; state.page = 1;
    $('cloudProviderFilter').value = value; $('cloudFindingSearch').value = '';
    $('cloudSeverityFilter').value = ''; $('cloudDomainFilter').value = ''; $('cloudStatusFilter').value = '';
    renderWorkspace();
  }
  function openDrawer(cloud, returnFocus) {
    const drawer = $('cloudDetailDrawer');
    state.cloudDrawer = cloud.name; state.drawerReturnFocus = returnFocus || document.activeElement;
    $('cloudDrawerTitle').textContent = cloud.name;
    const provider = getProvider(cloud.name);
    if (!cloud.hasData) {
      $('cloudDrawerBody').innerHTML = `${providerMark(cloud.name)}<span class="cloud-drawer-state" data-state="awaiting">Awaiting cloud scan data</span><p>No finding records for ${esc(cloud.name)} are present in the current dataset. Security posture, resources, services and regions cannot yet be assessed.</p><div class="drawer-unavailable-note">Connect a ${esc(cloud.name)} scanner to establish provider visibility.</div>`;
    } else {
      const domainItems = cloud.domains.length ? cloud.domains.map((item) => `<span class="cloud-drawer-chip">${esc(item.domain)} <strong>${item.count}</strong></span>`).join('') : '<span class="cloud-drawer-muted">No domain values recorded</span>';
      const types = cloud.resourceTypes.length ? cloud.resourceTypes.map((item) => `<span class="cloud-drawer-chip">${esc(item.type)} <strong>${item.count}</strong></span>`).join('') : '<span class="cloud-drawer-muted">No resource type values recorded</span>';
      $('cloudDrawerBody').innerHTML = `${providerMark(cloud.name)}<span class="cloud-drawer-state" data-state="available">Finding data available</span><div class="cloud-drawer-posture" data-posture="${cloud.posture.key}">${esc(cloud.posture.label)}</div><dl class="cloud-drawer-metrics"><div><dt>Total findings</dt><dd>${cloud.totalFindings}</dd></div><div><dt>Open findings</dt><dd>${cloud.openFindings}</dd></div><div><dt>Critical</dt><dd>${cloud.severity.critical || 0}</dd></div><div><dt>High</dt><dd>${cloud.severity.high || 0}</dd></div><div><dt>Monitored resources</dt><dd>${cloud.resourceCount}</dd></div></dl><section class="cloud-drawer-section"><h3>Security domains</h3><div class="cloud-drawer-chips">${domainItems}</div></section><section class="cloud-drawer-section"><h3>Resource types</h3><div class="cloud-drawer-chips">${types}</div></section>${cloud.environments.length ? `<section class="cloud-drawer-section"><h3>${esc(provider.environmentLabel)}${cloud.environments.length === 1 ? '' : 's'}</h3><p>${cloud.environments.length} observed</p></section>` : ''}${cloud.regions.length ? `<section class="cloud-drawer-section"><h3>Regions</h3><div class="cloud-drawer-chips">${cloud.regions.map((region) => `<span class="cloud-drawer-chip">${esc(region)}</span>`).join('')}</div></section>` : ''}<a class="cloud-drawer-link" href="findings.html">View ${esc(cloud.name)} findings <span aria-hidden="true">→</span></a>`;
    }
    drawer.inert = false; drawer.setAttribute('aria-hidden', 'false'); $('cloudDrawerBackdrop').hidden = false;
    document.body.classList.add('cloud-drawer-open'); requestAnimationFrame(() => drawer.classList.add('is-open'));
    $('cloudDrawerClose').focus();
  }
  function closeDrawer(restore = true) {
    const drawer = $('cloudDetailDrawer');
    drawer.classList.remove('is-open'); drawer.inert = true; drawer.setAttribute('aria-hidden', 'true'); $('cloudDrawerBackdrop').hidden = true;
    document.body.classList.remove('cloud-drawer-open');
    if (restore && state.drawerReturnFocus?.isConnected) state.drawerReturnFocus.focus();
    state.cloudDrawer = null;
  }
  function init() {
    window.getCloudSecurityData = getCloudSecurityData;
    window.getCloudPosture = getCloudPosture;
    window.getCloudResourceStats = getCloudResourceStats;
    window.getCloudRiskDistribution = getCloudRiskDistribution;
    window.getCloudDomainStats = getCloudDomainStats;
    window.getCloudResourceTypeStats = getCloudResourceTypeStats;
    window.getCloudRecommendations = getCloudRecommendations;
    $('cloudProviderFilter').addEventListener('change', (event) => setProvider(event.target.value));
    $('cloudProviderCards').addEventListener('click', (event) => {
      const card = event.target.closest('[data-provider]'); if (!card) return;
      setProvider(card.dataset.provider);
      openDrawer(data.clouds.find((cloud) => cloud.name === card.dataset.provider), $('cloudProviderCards').querySelector(`[data-provider="${card.dataset.provider}"]`));
    });
    document.addEventListener('click', (event) => {
      const select = event.target.closest('[data-select-cloud]');
      if (select) setProvider(select.dataset.selectCloud);
    });
    $('cloudFindingSearch').addEventListener('input', (event) => { state.query = event.target.value; state.page = 1; renderFindingsTable(); });
    $('cloudFindingsBody').addEventListener('click', (event) => { const row = event.target.closest('tr[data-finding-href]'); if (row && !event.target.closest('a')) window.location.href = row.dataset.findingHref; });
    $('cloudFindingsBody').addEventListener('keydown', (event) => {
      const row = event.target.closest('tr[data-finding-href]');
      if (row && event.target === row && (event.key === 'Enter' || event.key === ' ')) { event.preventDefault(); window.location.href = row.dataset.findingHref; }
    });
    $('cloudSeverityFilter').addEventListener('change', (event) => { state.severity = event.target.value; state.page = 1; renderFindingsTable(); });
    $('cloudDomainFilter').addEventListener('change', (event) => { state.domain = event.target.value; state.page = 1; renderFindingsTable(); });
    $('cloudStatusFilter').addEventListener('change', (event) => { state.status = event.target.value; state.page = 1; renderFindingsTable(); });
    $('cloudFindingsPrev').addEventListener('click', () => { state.page--; renderFindingsTable(); });
    $('cloudFindingsNext').addEventListener('click', () => { state.page++; renderFindingsTable(); });
    $('clearCloudFindingFilters').addEventListener('click', () => { state.query = ''; state.severity = ''; state.domain = ''; state.status = ''; state.page = 1; $('cloudFindingSearch').value = ''; $('cloudSeverityFilter').value = ''; $('cloudDomainFilter').value = ''; $('cloudStatusFilter').value = ''; renderFindingsTable(); });
    const retry = () => {
      $('cloudSecurityError').hidden = true; $('cloudSecurityLoading').hidden = false; $('cloudSecurityContent').setAttribute('aria-busy', 'true');
      try { setData(); $('cloudSecurityLoading').hidden = true; $('cloudSecurityWorkspace').hidden = false; $('cloudSecurityContent').setAttribute('aria-busy', 'false'); $('cloudSecurityLive').textContent = 'Cloud security data refreshed from the shared findings dataset.'; }
      catch (_) { showError(); }
    };
    $('cloudSecurityRefresh').addEventListener('click', retry); $('cloudSecurityRetry').addEventListener('click', retry);
    $('cloudDrawerClose').addEventListener('click', () => closeDrawer()); $('cloudDrawerBackdrop').addEventListener('click', () => closeDrawer());
    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape' && !$('cloudDetailDrawer').inert) closeDrawer();
      if (event.key === 'Tab' && !$('cloudDetailDrawer').inert) {
        const focusable = [...$('cloudDetailDrawer').querySelectorAll('button, a[href], [tabindex]:not([tabindex="-1"])')].filter((node) => !node.disabled);
        const first = focusable[0], last = focusable[focusable.length - 1];
        if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
      }
    });
    try {
      setTimeout(() => {
        try { setData(); $('cloudSecurityLoading').hidden = true; $('cloudSecurityWorkspace').hidden = false; $('cloudSecurityContent').setAttribute('aria-busy', 'false'); }
        catch (_) { showError(); }
      }, 70);
    } catch (_) { showError(); }
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init, { once: true }); else init();
})();
