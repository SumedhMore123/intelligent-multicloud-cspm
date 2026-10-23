// Compliance workspace. Generic posture always comes from CSPMShared;
// framework posture requires explicit framework and control identifiers.
(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const catalog = [
    { id: 'cis-aws', name: 'CIS AWS Foundations', family: 'cis', mark: 'CIS', cloud: 'AWS', aliases: ['cis aws', 'cis aws foundations', 'cis benchmark aws'] },
    { id: 'cis-azure', name: 'CIS Azure Foundations', family: 'cis', mark: 'CIS', cloud: 'Azure', aliases: ['cis azure', 'cis azure foundations', 'cis benchmark azure'] },
    { id: 'cis-gcp', name: 'CIS GCP Foundations', family: 'cis', mark: 'CIS', cloud: 'GCP', aliases: ['cis gcp', 'cis google cloud', 'cis gcp foundations'] },
    { id: 'iso-27001', name: 'ISO 27001', family: 'iso', mark: 'ISO', cloud: null, aliases: ['iso 27001', 'iso27001'] },
    { id: 'soc-2', name: 'SOC 2 Type II', family: 'soc2', mark: 'SOC 2', cloud: null, aliases: ['soc 2', 'soc2', 'soc 2 type ii'] },
    { id: 'nist-csf', name: 'NIST CSF', family: 'nist', mark: 'NIST', cloud: null, aliases: ['nist csf', 'nist cybersecurity framework'] },
  ];
  const providers = [
    { name: 'AWS', icon: 'aws' }, { name: 'Azure', icon: 'azure' }, { name: 'GCP', icon: 'gcp' },
  ];
  let pageData = null;
  let selectedCloud = 'all';
  let drawerReturnFocus = null;

  function esc(value) {
    return String(value ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]);
  }
  function normalizeFramework(value) { return String(value ?? '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim(); }
  function frameworkFor(value) {
    const normalized = normalizeFramework(value);
    return catalog.find((framework) => framework.aliases.some((alias) => normalized === normalizeFramework(alias) || normalized.includes(normalizeFramework(alias)))) || null;
  }
  function controlId(finding) { return String(finding.control_id ?? finding.controlId ?? finding.control ?? finding.benchmark_control_id ?? '').trim(); }
  function frameworkName(finding) { return finding.framework ?? finding.compliance_standard ?? finding.benchmark ?? finding.framework_id ?? ''; }

  // Public data adapter required by this page. Framework aggregates are built
  // only from explicit framework + control identifiers in the source records.
  function getCompliancePageData(findings) {
    const shared = window.CSPMShared;
    const generic = shared.getComplianceData(findings).generic;
    const controlGroups = new Map();
    findings.forEach((finding, index) => {
      const framework = frameworkFor(frameworkName(finding));
      const id = controlId(finding);
      if (!framework || !id) return;
      const key = `${framework.id}\u0000${id}`;
      if (!controlGroups.has(key)) controlGroups.set(key, { frameworkId: framework.id, id, records: [] });
      controlGroups.get(key).records.push({ finding, index });
    });
    const controls = [...controlGroups.values()].map((control) => {
      const evaluated = control.records.filter(({ finding }) => shared.normalizeStatus(finding.status) !== 'INFO' && shared.normalizeSeverity(finding.severity) !== 'INFO');
      const passed = evaluated.length > 0 && evaluated.every(({ finding }) => shared.normalizeStatus(finding.status) === 'PASS' || shared.normalizeSeverity(finding.severity) === 'PASS');
      const framework = catalog.find((item) => item.id === control.frameworkId);
      const resources = [...new Set(control.records.map(({ finding }) => finding.resource_id).filter(Boolean))];
      const clouds = [...new Set(control.records.map(({ finding }) => shared.normalizeCloud(finding.cloud)).filter((cloud) => cloud !== 'Other'))];
      const title = control.records.map(({ finding }) => finding.control_title ?? finding.controlTitle ?? finding.control_name ?? finding.title).find(Boolean) || null;
      return { ...control, frameworkName: framework?.name || 'Framework unavailable', title, resources, clouds, evaluated: evaluated.length > 0, passed };
    });
    const frameworks = catalog.map((definition) => {
      const mappedControls = controls.filter((control) => control.frameworkId === definition.id);
      const evaluated = mappedControls.filter((control) => control.evaluated);
      const passed = evaluated.filter((control) => control.passed).length;
      const score = evaluated.length ? Math.round(passed / evaluated.length * 100) : null;
      return { ...definition, mapped: mappedControls.length > 0, status: !mappedControls.length ? 'Not Mapped' : !evaluated.length ? 'Awaiting Data' : evaluated.length < mappedControls.length ? 'Partially Evaluated' : 'Evaluated', controlsEvaluated: mappedControls.length ? evaluated.length : null, controlsPassed: mappedControls.length ? passed : null, controlsFailed: mappedControls.length ? evaluated.length - passed : null, score, controls: mappedControls };
    });
    const complianceFindings = findings.map((finding, index) => ({ finding, index })).filter(({ finding }) => {
      const domain = String(finding.domain ?? '').toLowerCase();
      const category = String(finding.category ?? '').toLowerCase();
      return domain.includes('compliance') || category.includes('compliance');
    });
    const cloudFindingCounts = shared.getFindingsByCloud(findings);
    const clouds = providers.map((provider) => ({
      ...provider,
      hasData: cloudFindingCounts[provider.name] > 0,
      controls: controls.filter((control) => control.records.some(({ finding }) => shared.normalizeCloud(finding.cloud) === provider.name)),
    }));
    const latest = findings.map((finding, index) => ({ finding, index, timestamp: Date.parse(finding.detected_at) })).filter((item) => Number.isFinite(item.timestamp)).sort((a, b) => b.timestamp - a.timestamp)[0] || null;
    const iamOpen = findings.map((finding, index) => ({ finding, index })).filter(({ finding }) => {
      const domain = shared.normalizeDomain(finding);
      return (domain.includes('IAM') || domain.includes('IDENTITY')) && shared.isOpenFinding(finding);
    });
    return {
      genericPosture: generic,
      frameworks,
      clouds,
      complianceFindings,
      coverage: { frameworksMapped: frameworks.some((framework) => framework.mapped), evaluatedChecks: generic.evaluated, cloudsWithData: clouds.filter((cloud) => cloud.hasData).map((cloud) => cloud.name) },
      activity: latest,
      priority: { attention: generic.evaluated - generic.passed, iamOpen },
      controls,
    };
  }

  function frameworkStatus(framework) {
    return framework.mapped ? framework.status : 'Not Mapped';
  }
  function renderFrameworks() {
    const filter = $('frameworkFilter').value;
    const visible = pageData.frameworks.filter((item) => filter === 'all' || item.family === filter);
    $('frameworkCount').textContent = `${visible.length} ${visible.length === 1 ? 'framework' : 'frameworks'}`;
    $('frameworkGrid').innerHTML = visible.map((item, index) => `<button class="framework-card ${item.mapped ? 'is-mapped' : ''}" type="button" data-framework="${esc(item.id)}" style="--card-order:${index}" aria-label="${esc(item.name)}, ${esc(frameworkStatus(item))}. Open framework details.">
      <span class="framework-card-top"><span class="framework-mark" aria-hidden="true">${esc(item.mark)}</span><span class="framework-status" data-state="${item.mapped ? 'mapped' : 'unmapped'}">${esc(frameworkStatus(item))}</span></span>
      <strong class="framework-name">${esc(item.name)}</strong>
      <span class="framework-card-detail">${item.mapped ? `${item.controlsEvaluated ?? '—'} controls evaluated` : 'No control mappings available'}</span>
      <span class="framework-card-bottom">${item.mapped ? `<span>${item.controlsPassed} passed</span><span>${item.controlsFailed} attention</span><span>${item.score === null ? 'Awaiting score' : `${item.score}%`}</span>` : '<span>Control-level mappings are not available in the current scan data.</span>'}</span>
      <span class="framework-open-hint">View readiness <span aria-hidden="true">→</span></span>
    </button>`).join('') || '<p class="compliance-empty">No frameworks match this filter.</p>';
  }
  function renderPosture() {
    const data = pageData.genericPosture;
    const evaluated = data.evaluated;
    const passed = data.passed;
    const score = evaluated ? data.score : null;
    const attention = evaluated ? evaluated - passed : null;
    const state = score === null ? { label: 'Awaiting data', key: 'awaiting' } : score >= 70 ? { label: 'Healthy', key: 'healthy' } : score >= 50 ? { label: 'Needs Attention', key: 'attention' } : { label: 'High Risk', key: 'high-risk' };
    $('postureScore').textContent = score === null ? '—' : `${score}%`;
    $('complianceRing').style.setProperty('--score-angle', `${score ?? 0}%`);
    $('complianceRing').setAttribute('aria-label', score === null ? 'Awaiting evaluated scan check data' : `Overall scan posture ${score} percent`);
    $('postureState').textContent = state.label;
    $('postureState').dataset.state = state.key;
    $('posturePassCount').textContent = evaluated ? `${passed} passed / ${evaluated} evaluated` : 'No evaluated checks';
    $('postureDescription').textContent = evaluated ? 'Generic scan results' : 'Current CSPM evaluation';
    $('postureSummary').textContent = evaluated ? `${passed} of ${evaluated} evaluated checks currently pass.` : 'Generic scan posture will appear when evaluated check data is available.';
    $('checkEvaluated').textContent = evaluated || '—';
    $('checkPassed').textContent = evaluated ? passed : '—';
    $('checkAttention').textContent = evaluated ? attention : '—';
    $('checkBarPassed').style.width = evaluated ? `${passed / evaluated * 100}%` : '0%';
    $('checkBarAttention').style.width = evaluated ? `${attention / evaluated * 100}%` : '0%';
    $('checkBar').setAttribute('aria-label', evaluated ? `${passed} passed and ${attention} failed or need attention out of ${evaluated} evaluated checks` : 'No evaluated scan checks');
    $('heroFrameworkStatus').innerHTML = `<i></i> ${pageData.coverage.frameworksMapped ? 'Mapped controls available' : 'Framework mappings unavailable'}`;
  }
  function renderClouds() {
    const shared = window.CSPMShared;
    $('cloudCompliance').innerHTML = pageData.clouds.map((cloud) => `<button type="button" class="cloud-compliance-row ${selectedCloud === cloud.name ? 'is-selected' : ''}" data-cloud="${esc(cloud.name)}" aria-pressed="${selectedCloud === cloud.name}" aria-label="Filter compliance-related findings by ${esc(cloud.name)}"><span class="provider-mark provider-${cloud.name.toLowerCase()}">${window.CSPM_ICONS[cloud.icon]}</span><span class="cloud-name">${esc(cloud.name)}</span><span class="cloud-coverage">${cloud.controls.length ? `${cloud.controls.length} mapped controls` : 'No mapped controls'}<small>${cloud.hasData ? 'CSPM finding data available' : 'No current CSPM finding data'}</small></span><span class="cloud-arrow" aria-hidden="true">→</span></button>`).join('');
    const cloudName = selectedCloud === 'all' ? null : selectedCloud;
    const records = pageData.complianceFindings.filter(({ finding }) => !cloudName || shared.normalizeCloud(finding.cloud) === cloudName);
    renderComplianceFindings(records);
    $('cloudSelectionNote').textContent = selectedCloud === 'all' ? 'Select a provider to filter compliance-related findings.' : `Showing ${selectedCloud} compliance-related findings. Select it again to clear the filter.`;
  }
  function findingHref(finding, index) {
    const params = new URLSearchParams();
    if (finding.finding_id) params.set('id', finding.finding_id);
    if (Number.isInteger(index)) params.set('record', String(index));
    return `findings.html?${params.toString()}`;
  }
  function renderComplianceFindings(records) {
    if (!records.length) {
      $('complianceFindings').innerHTML = `<div class="compliance-empty-state"><span data-cspm-icon="findings" aria-hidden="true"></span><strong>${selectedCloud === 'all' ? 'No dedicated compliance-domain findings available.' : `No compliance-related findings are recorded for ${esc(selectedCloud)}.`}</strong><p>Findings are included here only when their domain or category explicitly identifies Compliance.</p><a class="text-link" href="findings.html">Browse all findings <span aria-hidden="true">→</span></a></div>`;
      return;
    }
    $('complianceFindings').innerHTML = records.slice(0, 4).map(({ finding, index }) => `<a class="compliance-finding-row" href="${esc(findingHref(finding, index))}"><span class="finding-severity-dot" data-severity="${esc(window.CSPMShared.normalizeSeverity(finding.severity).toLowerCase())}"></span><span class="compliance-finding-title"><strong>${esc(finding.finding || finding.finding_id || 'Untitled finding')}</strong><small>${esc(finding.finding_id || 'No finding ID')} · ${esc(window.CSPMShared.normalizeCloud(finding.cloud))}</small></span><span class="finding-status-label">${esc(window.CSPMShared.normalizeStatus(finding.status))}</span><span aria-hidden="true">→</span></a>`).join('');
  }
  function renderActions() {
    const actions = [];
    if (!pageData.coverage.frameworksMapped) actions.push({ icon: 'reports', title: 'Add framework control mappings', detail: 'Framework-specific posture is unavailable until control mappings are present in finding data.', href: 'findings.html', kind: 'mapping' });
    if (pageData.priority.attention > 0) actions.push({ icon: 'findings', title: `Review ${pageData.priority.attention} non-passing scan checks`, detail: 'These checks contribute to generic scan posture; they are not framework control failures.', href: 'findings.html', kind: 'attention' });
    const iam = pageData.priority.iamOpen[0];
    if (iam) actions.push({ icon: 'iam', title: `Review ${pageData.priority.iamOpen.length} open IAM findings`, detail: 'Open IAM records are present in the current findings dataset.', href: 'iam.html', kind: 'iam' });
    $('priorityActions').innerHTML = actions.map((action, index) => `<a class="priority-action" href="${esc(action.href)}" style="--card-order:${index}"><span class="action-icon" data-cspm-icon="${action.icon}" aria-hidden="true">${window.CSPM_ICONS[action.icon] || ''}</span><span class="action-copy"><strong>${esc(action.title)}</strong><small>${esc(action.detail)}</small></span><span class="action-arrow" aria-hidden="true">→</span></a>`).join('');
  }
  function renderCoverage() {
    const data = pageData.coverage;
    const clouds = data.cloudsWithData.length ? data.cloudsWithData.join(', ') : 'No current cloud data';
    const rows = [['Framework mappings', data.frameworksMapped ? 'Available' : 'Not available'], ['Evaluated checks', data.evaluatedChecks || 'No evaluated checks'], ['Clouds with current data', clouds]];
    $('complianceCoverage').innerHTML = rows.map(([label, value]) => `<div class="coverage-row"><dt>${esc(label)}</dt><dd>${esc(value)}</dd></div>`).join('');
    const mappedControls = pageData.controls;
    $('coverageSummaryState').innerHTML = `${mappedControls.length ? `${mappedControls.length} mapped controls` : 'No mappings available'} <span data-cspm-icon="chevronDown" aria-hidden="true">${window.CSPM_ICONS.chevronDown}</span>`;
    $('controlCoverageBody').innerHTML = mappedControls.length ? `<div class="control-table-wrap"><table class="control-table"><thead><tr><th>Control</th><th>Framework</th><th>Cloud</th><th>Status</th><th>Affected resources</th><th>Related findings</th></tr></thead><tbody>${mappedControls.map((control) => {
      const status = control.evaluated ? control.passed ? 'Passed' : 'Attention' : 'Awaiting Data';
      const resources = control.resources.length ? control.resources.join(', ') : 'Not recorded';
      const links = control.records.map(({ finding, index }) => `<a href="${esc(findingHref(finding, index))}">${esc(finding.finding_id || 'View finding')}</a>`).join(', ');
      return `<tr><td><code>${esc(control.id)}</code><small>${esc(control.title || 'Control title not recorded')}</small></td><td>${esc(control.frameworkName)}</td><td>${esc(control.clouds.join(', ') || 'Not recorded')}</td><td><span class="control-status" data-state="${status === 'Passed' ? 'passed' : status === 'Attention' ? 'attention' : 'waiting'}">${esc(status)}</span></td><td>${esc(resources)}</td><td>${links}</td></tr>`;
    }).join('')}</tbody></table></div>` : `<div class="coverage-empty-icon" data-cspm-icon="inventory" aria-hidden="true">${window.CSPM_ICONS.inventory}</div><div><strong>No control-level framework mappings are available.</strong><p>Framework-specific posture will appear after controls are mapped to CSPM findings.</p></div>`;
  }
  function renderActivity() {
    const activity = pageData.activity;
    if (!activity) {
      $('complianceActivity').innerHTML = '<div class="activity-empty"><strong>No observed finding activity</strong><p>No valid finding timestamps are available in the current data.</p></div>';
      return;
    }
    const finding = activity.finding;
    const date = new Date(activity.timestamp);
    $('complianceActivity').innerHTML = `<div class="activity-observed"><span class="activity-pulse" aria-hidden="true"></span><div><span class="activity-label">Latest observed finding</span><time datetime="${esc(finding.detected_at)}">${esc(date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }))}</time><a href="${esc(findingHref(finding, activity.index))}">${esc(finding.finding || finding.finding_id || 'View finding')} <span aria-hidden="true">→</span></a></div></div><p class="activity-note">This timestamp comes from the finding record; a scan completion time is not available.</p>`;
  }
  function render() {
    if (!pageData) throw new Error('Compliance data is not initialized');
    renderPosture(); renderFrameworks(); renderClouds(); renderActions(); renderCoverage(); renderActivity();
  }
  function setData() {
    const shared = window.CSPMShared;
    if (!shared || !shared.hasDataSource()) throw new Error('Shared CSPM finding data is unavailable');
    pageData = getCompliancePageData(shared.getFindings());
    render();
  }
  function showError() {
    $('complianceLoading').hidden = true; $('complianceWorkspace').hidden = true; $('complianceError').hidden = false;
    $('complianceContent').setAttribute('aria-busy', 'false');
  }
  function closeDrawer(restore = true) {
    const drawer = $('frameworkDrawer');
    drawer.classList.remove('is-open'); drawer.setAttribute('aria-hidden', 'true'); drawer.inert = true;
    $('frameworkBackdrop').hidden = true; document.body.classList.remove('framework-drawer-open');
    if (restore && drawerReturnFocus?.isConnected) drawerReturnFocus.focus();
  }
  function openFramework(framework) {
    const drawer = $('frameworkDrawer');
    drawerReturnFocus = document.activeElement;
    $('frameworkDrawerTitle').textContent = framework.name;
    $('frameworkDrawerBody').innerHTML = framework.mapped
      ? `<span class="framework-status" data-state="mapped">${esc(framework.status)}</span><p class="framework-drawer-summary">Control-level mapping evidence is available from the current records.</p><dl class="framework-drawer-metrics"><div><dt>Controls evaluated</dt><dd>${framework.controlsEvaluated}</dd></div><div><dt>Passed</dt><dd>${framework.controlsPassed}</dd></div><div><dt>Failed / Attention</dt><dd>${framework.controlsFailed}</dd></div><div><dt>Posture score</dt><dd>${framework.score === null ? 'Awaiting data' : `${framework.score}%`}</dd></div></dl><h3>Mapped controls</h3><div class="mapped-controls">${framework.controls.map((control) => `<div class="mapped-control"><code>${esc(control.id)}</code><span>${control.evaluated ? control.passed ? 'Passed' : 'Attention' : 'Awaiting Data'}</span></div>`).join('')}</div>`
      : `<span class="framework-status" data-state="unmapped">Not Mapped</span><h3>Framework not mapped</h3><p>Current finding records do not contain control-level mappings for ${esc(framework.name)}. The generic scan posture is not a framework score.</p><div class="drawer-explainer"><span data-cspm-icon="activity" aria-hidden="true"></span><span>No control metrics or score are available until mapped control evidence is included in the shared findings data.</span></div>`;
    drawer.inert = false; drawer.setAttribute('aria-hidden', 'false'); $('frameworkBackdrop').hidden = false;
    document.body.classList.add('framework-drawer-open'); requestAnimationFrame(() => drawer.classList.add('is-open'));
    $('frameworkDrawerClose').focus();
  }
  function exportSummary() {
    const posture = pageData.genericPosture;
    const json = {
      reportType: 'CSPM compliance summary',
      exportedAt: new Date().toISOString(),
      genericScanPosture: { score: posture.evaluated ? posture.score : null, evaluated: posture.evaluated, passed: posture.passed, attention: posture.evaluated ? posture.evaluated - posture.passed : null },
      frameworks: pageData.frameworks.map(({ id, name, mapped, status, controlsEvaluated, controlsPassed, controlsFailed, score }) => ({ id, name, mapped, status, controlsEvaluated, controlsPassed, controlsFailed, score })),
      clouds: pageData.clouds.map(({ name, hasData, controls }) => ({ name, findingDataAvailable: hasData, mappedControls: controls.length })),
      complianceFindingsAvailable: pageData.complianceFindings.length,
      frameworkCertification: false,
    };
    const blob = new Blob([JSON.stringify(json, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob); const anchor = document.createElement('a');
    anchor.href = url; anchor.download = 'cspm-compliance-summary.json'; document.body.append(anchor); anchor.click(); anchor.remove(); URL.revokeObjectURL(url);
    $('complianceLive').textContent = 'Compliance summary exported as JSON.';
  }
  function init() {
    $('frameworkFilter').addEventListener('change', renderFrameworks);
    $('frameworkGrid').addEventListener('click', (event) => { const card = event.target.closest('[data-framework]'); if (card) { const framework = pageData.frameworks.find((item) => item.id === card.dataset.framework); if (framework) openFramework(framework); } });
    $('cloudCompliance').addEventListener('click', (event) => { const row = event.target.closest('[data-cloud]'); if (!row) return; selectedCloud = selectedCloud === row.dataset.cloud ? 'all' : row.dataset.cloud; renderClouds(); });
    $('complianceExport').addEventListener('click', () => { try { exportSummary(); } catch (_) { $('complianceLive').textContent = 'Could not export the compliance summary.'; } });
    const retry = () => { $('complianceError').hidden = true; $('complianceLoading').hidden = false; $('complianceContent').setAttribute('aria-busy', 'true'); try { setData(); $('complianceLoading').hidden = true; $('complianceWorkspace').hidden = false; $('complianceContent').setAttribute('aria-busy', 'false'); $('complianceLive').textContent = 'Compliance posture refreshed from current CSPM findings.'; } catch (_) { showError(); } };
    $('complianceRefresh').addEventListener('click', retry); $('complianceRetry').addEventListener('click', retry);
    $('frameworkDrawerClose').addEventListener('click', () => closeDrawer()); $('frameworkBackdrop').addEventListener('click', () => closeDrawer());
    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape' && !$('frameworkDrawer').inert) closeDrawer();
      if (event.key === 'Tab' && !$('frameworkDrawer').inert) {
        const focusable = [...$('frameworkDrawer').querySelectorAll('button, a[href], [tabindex]:not([tabindex="-1"])')].filter((item) => !item.disabled);
        const first = focusable[0], last = focusable[focusable.length - 1];
        if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
      }
    });
    window.addEventListener('storage', (event) => { if (event.key === 'theme') document.documentElement.dataset.complianceTheme = event.newValue || ''; });
    window.getCompliancePageData = getCompliancePageData;
    try {
      setTimeout(() => { try { setData(); $('complianceLoading').hidden = true; $('complianceWorkspace').hidden = false; $('complianceContent').setAttribute('aria-busy', 'false'); } catch (_) { showError(); } }, 70);
    } catch (_) { showError(); }
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init, { once: true }); else init();
})();
