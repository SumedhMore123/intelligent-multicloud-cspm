(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  const PAGE_SIZE = 20;
  const severityRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0, PASS: 0 };
  let shared;
  let rows = [];
  let liveDataAssessment = false;
  const state = { search: "", cloud: "", severity: "", status: "", type: "", category: "", sort: "detected", page: 1, selected: null, lastFocus: null };
  const textOf = (value) => typeof value === "string" ? value : value == null ? "" : (() => { try { return JSON.stringify(value); } catch (_) { return String(value); } })();
  const domainOf = (f) => String(shared.normalizeDomain(f) || "").trim().toUpperCase();
  const cloudOf = (f) => shared.normalizeCloud(f.cloud);
  const severityOf = (f) => shared.normalizeSeverity(f.severity);
  const statusOf = (f) => shared.normalizeStatus(f.status);
  const identity = (f) => f?.resource_type && f?.resource_id ? JSON.stringify([String(f.resource_type), String(f.resource_id)]) : "";
  const timestamp = (value) => { const parsed = Date.parse(value); return Number.isFinite(parsed) ? parsed : null; };
  const normalizedText = (f) => [f.finding_id, f.finding, f.domain, f.category, f.resource_type, f.resource_id, textOf(f.evidence)].filter(Boolean).join(" ");

  function isDataDomain(f) {
    const d = domainOf(f);
    return /^(?:DATA(?:\b|[ &-])|STORAGE(?:\b|[ &-]))/.test(d);
  }
  function getDataSecurityFindings(findings) {
    return (Array.isArray(findings) ? findings : []).map((finding, index) => ({ finding, index }))
      .filter(({ finding }) => finding && typeof finding === "object" && isDataDomain(finding));
  }
  function getDataSecurityResources(records) {
    const groups = new Map();
    (records || []).forEach(({ finding, index }) => {
      const key = identity(finding);
      if (!key) return;
      if (!groups.has(key)) groups.set(key, { key, resource_type: String(finding.resource_type), resource_id: String(finding.resource_id), findings: [], clouds: new Set(), maxRisk: null, lastSeen: null });
      const resource = groups.get(key);
      resource.findings.push({ finding, index });
      resource.clouds.add(cloudOf(finding));
      const risk = finding.risk_score === null || finding.risk_score === undefined || finding.risk_score === "" ? NaN : Number(finding.risk_score);
      if (Number.isFinite(risk)) resource.maxRisk = resource.maxRisk === null ? risk : Math.max(resource.maxRisk, risk);
      const seen = timestamp(finding.detected_at);
      if (seen !== null) resource.lastSeen = resource.lastSeen === null ? finding.detected_at : timestamp(resource.lastSeen) >= seen ? resource.lastSeen : finding.detected_at;
    });
    return [...groups.values()].map((resource) => {
      const open = resource.findings.filter(({ finding }) => shared.isOpenFinding(finding));
      return { ...resource, open_findings: open.length, highest_severity: resource.findings.map(({ finding }) => severityOf(finding)).sort((a, b) => (severityRank[b] || 0) - (severityRank[a] || 0))[0] || "—" };
    });
  }
  function getDataSecuritySummary(records) {
    const resources = getDataSecurityResources(records);
    const open = records.filter(({ finding }) => shared.isOpenFinding(finding));
    return { findings: records.length, open: open.length, high_critical: open.filter(({ finding }) => ["HIGH", "CRITICAL"].includes(severityOf(finding))).length, resources: resources.length, clouds: new Set(records.map(({ finding }) => cloudOf(finding))).size };
  }
  function classifyExposure(f) {
    const value = `${f.domain || ""} ${f.category || ""} ${f.finding || ""} ${textOf(f.evidence)}`.toLowerCase();
    const categories = [];
    const publicClaim = /(?:public|internet)[^\n]{0,70}(?:bucket|storage|object|data)|(?:bucket|storage|object|data)[^\n]{0,70}(?:public|internet)/i.test(value);
    const publicNegation = /\b(?:not|no|never|without|isn't|is\s+not|non-)\s+(?:public(?:ly)?(?:\s+(?:exposed|accessible|access))?|internet(?:[- ]facing)?|exposed\s+to\s+the\s+internet)\b/i.test(value);
    if (publicClaim && !publicNegation) categories.push("Public storage exposure");
    if (/(?:database|db)[^\n]{0,70}(?:public|internet|expos|accessible)|(?:public|internet)[^\n]{0,70}(?:database|\bdb\b)/i.test(value)) categories.push("Database exposure");
    if (/(?:unencrypted|not encrypted|encryption (?:is )?(?:disabled|not enabled)|encryption at rest.*(?:disabled|missing|not enabled))/i.test(value)) categories.push("Unencrypted storage");
    if (/(?:sensitive data|personal data|data classification|\bdlp\b)/i.test(value)) categories.push("Sensitive-data protection gaps");
    if (/(?:retention|lifecycle policy)[^\n]{0,80}(?:misconfig|missing|disabled|risk|issue|not configured)|(?:misconfig|missing|disabled|risk|issue)[^\n]{0,80}(?:retention|lifecycle policy)/i.test(value)) categories.push("Data-retention configuration issues");
    if (/(?:overly broad|overly permissive|excessive|unrestricted)[^\n]{0,60}(?:data access|storage access|permission|policy)|(?:data|storage)[^\n]{0,60}(?:access|permission|policy)[^\n]{0,60}(?:broad|permissive|excessive|unrestricted)/i.test(value)) categories.push("Overly permissive data access");
    return categories;
  }
  function getDataExposureStats(records) {
    const labels = ["Public storage exposure", "Overly permissive data access", "Unencrypted storage", "Database exposure", "Sensitive-data protection gaps", "Data-retention configuration issues"];
    return labels.map((label) => ({ label, count: records.filter(({ finding }) => classifyExposure(finding).includes(label)).length })).filter((item) => item.count);
  }
  function isEncryptionFinding(f) { return /encrypt|encryption|kms|key management|cryptographic key/i.test(normalizedText(f)); }
  function isStorageFinding(f) { return /s3.?bucket|storage.?account|gcs.?bucket|object.?storage|storage|bucket|blob container|database/i.test(`${f.resource_type || ""} ${f.category || ""} ${f.finding || ""} ${textOf(f.evidence)}`); }
  function isDataAccessFinding(f) { return /data access|storage access|access[^\n]{0,60}(?:data|storage|bucket|database)|(?:data|storage|bucket|database)[^\n]{0,60}(?:access|permission|policy)|(?:excessive|broad|overly permissive)[^\n]{0,60}(?:permission|policy)[^\n]{0,60}(?:data|storage|bucket|database)|public access|cross.account|cross.project|privileged access/i.test(`${f.category || ""} ${f.finding || ""} ${textOf(f.evidence)}`); }
  function isSensitiveDataFinding(f) { return /sensitive data|personal data|data classification|\bdlp\b|data discovery/i.test(`${f.category || ""} ${f.finding || ""} ${textOf(f.evidence)}`); }
  function getEncryptionStats(records) { const matches = records.filter(({ finding }) => isEncryptionFinding(finding)); return { findings: matches.length, resources: getDataSecurityResources(matches).length, records: matches }; }
  function getDataSecurityCloudStats(records) {
    return ["AWS", "Azure", "GCP", "Other"].map((cloud) => { const matches = records.filter(({ finding }) => cloudOf(finding) === cloud); return { cloud, findings: matches.length, resources: getDataSecurityResources(matches).length, assessed: matches.length > 0 }; });
  }
  function getDataSecurityRecommendations(records) {
    const recommendations = records.map(({ finding }) => finding.recommendation || finding.remediation).filter((value) => typeof value === "string" && value.trim());
    return [...new Set(recommendations)];
  }
  function setUnavailable(id, heading, description = "") {
    const el = $(id); el.className = "data-unavailable";
    el.innerHTML = `<strong>${esc(heading)}</strong>${description ? `<span>${esc(description)}</span>` : ""}`;
  }
  function renderMetrics(records) {
    const metrics = $("dataMetrics");
    if (!records.length) { metrics.hidden = true; metrics.innerHTML = ""; return; }
    const summary = getDataSecuritySummary(records);
    metrics.hidden = false;
    metrics.innerHTML = [["Data security findings", summary.findings], ["Open findings", summary.open], ["Open high / critical", summary.high_critical], ["Affected data resources", summary.resources], ["Clouds with data findings", summary.clouds]].map(([label, value]) => `<article class="data-metric"><span>${esc(label)}</span><strong data-count-to="${value}">0</strong></article>`).join("");
    const counters = [...metrics.querySelectorAll("[data-count-to]")];
    counters.forEach((counter) => {
      const target = Number(counter.dataset.countTo) || 0;
      if (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches || typeof window.requestAnimationFrame !== "function") { counter.textContent = String(target); return; }
      const start = Date.now(), duration = 360;
      const tick = () => { const progress = Math.min(1, (Date.now() - start) / duration); counter.textContent = String(Math.round(target * (1 - Math.pow(1 - progress, 3)))); if (progress < 1) window.requestAnimationFrame(tick); };
      window.requestAnimationFrame(tick);
    });
  }
  function renderExposure(records) {
    const stats = getDataExposureStats(records);
    if (!records.length) { setUnavailable("dataExposure", "No data-exposure assessment available", "Data-security findings are required to evaluate exposure categories."); return; }
    if (!stats.length) { setUnavailable("dataExposure", "No classified exposure signals in available data", "No finding text or category clearly supports the listed exposure classifications."); return; }
    $("dataExposure").className = "data-bars";
    $("dataExposure").innerHTML = stats.map(({ label, count }) => `<div class="data-bar-row"><span>${esc(label)}</span><b>${count}</b></div>`).join("");
  }
  function renderSeverity(records) {
    const risks = records.filter(({ finding }) => shared.isRiskFinding(finding));
    if (!records.length) { setUnavailable("dataSeverity", "Severity distribution unavailable", "No data-security assessment is available in the current findings."); return; }
    if (!risks.length) { setUnavailable("dataSeverity", "Assessment findings contain no risk severities", "All available Data-domain records are PASS or INFO."); return; }
    $("dataSeverity").className = "data-severity-list";
    $("dataSeverity").innerHTML = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((severity) => {
      const count = risks.filter(({ finding }) => severityOf(finding) === severity).length;
      const percentage = Math.round(count / risks.length * 100);
      return `<div class="data-severity-row" data-severity="${severity.toLowerCase()}"><span>${severity}</span><i><b style="--data-bar-width:${percentage}%"></b></i><strong>${count}</strong><small>${percentage}%</small></div>`;
    }).join("");
  }
  function renderStorage(records) {
    const matches = records.filter(({ finding }) => isStorageFinding(finding));
    if (!matches.length) { setUnavailable("dataStorage", "Storage assessment data unavailable.", "No storage-specific findings are represented in current Data-domain records."); return; }
    $("dataStorage").className = "data-signal-list";
    $("dataStorage").innerHTML = matches.slice(0, 5).map(({ finding }) => `<div><strong>${esc(finding.finding || finding.category || "Storage security finding")}</strong><span>${esc([finding.resource_type, finding.resource_id].filter(Boolean).join(" · ") || "Resource identity unavailable")}</span></div>`).join("");
  }
  function renderEncryption(records) {
    const matches = getEncryptionStats(records).records;
    if (!matches.length) { setUnavailable("dataEncryption", "Encryption posture cannot be assessed from current data.", "No explicit encryption-related Data-domain findings or evaluated-resource totals are available."); return; }
    $("dataEncryption").className = "data-signal-list";
    $("dataEncryption").innerHTML = matches.slice(0, 5).map(({ finding }) => `<div><strong>${esc(finding.finding || finding.category || "Encryption-related finding")}</strong><span>${esc(finding.evidence ? textOf(finding.evidence) : "Evidence not recorded")}</span></div>`).join("");
  }
  function renderAccess(records) {
    const matches = records.filter(({ finding }) => isDataAccessFinding(finding));
    if (!matches.length) { setUnavailable("dataAccess", "Dedicated data-access assessment is unavailable.", "Only data-domain findings with explicit access-control meaning appear here."); return; }
    const resources = getDataSecurityResources(matches);
    const highest = matches.map(({ finding }) => severityOf(finding)).sort((a, b) => (severityRank[b] || 0) - (severityRank[a] || 0))[0];
    $("dataAccess").className = "data-access-summary";
    $("dataAccess").innerHTML = `<div><strong>${matches.length}</strong><span>data-access findings</span></div><div><strong>${resources.length || "—"}</strong><span>identified resources</span></div><div><strong>${esc(highest)}</strong><span>highest severity</span></div>`;
  }
  function renderSensitive(records) {
    const matches = records.filter(({ finding }) => isSensitiveDataFinding(finding));
    if (!matches.length) { setUnavailable("dataSensitive", "Sensitive-data discovery is not available in the current assessment data.", "No discovery or classification results are present."); return; }
    $("dataSensitive").className = "data-signal-list";
    $("dataSensitive").innerHTML = matches.slice(0, 3).map(({ finding }) => `<div><strong>${esc(finding.finding || finding.category || "Sensitive-data finding")}</strong><span>${esc(finding.resource_type && finding.resource_id ? `${finding.resource_type} · ${finding.resource_id}` : "Resource identity unavailable")}</span></div>`).join("");
  }
  function renderClouds(records, source) {
    const allClouds = new Set(source.map((finding) => shared.normalizeCloud(finding.cloud)));
    getDataSecurityCloudStats(records).forEach(({ cloud, findings: count, resources }) => {
      const suffix = cloud === "Other" ? "Other" : cloud;
      const label = count ? "Data-security findings available" : allClouds.has(cloud) ? "General CSPM data; data assessment unavailable" : "No data-security assessment available.";
      $("dataCloud" + suffix).textContent = label;
      const badge = $("dataCloudCount" + suffix); badge.textContent = count ? `${count} findings · ${resources} resources` : ""; badge.hidden = !count;
    });
  }
  function renderResources(records) {
    const resources = getDataSecurityResources(records);
    if (!resources.length) { setUnavailable("dataResourceState", "No data resources are represented in the available CSPM data.", "Complete data-resource visibility requires actual asset discovery."); $("dataResourceTypes").innerHTML = ""; return; }
    $("dataResourceState").className = "data-resource-list";
    $("dataResourceState").innerHTML = resources.map((resource) => `<div><span><strong>${esc(resource.resource_id)}</strong><small>${esc(resource.resource_type)} · ${esc([...resource.clouds].join(", "))}</small></span><span class="data-resource-meta"><b>${resource.findings.length} findings · ${resource.open_findings} open</b><small>Highest ${esc(resource.highest_severity)} · Risk ${esc(resource.maxRisk ?? "not recorded")} · Last seen ${esc(dateLabel(resource.lastSeen))}</small></span></div>`).join("");
    const byType = new Map(); resources.forEach((resource) => byType.set(resource.resource_type, (byType.get(resource.resource_type) || 0) + 1));
    $("dataResourceTypes").innerHTML = `<h3>Resources by Type</h3>` + [...byType].sort(([a], [b]) => a.localeCompare(b)).map(([type, count]) => `<span>${esc(type)} <b>${count}</b></span>`).join("");
  }
  function renderCoverage(records) {
    const resources = getDataSecurityResources(records);
    const clouds = new Set(records.map(({ finding }) => cloudOf(finding)));
    const mappingPresent = records.some(({ finding }) => Boolean((finding.framework || finding.compliance_standard || finding.benchmark || finding.framework_id) && (finding.control_id || finding.controlId || finding.control || finding.benchmark_control_id)));
    $("dataCoverage").innerHTML = `<div><span>Data-related findings</span><strong>${records.length ? `${records.length} available` : "Unavailable"}</strong></div><div><span>Data resources represented</span><strong>${resources.length || "Unavailable"}</strong></div><div><span>Clouds with data findings</span><strong>${clouds.size || "Unavailable"}</strong></div><div><span>Framework mappings</span><strong>${mappingPresent ? "Present in source" : "Not present in source"}</strong></div><p>Assessment coverage is not established by the current data.</p>`;
  }
  function renderRecommendations(records) {
    if (!records.length) { setUnavailable("dataRecommendations", "Configure or run a data-security scan to evaluate this domain.", "The Data scanner currently checks S3 bucket access and default encryption."); return; }
    const provided = getDataSecurityRecommendations(records);
    const items = provided.length ? provided : ["Review the evidence and source-defined controls attached to these data-security findings."];
    $("dataRecommendations").className = "data-recommendation-list";
    $("dataRecommendations").innerHTML = items.slice(0, 5).map((item) => `<div><strong>${esc(item)}</strong></div>`).join("");
  }
  function setOptions(id, values, label) {
    const select = $(id), current = select.value;
    select.innerHTML = `<option value="">${esc(label)}</option>` + values.map((value) => `<option value="${esc(value)}">${esc(value)}</option>`).join("");
    select.value = values.includes(current) ? current : "";
    return select.value;
  }
  function categoryOf(f) { return String(f.category || f.domain || "Unspecified"); }
  function updatePage() {
    const source = shared.getFindings();
    rows = getDataSecurityFindings(source);
    const assessed = rows.length > 0 || liveDataAssessment;
    $("dataViewFindings").hidden = !assessed; $("dataAllFindings").hidden = !assessed;
    if (!assessed) {
      $("dataAssessmentTitle").textContent = "Awaiting Data Security Assessment";
      $("dataAssessmentDescription").textContent = "Data-security posture will appear when data-related CSPM findings or assessment results become available.";
      $("dataAssessmentState").innerHTML = "<i></i>Assessment coverage unavailable";
    } else if (!rows.length) {
      $("dataAssessmentTitle").textContent = "No Data Security Findings Detected";
      $("dataAssessmentDescription").textContent = "The latest live Data scan completed successfully and did not identify any configured S3 data-protection findings.";
      $("dataAssessmentState").innerHTML = "<i></i>Assessment completed; no findings";
    } else {
      $("dataAssessmentTitle").textContent = "Data Security Findings Available";
      $("dataAssessmentDescription").textContent = "This view reflects findings with an explicit Data or Storage domain/category in the shared CSPM data.";
      $("dataAssessmentState").innerHTML = "<i></i>Assessment data available";
    }
    renderMetrics(rows); renderExposure(rows); renderSeverity(rows); renderStorage(rows); renderEncryption(rows); renderAccess(rows); renderSensitive(rows); renderClouds(rows, source); renderResources(rows); renderCoverage(rows); renderRecommendations(rows);
    state.cloud = setOptions("dataCloudFilter", [...new Set(rows.map(({ finding }) => cloudOf(finding)))].sort(), "All clouds");
    state.severity = setOptions("dataSeverityFilter", [...new Set(rows.map(({ finding }) => severityOf(finding)))].sort((a, b) => (severityRank[b] || 0) - (severityRank[a] || 0)), "All severities");
    state.status = setOptions("dataStatusFilter", [...new Set(rows.map(({ finding }) => statusOf(finding)))].sort(), "All statuses");
    state.type = setOptions("dataTypeFilter", [...new Set(rows.map(({ finding }) => String(finding.resource_type || "")).filter(Boolean))].sort(), "All resource types");
    state.category = setOptions("dataCategoryFilter", [...new Set(rows.map(({ finding }) => categoryOf(finding)))].sort(), "All categories");
    renderTable();
  }
  function setLiveStatus(message, isError) {
    const element = $("dataLive");
    element.textContent = message;
    element.dataset.state = isError ? "error" : "ready";
  }
  function applyLiveDataResult(payload) {
    if (!payload || payload.source !== "live-data-scan" || !Array.isArray(payload.findings)) {
      throw new Error("The backend returned an invalid data scan result.");
    }
    try { localStorage.setItem("cspm-live-data-scan", JSON.stringify(payload)); } catch (error) {
      console.error("Unable to persist data scan in browser storage:", error);
    }
    for (let index = SAMPLE_FINDINGS.length - 1; index >= 0; index -= 1) {
      if (isDataDomain(SAMPLE_FINDINGS[index])) SAMPLE_FINDINGS.splice(index, 1);
    }
    payload.findings.forEach((finding) => SAMPLE_FINDINGS.push(finding));
    window.CSPM_LIVE_DATA_META = payload;
    liveDataAssessment = true;
    updatePage();
  }
  async function loadSavedDataScan() {
    try {
      const response = await fetch("http://127.0.0.1:8765/api/data/results", { cache: "no-store" });
      if (!response.ok) return;
      const payload = await response.json();
      if (payload.source === "live-data-scan") {
        applyLiveDataResult(payload);
        setLiveStatus(`Last successful live data scan completed. ${payload.findings.length} findings recorded.`);
      }
    } catch (error) {
      setLiveStatus("Backend unavailable. Start the local backend to run a data scan.", true);
    }
  }
  async function runLiveDataScan() {
    const button = $("runDataScanBtn");
    button.disabled = true;
    button.setAttribute("aria-busy", "true");
    setLiveStatus("Data scan is running. Waiting for AWS S3 results...");
    try {
      const body = {};
      const profile = $("dataAwsProfile").value.trim();
      const region = $("dataAwsRegion").value.trim();
      if (profile) body.profile_name = profile;
      if (region) body.region_name = region;
      const response = await fetch("http://127.0.0.1:8765/api/data/scans", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || "Unable to start data scan.");
      let status = payload.status;
      while (status.state === "RUNNING") {
        await new Promise((resolve) => window.setTimeout(resolve, 500));
        status = (await (await fetch("http://127.0.0.1:8765/api/data/status", { cache: "no-store" })).json()).status;
      }
      if (status.state !== "SUCCEEDED") throw new Error(status.error || "Data scan failed.");
      const result = await (await fetch("http://127.0.0.1:8765/api/data/results", { cache: "no-store" })).json();
      applyLiveDataResult(result);
      setLiveStatus(`Live data scan completed. ${result.findings.length} findings recorded.`);
    } catch (error) {
      setLiveStatus(error instanceof Error ? error.message : "Data scan failed.", true);
    } finally {
      button.disabled = false;
      button.removeAttribute("aria-busy");
    }
  }
  function filterRecords() {
    const q = state.search.trim().toLocaleLowerCase();
    return rows.filter(({ finding: f }) => {
      const haystack = [f.finding_id, f.finding, f.cloud, f.domain, f.category, f.resource_type, f.resource_id, textOf(f.evidence)].filter(Boolean).join(" ").toLocaleLowerCase();
      return (!q || haystack.includes(q)) && (!state.cloud || cloudOf(f) === state.cloud) && (!state.severity || severityOf(f) === state.severity) && (!state.status || statusOf(f) === state.status) && (!state.type || String(f.resource_type || "") === state.type) && (!state.category || categoryOf(f) === state.category);
    }).sort((a, b) => {
      const x = a.finding, y = b.finding;
      if (state.sort === "severity") return (severityRank[severityOf(y)] || 0) - (severityRank[severityOf(x)] || 0);
      if (state.sort === "risk") return (Number(y.risk_score) || 0) - (Number(x.risk_score) || 0) || (timestamp(y.detected_at) || 0) - (timestamp(x.detected_at) || 0);
      if (state.sort === "cloud") return cloudOf(x).localeCompare(cloudOf(y));
      if (state.sort === "resource") return `${x.resource_type || ""} ${x.resource_id || ""}`.localeCompare(`${y.resource_type || ""} ${y.resource_id || ""}`);
      return (timestamp(y.detected_at) || 0) - (timestamp(x.detected_at) || 0) || a.index - b.index;
    });
  }
  function dateLabel(value) { if (!value) return "Not recorded"; const date = new Date(value); return Number.isNaN(date.getTime()) ? String(value) : new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(date); }
  function renderTable() {
    const filtered = filterRecords(), pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
    state.page = Math.max(1, Math.min(state.page, pages));
    const visible = filtered.slice((state.page - 1) * PAGE_SIZE, state.page * PAGE_SIZE);
    $("dataFindingsBody").innerHTML = visible.map(({ finding: f, index }) => `<tr data-record-index="${index}" tabindex="0"><td><span class="data-severity-pill" data-severity="${esc(severityOf(f).toLowerCase())}">${esc(severityOf(f))}</span></td><td><button class="data-finding-open" type="button" data-index="${index}"><strong>${esc(f.finding || f.finding_id || "Data security finding")}</strong><small>${esc(f.finding_id || "ID unavailable")}</small></button></td><td>${esc(cloudOf(f))}</td><td><span class="data-resource-cell"><strong>${esc(f.resource_type || "Type unavailable")}</strong><small>${esc(f.resource_id || "ID unavailable")}</small></span></td><td>${esc(categoryOf(f))}</td><td>${esc(f.risk_score ?? "—")}</td><td>${esc(statusOf(f))}</td><td>${esc(dateLabel(f.detected_at))}</td></tr>`).join("");
    const active = Boolean(state.search || state.cloud || state.severity || state.status || state.type || state.category);
    $("dataEmpty").hidden = visible.length > 0;
    const emptyTitle = !rows.length ? (liveDataAssessment ? "No data-security findings detected." : "Awaiting Data Security Assessment") : active ? "No findings match the current filters." : "No data-security findings available.";
    const emptyDescription = !rows.length ? (liveDataAssessment ? "The latest live Data scan completed successfully with no matching findings." : "Data-security posture will appear when data-related findings or assessment results become available.") : active ? "Adjust or clear the filters to view other data-security findings." : "Assessment completion cannot be inferred from an empty result set.";
    $("dataEmpty").innerHTML = `<strong>${esc(emptyTitle)}</strong><span>${esc(emptyDescription)}</span>`;
    $("dataResult").textContent = rows.length ? `${filtered.length} of ${rows.length} data-security findings` : "Data-security assessment data unavailable";
    $("dataFindingsDescription").textContent = rows.length ? "Search and investigate findings explicitly identified as Data or Storage domain records." : "Only findings with an explicit Data or Storage domain/category will appear here.";
    $("dataPagination").hidden = filtered.length <= PAGE_SIZE;
    $("dataPageLabel").textContent = `${filtered.length ? (state.page - 1) * PAGE_SIZE + 1 : 0}–${Math.min(state.page * PAGE_SIZE, filtered.length)} of ${filtered.length}`;
    $("dataPageNumber").textContent = `${state.page} / ${pages}`; $("dataPrev").disabled = state.page <= 1; $("dataNext").disabled = state.page >= pages; $("dataClearFilters").hidden = !active;
  }
  function findingHref(f, index) { const url = new URL("findings.html", location.href); if (f.finding_id) url.searchParams.set("id", f.finding_id); url.searchParams.set("record", String(index)); return url.pathname.split("/").pop() + url.search; }
  function openDrawer(row) {
    const f = row.finding; const alreadyOpen = $("dataDrawer").classList.contains("is-open"); state.selected = row; if (!alreadyOpen) state.lastFocus = document.activeElement;
    const fields = [["Finding ID", f.finding_id], ["Severity", severityOf(f)], ["Status", statusOf(f)], ["Risk score", f.risk_score], ["Cloud", f.cloud], ["Domain", f.domain], ["Category", f.category], ["Resource type", f.resource_type], ["Resource ID", f.resource_id], ["Detected", dateLabel(f.detected_at)]];
    const related = identity(f) ? rows.filter((candidate) => candidate.index !== row.index && identity(candidate.finding) === identity(f)) : [];
    const resourceUrl = identity(f) ? `inventory.html?resource=${encodeURIComponent(identity(f))}` : "";
    $("dataDrawerTitle").textContent = f.finding || f.finding_id || "Data security finding";
    $("dataDrawerBody").innerHTML = `<dl class="data-detail-fields">${fields.map(([label, value]) => `<div><dt>${esc(label)}</dt><dd>${esc(value ?? "Not recorded")}</dd></div>`).join("")}</dl><section class="data-detail-section"><h3>Evidence</h3><pre>${esc(f.evidence ? textOf(f.evidence) : "No evidence recorded for this finding.")}</pre></section><section class="data-detail-section"><h3>Remediation guidance</h3><p>${esc(f.recommendation || f.remediation || "Remediation guidance not available.")}</p></section><section class="data-detail-section"><h3>Related findings</h3>${related.length ? `<div class="data-related-list">${related.map(({ finding, index }) => `<button type="button" data-related-index="${index}"><strong>${esc(finding.finding || finding.finding_id || "Data security finding")}</strong><span>${esc(finding.finding_id || "ID unavailable")} · ${esc(severityOf(finding))}</span></button>`).join("")}</div>` : `<p>No related findings.</p>`}</section><div class="data-detail-links"><a class="btn btn-outline" href="${esc(findingHref(f, row.index))}">Open in Findings</a>${resourceUrl ? `<a class="btn btn-outline" href="${esc(resourceUrl)}">View resource in Inventory</a>` : ""}</div>`;
    $("dataDrawer").classList.add("is-open"); $("dataDrawer").setAttribute("aria-hidden", "false"); $("dataDrawer").inert = false; $("dataDrawerBackdrop").hidden = false; document.body.classList.add("data-drawer-open"); $("dataDrawerClose").focus();
  }
  function closeDrawer() { if (!$("dataDrawer").classList.contains("is-open")) return; $("dataDrawer").classList.remove("is-open"); $("dataDrawer").setAttribute("aria-hidden", "true"); $("dataDrawer").inert = true; $("dataDrawerBackdrop").hidden = true; document.body.classList.remove("data-drawer-open"); state.selected = null; state.lastFocus?.focus?.(); }
  function clearFilters() { state.search = state.cloud = state.severity = state.status = state.type = state.category = ""; state.page = 1; $("dataSearch").value = ""; ["dataCloudFilter", "dataSeverityFilter", "dataStatusFilter", "dataTypeFilter", "dataCategoryFilter"].forEach((id) => { $(id).value = ""; }); renderTable(); }
  function init() {
    shared = window.CSPMShared;
    if (!shared || !Array.isArray(shared.getFindings())) { $("dataAssessmentTitle").textContent = "CSPM findings source unavailable"; $("dataAssessmentDescription").textContent = "Data-security assessment status cannot be established from the current source."; renderTable(); return; }
    $("dataSearch").addEventListener("input", (event) => { state.search = event.target.value; state.page = 1; renderTable(); });
    [["dataCloudFilter", "cloud"], ["dataSeverityFilter", "severity"], ["dataStatusFilter", "status"], ["dataTypeFilter", "type"], ["dataCategoryFilter", "category"], ["dataSort", "sort"]].forEach(([id, key]) => $(id).addEventListener("change", (event) => { state[key] = event.target.value; state.page = 1; renderTable(); }));
    $("dataClearFilters").addEventListener("click", clearFilters); $("dataPrev").addEventListener("click", () => { state.page--; renderTable(); }); $("dataNext").addEventListener("click", () => { state.page++; renderTable(); });
    $("dataSecurityRefresh").addEventListener("click", () => { updatePage(); setLiveStatus("Data security view refreshed from current shared CSPM findings."); });
    $("runDataScanBtn").addEventListener("click", runLiveDataScan);
    $("dataFindingsBody").addEventListener("click", (event) => { const button = event.target.closest("[data-index]"); if (button) { const row = rows.find((candidate) => candidate.index === Number(button.dataset.index)); if (row) openDrawer(row); } });
    $("dataFindingsBody").addEventListener("keydown", (event) => { if (["Enter", " "].includes(event.key) && event.target.matches("tr[data-record-index]")) { event.preventDefault(); const row = rows.find((candidate) => candidate.index === Number(event.target.dataset.recordIndex)); if (row) openDrawer(row); } });
    $("dataDrawerBody").addEventListener("click", (event) => { const button = event.target.closest("[data-related-index]"); if (button) { const row = rows.find((candidate) => candidate.index === Number(button.dataset.relatedIndex)); if (row) openDrawer(row); } });
    $("dataDrawerClose").addEventListener("click", closeDrawer); $("dataDrawerBackdrop").addEventListener("click", closeDrawer);
    document.addEventListener("keydown", (event) => {
      if (!$("dataDrawer").classList.contains("is-open")) return;
      if (event.key === "Escape") { closeDrawer(); return; }
      if (event.key === "Tab") { const items = [...$("dataDrawer").querySelectorAll("button:not([disabled]),a[href],[tabindex='0']")]; if (!items.length) return; const first = items[0], last = items.at(-1); if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); } else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); } }
    });
    updatePage();
    if (window.CSPM_LIVE_DATA_META) {
      liveDataAssessment = true;
      setLiveStatus(`Last successful live data scan completed. ${window.CSPM_LIVE_DATA_META.findings.length} findings recorded.`);
    } else {
      loadSavedDataScan();
    }
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init, { once: true }); else init();
  window.CSPMDataSecurity = Object.freeze({ isDataDomain, getDataSecurityFindings, getDataSecuritySummary, getDataSecurityResources, getDataExposureStats, getEncryptionStats, getDataSecurityCloudStats, getDataSecurityRecommendations });
})();
