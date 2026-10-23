(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  let shared;
  let source = [];
  let reviewRows = [];
  const state = { selectedIndex: null, search: "", severity: "" };
  const evidenceText = (value) => typeof value === "string" ? value : value == null ? "" : (() => { try { return JSON.stringify(value, null, 2); } catch (_) { return String(value); } })();
  const severityOf = (finding) => shared.normalizeSeverity(typeof finding.severity === "string" ? finding.severity : "");
  const statusOf = (finding) => shared.normalizeStatus(typeof finding.status === "string" ? finding.status : "");
  const cloudOf = (finding) => { const value = finding.cloud == null ? "" : String(finding.cloud).trim(); return value ? shared.normalizeCloud(value) : "Not recorded"; };
  const domainOf = (finding) => String(shared.normalizeDomain({ domain: typeof finding.domain === "string" ? finding.domain : "", category: typeof finding.category === "string" ? finding.category : "" }) || "Unspecified");
  const resourceOf = (finding) => [finding.resource_type, finding.resource_id].filter(Boolean).join(" · ") || "Not recorded";

  function getReviewRows(findings) {
    return (Array.isArray(findings) ? findings : []).map((finding, index) => ({ finding, index }))
      .filter(({ finding }) => finding && typeof finding === "object" && shared.isRiskFinding({ ...finding, severity: severityOf(finding) }) && !["PASS", "INFO", "RESOLVED"].includes(statusOf(finding)));
  }
  function displayValue(value) { return value === 0 ? "0" : value ? String(value) : "Not recorded"; }
  function renderFindingDetails() {
    const item = source[state.selectedIndex];
    if (!item || !item.finding || typeof item.finding !== "object") {
      $("aiSelectedFinding").innerHTML = `<div class="ai-no-selection"><span data-cspm-icon="findings" aria-hidden="true"></span><strong>${source.length ? "No finding selected" : "No security findings available"}</strong><span>${source.length ? "Choose a finding from the selector or review table." : "The shared CSPM source contains no finding records."}</span></div>`;
      $("aiAnalysisInputs").innerHTML = `<span class="ai-input-placeholder">Select a finding to inspect its available fields.</span>`;
      return;
    }
    const f = item.finding;
    const severity = severityOf(f), status = statusOf(f);
    $("aiSelectedFinding").innerHTML = `<div class="ai-selected-heading"><div><span class="ai-eyebrow">SOURCE FINDING</span><h3>${esc(f.finding || f.finding_id || "Untitled finding")}</h3></div><span class="ai-severity-pill" data-severity="${esc(severity.toLowerCase())}">${esc(severity)}</span></div><dl class="ai-finding-fields"><div><dt>Finding ID</dt><dd>${esc(displayValue(f.finding_id))}</dd></div><div><dt>Cloud</dt><dd>${esc(cloudOf(f))}</dd></div><div><dt>Domain</dt><dd>${esc(domainOf(f))}</dd></div><div><dt>Resource</dt><dd>${esc(resourceOf(f))}</dd></div><div><dt>Current status</dt><dd>${esc(status)}</dd></div><div><dt>Risk score</dt><dd>${esc(displayValue(f.risk_score))}</dd></div></dl><div class="ai-source-evidence"><strong>Recorded evidence</strong><p>${esc(evidenceText(f.evidence) || "No evidence recorded for this finding.")}</p></div>`;
    const inputs = [["Finding", f.finding], ["Severity", severity], ["Cloud", f.cloud ? cloudOf(f) : ""], ["Domain / category", f.domain || f.category], ["Resource", f.resource_type || f.resource_id ? resourceOf(f) : ""], ["Evidence", f.evidence ? evidenceText(f.evidence) : ""], ["Risk score", f.risk_score === 0 || f.risk_score ? String(f.risk_score) : ""]].filter(([, value]) => value !== "");
    $("aiAnalysisInputs").innerHTML = inputs.length ? inputs.map(([label, value]) => `<div><span>${esc(label)}</span><strong>${esc(value)}</strong></div>`).join("") : `<span class="ai-input-placeholder">No supported source fields were recorded for this finding.</span>`;
  }
  function renderReadiness() {
    const total = source.length;
    const review = reviewRows.length;
    $("aiReadinessList").innerHTML = `<div><span class="ai-readiness-dot ai-ready"></span><span>Existing CSPM findings</span><strong>${total} available</strong></div><div><span class="ai-readiness-dot ai-pending"></span><span>Risk findings for analyst review</span><strong>${review} available</strong></div><div><span class="ai-readiness-dot ai-pending"></span><span>AI provider</span><strong>Not configured</strong></div><div><span class="ai-readiness-dot ai-pending"></span><span>AI-generated analysis</span><strong>Unavailable</strong></div>`;
    $("aiReviewCount").textContent = String(review);
    $("aiReviewSummary").textContent = review === 1 ? "Open risk finding available for review" : "Open risk findings available for review";
  }
  function renderSeverityOptions() {
    const select = $("aiSeverityFilter"), current = state.severity;
    const values = [...new Set(reviewRows.map(({ finding }) => severityOf(finding)))].sort((a, b) => ({ CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }[b] || 0) - ({ CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }[a] || 0));
    select.innerHTML = `<option value="">All severities</option>` + values.map((value) => `<option value="${esc(value)}">${esc(value)}</option>`).join("");
    state.severity = values.includes(current) ? current : ""; select.value = state.severity;
  }
  function matches({ finding }) {
    const query = state.search.trim().toLocaleLowerCase();
    const haystack = [finding.finding_id, finding.finding, finding.cloud, finding.domain, finding.category, finding.resource_type, finding.resource_id, evidenceText(finding.evidence)].filter((value) => value != null).join(" ").toLocaleLowerCase();
    return (!query || haystack.includes(query)) && (!state.severity || severityOf(finding) === state.severity);
  }
  function renderTable() {
    const filtered = reviewRows.filter(matches);
    $("aiFindingsBody").innerHTML = filtered.map(({ finding: f, index }) => `<tr tabindex="0" data-index="${index}" aria-selected="${state.selectedIndex === index}"><td><span class="ai-severity-pill" data-severity="${esc(severityOf(f).toLowerCase())}">${esc(severityOf(f))}</span></td><td><strong class="ai-finding-name">${esc(f.finding || f.finding_id || "Untitled finding")}</strong><small class="ai-finding-id">${esc(f.finding_id || "ID unavailable")}</small></td><td>${esc(cloudOf(f))}</td><td>${esc(domainOf(f))}</td><td><span class="ai-resource-cell">${esc(resourceOf(f))}</span></td><td>${esc(displayValue(f.risk_score))}</td><td>${esc(statusOf(f))}</td></tr>`).join("");
    $("aiFilteredCount").textContent = `${filtered.length} / ${reviewRows.length}`;
    $("aiFindingsEmpty").hidden = filtered.length > 0;
    let title = "No findings match the current search or severity filter.";
    let detail = "Clear or adjust the filters to review other findings.";
    if (!source.length) { title = "No security findings are available."; detail = "No finding records were returned by the shared CSPM source."; }
    else if (!reviewRows.length) { title = "No open risk findings are available for review."; detail = "PASS, INFO, and RESOLVED records are excluded from this review list."; }
    $("aiFindingsEmpty").innerHTML = `<strong>${esc(title)}</strong><span>${esc(detail)}</span>`;
    $("aiClearFilters").hidden = !(state.search || state.severity);
  }
  function renderAll() {
    const rawFindings = shared.getFindings();
    source = (Array.isArray(rawFindings) ? rawFindings : []).map((finding, index) => ({ finding, index })).filter(({ finding }) => finding && typeof finding === "object");
    reviewRows = getReviewRows(rawFindings);
    const selector = $("aiFindingSelect");
    const previous = state.selectedIndex;
    selector.innerHTML = `<option value="">Select a security finding</option>` + source.map(({ finding, index }) => `<option value="${index}">${esc(severityOf(finding))} · ${esc(finding.finding_id || `Record ${index + 1}`)} — ${esc(finding.finding || "Untitled finding")}</option>`).join("");
    const hasPrevious = source.some(({ index }) => index === previous);
    if (!hasPrevious) state.selectedIndex = reviewRows[0]?.index ?? source[0]?.index ?? null;
    selector.value = state.selectedIndex == null ? "" : String(state.selectedIndex);
    renderSeverityOptions(); renderReadiness(); renderFindingDetails(); renderTable();
  }
  function selectFinding(index) {
    state.selectedIndex = Number.isInteger(index) ? index : null;
    $("aiFindingSelect").value = state.selectedIndex == null ? "" : String(state.selectedIndex);
    renderFindingDetails(); renderTable();
    const finding = source.find((item) => item.index === state.selectedIndex)?.finding;
    $("aiLive").textContent = finding ? `Selected finding ${finding.finding_id || finding.finding || "record"}. AI analysis is unavailable because no provider is configured.` : "No finding selected.";
  }
  function clearFilters() { state.search = ""; state.severity = ""; $("aiFindingSearch").value = ""; $("aiSeverityFilter").value = ""; renderTable(); }
  function init() {
    shared = window.CSPMShared;
    if (!shared || typeof shared.getFindings !== "function") {
      $("aiReviewCount").textContent = "—"; $("aiReviewSummary").textContent = "Shared CSPM findings source unavailable";
      $("aiFindingsEmpty").hidden = false; $("aiFindingsEmpty").innerHTML = `<strong>Finding data unavailable.</strong><span>The AI provider is not configured, and the shared finding source could not be read.</span>`;
      $("aiAnalyzeButton").disabled = true;
      return;
    }
    $("aiFindingSelect").addEventListener("change", (event) => selectFinding(event.target.value === "" ? null : Number(event.target.value)));
    $("aiFindingSearch").addEventListener("input", (event) => { state.search = event.target.value; renderTable(); });
    $("aiSeverityFilter").addEventListener("change", (event) => { state.severity = event.target.value; renderTable(); });
    $("aiClearFilters").addEventListener("click", clearFilters);
    $("aiFindingsBody").addEventListener("click", (event) => { const row = event.target.closest("tr[data-index]"); if (row) selectFinding(Number(row.dataset.index)); });
    $("aiFindingsBody").addEventListener("keydown", (event) => { if (["Enter", " "].includes(event.key) && event.target.matches("tr[data-index]")) { event.preventDefault(); selectFinding(Number(event.target.dataset.index)); } });
    renderAll();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init, { once: true }); else init();
  window.CSPMAIIntelligence = Object.freeze({ getReviewRows });
})();
