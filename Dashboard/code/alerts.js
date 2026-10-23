(() => {
  "use strict";
  if (!document.getElementById("alertsContent")) return;

  const $ = (id) => document.getElementById(id);
  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  const rank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  const state = { query: "", severity: "", cloud: "", domain: "", status: "", source: "", sort: "detected_at", dir: "desc", page: 1, pageSize: window.CSPMSettings?.getCSPMSettings?.().tablePageSize || 20, filterPreference: false, filtersCollapsed: null, focusIndex: null };
  let shared = null;
  let findings = [];
  let alerts = [];

  function isAlertEligible(finding) {
    if (!finding || typeof finding !== "object" || !shared) return false;
    const severity = shared.normalizeSeverity(finding.severity);
    return shared.isOpenFinding(finding) && shared.isRiskFinding(finding) && ["CRITICAL", "HIGH", "MEDIUM"].includes(severity);
  }
  function domainLabel(finding) {
    const value = String(shared.normalizeDomain(finding) || "").trim().toUpperCase();
    if (!value) return "Unspecified";
    if (value.includes("IAM") || value.includes("IDENTITY")) return "IAM";
    if (value.includes("NETWORK")) return "Network";
    if (value.includes("DATA")) return "Data";
    if (value.includes("COMPLIANCE")) return "Compliance";
    if (value.includes("AI")) return "AI";
    return value.charAt(0) + value.slice(1).toLowerCase();
  }
  function buildAlert(finding, recordIndex, duplicateId) {
    const findingId = String(finding.finding_id || "").trim();
    const alertId = `ALERT-${findingId || `RECORD-${recordIndex + 1}`}${duplicateId ? `-R${recordIndex + 1}` : ""}`;
    const severity = shared.normalizeSeverity(finding.severity);
    return {
      alert_id: alertId, source: "CSPM Finding", severity,
      title: String(finding.finding || "Untitled finding"), description: typeof finding.description === "string" ? finding.description : "",
      cloud: shared.normalizeCloud(finding.cloud), domain: domainLabel(finding),
      resource_type: String(finding.resource_type || ""), resource_id: String(finding.resource_id || ""),
      finding_id: findingId, risk_score: finding.risk_score === 0 || finding.risk_score ? finding.risk_score : null,
      status: shared.normalizeStatus(finding.status), detected_at: finding.detected_at || null,
      priority: severity, state: "Awaiting triage", evidence: finding.evidence,
      recommendation: finding.recommendation || finding.remediation || "", record_index: recordIndex, finding
    };
  }
  function getDerivedAlerts(records) {
    const eligible = records.map((finding, recordIndex) => ({ finding, recordIndex })).filter(({ finding }) => isAlertEligible(finding));
    const idCounts = new Map();
    eligible.forEach(({ finding }) => { const id = String(finding.finding_id || "").trim(); if (id) idCounts.set(id, (idCounts.get(id) || 0) + 1); });
    return eligible.map(({ finding, recordIndex }) => buildAlert(finding, recordIndex, (idCounts.get(String(finding.finding_id || "").trim()) || 0) > 1));
  }
  function summarize(records) {
    return { active: records.length, critical: records.filter((a) => a.severity === "CRITICAL").length, high: records.filter((a) => a.severity === "HIGH").length, medium: records.filter((a) => a.severity === "MEDIUM").length, low: records.filter((a) => a.severity === "LOW").length };
  }
  function renderSummary() {
    const s = summarize(alerts);
    const cards = [
      ["Active alerts", s.active, "alerts", "all"], ["Critical", s.critical, "critical", "critical"],
      ["High", s.high, "high", "high"], ["Medium", s.medium, "activity", "medium"], ["Awaiting triage", s.active, "filter", "triage"]
    ];
    $("alertsSummary").innerHTML = cards.map(([label, value, icon, key]) => `<article class="alerts-metric" data-tone="${key}"><span class="alerts-metric-icon" aria-hidden="true">${window.CSPM_ICONS[icon] || ""}</span><span class="alerts-metric-label">${label}</span><strong>${value}</strong>${key === "triage" ? '<small>Finding status: open</small>' : ""}</article>`).join("");
    $("alertsQueue").innerHTML = `<div class="alerts-queue-intro"><div><span class="alerts-section-kicker">Operations</span><h2>Priority queue</h2></div><span>Open risk findings by severity</span></div><div class="alerts-queue-items"><button type="button" data-queue-severity="CRITICAL"><span class="alerts-queue-dot critical"></span><span>Critical</span><strong>${s.critical}</strong></button><button type="button" data-queue-severity="HIGH"><span class="alerts-queue-dot high"></span><span>High</span><strong>${s.high}</strong></button><button type="button" data-queue-severity="MEDIUM"><span class="alerts-queue-dot medium"></span><span>Medium</span><strong>${s.medium}</strong></button></div>`;
  }
  const optionsFor = (key, label) => [...new Set(alerts.map((a) => a[key]).filter(Boolean))].sort((a, b) => String(a).localeCompare(String(b))).map((value) => `<option value="${esc(value)}">${esc(value)}</option>`).join("");
  function renderFilters() {
    const defs = [["severity", "Severity", ["CRITICAL", "HIGH", "MEDIUM"]], ["cloud", "Cloud", null], ["domain", "Domain", null], ["status", "Finding status", null], ["source", "Source", null]];
    $("alertsFilters").innerHTML = defs.map(([key, label, fixed]) => { const allLabel = key === "severity" ? "All severities" : key === "status" ? "All statuses" : `All ${label.toLowerCase()}s`; return `<label class="alerts-filter" for="alerts-filter-${key}"><span>${label}</span><select id="alerts-filter-${key}" data-alert-filter="${key}" aria-label="Filter by ${label}"><option value="">${allLabel}</option>${(fixed ? fixed : [...new Set(alerts.map((a) => a[key]).filter(Boolean))].sort()).map((value) => `<option value="${esc(value)}">${esc(value === "OPEN" ? "Open (finding)" : value)}</option>`).join("")}</select></label>`; }).join("");
  }
  function matches(alert, query) {
    const haystack = [alert.alert_id, alert.finding_id, alert.title, alert.resource_id, alert.resource_type, alert.cloud, alert.domain, alert.source].join(" ").toLowerCase();
    return !query || haystack.includes(query.toLowerCase());
  }
  function getFiltered() {
    return alerts.filter((a) => matches(a, state.query) && ["severity", "cloud", "domain", "status", "source"].every((key) => !state[key] || String(a[key]) === state[key]));
  }
  function renderSortIndicators() {
    document.querySelectorAll(".alerts-table thead th[data-sort]").forEach((th) => {
      const active = th.dataset.sort === state.sort;
      th.setAttribute("aria-sort", active ? (state.dir === "asc" ? "ascending" : "descending") : "none");
      const button = th.querySelector(".alerts-sort");
      const mark = button?.querySelector("span");
      if (mark) mark.innerHTML = window.CSPM_ICONS[active ? (state.dir === "asc" ? "sortAsc" : "sortDesc") : "sort"] || "";
      if (button) button.setAttribute("aria-label", `Sort by ${button.childNodes[0]?.textContent?.trim() || "column"}${active ? `, ${state.dir === "asc" ? "ascending" : "descending"}` : ""}`);
    });
  }
  function timestamp(alert) { const time = Date.parse(alert.detected_at || ""); return Number.isNaN(time) ? null : time; }
  function compare(a, b, key) {
    if (key === "severity") return (rank[a.severity] || 0) - (rank[b.severity] || 0);
    if (key === "risk_score") return (Number(a.risk_score) || 0) - (Number(b.risk_score) || 0);
    if (key === "detected_at") { const at = timestamp(a), bt = timestamp(b); return at == null ? (bt == null ? 0 : -1) : bt == null ? 1 : at - bt; }
    if (key === "resource") return `${a.resource_type} ${a.resource_id}`.localeCompare(`${b.resource_type} ${b.resource_id}`);
    return String(a[key] ?? "").localeCompare(String(b[key] ?? ""), undefined, { sensitivity: "base" });
  }
  function getSorted(records) { return [...records].sort((a, b) => compare(a, b, state.sort) * (state.dir === "asc" ? 1 : -1) || a.record_index - b.record_index); }
  function formatDate(value) {
    if (!value || Number.isNaN(Date.parse(value))) return "Not recorded";
    return new Intl.DateTimeFormat(undefined, { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", timeZoneName: "short" }).format(new Date(value));
  }
  function cloudMarkup(cloud) {
    const key = cloud === "AWS" ? "aws" : cloud === "Azure" ? "azure" : cloud === "GCP" ? "gcp" : "cloud";
    return `<span class="alerts-cloud" data-cloud="${esc(cloud)}"><span class="alerts-provider-mark" aria-hidden="true">${window.CSPM_ICONS[key] || window.CSPM_ICONS.cloud}</span>${esc(cloud)}</span>`;
  }
  function severityMarkup(value) { return `<span class="alerts-severity" data-severity="${esc(value.toLowerCase())}"><span class="alerts-severity-dot" aria-hidden="true"></span>${esc(value)}</span>`; }
  function detailMarkup(alert) {
    const findingUrl = new URL("findings.html", window.location.href);
    if (alert.finding_id) findingUrl.searchParams.set("id", alert.finding_id);
    findingUrl.searchParams.set("record", String(alert.record_index));
    const resourceUrl = new URL("inventory.html", window.location.href);
    resourceUrl.searchParams.set("resource", JSON.stringify([alert.resource_type, alert.resource_id]));
    const evidence = alert.evidence == null || alert.evidence === "" ? "No evidence recorded for this finding." : typeof alert.evidence === "string" ? alert.evidence : JSON.stringify(alert.evidence, null, 2);
    const recommendation = String(alert.recommendation || "").trim();
    const fields = [["Alert ID", alert.alert_id], ["Source", alert.source], ["Severity", alert.severity], ["Risk score", alert.risk_score == null ? "Not recorded" : alert.risk_score], ["Finding status", `${alert.status} · derived from finding`], ["Detected at", formatDate(alert.detected_at)], ["Cloud", alert.cloud], ["Domain", alert.domain], ["Resource type", alert.resource_type || "Not recorded"], ["Resource ID", alert.resource_id || "Not recorded"], ["Finding ID", alert.finding_id || "Not recorded"]];
    return `<span class="alerts-state-label">Awaiting triage <span>Derived interpretation · no saved alert state</span></span><dl class="alerts-detail-grid">${fields.map(([label, value]) => `<div><dt>${esc(label)}</dt><dd>${esc(value)}</dd></div>`).join("")}</dl><section class="alerts-detail-section"><h3>Related finding</h3><p>${esc(alert.title)}</p>${alert.finding_id ? `<a class="alerts-action-link" href="${esc(findingUrl.href)}"><span aria-hidden="true">${window.CSPM_ICONS.findings}</span> View Finding</a>` : ""}${alert.resource_type && alert.resource_id ? `<a class="alerts-action-link" href="${esc(resourceUrl.href)}"><span aria-hidden="true">${window.CSPM_ICONS.inventory}</span> View Resource</a>` : ""}</section><section class="alerts-detail-section"><h3>Evidence</h3><pre class="alerts-evidence">${esc(evidence)}</pre></section><section class="alerts-detail-section"><h3>Recommended action</h3><p>${esc(recommendation || "Remediation guidance not available.")}</p></section>`;
  }
  function openDrawer(alert) {
    state.focusIndex = alert.record_index;
    $("alertsDrawerTitle").textContent = alert.title;
    $("alertsDrawerBody").innerHTML = detailMarkup(alert);
    const drawer = $("alertsDrawer"); drawer.classList.add("is-open"); drawer.setAttribute("aria-hidden", "false"); drawer.inert = false;
    $("alertsBackdrop").hidden = false; document.body.classList.add("alerts-drawer-open"); $("alertsDrawerClose").focus();
  }
  function closeDrawer() {
    const drawer = $("alertsDrawer"); if (!drawer.classList.contains("is-open")) return;
    drawer.classList.remove("is-open"); drawer.setAttribute("aria-hidden", "true"); drawer.inert = true; $("alertsBackdrop").hidden = true; document.body.classList.remove("alerts-drawer-open");
    const target = [...document.querySelectorAll("[data-open-alert]")].find((node) => Number(node.dataset.recordIndex) === state.focusIndex); (target || $("alertsSearch")).focus();
  }
  function renderTable() {
    renderSortIndicators();
    const filtered = getFiltered();
    const sorted = getSorted(filtered);
    const pages = Math.max(1, Math.ceil(sorted.length / state.pageSize)); state.page = Math.min(Math.max(1, state.page), pages);
    const start = (state.page - 1) * state.pageSize; const visible = sorted.slice(start, start + state.pageSize);
    $("alertsBody").innerHTML = visible.map((a, i) => `<tr tabindex="0" data-open-alert data-record-index="${a.record_index}" data-severity="${a.severity.toLowerCase()}" style="--row-order:${i}"><td>${severityMarkup(a.severity)}</td><td class="alerts-title-cell"><button type="button" data-open-alert data-record-index="${a.record_index}" aria-label="View alert ${esc(a.alert_id)}: ${esc(a.title)}"><strong title="${esc(a.title)}">${esc(a.title)}</strong><small>${esc(a.alert_id)} <span>·</span> ${esc(a.source)}</small></button></td><td>${cloudMarkup(a.cloud)}</td><td><span class="alerts-domain">${esc(a.domain)}</span></td><td class="alerts-resource"><span title="${esc(a.resource_type)}">${esc(a.resource_type || "Not recorded")}</span><code title="${esc(a.resource_id)}">${esc(a.resource_id || "Not recorded")}</code></td><td><span class="alerts-risk" data-level="${a.risk_score == null ? "none" : Number(a.risk_score) >= 70 ? "high" : Number(a.risk_score) >= 40 ? "medium" : "low"}">${a.risk_score == null ? "—" : esc(a.risk_score)}</span></td><td><span class="alerts-status"><i aria-hidden="true"></i>Open <small>finding</small></span></td><td><time datetime="${esc(a.detected_at || "")}" title="${esc(a.detected_at || "Not recorded")}">${esc(formatDate(a.detected_at))}</time></td></tr>`).join("");
    $("alertsResultCount").textContent = `${filtered.length} ${filtered.length === 1 ? "alert" : "alerts"}`;
    $("alertsPaginationLabel").textContent = sorted.length ? `Showing ${start + 1}–${Math.min(start + state.pageSize, sorted.length)} of ${sorted.length} alerts` : "Showing 0 alerts";
    $("alertsPageIndicator").textContent = `${state.page} / ${pages}`; $("alertsPrev").disabled = state.page <= 1; $("alertsNext").disabled = state.page >= pages;
    $("alertsEmpty").hidden = sorted.length > 0;
    if (!sorted.length) {
      const hasFilters = Boolean(state.query || state.severity || state.cloud || state.domain || state.status || state.source);
      $("alertsEmpty").innerHTML = hasFilters ? `<span>${window.CSPM_ICONS.search}</span><h2>No alerts match these filters</h2><p>Adjust the search or clear the active filters.</p><button class="btn btn-outline" id="alertsEmptyClear" type="button">Clear filters</button>` : `<span>${window.CSPM_ICONS.alerts}</span><h2>No active alerts</h2><p>No open findings currently require alerting.</p>`;
    }
    renderChips();
  }
  function renderChips() {
    const labels = { severity: "Severity", cloud: "Cloud", domain: "Domain", status: "Finding status", source: "Source" };
    const chips = Object.keys(labels).filter((key) => state[key]).map((key) => `<span class="alerts-chip">${labels[key]}: ${esc(state[key] === "OPEN" ? "Open" : state[key])}<button type="button" data-remove-alert-filter="${key}" aria-label="Remove ${labels[key]} filter"><span aria-hidden="true">${window.CSPM_ICONS.close}</span></button></span>`);
    if (state.query) chips.unshift(`<span class="alerts-chip">Search: ${esc(state.query)}<button type="button" data-remove-alert-query aria-label="Clear search"><span aria-hidden="true">${window.CSPM_ICONS.close}</span></button></span>`);
    $("alertsChips").innerHTML = chips.join("");
    const active = chips.length > 0; $("alertsClear").hidden = !active; $("alertsFilterToggle").classList.toggle("has-filters", active);
  }
  function clearFilters() {
    state.query = ""; ["severity", "cloud", "domain", "status", "source"].forEach((key) => { state[key] = ""; const select = $("alerts-filter-" + key); if (select) select.value = ""; });
    $("alertsSearch").value = ""; state.page = 1; renderTable();
  }
  function setData() {
    shared = window.CSPMShared;
    if (!shared || typeof shared.hasDataSource !== "function" || typeof shared.getFindings !== "function") throw new Error("Shared CSPM findings are unavailable");
    if (!shared.hasDataSource()) { showNoData(); return; }
    const records = shared.getFindings(); if (!Array.isArray(records)) throw new Error("Shared CSPM findings are invalid");
    findings = records.filter((finding) => finding && typeof finding === "object"); alerts = getDerivedAlerts(findings);
    renderSummary(); renderFilters(); renderTable();
    if (state.filtersCollapsed == null) state.filtersCollapsed = window.innerWidth <= 768;
    $("alertsFilters").hidden = state.filtersCollapsed; $("alertsFilterToggle").setAttribute("aria-expanded", String(!state.filtersCollapsed));
    $("alertsContent").setAttribute("aria-busy", "false"); $("alertsError").hidden = true;
    ["alertsSummary", "alertsQueue", "alertsToolbar", "alertsTablePanel"].forEach((id) => $(id).hidden = false);
  }
  function showNoData() {
    $("alertsContent").setAttribute("aria-busy", "false");
    ["alertsSummary", "alertsQueue", "alertsToolbar", "alertsTablePanel"].forEach((id) => $(id).hidden = true);
    $("alertsError").hidden = false; $("alertsError").querySelector("h2").textContent = "No alert data available"; $("alertsError").querySelector("p").textContent = "Alerts are currently derived from CSPM findings. Load a findings dataset to evaluate alerts.";
  }
  function showError() {
    $("alertsContent").setAttribute("aria-busy", "false");
    ["alertsSummary", "alertsQueue", "alertsToolbar", "alertsTablePanel"].forEach((id) => $(id).hidden = true);
    $("alertsError").hidden = false; $("alertsError").querySelector("h2").textContent = "Unable to load alerts"; $("alertsError").querySelector("p").textContent = "Refresh to retry.";
  }
  function init() {
    try { setData(); } catch (error) { console.error("Alerts could not load current CSPM findings:", error); showError(); }
    $("alertsPageSize").value = String(state.pageSize);
    $("alertsFilters").addEventListener("change", (event) => { const key = event.target.dataset.alertFilter; if (!key) return; state[key] = event.target.value; state.page = 1; renderTable(); });
    $("alertsSearch").addEventListener("input", (event) => { state.query = event.target.value; state.page = 1; renderTable(); });
    $("alertsFilterToggle").addEventListener("click", () => { const open = $("alertsFilterToggle").getAttribute("aria-expanded") !== "true"; state.filterPreference = true; state.filtersCollapsed = !open; $("alertsFilterToggle").setAttribute("aria-expanded", String(open)); $("alertsFilters").hidden = !open; });
    window.addEventListener("resize", () => { if (state.filterPreference) return; state.filtersCollapsed = window.innerWidth <= 768; $("alertsFilters").hidden = state.filtersCollapsed; $("alertsFilterToggle").setAttribute("aria-expanded", String(!state.filtersCollapsed)); });
    $("alertsClear").addEventListener("click", clearFilters);
    $("alertsChips").addEventListener("click", (event) => { const remove = event.target.closest("[data-remove-alert-filter]"); if (remove) { const key = remove.dataset.removeAlertFilter; state[key] = ""; $("alerts-filter-" + key).value = ""; state.page = 1; renderTable(); } if (event.target.closest("[data-remove-alert-query]")) { $("alertsSearch").value = ""; state.query = ""; state.page = 1; renderTable(); } });
    $("alertsEmpty").addEventListener("click", (event) => { if (event.target.id === "alertsEmptyClear") clearFilters(); });
    $("alertsQueue").addEventListener("click", (event) => { const button = event.target.closest("[data-queue-severity]"); if (!button) return; const severity = button.dataset.queueSeverity; state.severity = state.severity === severity ? "" : severity; $("alerts-filter-severity").value = state.severity; state.page = 1; renderTable(); });
    document.querySelector(".alerts-table thead").addEventListener("click", (event) => { const th = event.target.closest("th[data-sort]"); if (!th) return; const key = th.dataset.sort; if (state.sort === key) state.dir = state.dir === "asc" ? "desc" : "asc"; else { state.sort = key; state.dir = ["severity", "risk_score", "detected_at"].includes(key) ? "desc" : "asc"; } state.page = 1; renderTable(); });
    $("alertsBody").addEventListener("click", (event) => { const opener = event.target.closest("[data-open-alert]"); if (!opener) return; const item = alerts.find((a) => a.record_index === Number(opener.dataset.recordIndex)); if (item) openDrawer(item); });
    $("alertsBody").addEventListener("keydown", (event) => { if ((event.key === "Enter" || event.key === " ") && event.target.matches("tr[data-open-alert]")) { event.preventDefault(); const item = alerts.find((a) => a.record_index === Number(event.target.dataset.recordIndex)); if (item) openDrawer(item); } });
    $("alertsDrawerClose").addEventListener("click", closeDrawer); $("alertsBackdrop").addEventListener("click", closeDrawer);
    $("alertsRefresh").addEventListener("click", () => { try { setData(); $("alertsStatus").textContent = "Alerts refreshed from current CSPM findings"; } catch (_) { showError(); } });
    $("alertsRetry").addEventListener("click", () => { try { setData(); } catch (_) { showError(); } });
    $("alertsPageSize").addEventListener("change", (event) => { state.pageSize = [20, 50, 100].includes(Number(event.target.value)) ? Number(event.target.value) : 20; window.CSPMSettings?.saveCSPMSettings?.({ tablePageSize: state.pageSize }); state.page = 1; renderTable(); });
    $("alertsPrev").addEventListener("click", () => { state.page = Math.max(1, state.page - 1); renderTable(); }); $("alertsNext").addEventListener("click", () => { state.page++; renderTable(); });
    document.addEventListener("keydown", (event) => {
      if (event.key === "/" && !event.ctrlKey && !event.metaKey && !/INPUT|TEXTAREA|SELECT/.test(document.activeElement?.tagName || "")) { event.preventDefault(); $("alertsSearch").focus(); }
      if (event.key === "Escape" && $("alertsDrawer").classList.contains("is-open")) closeDrawer();
      if (event.key === "Tab" && $("alertsDrawer").classList.contains("is-open")) { const items = [...$("alertsDrawer").querySelectorAll('button:not(:disabled),a[href],[tabindex]:not([tabindex="-1"])')]; const first = items[0], last = items[items.length - 1]; if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); } else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); } }
    });
  }
  window.CSPMAlerts = Object.freeze({ isAlertEligible, buildAlertFromFinding: (finding, index = 0) => buildAlert(finding, index, false), getDerivedAlerts: (records) => { shared = window.CSPMShared; return getDerivedAlerts(records); }, getAlertSummary: summarize, filterAlerts: (records, filters = {}, query = "") => records.filter((a) => matches(a, query) && Object.keys(filters).every((key) => !filters[key] || String(a[key]) === String(filters[key]))), sortAlerts: (records, key = "detected_at", direction = "desc") => [...records].sort((a, b) => compare(a, b, key) * (direction === "asc" ? 1 : -1)) });
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init, { once: true }); else init();
})();
