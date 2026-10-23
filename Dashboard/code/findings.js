(() => {
  "use strict";

  const state = { search: "", cloud: "", severity: "", status: "", domain: "", resourceType: "", risk: "", sortKey: "detected_at", sortDir: "desc", page: 1, pageSize: window.CSPMSettings?.getCSPMSettings?.().tablePageSize || 20, selectedIndex: null, lastFocus: null, lastFocusId: null, lastFocusIndex: null, filterPreferenceSet: false, filtersCollapsed: null };
  const $ = (id) => document.getElementById(id);
  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
  const labels = { cloud: "Cloud", severity: "Severity", status: "Status", domain: "Domain", resourceType: "Resource type", risk: "Risk" };
  const filterDefs = [
    { key: "cloud", label: "Cloud", all: "All clouds", values: [["AWS", "AWS"], ["Azure", "Azure"], ["GCP", "GCP"], ["Other", "Other"]] },
    { key: "severity", label: "Severity", all: "All severities", values: [["CRITICAL", "Critical"], ["HIGH", "High"], ["MEDIUM", "Medium"], ["LOW", "Low"], ["INFO", "Info"], ["PASS", "Pass"]] },
    { key: "status", label: "Status", all: "All statuses", values: [["OPEN", "Open"], ["PASS", "Pass"], ["INFO", "Info"], ["RESOLVED", "Resolved"]] },
    { key: "domain", label: "Domain", all: "All domains", values: [] },
    { key: "resourceType", label: "Resource type", all: "All resource types", values: [] },
    { key: "risk", label: "Risk level", all: "All risk", values: [["CRITICAL", "Critical risk"], ["HIGH", "High risk"], ["MEDIUM", "Medium risk"], ["LOW", "Low risk"], ["NO_RISK", "No risk"]] }
  ];
  let shared = null;
  let findings = [];

  function domainLabel(finding) {
    const value = shared.normalizeDomain(finding).trim();
    if (!value) return "Unspecified";
    if (value.includes("IAM") || value.includes("IDENTITY")) return "IAM";
    if (value.includes("NETWORK")) return "Network";
    if (value.includes("DATA")) return "Data";
    if (value.includes("COMPLIANCE")) return "Compliance";
    if (value.includes("AI")) return "AI";
    return value.charAt(0) + value.slice(1).toLowerCase();
  }

  function severity(f) { return shared.normalizeSeverity(f.severity); }
  function status(f) { return shared.normalizeStatus(f.status); }
  function cloud(f) { return shared.normalizeCloud(f.cloud); }
  function riskLevel(f) { return shared.isRiskFinding(f) ? severity(f) : "NO_RISK"; }
  function evidenceText(value) {
    if (typeof value === "string") return value;
    if (value == null) return "";
    try { return JSON.stringify(value, null, 2); } catch (_) { return String(value); }
  }
  function displayDate(value) {
    if (!value) return "Not recorded";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    return new Intl.DateTimeFormat(undefined, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", timeZoneName: "short" }).format(date);
  }
  function availableOptions() {
    const domains = [...new Set(findings.map(domainLabel))].sort((a, b) => a.localeCompare(b));
    const types = [...new Set(findings.map((f) => String(f.resource_type || "").trim()).filter(Boolean))].sort((a, b) => a.localeCompare(b));
    filterDefs.find((d) => d.key === "domain").values = domains.map((value) => [value, value]);
    filterDefs.find((d) => d.key === "resourceType").values = types.map((value) => [value, value]);
  }
  function renderFilters() {
    availableOptions();
    $("findingFilters").innerHTML = filterDefs.map((def) => `<div class="finding-filter"><label for="filter-${def.key}">${def.label}</label><select id="filter-${def.key}" data-filter="${def.key}"><option value="">${def.all}</option>${def.values.map(([value, label]) => `<option value="${esc(value)}">${esc(label)}</option>`).join("")}</select></div>`).join("");
    filterDefs.forEach((def) => { $("filter-" + def.key).value = state[def.key]; });
  }
  function renderSummary() {
    const dist = shared.getSeverityDistribution(findings);
    const metrics = [
      ["Total Findings", shared.calcTotalFindings(findings), ""], ["Open Findings", shared.calcOpenFindings(findings), ""],
      ["Critical", dist.critical || 0, "critical"], ["High", dist.high || 0, "high"], ["Medium", dist.medium || 0, "medium"], ["Low", dist.low || 0, ""]
    ];
    $("findingSummary").innerHTML = metrics.map(([label, value, tone]) => `<div class="finding-metric"${tone ? ` data-tone="${tone}"` : ""}><div class="finding-metric-label">${label}</div><div class="finding-metric-value">${value}</div></div>`).join("");
  }
  function matches(f) {
    const q = state.search.trim().toLocaleLowerCase();
    if (q) {
      const text = [f.finding, f.finding_id, f.resource_id, f.resource_type, f.cloud, f.domain, f.category, evidenceText(f.evidence)].filter((v) => v != null).join(" ").toLocaleLowerCase();
      if (!text.includes(q)) return false;
    }
    if (state.cloud && cloud(f) !== state.cloud) return false;
    if (state.severity && severity(f) !== state.severity) return false;
    if (state.status && status(f) !== state.status) return false;
    if (state.domain && domainLabel(f) !== state.domain) return false;
    if (state.resourceType && String(f.resource_type || "") !== state.resourceType) return false;
    if (state.risk && riskLevel(f) !== state.risk) return false;
    return true;
  }
  const severityRank = { CRITICAL: 6, HIGH: 5, MEDIUM: 4, LOW: 3, INFO: 2, PASS: 1 };
  function sortValue(f, key) {
    if (key === "severity") return severityRank[severity(f)] || 0;
    if (key === "cloud") return cloud(f);
    if (key === "domain") return domainLabel(f);
    if (key === "status") return status(f);
    if (key === "resource") return `${f.resource_type || ""} ${f.resource_id || ""}`;
    if (key === "risk_score") return Number.isFinite(Number(f.risk_score)) && f.risk_score !== "" ? Number(f.risk_score) : null;
    if (key === "detected_at") { const n = Date.parse(f.detected_at || ""); return Number.isNaN(n) ? null : n; }
    return String(f.finding || "");
  }
  function getFiltered() {
    return findings.map((finding, index) => ({ finding, index })).filter(({ finding }) => matches(finding)).sort((a, b) => {
      const av = sortValue(a.finding, state.sortKey), bv = sortValue(b.finding, state.sortKey);
      if (av == null || bv == null) { if (av == null && bv != null) return 1; if (bv == null && av != null) return -1; }
      let cmp = 0;
      if (typeof av === "number" && typeof bv === "number") cmp = av - bv;
      else cmp = String(av ?? "").localeCompare(String(bv ?? ""), undefined, { numeric: true, sensitivity: "base" });
      return cmp ? cmp * (state.sortDir === "asc" ? 1 : -1) : a.index - b.index;
    });
  }
  function severityPill(f) { const s = severity(f); return `<span class="severity-pill severity-${s.toLowerCase()}" aria-label="Severity ${esc(s)}">${esc(s)}</span>`; }
  function statusPill(f) { const s = status(f); const valid = ["OPEN", "PASS", "INFO", "RESOLVED"].includes(s) ? s : "OPEN"; return `<span class="status-pill status-${valid.toLowerCase()}" aria-label="Status ${esc(valid)}">${esc(valid)}</span>`; }
  function provider(f) {
    const name = cloud(f), key = ({ AWS: "aws", Azure: "azure", GCP: "gcp" })[name];
    return key ? `<span class="cloud-mark" data-cloud="${name}"><span aria-hidden="true">${window.CSPM_ICONS[key]}</span>${name}</span>` : `<span class="cloud-mark"><span aria-hidden="true">${window.CSPM_ICONS.cloud}</span>Other</span>`;
  }
  function renderChips() {
    const chips = filterDefs.filter((d) => state[d.key]).map((d) => {
      const option = d.values.find(([v]) => v === state[d.key]);
      const label = option ? option[1] : state[d.key];
      return `<span class="filter-chip">${d.label}: ${esc(label)}<button type="button" data-remove-filter="${d.key}" aria-label="Remove ${d.label} filter"><span data-cspm-icon="close">${window.CSPM_ICONS.close}</span></button></span>`;
    });
    $("activeChips").innerHTML = chips.join("");
    const count = filterDefs.filter((d) => state[d.key]).length;
    $("filterCount").textContent = count;
    $("filterCount").hidden = count === 0;
    $("clearFilters").hidden = count === 0 && !state.search;
  }
  function renderTable() {
    const all = getFiltered();
    const pages = Math.max(1, Math.ceil(all.length / state.pageSize));
    state.page = Math.min(Math.max(1, state.page), pages);
    const start = (state.page - 1) * state.pageSize;
    const visible = all.slice(start, start + state.pageSize);
    $("findingsBody").innerHTML = visible.map(({ finding: f, index: recordIndex }, i) => {
      const id = f.finding_id || "";
      const resourceId = f.resource_id || "Not recorded";
      const resourceType = f.resource_type || "Unknown resource";
      const score = f.risk_score === 0 || f.risk_score ? f.risk_score : "—";
      return `<tr tabindex="0" aria-label="${esc(f.finding || id || "Finding")}; ${esc(severity(f))}; ${esc(id)}" class="${state.selectedIndex === recordIndex ? "is-selected" : ""}" data-record-index="${recordIndex}" data-finding-id="${esc(id)}" style="animation-delay:${Math.min(i * 12, 120)}ms"><td>${severityPill(f)}</td><td><button class="finding-open" type="button" data-open-id="${esc(id)}" data-record-index="${recordIndex}" aria-label="Open details for ${esc(f.finding || id)} on ${esc(resourceId)}"><span class="finding-name">${esc(f.finding || "Untitled finding")}</span><span class="finding-id">${esc(id || "No finding ID")}</span></button></td><td>${provider(f)}</td><td>${esc(domainLabel(f))}</td><td><div class="resource-cell"><span class="resource-type">${esc(resourceType)}</span><span class="resource-id" title="${esc(resourceId)}">${esc(resourceId)}</span></div></td><td><span class="risk-score">${esc(score)}</span></td><td>${statusPill(f)}</td><td class="detected-cell" title="${esc(f.detected_at || "Not recorded")}">${esc(displayDate(f.detected_at))}</td></tr>`;
    }).join("");
    const hasData = findings.length > 0;
    const noResults = all.length === 0;
    $("findingsEmpty").hidden = !noResults;
    if (noResults) {
      const filtered = Boolean(state.search || filterDefs.some((d) => state[d.key]));
      $("findingsEmpty").innerHTML = filtered ? `<h3>No findings match these filters</h3><p>Adjust the search or clear the active filters to see more findings.</p><button class="btn btn-outline" id="emptyClear" type="button">Clear filters</button>` : hasData ? `<h3>No findings to display</h3><p>The shared dataset contains no records.</p>` : `<h3>Findings data is empty</h3><p>The shared data source loaded, but it contains no finding records.</p>`;
    }
    $("resultCount").textContent = all.length ? `${all.length} matching ${all.length === 1 ? "finding" : "findings"}` : "0 matching findings";
    $("paginationLabel").textContent = all.length ? `Showing ${start + 1}–${Math.min(start + visible.length, all.length)} of ${all.length}` : "Showing 0 of 0";
    $("pageIndicator").textContent = `${state.page} / ${pages}`;
    $("prevPage").disabled = state.page <= 1;
    $("nextPage").disabled = state.page >= pages;
    $("findingsStatus").textContent = `${all.length} findings match current search and filters`;
    renderChips();
  }
  function renderSortState() {
    document.querySelectorAll(".findings-table th[data-sort]").forEach((th) => {
      const active = th.dataset.sort === state.sortKey;
      th.setAttribute("aria-sort", active ? (state.sortDir === "asc" ? "ascending" : "descending") : "none");
      const mark = th.querySelector(".sort-indicator");
      if (mark) { const key = active ? (state.sortDir === "asc" ? "sortAsc" : "sortDesc") : "sort"; mark.innerHTML = window.CSPM_ICONS[key]; }
    });
  }
  function render() { renderTable(); renderSortState(); }
  function isActive() { return Boolean(state.search || filterDefs.some((d) => state[d.key])); }
  function clearAll() {
    state.search = ""; filterDefs.forEach((d) => { state[d.key] = ""; const select = $("filter-" + d.key); if (select) select.value = ""; });
    $("findingSearch").value = ""; state.page = 1; render(); $("findingSearch").focus();
  }
  function formatRisk(f) { return f.risk_score === 0 || f.risk_score ? String(f.risk_score) : "Not recorded"; }
  function relationType(a, b) {
    if (a.resource_id && b.resource_id && String(a.resource_id).toLowerCase() === String(b.resource_id).toLowerCase() && (!a.resource_type || !b.resource_type || String(a.resource_type).toLowerCase() === String(b.resource_type).toLowerCase())) return "Same resource";
    if (a.resource_type && b.resource_type && String(a.resource_type).toLowerCase() === String(b.resource_type).toLowerCase()) return "Same resource type";
    if (a.category && b.category && String(a.category).toLowerCase() === String(b.category).toLowerCase()) return "Same category";
    if (domainLabel(a) !== "Unspecified" && domainLabel(a) === domainLabel(b)) return "Same domain";
    return "";
  }
  function relatedFindings(f) {
    const order = ["Same resource", "Same resource type", "Same category", "Same domain"];
    return findings.map((candidate, index) => ({ finding: candidate, index, reason: relationType(f, candidate) })).filter((x) => x.finding !== f && x.reason).sort((a, b) => order.indexOf(a.reason) - order.indexOf(b.reason)).slice(0, 5);
  }
  function detailMarkup(f) {
    const related = relatedFindings(f);
    const fields = [
      ["Severity", severityPill(f)], ["Status", statusPill(f)], ["Cloud", provider(f)], ["Domain", esc(domainLabel(f))],
      ["Resource type", esc(f.resource_type || "Not recorded")], ["Resource ID", esc(f.resource_id || "Not recorded")],
      ["Risk score", esc(formatRisk(f))], ["Detected", `<time datetime="${esc(f.detected_at || "")}">${esc(displayDate(f.detected_at))}</time>`]
    ];
    return `<div class="drawer-id-row"><code id="copyValue">${esc(f.finding_id || "Not recorded")}</code><button class="copy-id" id="copyFindingId" type="button"><span data-cspm-icon="copy">${window.CSPM_ICONS.copy}</span><span>Copy ID</span></button></div>
      <dl class="drawer-meta">${fields.map(([label, value]) => `<div class="drawer-field"><dt>${label}</dt><dd>${value}</dd></div>`).join("")}</dl>
      <section class="drawer-section"><h3>Evidence</h3><p class="evidence-text">${esc(evidenceText(f.evidence) || "No evidence recorded for this finding.")}</p></section>
      <section class="drawer-section"><h3>Related findings</h3>${related.length ? `<div class="related-list">${related.map(({ finding: item, index, reason }) => `<button class="related-item" type="button" data-open-id="${esc(item.finding_id || "")}" data-record-index="${index}"><span class="related-main"><strong>${esc(item.finding || "Untitled finding")}</strong><small>${esc(item.finding_id || "No ID")} · ${esc(item.resource_id || "Resource not recorded")} · ${esc(severity(item))}</small></span><span class="related-reason">${esc(reason)}</span></button>`).join("")}</div>` : `<p class="evidence-text">No directly related findings found.</p>`}</section>
      ${domainLabel(f) === "IAM" ? `<a class="drawer-action" href="iam.html"><span data-cspm-icon="iam" aria-hidden="true"></span>Open IAM Security</a>` : `<a class="drawer-action" href="index.html#latestFindingsPanel"><span data-cspm-icon="dashboard" aria-hidden="true"></span>Open Dashboard</a>`}`;
  }
  function updateUrl(id, recordIndex = null, replace = false) {
    const url = new URL(window.location.href);
    if (id) {
      url.searchParams.set("id", id);
      const duplicates = findings.reduce((count, finding) => count + (String(finding.finding_id || "") === String(id) ? 1 : 0), 0);
      if (duplicates > 1 && Number.isInteger(recordIndex)) url.searchParams.set("record", String(recordIndex));
      else url.searchParams.delete("record");
    } else { url.searchParams.delete("id"); url.searchParams.delete("record"); }
    history[replace ? "replaceState" : "pushState"]({}, "", url);
  }
  function openDrawer(id, fromUrl = false, recordIndex = null) {
    const indexed = Number.isInteger(recordIndex) && findings[recordIndex] && String(findings[recordIndex].finding_id || "") === String(id) ? recordIndex : null;
    const resolvedIndex = indexed ?? findings.findIndex((f) => String(f.finding_id || "") === String(id));
    const finding = resolvedIndex >= 0 ? findings[resolvedIndex] : null;
    if (!finding) { if (fromUrl) { updateUrl(null, null, true); $("findingsStatus").textContent = "The requested finding ID was not found."; } return; }
    if (!$("findingDrawer").classList.contains("is-open")) {
      state.lastFocus = document.activeElement === document.body ? null : document.activeElement;
      state.lastFocusId = state.lastFocus?.dataset?.openId || state.lastFocus?.closest?.("tr[data-finding-id]")?.dataset?.findingId || null;
      const focusIndex = state.lastFocus?.dataset?.recordIndex || state.lastFocus?.closest?.("tr[data-record-index]")?.dataset?.recordIndex;
      state.lastFocusIndex = focusIndex == null ? null : Number(focusIndex);
    }
    state.selectedIndex = resolvedIndex;
    $("drawerTitle").textContent = finding.finding || finding.finding_id || "Finding";
    $("drawerContent").innerHTML = detailMarkup(finding);
    $("findingDrawer").classList.add("is-open"); $("findingDrawer").setAttribute("aria-hidden", "false"); $("findingDrawer").inert = false;
    $("drawerBackdrop").hidden = false; document.body.classList.add("drawer-open");
    if (!fromUrl) updateUrl(finding.finding_id, resolvedIndex);
    renderTable(); $("drawerClose").focus();
  }
  function closeDrawer(fromPop = false) {
    if (!$("findingDrawer").classList.contains("is-open")) return;
    $("findingDrawer").classList.remove("is-open"); $("findingDrawer").setAttribute("aria-hidden", "true"); $("findingDrawer").inert = true;
    $("drawerBackdrop").hidden = true; document.body.classList.remove("drawer-open"); state.selectedIndex = null;
    if (!fromPop) updateUrl(null, null, true);
    renderTable();
    const target = state.lastFocus && state.lastFocus.isConnected ? state.lastFocus : state.lastFocusIndex != null ? [...document.querySelectorAll("[data-record-index]")].find((node) => Number(node.dataset.recordIndex) === state.lastFocusIndex) : state.lastFocusId ? [...document.querySelectorAll("[data-open-id]")].find((node) => node.dataset.openId === state.lastFocusId) : $("findingSearch");
    target?.focus();
  }
  async function copyId() {
    const value = $("copyValue")?.textContent || "";
    if (!value || value === "Not recorded") return;
    try {
      if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(value);
      else { const area = document.createElement("textarea"); area.value = value; area.style.position = "fixed"; area.style.opacity = "0"; document.body.append(area); area.select(); const ok = document.execCommand("copy"); area.remove(); if (!ok) throw new Error("Clipboard unavailable"); }
      $("findingsStatus").textContent = `Copied finding ID ${value}`;
      $("copyFindingId").lastElementChild.textContent = "Copied";
    } catch (_) { $("findingsStatus").textContent = "Could not copy the finding ID. Select and copy it from the detail panel."; }
  }
  function exportJson() {
    const rows = getFiltered().map(({ finding }) => finding);
    const blob = new Blob([JSON.stringify(rows, null, 2)], { type: "application/json;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a"); anchor.href = url; anchor.download = `cspm-findings-${new Date().toISOString().slice(0, 10)}.json`; document.body.append(anchor); anchor.click(); anchor.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    $("findingsStatus").textContent = `Exported ${rows.length} matching findings as JSON`;
  }
  function setData() {
    shared = window.CSPMShared;
    if (!shared || typeof shared.getFindings !== "function" || !shared.hasDataSource()) throw new Error("Shared findings source is unavailable");
    const records = shared.getFindings();
    if (!Array.isArray(records)) throw new Error("Shared findings data is invalid");
    findings = records.filter((f) => f && typeof f === "object");
    renderFilters(); renderSummary(); render();
    if (state.filtersCollapsed == null) state.filtersCollapsed = window.innerWidth <= 768;
    const collapsed = state.filtersCollapsed;
    $("findingFilters").hidden = collapsed;
    $("filterToggle").setAttribute("aria-expanded", String(!collapsed));
    $("findingsError").hidden = true; $("findingSummary").hidden = false; $("findingSearch").disabled = false;
    $("findingToolbar").hidden = false; $("findingsTablePanel").hidden = false;
    $("findingsContent").setAttribute("aria-busy", "false");
  }
  function showError() {
    $("findingSummary").hidden = true; $("findingSearch").disabled = true; $("findingFilters").hidden = true;
    $("findingToolbar").hidden = true; $("findingsTablePanel").hidden = true;
    $("findingsError").hidden = false; $("findingsContent").setAttribute("aria-busy", "false");
  }
  function init() {
    if (window.innerWidth <= 768) {
      state.filtersCollapsed = true;
      $("findingFilters").hidden = true;
      $("filterToggle").setAttribute("aria-expanded", "false");
    }
    try { setData(); }
    catch (error) { console.error("Findings page could not load shared data:", error); showError(); }
    $("pageSize").value = String(state.pageSize);
    $("findingFilters").addEventListener("change", (event) => { const key = event.target.dataset.filter; if (!key) return; state[key] = event.target.value; state.page = 1; render(); });
    $("findingSearch").addEventListener("input", (event) => { state.search = event.target.value; state.page = 1; render(); });
    $("clearFilters").addEventListener("click", clearAll);
    $("activeChips").addEventListener("click", (event) => { const button = event.target.closest("[data-remove-filter]"); if (!button) return; state[button.dataset.removeFilter] = ""; const control = $("filter-" + button.dataset.removeFilter); if (control) control.value = ""; state.page = 1; render(); });
    $("findingsEmpty").addEventListener("click", (event) => { if (event.target.id === "emptyClear") clearAll(); });
    $("filterToggle").addEventListener("click", () => { const filters = $("findingFilters"); const open = $("filterToggle").getAttribute("aria-expanded") !== "true"; state.filterPreferenceSet = true; state.filtersCollapsed = !open; $("filterToggle").setAttribute("aria-expanded", String(open)); filters.hidden = !open; });
    window.addEventListener("resize", () => { if (state.filterPreferenceSet) return; state.filtersCollapsed = window.innerWidth <= 768; $("findingFilters").hidden = state.filtersCollapsed; $("filterToggle").setAttribute("aria-expanded", String(!state.filtersCollapsed)); });
    document.querySelector(".findings-table thead").addEventListener("click", (event) => { const th = event.target.closest("th[data-sort]"); if (!th) return; if (state.sortKey === th.dataset.sort) state.sortDir = state.sortDir === "asc" ? "desc" : "asc"; else { state.sortKey = th.dataset.sort; state.sortDir = ["severity", "risk_score"].includes(th.dataset.sort) ? "desc" : "asc"; } state.page = 1; render(); });
    $("findingsBody").addEventListener("click", (event) => { const opener = event.target.closest("[data-open-id]"); const row = event.target.closest("tr[data-finding-id]"); const id = opener?.dataset.openId || row?.dataset.findingId; const index = opener?.dataset.recordIndex ?? row?.dataset.recordIndex; if (id) openDrawer(id, false, index == null ? null : Number(index)); });
    $("findingsBody").addEventListener("keydown", (event) => { if ((event.key === "Enter" || event.key === " ") && event.target.matches("tr[data-finding-id]")) { event.preventDefault(); openDrawer(event.target.dataset.findingId, false, Number(event.target.dataset.recordIndex)); } });
    $("drawerContent").addEventListener("click", (event) => { if (event.target.closest("#copyFindingId")) { copyId(); return; } const related = event.target.closest("[data-open-id]"); if (related) openDrawer(related.dataset.openId, false, Number(related.dataset.recordIndex)); });
    $("drawerClose").addEventListener("click", () => closeDrawer()); $("drawerBackdrop").addEventListener("click", () => closeDrawer());
    $("findingsExport").addEventListener("click", exportJson);
    $("findingsRefresh").addEventListener("click", () => { try { setData(); $("findingsStatus").textContent = "Findings refreshed from the shared data source"; } catch (_) { showError(); } });
    $("findingsRetry").addEventListener("click", () => { try { setData(); } catch (_) { showError(); } });
    $("pageSize").addEventListener("change", (event) => { state.pageSize = [20, 50, 100].includes(Number(event.target.value)) ? Number(event.target.value) : 20; window.CSPMSettings?.saveCSPMSettings?.({ tablePageSize: state.pageSize }); state.page = 1; render(); });
    $("prevPage").addEventListener("click", () => { state.page = Math.max(1, state.page - 1); render(); });
    $("nextPage").addEventListener("click", () => { state.page += 1; render(); });
    document.addEventListener("keydown", (event) => {
      if (event.key === "/" && !event.ctrlKey && !event.metaKey && !/INPUT|TEXTAREA|SELECT/.test(document.activeElement?.tagName || "")) { event.preventDefault(); $("findingSearch").focus(); }
      if (event.key === "Escape" && $("findingDrawer").classList.contains("is-open")) closeDrawer();
      if (event.key === "Tab" && $("findingDrawer").classList.contains("is-open")) {
        const nodes = [...$("findingDrawer").querySelectorAll('button:not(:disabled),a[href],input,select,[tabindex]:not([tabindex="-1"])')].filter((node) => !node.hidden);
        const first = nodes[0], last = nodes[nodes.length - 1];
        if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
      }
    });
    window.addEventListener("popstate", () => { const params = new URLSearchParams(location.search); const id = params.get("id"); if (id) openDrawer(id, true, params.has("record") ? Number(params.get("record")) : null); else closeDrawer(true); });
    const initialParams = new URLSearchParams(location.search); const initialId = initialParams.get("id"); if (initialId) openDrawer(initialId, true, initialParams.has("record") ? Number(initialParams.get("record")) : null);
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init, { once: true }); else init();
})();
