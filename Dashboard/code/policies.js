(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  const rank = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
  const state = { query: "", cloud: "", domain: "", severity: "", status: "", category: "", sort: "open", dir: "desc", page: 1, pageSize: window.CSPMSettings?.getCSPMSettings?.().tablePageSize || 20, selected: null, returnFocus: null, filterPreference: false, filtersCollapsed: null };
  let shared = null;
  let findings = [];
  let policies = [];
  const filterDefs = [
    { key: "cloud", label: "Cloud", all: "All clouds" },
    { key: "domain", label: "Domain", all: "All domains" },
    { key: "severity", label: "Severity", all: "All severities" },
    { key: "status", label: "Status", all: "All statuses" },
    { key: "category", label: "Policy category", all: "All categories" }
  ];

  function domainOf(finding) {
    const value = String(shared.normalizeDomain(finding) || "").trim();
    if (!value) return "Unspecified";
    const upper = value.toUpperCase();
    if (upper.includes("IAM") || upper.includes("IDENTITY")) return "IAM";
    if (upper.includes("NETWORK")) return "Network";
    if (upper.includes("DATA")) return "Data";
    if (upper.includes("COMPLIANCE")) return "Compliance";
    if (upper.includes("AI")) return "AI";
    return value.charAt(0).toUpperCase() + value.slice(1).toLowerCase();
  }
  function cloudOf(f) { return shared.normalizeCloud(f.cloud); }
  function severityOf(f) { return shared.normalizeSeverity(f.severity); }
  function statusOf(f) { return shared.normalizeStatus(f.status); }
  function dateValue(value) {
    if (typeof value === "number") return Number.isFinite(value) ? value : null;
    const n = Date.parse(value || ""); return Number.isFinite(n) ? n : null;
  }
  function formatDate(value) {
    const n = dateValue(value);
    return n == null ? "Not recorded" : new Intl.DateTimeFormat(undefined, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }).format(n);
  }
  function distinctResources(records) {
    const values = new Set();
    records.forEach((f) => {
      const type = String(f.resource_type || "").trim();
      const id = String(f.resource_id || "").trim();
      if (type && id) values.add(`${type}\u0000${id}`);
    });
    return values;
  }
  function policyKey(f) {
    const id = String(f.finding_id || "").trim();
    if (id) return `id:${id}`;
    return `observed:${[f.finding, shared.normalizeDomain(f), f.category, cloudOf(f)].map((v) => String(v || "").trim().toLocaleLowerCase()).join("\u0000")}`;
  }
  function getObservedPolicies(records) {
    const groups = new Map();
    records.forEach((finding, index) => {
      const key = policyKey(finding);
      if (!groups.has(key)) groups.set(key, { key, id: String(finding.finding_id || "").trim() || null, records: [], titleCounts: new Map(), index });
      const group = groups.get(key);
      group.records.push({ finding, index });
      const title = String(finding.finding || "").trim();
      if (title) group.titleCounts.set(title, (group.titleCounts.get(title) || 0) + 1);
    });
    return [...groups.values()].map((group) => {
      const recordsForPolicy = group.records.map((item) => item.finding);
      const title = [...group.titleCounts].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))[0]?.[0] || "Untitled observed finding";
      const latest = group.records.reduce((max, item) => Math.max(max, dateValue(item.finding.detected_at) ?? -Infinity), -Infinity);
      const severities = recordsForPolicy.map(severityOf).filter((s) => rank[s]);
      const severity = severities.sort((a, b) => rank[b] - rank[a])[0] || "—";
      const clouds = [...new Set(recordsForPolicy.map(cloudOf).filter(Boolean))].sort((a, b) => a.localeCompare(b));
      const domains = [...new Set(recordsForPolicy.map(domainOf))].sort((a, b) => a.localeCompare(b));
      const categories = [...new Set(recordsForPolicy.map((f) => String(f.category || "").trim()).filter(Boolean))].sort((a, b) => a.localeCompare(b));
      const resources = distinctResources(recordsForPolicy);
      return {
        key: group.key, id: group.id, name: title, domain: domains[0] || "Unspecified", domains,
        category: categories[0] || "Unspecified", categories, clouds, severity, status: "Observed",
        findingCount: recordsForPolicy.length, openCount: recordsForPolicy.filter(shared.isOpenFinding).length,
        resources: resources.size, resourceKeys: resources,
        lastObserved: latest === -Infinity ? null : latest,
        related: group.records
      };
    });
  }
  function optionsFor(key) {
    const values = new Set();
    policies.forEach((p) => {
      const entries = key === "cloud" ? p.clouds : key === "domain" ? p.domains : key === "category" ? p.categories : [key === "severity" ? p.severity : p.status];
      entries.forEach((value) => { if (value && value !== "—") values.add(value); });
    });
    if (key === "severity") return [...values].sort((a, b) => (rank[b] || 0) - (rank[a] || 0));
    return [...values].sort((a, b) => a.localeCompare(b));
  }
  function renderFilters() {
    filterDefs.forEach((def) => { def.values = optionsFor(def.key); });
    $("policyFilters").innerHTML = filterDefs.map((def) => `<label class="policies-filter" for="policy-filter-${def.key}"><span>${def.label}</span><select id="policy-filter-${def.key}" data-filter="${def.key}" aria-label="Filter policies by ${esc(def.label.toLowerCase())}"><option value="">${def.all}</option>${def.values.map((v) => `<option value="${esc(v)}">${esc(v)}</option>`).join("")}</select></label>`).join("");
    filterDefs.forEach((def) => { const control = $("policy-filter-" + def.key); control.value = state[def.key]; control.disabled = !def.values.length; });
  }
  function providerMark(name) {
    const key = ({ AWS: "aws", Azure: "azure", GCP: "gcp" })[name];
    return key ? `<span class="policies-provider" aria-label="${esc(name)}"><span aria-hidden="true">${window.CSPM_ICONS[key]}</span>${esc(name)}</span>` : `<span class="policies-provider"><span aria-hidden="true">${window.CSPM_ICONS.cloud}</span>${esc(name)}</span>`;
  }
  function severityPill(value) {
    return value === "—" ? `<span class="policies-muted">Not recorded</span>` : `<span class="policies-severity" data-severity="${esc(value.toLowerCase())}">${esc(value)}</span>`;
  }
  function renderSummary() {
    const clouds = new Set(policies.flatMap((p) => p.clouds));
    const categories = new Set(policies.map((p) => p.domain));
    const cards = [
      ["Observed Policies", policies.length, "policies"],
      ["With Open Findings", policies.filter((p) => p.openCount > 0).length, "findings"],
      ["Open Findings", policies.reduce((sum, p) => sum + p.openCount, 0), "findings"],
      ["High / Critical", policies.filter((p) => ["HIGH", "CRITICAL"].includes(p.severity)).length, "high"],
      ["Clouds Observed", clouds.size, "cloud"],
      ["Domains Observed", categories.size, "network"]
    ];
    $("policiesSummary").innerHTML = cards.map(([label, value, icon], index) => `<article class="policies-metric" style="--metric-delay:${index * 35}ms"><span class="policies-metric-icon" data-cspm-icon="${icon}" aria-hidden="true">${window.CSPM_ICONS[icon] || ""}</span><span class="policies-metric-label">${esc(label)}</span><strong>${value}</strong></article>`).join("");
    const byCloud = new Map(), byDomain = new Map();
    policies.forEach((p) => { p.clouds.forEach((cloud) => byCloud.set(cloud, (byCloud.get(cloud) || 0) + 1)); p.domains.forEach((domain) => byDomain.set(domain, (byDomain.get(domain) || 0) + 1)); });
    const renderBars = (map, target, empty) => {
      const entries = [...map].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
      $(target).innerHTML = entries.length ? entries.map(([name, count]) => `<div class="policies-coverage-row"><span class="policies-coverage-name">${target === "policiesCloudCoverage" ? providerMark(name) : `<span>${esc(name)}</span>`}</span><span class="policies-coverage-track"><i style="--coverage:${Math.max(4, count / Math.max(...entries.map((e) => e[1])) * 100)}%"></i></span><strong>${count}</strong></div>`).join("") : `<p class="policies-coverage-empty">${empty}</p>`;
    };
    renderBars(byCloud, "policiesCloudCoverage", "No cloud coverage observed.");
    renderBars(byDomain, "policiesDomainCoverage", "No policy domains observed.");
  }
  function matches(p) {
    const query = state.query.trim().toLocaleLowerCase();
    if (query) {
      const corpus = [p.id, p.name, p.domain, p.category, ...p.domains, ...p.categories, ...p.clouds, ...p.related.map(({ finding }) => finding.finding), ...p.related.map(({ finding }) => finding.resource_id), ...p.related.map(({ finding }) => finding.resource_type)].filter(Boolean).join(" ").toLocaleLowerCase();
      if (!corpus.includes(query)) return false;
    }
    if (state.cloud && !p.clouds.includes(state.cloud)) return false;
    if (state.domain && !p.domains.includes(state.domain)) return false;
    if (state.severity && p.severity !== state.severity) return false;
    if (state.status && p.status !== state.status) return false;
    if (state.category && !p.categories.includes(state.category)) return false;
    return true;
  }
  function sortValue(p, key) {
    if (key === "name") return p.name;
    if (key === "id") return p.id || "";
    if (key === "cloud") return p.clouds.join(", ");
    if (key === "domain") return p.domain;
    if (key === "severity") return rank[p.severity] || 0;
    if (key === "findings") return p.findingCount;
    if (key === "open") return p.openCount;
    if (key === "resources") return p.resources;
    if (key === "status") return p.status;
    if (key === "lastObserved") return p.lastObserved;
    return p.openCount;
  }
  function getVisible() {
    return policies.filter(matches).slice().sort((a, b) => {
      const av = sortValue(a, state.sort), bv = sortValue(b, state.sort);
      let cmp = av == null || bv == null ? av == null && bv != null ? 1 : bv == null && av != null ? -1 : 0 : typeof av === "number" && typeof bv === "number" ? av - bv : String(av).localeCompare(String(bv), undefined, { numeric: true, sensitivity: "base" });
      if (cmp) return cmp * (state.dir === "asc" ? 1 : -1);
      return String(a.id || a.name).localeCompare(String(b.id || b.name));
    });
  }
  function renderChips() {
    const active = filterDefs.filter((d) => state[d.key]);
    $("policyActiveChips").innerHTML = active.map((d) => `<span class="policies-chip">${esc(d.label)}: ${esc(state[d.key])}<button type="button" data-remove-filter="${d.key}" aria-label="Remove ${esc(d.label)} filter">${window.CSPM_ICONS.close}</button></span>`).join("");
    $("policyClearFilters").hidden = !active.length && !state.query;
    $("policyFilterCount").hidden = !active.length;
    $("policyFilterCount").textContent = String(active.length);
  }
  function renderTable() {
    const all = getVisible();
    const pages = Math.max(1, Math.ceil(all.length / state.pageSize));
    state.page = Math.min(state.page, pages);
    const start = (state.page - 1) * state.pageSize;
    const rows = all.slice(start, start + state.pageSize);
    $("policiesBody").innerHTML = rows.map((p, i) => `<tr data-policy-key="${esc(p.key)}" tabindex="0" aria-label="Open details for ${esc(p.name)}${p.id ? `, ${esc(p.id)}` : ""}" style="--row-delay:${Math.min(i, 12) * 18}ms"><td><button class="policies-name-button" type="button" data-open-policy="${esc(p.key)}">${esc(p.name)}</button><small>${p.id ? "Observed finding title" : "Observed title; no ID recorded"}</small></td><td><code class="policies-id">${esc(p.id || "—")}</code></td><td><div class="policies-provider-list">${p.clouds.map(providerMark).join("") || "—"}</div></td><td>${esc(p.domain)}</td><td>${severityPill(p.severity)}</td><td>${p.findingCount}</td><td><strong class="policies-open-count">${p.openCount}</strong></td><td>${p.resources}</td><td><span class="policies-status">Observed</span></td><td>${esc(p.lastObserved == null ? "Not recorded" : formatDate(p.lastObserved))}</td></tr>`).join("");
    $("policiesEmpty").hidden = rows.length > 0;
    $("policiesEmpty").innerHTML = policies.length ? `No policies match the current filters. <button id="policiesEmptyClear" class="btn btn-quiet" type="button">Clear filters</button>` : "No policies observed in current CSPM data.";
    $("policyResultCount").textContent = `Showing ${all.length ? start + 1 : 0}–${Math.min(start + rows.length, all.length)} of ${all.length} policies`;
    $("policiesPageLabel").textContent = `Showing ${all.length ? start + 1 : 0}–${Math.min(start + rows.length, all.length)} of ${all.length} policies`;
    $("policiesPageNumber").textContent = `${state.page} / ${pages}`;
    $("policiesPrev").disabled = state.page <= 1;
    $("policiesNext").disabled = state.page >= pages;
    $("policiesRecordTotal").textContent = `${policies.length} observed`;
    document.querySelectorAll(".policies-table th[data-sort]").forEach((th) => {
      const current = th.dataset.sort === state.sort;
      th.setAttribute("aria-sort", current ? state.dir === "asc" ? "ascending" : "descending" : "none");
      const indicator = th.querySelector("span");
      if (indicator) indicator.innerHTML = current ? (state.dir === "asc" ? window.CSPM_ICONS.sortAsc : window.CSPM_ICONS.sortDesc) : window.CSPM_ICONS.sort;
    });
    renderChips();
  }
  function render() { renderTable(); }
  function clearFilters() {
    state.query = "";
    filterDefs.forEach((d) => { state[d.key] = ""; const control = $("policy-filter-" + d.key); if (control) control.value = ""; });
    $("policySearch").value = ""; state.page = 1; render();
  }
  function resourceLabel(f) { return [f.resource_type, f.resource_id].filter(Boolean).join(" · ") || "Resource not recorded"; }
  function statusPill(f) { const value = statusOf(f); return `<span class="policies-finding-status" data-status="${esc(value.toLowerCase())}">${esc(value)}</span>`; }
  function openDrawer(key, opener) {
    const policy = policies.find((p) => p.key === key);
    if (!policy) return;
    state.selected = key; state.returnFocus = opener || document.activeElement;
    const cloudCoverage = policy.clouds.map(providerMark).join("") || "Not recorded";
    const related = policy.related.slice().sort((a, b) => (dateValue(b.finding.detected_at) ?? 0) - (dateValue(a.finding.detected_at) ?? 0));
    $("policyDrawerTitle").textContent = policy.name;
    $("policyDrawerBody").innerHTML = `<div class="policies-drawer-id-row"><span>Observed ID</span><code>${esc(policy.id || "Not recorded")}</code>${policy.id ? `<button id="copyPolicyId" class="btn btn-quiet" type="button"><span data-cspm-icon="copy" aria-hidden="true">${window.CSPM_ICONS.copy}</span> Copy ID</button>` : ""}</div>
      <dl class="policies-drawer-meta"><div><dt>Cloud</dt><dd>${cloudCoverage}</dd></div><div><dt>Domain</dt><dd>${esc(policy.domains.join(", ") || "Not recorded")}</dd></div><div><dt>Category</dt><dd>${esc(policy.categories.join(", ") || "Not recorded")}</dd></div><div><dt>Severity</dt><dd>${severityPill(policy.severity)}</dd></div><div><dt>Status</dt><dd><span class="policies-status">Observed</span></dd></div></dl>
      <section class="policies-drawer-section"><h3>Description</h3><p>Policy metadata unavailable. This record is inferred from findings and is not a full policy definition.</p></section>
      <section class="policies-drawer-section"><h3>Evaluation records</h3><div class="policies-eval-grid"><div><span>Findings</span><strong>${policy.findingCount}</strong></div><div><span>Open</span><strong>${policy.openCount}</strong></div><div><span>Affected resources</span><strong>${policy.resources}</strong></div><div><span>Last observed</span><strong>${esc(policy.lastObserved == null ? "Not recorded" : formatDate(policy.lastObserved))}</strong></div></div></section>
      <section class="policies-drawer-section"><h3>Observed coverage</h3><dl class="policies-drawer-meta"><div><dt>Clouds</dt><dd>${cloudCoverage}</dd></div><div><dt>Domains</dt><dd>${esc(policy.domains.join(", ") || "Not recorded")}</dd></div><div><dt>Resource types</dt><dd>${esc([...new Set(related.map(({ finding }) => String(finding.resource_type || "").trim()).filter(Boolean))].join(", ") || "Not recorded")}</dd></div></dl></section>
      <section class="policies-drawer-section"><h3>Related findings <span>${related.length}</span></h3><div class="policies-related-list">${related.length ? related.map(({ finding: f, index }) => { const query = new URLSearchParams(); if (f.finding_id) query.set("id", f.finding_id); query.set("record", String(index)); return `<a class="policies-related-item" href="findings.html?${query.toString()}"><span class="policies-related-top">${severityPill(severityOf(f))}${statusPill(f)}</span><strong>${esc(f.finding || f.finding_id || "Untitled finding")}</strong><small>${esc(resourceLabel(f))}</small><span class="policies-related-foot"><span>Risk ${f.risk_score === 0 || f.risk_score ? esc(f.risk_score) : "not recorded"}</span><span>${esc(formatDate(f.detected_at))}</span></span></a>`; }).join("") : `<p>No related findings recorded.</p>`}</div></section>`;
    const drawer = $("policyDrawer"); drawer.inert = false; drawer.setAttribute("aria-hidden", "false"); $("policyDrawerBackdrop").hidden = false; document.body.classList.add("policies-drawer-open"); requestAnimationFrame(() => drawer.classList.add("is-open")); $("policyDrawerClose").focus();
    const copy = $("copyPolicyId"); if (copy) copy.addEventListener("click", async () => { try { await navigator.clipboard.writeText(policy.id); $("policiesLive").textContent = `Copied observed ID ${policy.id}`; } catch (_) { $("policiesLive").textContent = "Copy unavailable; select the ID text to copy it."; } });
  }
  function closeDrawer(restore = true) {
    const drawer = $("policyDrawer"); drawer.classList.remove("is-open"); drawer.inert = true; drawer.setAttribute("aria-hidden", "true"); $("policyDrawerBackdrop").hidden = true; document.body.classList.remove("policies-drawer-open"); state.selected = null;
    if (restore && state.returnFocus?.isConnected) state.returnFocus.focus();
  }
  function setData() {
    shared = window.CSPMShared;
    if (!shared || typeof shared.getFindings !== "function" || !shared.hasDataSource()) throw new Error("Shared finding source unavailable");
    const source = shared.getFindings(); if (!Array.isArray(source)) throw new Error("Shared finding source is invalid");
    findings = source.filter((f) => f && typeof f === "object");
    policies = getObservedPolicies(findings);
    renderFilters(); renderSummary(); render();
    $("policiesSourceText").textContent = "Observed records are aggregated from the shared CSPM findings dataset. The Python scanner contains inline AWS network checks, but has no central catalog and is not connected to these dashboard evaluations.";
    $("policiesContent").setAttribute("aria-busy", "false"); $("policiesError").hidden = true;
    $("policiesSource").hidden = false; $("policiesSummary").hidden = false; $("policiesCoverage").hidden = false; $("policiesWorkspace").hidden = false;
    if (window.location.search) { const params = new URLSearchParams(window.location.search); const match = policies.find((p) => p.id && p.id === params.get("id")); if (match) openDrawer(match.key, null); }
  }
  function showError() {
    $("policiesContent").setAttribute("aria-busy", "false");
    $("policiesSource").hidden = true; $("policiesSummary").hidden = true; $("policiesCoverage").hidden = true; $("policiesWorkspace").hidden = true;
    $("policiesError").hidden = false;
  }
  function init() {
    try { setData(); } catch (error) { console.error("Policies page could not load shared findings:", error); showError(); }
    $("policiesPageSize").value = String(state.pageSize);
    if (window.innerWidth <= 768) { state.filtersCollapsed = true; $("policyFilters").hidden = true; $("policyFilterToggle").setAttribute("aria-expanded", "false"); }
    $("policySearch").addEventListener("input", (event) => { state.query = event.target.value; state.page = 1; render(); });
    $("policyFilters").addEventListener("change", (event) => { const key = event.target.dataset.filter; if (!key) return; state[key] = event.target.value; state.page = 1; render(); });
    $("policyClearFilters").addEventListener("click", clearFilters);
    $("policyActiveChips").addEventListener("click", (event) => { const button = event.target.closest("[data-remove-filter]"); if (!button) return; state[button.dataset.removeFilter] = ""; const select = $("policy-filter-" + button.dataset.removeFilter); if (select) select.value = ""; state.page = 1; render(); });
    $("policiesEmpty").addEventListener("click", (event) => { if (event.target.id === "policiesEmptyClear") clearFilters(); });
    $("policyFilterToggle").addEventListener("click", () => { const open = $("policyFilterToggle").getAttribute("aria-expanded") !== "true"; state.filterPreference = true; $("policyFilterToggle").setAttribute("aria-expanded", String(open)); $("policyFilters").hidden = !open; });
    window.addEventListener("resize", () => { if (state.filterPreference) return; state.filtersCollapsed = window.innerWidth <= 768; $("policyFilters").hidden = state.filtersCollapsed; $("policyFilterToggle").setAttribute("aria-expanded", String(!state.filtersCollapsed)); });
    document.querySelector(".policies-table thead").addEventListener("click", (event) => { const th = event.target.closest("th[data-sort]"); if (!th) return; if (state.sort === th.dataset.sort) state.dir = state.dir === "asc" ? "desc" : "asc"; else { state.sort = th.dataset.sort; state.dir = ["open", "findings", "resources", "severity", "lastObserved"].includes(state.sort) ? "desc" : "asc"; } state.page = 1; render(); });
    $("policiesBody").addEventListener("click", (event) => { const opener = event.target.closest("[data-open-policy]"); const row = event.target.closest("tr[data-policy-key]"); if (opener || row) openDrawer(opener?.dataset.openPolicy || row.dataset.policyKey, opener || row); });
    $("policiesBody").addEventListener("keydown", (event) => { if ((event.key === "Enter" || event.key === " ") && event.target.matches("tr[data-policy-key]")) { event.preventDefault(); openDrawer(event.target.dataset.policyKey, event.target); } });
    $("policyDrawerClose").addEventListener("click", () => closeDrawer()); $("policyDrawerBackdrop").addEventListener("click", () => closeDrawer());
    document.addEventListener("keydown", (event) => { if (event.key === "/" && !/INPUT|TEXTAREA|SELECT/.test(document.activeElement?.tagName || "")) { event.preventDefault(); $("policySearch").focus(); } if (event.key === "Escape" && $("policyDrawer").classList.contains("is-open")) closeDrawer(); if (event.key === "Tab" && $("policyDrawer").classList.contains("is-open")) { const items = [...$("policyDrawer").querySelectorAll('button:not(:disabled),a[href],select,[tabindex]:not([tabindex="-1"])')]; const first = items[0], last = items[items.length - 1]; if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); } else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); } } });
    $("policiesRefresh").addEventListener("click", () => { try { setData(); $("policiesLive").textContent = "Observed policy records refreshed from the shared findings source"; } catch (_) { showError(); } });
    $("policiesRetry").addEventListener("click", () => { try { setData(); } catch (_) { showError(); } });
    $("policiesPageSize").addEventListener("change", (event) => { state.pageSize = [20, 50, 100].includes(Number(event.target.value)) ? Number(event.target.value) : 20; window.CSPMSettings?.saveCSPMSettings?.({ tablePageSize: state.pageSize }); state.page = 1; render(); });
    $("policiesPrev").addEventListener("click", () => { state.page = Math.max(1, state.page - 1); render(); });
    $("policiesNext").addEventListener("click", () => { state.page += 1; render(); });
  }
  window.CSPMPolicyAdapter = Object.freeze({
    getObservedPolicies(records) {
      shared = window.CSPMShared;
      if (!shared) throw new Error("Shared CSPM helpers are unavailable");
      return getObservedPolicies(records);
    },
  });
  if ($("policiesContent")) {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init, { once: true });
    else init();
  }
})();
