(() => {
  "use strict";

  const state = {
    query: "", cloud: "", resourceType: "", domain: "", status: "", severity: "",
    sortKey: "last_seen", sortDir: "desc", page: 1, pageSize: window.CSPMSettings?.getCSPMSettings?.().tablePageSize || 20,
    selectedKey: null, lastFocus: null, lastFocusKey: null,
    filtersCollapsed: null, filterPreferenceSet: false
  };
  const $ = (id) => document.getElementById(id);
  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
  const ranks = { CRITICAL: 6, HIGH: 5, MEDIUM: 4, LOW: 3, INFO: 2, PASS: 1 };
  const severityOptions = [["CRITICAL", "Critical"], ["HIGH", "High"], ["MEDIUM", "Medium"], ["LOW", "Low"], ["INFO", "Info"], ["PASS", "Pass"]];
  const statusOptions = [["Healthy", "Healthy"], ["Attention", "Attention"], ["High Risk", "High Risk"], ["Critical Risk", "Critical Risk"], ["No Assessment", "No Assessment"]];
  let shared = null;
  let findings = [];
  let resources = [];
  let filterDefs = [];

  function normalizeDomainLabel(finding) {
    const value = shared.normalizeDomain(finding).trim();
    if (!value) return "Unspecified";
    if (value.includes("IAM") || value.includes("IDENTITY")) return "IAM";
    if (value.includes("NETWORK")) return "Network";
    if (value.includes("DATA")) return "Data";
    if (value.includes("COMPLIANCE")) return "Compliance";
    if (value.includes("AI")) return "AI";
    return value.charAt(0) + value.slice(1).toLowerCase();
  }
  function safeTimestamp(value) {
    if (!value) return null;
    const time = Date.parse(value);
    return Number.isNaN(time) ? null : time;
  }
  function getResourceStatus(resource) {
    if (!resource.assessed) return "No Assessment";
    if (resource.critical_findings > 0) return "Critical Risk";
    if (resource.high_findings > 0) return "High Risk";
    if (resource.open_risk_findings > 0) return "Attention";
    return "Healthy";
  }

  // One inventory asset is one case-sensitive resource_type + resource_id pair,
  // matching calcMonitoredResources() in the Dashboard's shared data layer.
  function getInventoryResources(records) {
    const groups = new Map();
    records.forEach((finding, findingIndex) => {
      if (!finding || typeof finding !== "object") return;
      const resourceType = String(finding.resource_type || "");
      const resourceId = String(finding.resource_id || "");
      if (!resourceType.trim() || !resourceId.trim()) return;
      const key = JSON.stringify([resourceType, resourceId]);
      if (!groups.has(key)) {
        groups.set(key, {
          key, resource_type: resourceType, resource_id: resourceId,
          findings: [], cloud_set: new Set(), domain_set: new Set()
        });
      }
      const resource = groups.get(key);
      resource.findings.push({ finding, finding_index: findingIndex });
      resource.cloud_set.add(shared.normalizeCloud(finding.cloud));
      resource.domain_set.add(normalizeDomainLabel(finding));
    });

    return [...groups.values()].map((group) => {
      const items = group.findings;
      const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0, PASS: 0 };
      let openFindings = 0;
      let openRiskFindings = 0;
      let maxRisk = null;
      let firstSeen = null;
      let lastSeen = null;
      let assessed = false;
      items.forEach(({ finding }) => {
        const normalizedSeverity = shared.normalizeSeverity(finding.severity);
        const normalizedStatus = shared.normalizeStatus(finding.status);
        if (Object.hasOwn(counts, normalizedSeverity)) counts[normalizedSeverity]++;
        const hasSeverity = Object.hasOwn(ranks, String(finding.severity || "").trim().toUpperCase());
        const hasStatus = ["OPEN", "PASS", "INFO", "RESOLVED"].includes(String(finding.status || "").trim().toUpperCase());
        if (hasSeverity && hasStatus && normalizedStatus) assessed = true;
        if (shared.isOpenFinding(finding)) openFindings++;
        if (shared.isOpenFinding(finding) && shared.isRiskFinding(finding)) openRiskFindings++;
        if (finding.risk_score !== "" && finding.risk_score != null && Number.isFinite(Number(finding.risk_score))) {
          const risk = Number(finding.risk_score);
          maxRisk = maxRisk == null ? risk : Math.max(maxRisk, risk);
        }
        const observed = safeTimestamp(finding.detected_at);
        if (observed != null) {
          if (firstSeen == null || observed < firstSeen) firstSeen = observed;
          if (lastSeen == null || observed > lastSeen) lastSeen = observed;
        }
      });
      const highestSeverity = Object.keys(ranks).filter((value) => counts[value] > 0).sort((a, b) => ranks[b] - ranks[a])[0] || null;
      const clouds = [...group.cloud_set].sort((a, b) => a.localeCompare(b));
      const domains = [...group.domain_set].sort((a, b) => a.localeCompare(b));
      const resource = {
        key: group.key,
        resource_type: group.resource_type,
        resource_id: group.resource_id,
        clouds,
        cloud: clouds.length === 1 ? clouds[0] : "Multiple clouds",
        domains,
        domain: domains.length === 1 ? domains[0] : "Multiple domains",
        finding_count: items.length,
        open_findings: openFindings,
        open_risk_findings: openRiskFindings,
        critical_findings: counts.CRITICAL,
        high_findings: counts.HIGH,
        medium_findings: counts.MEDIUM,
        low_findings: counts.LOW,
        info_findings: counts.INFO,
        pass_findings: counts.PASS,
        severity_counts: counts,
        highest_severity: highestSeverity,
        max_risk_score: maxRisk,
        first_seen: firstSeen == null ? null : new Date(firstSeen).toISOString(),
        last_seen: lastSeen == null ? null : new Date(lastSeen).toISOString(),
        findings: items,
        assessed
      };
      resource.status = getResourceStatus(resource);
      return resource;
    });
  }

  function getInventorySummary(items) {
    const clouds = new Set(items.flatMap((resource) => resource.clouds));
    const resourceTypes = new Set(items.map((resource) => resource.resource_type));
    return {
      total_resources: items.length,
      clouds: clouds.size,
      resource_types: resourceTypes.size,
      resources_with_findings: items.filter((resource) => resource.finding_count > 0).length,
      high_risk_resources: items.filter((resource) => resource.high_findings > 0 || resource.critical_findings > 0).length,
      healthy_resources: items.filter((resource) => resource.status === "Healthy").length,
      resources_with_open_findings: items.filter((resource) => resource.open_findings > 0).length,
      critical_risk_resources: items.filter((resource) => resource.critical_findings > 0).length
    };
  }

  function buildFilterDefinitions() {
    const clouds = [...new Set(resources.flatMap((resource) => resource.clouds))].sort((a, b) => a.localeCompare(b));
    const resourceTypes = [...new Set(resources.map((resource) => resource.resource_type))].sort((a, b) => a.localeCompare(b));
    const domains = [...new Set(resources.flatMap((resource) => resource.domains))].sort((a, b) => a.localeCompare(b));
    filterDefs = [
      { key: "cloud", label: "Cloud", all: "All clouds", values: clouds.map((value) => [value, value]) },
      { key: "resourceType", label: "Resource type", all: "All resource types", values: resourceTypes.map((value) => [value, value]) },
      { key: "domain", label: "Domain", all: "All domains", values: domains.map((value) => [value, value]) },
      { key: "status", label: "Security status", all: "All statuses", values: statusOptions },
      { key: "severity", label: "Finding severity", all: "All severities", values: severityOptions }
    ];
    $("inventoryFilters").innerHTML = filterDefs.map((def) => `<div class="inventory-filter"><label for="inventory-filter-${def.key}">${def.label}</label><select id="inventory-filter-${def.key}" data-inventory-filter="${def.key}"><option value="">${esc(def.all)}</option>${def.values.map(([value, label]) => `<option value="${esc(value)}">${esc(label)}</option>`).join("")}</select></div>`).join("");
    filterDefs.forEach((def) => { $("inventory-filter-" + def.key).value = state[def.key]; });
  }
  function renderSummary() {
    const summary = getInventorySummary(resources);
    const metrics = [
      ["Monitored Resources", summary.total_resources, ""],
      ["Clouds", summary.clouds, ""],
      ["Resource Types", summary.resource_types, ""],
      ["Resources with Findings", summary.resources_with_findings, ""],
      ["High-Risk Resources", summary.high_risk_resources, "risk"]
    ];
    $("inventorySummary").innerHTML = metrics.map(([label, value, tone], index) => `<div class="inventory-metric"${tone ? ` data-tone="${tone}"` : ""} style="animation-delay:${index * 35}ms"><div class="inventory-metric-label">${label}</div><div class="inventory-metric-value">${value}</div></div>`).join("");
    const posture = [
      ["Healthy", summary.healthy_resources],
      ["Resources with open findings", summary.resources_with_open_findings],
      ["Critical-risk resources", summary.critical_risk_resources]
    ];
    $("inventoryPosture").innerHTML = posture.map(([label, value]) => `<div class="inventory-posture-stat"><span>${label}</span><strong>${value}</strong></div>`).join("");
  }
  function cloudIcon(name) {
    const key = ({ AWS: "aws", Azure: "azure", GCP: "gcp" })[name];
    return key ? window.CSPM_ICONS[key] : window.CSPM_ICONS.cloud;
  }
  function renderDistribution() {
    const cloudCounts = new Map();
    const typeCounts = new Map();
    const crossCounts = new Map();
    resources.forEach((resource) => {
      resource.clouds.forEach((provider) => {
        cloudCounts.set(provider, (cloudCounts.get(provider) || 0) + 1);
        if (!crossCounts.has(provider)) crossCounts.set(provider, new Map());
        const types = crossCounts.get(provider);
        types.set(resource.resource_type, (types.get(resource.resource_type) || 0) + 1);
      });
      typeCounts.set(resource.resource_type, (typeCounts.get(resource.resource_type) || 0) + 1);
    });
    const renderBars = (container, entries, iconFn = null) => {
      if (!entries.length) { container.innerHTML = '<p class="inventory-chart-empty">No resource data available.</p>'; return; }
      const max = Math.max(1, ...entries.map(([, count]) => count));
      container.innerHTML = entries.map(([label, count], index) => `<div class="inventory-bar-row"><span class="inventory-bar-label">${iconFn ? iconFn(label) : ""}${esc(label)}</span><span class="inventory-bar-track"><span class="inventory-bar-fill" style="--bar-width:${Math.max(3, count / max * 100)}%;animation-delay:${index * 35}ms"></span></span><span class="inventory-bar-count">${count}</span></div>`).join("");
    };
    const cloudEntries = [...cloudCounts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    const typeEntries = [...typeCounts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    renderBars($("cloudDistribution"), cloudEntries, (provider) => `<span class="inventory-bar-cloud" data-cloud="${esc(provider)}" aria-hidden="true">${cloudIcon(provider)}</span>`);
    renderBars($("typeDistribution"), typeEntries, () => `<span class="inventory-type-mark" aria-hidden="true">${window.CSPM_ICONS.resources}</span>`);
    $("crossDistribution").innerHTML = [...crossCounts.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([provider, typeMap]) => `<section class="inventory-cross-cloud"><h3><span aria-hidden="true">${cloudIcon(provider)}</span>${esc(provider)}</h3><ul>${[...typeMap.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([type, count]) => `<li><strong>${esc(type)}</strong><span>${count}</span></li>`).join("")}</ul></section>`).join("") || '<p class="inventory-chart-empty">No resource data available.</p>';
  }

  function resourceMatches(resource) {
    const query = state.query.trim().toLocaleLowerCase();
    if (query) {
      const findingText = resource.findings.map(({ finding }) => [finding.finding, finding.finding_id, finding.evidence].map((value) => typeof value === "string" ? value : value == null ? "" : JSON.stringify(value)).join(" ")).join(" ");
      const text = [resource.resource_id, resource.resource_type, resource.clouds.join(" "), resource.domains.join(" "), findingText].join(" ").toLocaleLowerCase();
      if (!text.includes(query)) return false;
    }
    if (state.cloud && !resource.clouds.includes(state.cloud)) return false;
    if (state.resourceType && resource.resource_type !== state.resourceType) return false;
    if (state.domain && !resource.domains.includes(state.domain)) return false;
    if (state.status && resource.status !== state.status) return false;
    if (state.severity && !resource.findings.some(({ finding }) => shared.normalizeSeverity(finding.severity) === state.severity)) return false;
    return true;
  }
  function inventorySortValue(resource, key) {
    if (key === "resource") return resource.resource_id;
    if (key === "cloud") return resource.cloud;
    if (key === "resource_type") return resource.resource_type;
    if (key === "domain") return resource.domain;
    if (key === "highest_severity") return ranks[resource.highest_severity] || 0;
    if (key === "status") return ["Critical Risk", "High Risk", "Attention", "Healthy", "No Assessment"].indexOf(resource.status);
    if (key === "max_risk_score") return resource.max_risk_score;
    if (key === "last_seen") return safeTimestamp(resource.last_seen);
    return resource[key];
  }
  function filterAndSortInventory(items) {
    return items.filter(resourceMatches).slice().sort((a, b) => {
      const av = inventorySortValue(a, state.sortKey), bv = inventorySortValue(b, state.sortKey);
      if (av == null || bv == null) { if (av == null && bv != null) return 1; if (bv == null && av != null) return -1; }
      let comparison;
      if (typeof av === "number" && typeof bv === "number") comparison = av - bv;
      else comparison = String(av ?? "").localeCompare(String(bv ?? ""), undefined, { numeric: true, sensitivity: "base" });
      return comparison ? comparison * (state.sortDir === "asc" ? 1 : -1) : a.resource_id.localeCompare(b.resource_id);
    });
  }
  function statusClass(value) { return value.toLowerCase().replaceAll(" ", "-"); }
  function severityBadge(value) {
    return value ? `<span class="inventory-severity inventory-severity-${value.toLowerCase()}" aria-label="Highest severity ${esc(value)}">${esc(value)}</span>` : '<span class="inventory-severity inventory-severity-no-assessment">No data</span>';
  }
  function statusBadge(value) { return `<span class="inventory-status inventory-status-${statusClass(value)}">${esc(value)}</span>`; }
  function cloudMarkup(resource) {
    if (resource.clouds.length > 1) return `<span class="inventory-cloud" aria-label="Multiple cloud providers"><span aria-hidden="true">${window.CSPM_ICONS.cloud}</span>Multiple</span>`;
    const provider = resource.clouds[0] || "Other";
    return `<span class="inventory-cloud" data-cloud="${esc(provider)}"><span aria-hidden="true">${cloudIcon(provider)}</span>${esc(provider)}</span>`;
  }
  function renderChips() {
    const chips = filterDefs.filter((def) => state[def.key]).map((def) => {
      const option = def.values.find(([value]) => value === state[def.key]);
      const label = option ? option[1] : state[def.key];
      return `<span class="inventory-chip">${def.label}: ${esc(label)}<button type="button" data-remove-inventory-filter="${def.key}" aria-label="Remove ${def.label} filter"><span>${window.CSPM_ICONS.close}</span></button></span>`;
    });
    $("inventoryChips").innerHTML = chips.join("");
    const count = filterDefs.filter((def) => state[def.key]).length;
    $("inventoryFilterCount").textContent = count;
    $("inventoryFilterCount").hidden = count === 0;
    $("inventoryClearFilters").hidden = count === 0 && !state.query;
  }
  function renderSortState() {
    document.querySelectorAll(".inventory-table th[data-sort]").forEach((th) => {
      const active = th.dataset.sort === state.sortKey;
      th.setAttribute("aria-sort", active ? (state.sortDir === "asc" ? "ascending" : "descending") : "none");
      const icon = active ? (state.sortDir === "asc" ? "sortAsc" : "sortDesc") : "sort";
      th.querySelector(".inventory-sort-icon").innerHTML = window.CSPM_ICONS[icon];
    });
  }
  function renderTable() {
    const matches = filterAndSortInventory(resources);
    const pages = Math.max(1, Math.ceil(matches.length / state.pageSize));
    state.page = Math.min(Math.max(1, state.page), pages);
    const start = (state.page - 1) * state.pageSize;
    const visible = matches.slice(start, start + state.pageSize);
    $("inventoryBody").innerHTML = visible.map((resource, index) => `<tr tabindex="0" data-resource-key="${esc(resource.key)}" class="${state.selectedKey === resource.key ? "is-selected" : ""}" style="animation-delay:${Math.min(index * 10, 100)}ms"><td><button class="inventory-resource-button" type="button" data-open-resource="${esc(resource.key)}" aria-label="Open resource ${esc(resource.resource_id)}, ${esc(resource.resource_type)}"><span class="inventory-resource-icon" aria-hidden="true">${window.CSPM_ICONS.resources}</span><span class="inventory-resource-id" title="${esc(resource.resource_id)}">${esc(resource.resource_id)}</span><span class="inventory-resource-sub">${esc(resource.resource_type)}</span></button></td><td>${esc(resource.resource_type)}</td><td>${cloudMarkup(resource)}</td><td>${esc(resource.domain)}</td><td><span class="inventory-count" aria-label="${resource.finding_count} findings">${resource.finding_count}</span></td><td><span class="inventory-count ${resource.open_findings ? "inventory-count-open" : ""}" aria-label="${resource.open_findings} open findings">${resource.open_findings}</span></td><td>${severityBadge(resource.highest_severity)}</td><td><span class="inventory-risk-number">${resource.max_risk_score == null ? "—" : esc(resource.max_risk_score)}</span></td><td>${statusBadge(resource.status)}</td><td class="inventory-last-seen" title="${esc(resource.last_seen || "No observation timestamp in findings")}">${esc(formatDate(resource.last_seen))}</td></tr>`).join("");
    const empty = matches.length === 0;
    $("inventoryEmpty").hidden = !empty;
    if (empty) {
      const filtered = Boolean(state.query || filterDefs.some((def) => state[def.key]));
      $("inventoryEmpty").innerHTML = filtered ? '<h3>No resources match the current filters</h3><p>Clear or adjust the search and filters to see more resources.</p><button class="btn btn-outline" id="inventoryEmptyClear" type="button">Clear filters</button>' : '<h3>No inventory data available</h3><p>Resources will appear after CSPM scan data is available.</p>';
    }
    $("inventoryResultCount").textContent = `${matches.length} ${matches.length === 1 ? "resource" : "resources"}`;
    $("inventoryPaginationLabel").textContent = matches.length ? `Showing ${start + 1}–${Math.min(start + visible.length, matches.length)} of ${matches.length} resources` : "Showing 0 of 0 resources";
    $("inventoryPageIndicator").textContent = `${state.page} / ${pages}`;
    $("inventoryPrev").disabled = state.page <= 1;
    $("inventoryNext").disabled = state.page >= pages;
    $("inventoryStatus").textContent = `${matches.length} resources match current search and filters`;
    renderChips();
    renderSortState();
  }
  function formatDate(value) {
    if (!value) return "Not recorded";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "Not recorded";
    return new Intl.DateTimeFormat(undefined, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", timeZoneName: "short" }).format(date);
  }

  function drawerMarkup(resource) {
    const fields = [
      ["Resource type", resource.resource_type], ["Cloud", resource.cloud],
      ["Domain", resource.domain], ["Status", resource.status],
      ["Highest severity", resource.highest_severity || "No assessment"],
      ["Maximum risk score", resource.max_risk_score == null ? "Not recorded" : resource.max_risk_score],
      ["Finding count", resource.finding_count], ["Open findings", resource.open_findings],
      ["Last seen", formatDate(resource.last_seen)]
    ];
    const severityRows = [["CRITICAL", "Critical", "var(--critical)"], ["HIGH", "High", "var(--high)"], ["MEDIUM", "Medium", "var(--medium)"], ["LOW", "Low", "#2563eb"]];
    const maxCount = Math.max(1, ...severityRows.map(([key]) => resource.severity_counts[key]));
    const findingsMarkup = resource.findings.map(({ finding, finding_index }) => {
      const findingId = finding.finding_id || "";
      const url = new URL("findings.html", window.location.href);
      if (findingId) url.searchParams.set("id", findingId);
      url.searchParams.set("record", String(finding_index));
      const sev = shared.normalizeSeverity(finding.severity);
      return `<article class="resource-finding"><div class="resource-finding-main"><strong>${esc(finding.finding || "Untitled finding")}</strong><div class="resource-finding-meta"><span class="inventory-severity inventory-severity-${sev.toLowerCase()}">${esc(sev)}</span><span>Risk ${finding.risk_score === 0 || finding.risk_score ? esc(finding.risk_score) : "—"}</span><span>${esc(shared.normalizeStatus(finding.status))}</span><time datetime="${esc(finding.detected_at || "")}">${esc(formatDate(finding.detected_at))}</time></div></div>${findingId ? `<a class="inventory-related-link" href="${esc(url.href)}">View finding</a>` : ""}</article>`;
    }).join("");
    return `<dl class="resource-detail-grid">${fields.map(([label, value]) => `<div class="resource-detail-field"><dt>${label}</dt><dd>${esc(value)}</dd></div>`).join("")}</dl>
      <section class="resource-detail-section"><h3>Security posture</h3><div class="resource-posture">${severityRows.map(([key, label, color]) => `<div class="resource-posture-row"><span>${label}</span><span class="resource-posture-track"><span class="resource-posture-fill" style="--bar-width:${resource.severity_counts[key] / maxCount * 100}%;--tone:${color}"></span></span><strong class="resource-posture-count">${resource.severity_counts[key]}</strong></div>`).join("")}</div></section>
      <section class="resource-detail-section"><h3>Security Findings <span>(${resource.finding_count})</span></h3><div class="resource-finding-list">${findingsMarkup || '<p class="inventory-chart-empty">No associated findings are available.</p>'}</div></section>`;
  }
  function updateUrl(resource, replace = false) {
    const url = new URL(window.location.href);
    if (resource) url.searchParams.set("resource", resource.key); else url.searchParams.delete("resource");
    history[replace ? "replaceState" : "pushState"]({}, "", url);
  }
  function openResource(resourceOrKey, fromUrl = false) {
    const resource = typeof resourceOrKey === "string" ? resources.find((item) => item.key === resourceOrKey) : resourceOrKey;
    if (!resource) return;
    if (!$("resourceDrawer").classList.contains("is-open")) {
      state.lastFocus = document.activeElement === document.body ? null : document.activeElement;
      state.lastFocusKey = state.lastFocus?.dataset?.openResource || state.lastFocus?.closest?.("tr[data-resource-key]")?.dataset?.resourceKey || null;
    }
    state.selectedKey = resource.key;
    $("resourceDrawerTitle").textContent = resource.resource_id;
    $("resourceDrawerBody").innerHTML = drawerMarkup(resource);
    $("resourceDrawer").classList.add("is-open");
    $("resourceDrawer").setAttribute("aria-hidden", "false");
    $("resourceDrawer").inert = false;
    $("resourceBackdrop").hidden = false;
    document.body.classList.add("inventory-drawer-open");
    if (!fromUrl) updateUrl(resource);
    renderTable();
    $("resourceDrawerClose").focus();
  }
  function closeDrawer(fromPop = false) {
    if (!$("resourceDrawer").classList.contains("is-open")) return;
    $("resourceDrawer").classList.remove("is-open");
    $("resourceDrawer").setAttribute("aria-hidden", "true");
    $("resourceDrawer").inert = true;
    $("resourceBackdrop").hidden = true;
    document.body.classList.remove("inventory-drawer-open");
    state.selectedKey = null;
    if (!fromPop) updateUrl(null, true);
    renderTable();
    const target = state.lastFocus?.isConnected ? state.lastFocus : state.lastFocusKey ? [...document.querySelectorAll("[data-open-resource]")].find((node) => node.dataset.openResource === state.lastFocusKey) : $("inventorySearch");
    target?.focus();
  }

  function clearFilters() {
    state.query = "";
    filterDefs.forEach((def) => { state[def.key] = ""; const select = $("inventory-filter-" + def.key); if (select) select.value = ""; });
    $("inventorySearch").value = "";
    state.page = 1;
    renderTable();
    $("inventorySearch").focus();
  }
  function exportCsv() {
    const values = filterAndSortInventory(resources);
    const headers = ["resource_id", "resource_type", "cloud", "domains", "finding_count", "open_findings", "critical_findings", "high_findings", "medium_findings", "low_findings", "info_findings", "pass_findings", "highest_severity", "max_risk_score", "status", "first_seen", "last_seen"];
    const quote = (value) => `"${String(value ?? "").replaceAll('"', '""')}"`;
    const rows = values.map((resource) => [resource.resource_id, resource.resource_type, resource.clouds.join("; "), resource.domains.join("; "), resource.finding_count, resource.open_findings, resource.critical_findings, resource.high_findings, resource.medium_findings, resource.low_findings, resource.info_findings, resource.pass_findings, resource.highest_severity, resource.max_risk_score, resource.status, resource.first_seen, resource.last_seen].map(quote).join(","));
    const blob = new Blob([[headers.map(quote).join(","), ...rows].join("\r\n")], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `cspm-inventory-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.append(anchor); anchor.click(); anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    $("inventoryStatus").textContent = `Exported ${values.length} filtered inventory resources as CSV`;
  }

  function setData() {
    const openResourceKey = $("resourceDrawer").classList.contains("is-open") ? state.selectedKey : null;
    shared = window.CSPMShared;
    if (!shared || !shared.hasDataSource?.() || typeof shared.getFindings !== "function") throw new Error("Shared CSPM findings are unavailable");
    const source = shared.getFindings();
    if (!Array.isArray(source)) throw new Error("Shared CSPM findings are invalid");
    findings = source.filter((finding) => finding && typeof finding === "object");
    resources = getInventoryResources(findings);
    buildFilterDefinitions();
    renderSummary();
    renderDistribution();
    renderTable();
    if (openResourceKey) {
      const refreshedResource = resources.find((resource) => resource.key === openResourceKey);
      if (refreshedResource) {
        $("resourceDrawerTitle").textContent = refreshedResource.resource_id;
        $("resourceDrawerBody").innerHTML = drawerMarkup(refreshedResource);
      } else closeDrawer();
    }
    if (state.filtersCollapsed == null) state.filtersCollapsed = window.innerWidth <= 768;
    $("inventoryFilters").hidden = state.filtersCollapsed;
    $("inventoryFilterToggle").setAttribute("aria-expanded", String(!state.filtersCollapsed));
    $("inventoryError").hidden = true;
    $("inventorySummary").hidden = false;
    $("inventoryPosture").hidden = false;
    $("inventoryToolbar").hidden = false;
    $("inventoryTablePanel").hidden = false;
    document.querySelector(".inventory-limitation").hidden = false;
    $("inventoryContent").setAttribute("aria-busy", "false");
  }
  function showError() {
    if ($("resourceDrawer").classList.contains("is-open")) closeDrawer();
    $("inventoryError").hidden = false;
    $("inventorySummary").hidden = true;
    $("inventoryPosture").hidden = true;
    $("inventoryToolbar").hidden = true;
    $("inventoryTablePanel").hidden = true;
    document.querySelector(".inventory-overview").hidden = true;
    document.querySelector(".inventory-limitation").hidden = true;
    $("inventoryContent").setAttribute("aria-busy", "false");
  }
  function init() {
    try { setData(); }
    catch (error) { console.error("Inventory page could not load the shared data:", error); showError(); }
    $("inventoryPageSize").value = String(state.pageSize);
    $("inventoryFilters").addEventListener("change", (event) => {
      const key = event.target.dataset.inventoryFilter;
      if (!key) return;
      state[key] = event.target.value;
      state.page = 1;
      renderTable();
    });
    $("inventorySearch").addEventListener("input", (event) => { state.query = event.target.value; state.page = 1; renderTable(); });
    $("inventoryClearFilters").addEventListener("click", clearFilters);
    $("inventoryChips").addEventListener("click", (event) => {
      const button = event.target.closest("[data-remove-inventory-filter]");
      if (!button) return;
      state[button.dataset.removeInventoryFilter] = "";
      $("inventory-filter-" + button.dataset.removeInventoryFilter).value = "";
      state.page = 1;
      renderTable();
    });
    $("inventoryEmpty").addEventListener("click", (event) => { if (event.target.id === "inventoryEmptyClear") clearFilters(); });
    $("inventoryFilterToggle").addEventListener("click", () => {
      const open = $("inventoryFilterToggle").getAttribute("aria-expanded") !== "true";
      state.filterPreferenceSet = true;
      state.filtersCollapsed = !open;
      $("inventoryFilterToggle").setAttribute("aria-expanded", String(open));
      $("inventoryFilters").hidden = !open;
    });
    window.addEventListener("resize", () => {
      if (state.filterPreferenceSet) return;
      state.filtersCollapsed = window.innerWidth <= 768;
      $("inventoryFilters").hidden = state.filtersCollapsed;
      $("inventoryFilterToggle").setAttribute("aria-expanded", String(!state.filtersCollapsed));
    });
    document.querySelector(".inventory-table thead").addEventListener("click", (event) => {
      const th = event.target.closest("th[data-sort]");
      if (!th) return;
      if (state.sortKey === th.dataset.sort) state.sortDir = state.sortDir === "asc" ? "desc" : "asc";
      else { state.sortKey = th.dataset.sort; state.sortDir = ["finding_count", "open_findings", "highest_severity", "max_risk_score"].includes(state.sortKey) ? "desc" : state.sortKey === "last_seen" ? "desc" : "asc"; }
      state.page = 1;
      renderTable();
    });
    $("inventoryBody").addEventListener("click", (event) => {
      const button = event.target.closest("[data-open-resource]");
      const row = event.target.closest("tr[data-resource-key]");
      const key = button?.dataset.openResource || row?.dataset.resourceKey;
      if (key) openResource(key);
    });
    $("inventoryBody").addEventListener("keydown", (event) => {
      if ((event.key === "Enter" || event.key === " ") && event.target.matches("tr[data-resource-key]")) {
        event.preventDefault();
        openResource(event.target.dataset.resourceKey);
      }
    });
    $("resourceDrawerClose").addEventListener("click", () => closeDrawer());
    $("resourceBackdrop").addEventListener("click", () => closeDrawer());
    $("inventoryExport").addEventListener("click", exportCsv);
    $("inventoryRefresh").addEventListener("click", () => { try { setData(); $("inventoryStatus").textContent = "Inventory refreshed from current CSPM findings"; } catch (_) { showError(); } });
    $("inventoryRetry").addEventListener("click", () => { try { setData(); } catch (_) { showError(); } });
    $("inventoryPageSize").addEventListener("change", (event) => { state.pageSize = [20, 50, 100].includes(Number(event.target.value)) ? Number(event.target.value) : 20; window.CSPMSettings?.saveCSPMSettings?.({ tablePageSize: state.pageSize }); state.page = 1; renderTable(); });
    $("inventoryPrev").addEventListener("click", () => { state.page = Math.max(1, state.page - 1); renderTable(); });
    $("inventoryNext").addEventListener("click", () => { state.page++; renderTable(); });
    document.addEventListener("keydown", (event) => {
      if (event.key === "/" && !event.ctrlKey && !event.metaKey && !/INPUT|TEXTAREA|SELECT/.test(document.activeElement?.tagName || "")) { event.preventDefault(); $("inventorySearch").focus(); }
      if (event.key === "Escape" && $("resourceDrawer").classList.contains("is-open")) closeDrawer();
      if (event.key === "Tab" && $("resourceDrawer").classList.contains("is-open")) {
        const focusable = [...$("resourceDrawer").querySelectorAll('button:not(:disabled),a[href],input,select,[tabindex]:not([tabindex="-1"])')].filter((node) => !node.hidden);
        const first = focusable[0], last = focusable[focusable.length - 1];
        if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
      }
    });
    window.addEventListener("popstate", () => {
      const key = new URLSearchParams(location.search).get("resource");
      if (key) openResource(key, true); else closeDrawer(true);
    });
    const initialResource = new URLSearchParams(location.search).get("resource");
    if (initialResource) openResource(initialResource, true);
  }
  window.CSPMInventoryAdapter = Object.freeze({
    getInventoryResources(records) {
      shared = window.CSPMShared;
      if (!shared) throw new Error("Shared CSPM helpers are unavailable");
      return getInventoryResources(records);
    },
  });
  if ($("inventoryContent")) {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init, { once: true });
    else init();
  }
})();
