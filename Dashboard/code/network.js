(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  const PAGE_SIZE = 20;
  const severityRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0, PASS: 0 };
  let shared;
  let rows = [];
  const state = { search: "", cloud: "", severity: "", status: "", type: "", sort: "detected", page: 1, selected: null, lastFocus: null };
  const evidenceText = (value) => typeof value === "string" ? value : value == null ? "" : (() => { try { return JSON.stringify(value, null, 2); } catch (_) { return String(value); } })();
  const domainOf = (f) => String(shared.normalizeDomain(f) || "").toUpperCase();
  const cloudOf = (f) => shared.normalizeCloud(f.cloud);
  const severityOf = (f) => shared.normalizeSeverity(f.severity);
  const statusOf = (f) => shared.normalizeStatus(f.status);
  const resourceKey = (f) => f.resource_type && f.resource_id ? JSON.stringify([String(f.resource_type), String(f.resource_id)]) : "";
  function getNetworkFindings(source) { return source.map((finding, index) => ({ finding, index })).filter(({ finding }) => domainOf(finding).includes("NETWORK")); }
  function getResources(records) {
    const seen = new Set();
    return records.flatMap(({ finding }) => { const key = resourceKey(finding); if (!key || seen.has(key)) return []; seen.add(key); return [{ key, type: String(finding.resource_type), id: String(finding.resource_id), cloud: cloudOf(finding) }]; });
  }
  function setOptions(id, values, label) {
    const select = $(id), prior = select.value;
    select.innerHTML = `<option value="">${label}</option>` + values.map((x) => `<option value="${esc(x)}">${esc(x)}</option>`).join("");
    select.value = values.includes(prior) ? prior : "";
  }
  function setAvailability(id, title, body) { $(id).innerHTML = `<strong>${esc(title)}</strong><span>${esc(body)}</span>`; $(id).classList.add("network-unavailable"); }
  function applyLiveNetwork(payload) {
    if (!payload || payload.source !== "live-network-scan" || !Array.isArray(payload.findings)) throw new Error("Invalid network scan result");
    localStorage.setItem("cspm-live-network-scan", JSON.stringify(payload));
    const findings = shared.getFindings();
    for (let index = findings.length - 1; index >= 0; index -= 1) {
      if (String(findings[index].domain || findings[index].category || "").toUpperCase().includes("NETWORK")) findings.splice(index, 1);
    }
    payload.findings.forEach((finding) => findings.push(finding));
    if (typeof window.refreshDashboard === "function") window.refreshDashboard();
    updatePanels();
  }
  async function runLiveNetworkScan() {
    const button = $("runNetworkScan");
    button.disabled = true;
    $("networkLive").textContent = "Network scan is running...";
    try {
      const body = { profile_name: $("networkProfile").value.trim() || null, region_name: $("networkRegion").value.trim() || null };
      const response = await fetch("http://127.0.0.1:8765/api/network/scans", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      const start = await response.json();
      if (!response.ok) throw new Error(start.error || "Network scan could not be started.");
      let status = start.status;
      while (status.state === "RUNNING") {
        await new Promise((resolve) => setTimeout(resolve, 500));
        status = (await (await fetch("http://127.0.0.1:8765/api/network/status", { cache: "no-store" })).json()).status;
      }
      if (status.state !== "SUCCEEDED") throw new Error(status.error || "Network scan failed.");
      const result = await (await fetch("http://127.0.0.1:8765/api/network/results", { cache: "no-store" })).json();
      applyLiveNetwork(result);
      $("networkLive").textContent = `Live network scan completed. ${result.findings.length} findings recorded.`;
    } catch (error) {
      $("networkLive").textContent = error instanceof Error ? error.message : "Network scan failed.";
    } finally {
      button.disabled = false;
    }
  }
  async function loadSavedNetworkScan() {
    try {
      const response = await fetch("http://127.0.0.1:8765/api/network/results", { cache: "no-store" });
      if (!response.ok) return;
      const payload = await response.json();
      if (payload.source === "live-network-scan") {
        applyLiveNetwork(payload);
        $("networkLive").textContent = `Last successful live network scan completed. ${payload.findings.length} findings recorded.`;
      }
    } catch (error) {
      $("networkLive").textContent = "Backend unavailable. Start the local backend to run a network scan.";
    }
  }
  function updatePanels() {
    const source = shared.getFindings();
    const network = getNetworkFindings(source);
    const resources = getResources(network);
    const hasFindings = network.length > 0;
    $("networkViewFindings").hidden = !hasFindings;
    $("networkAllFindings").hidden = !hasFindings;
    if (!hasFindings) {
      $("networkStateTitle").textContent = "Awaiting Network Scan Data";
      $("networkStateDescription").textContent = "Network posture will appear when network-related CSPM data becomes available.";
      $("networkStateLabel").textContent = "Awaiting scan data";
      $("networkMetrics").hidden = true;
      setAvailability("networkExposure", "No network exposure data available", "A network assessment is required before exposure categories can be evaluated.");
      setAvailability("networkSeverity", "Severity distribution unavailable", "Network findings are not present in the current CSPM data.");
      setAvailability("networkResources", "No network resources available in the current CSPM data.", "A complete inventory requires actual cloud asset discovery.");
      setAvailability("networkPublic", "Public exposure assessment unavailable", "No explicit public exposure assessment is available.");
      setAvailability("networkFirewall", "Awaiting security group/firewall assessment.", "Rule details appear when supported by Network findings.");
      setAvailability("networkSegmentation", "Segmentation analysis requires network topology or control evaluation data.", "");
      setAvailability("networkRecommendations", "Recommendations unavailable", "Network findings are required to produce relevant remediation guidance.");
      $("networkResourceTypes").innerHTML = "";
    } else {
      $("networkStateTitle").textContent = "Network Assessment Findings Available";
      $("networkStateDescription").textContent = "The summary below reflects Network domain findings in the shared CSPM data.";
      $("networkStateLabel").textContent = "Findings available";
      const open = network.filter(({ finding: f }) => shared.isOpenFinding(f));
      const highCrit = open.filter(({ finding: f }) => ["CRITICAL", "HIGH"].includes(severityOf(f)));
      const clouds = new Set(network.map(({ finding: f }) => cloudOf(f)));
      $("networkMetrics").hidden = false;
      $("networkMetrics").innerHTML = [["Network findings", network.length], ["Open findings", open.length], ["Critical / high", highCrit.length], ["Affected resources", resources.length], ["Clouds with findings", clouds.size]].map(([label, value]) => `<article class="network-metric"><span>${esc(label)}</span><strong>${value}</strong></article>`).join("");
      const buckets = [{ key: "public", label: "Public exposure", test: (f) => explicitPublic(f) }, { key: "firewall", label: "Security groups & firewall", test: (f) => /security.?group|firewall|network acl|inbound rule|outbound rule/i.test(`${f.resource_type || ""} ${f.category || ""} ${f.finding || ""}`) }, { key: "segmentation", label: "Segmentation concerns", test: (f) => /segmentation|isolation|public.private subnet|network path/i.test(`${f.category || ""} ${f.finding || ""} ${evidenceText(f.evidence)}`) }];
      const exposure = buckets.map((b) => ({ ...b, count: network.filter(({ finding }) => b.test(finding)).length })).filter((b) => b.count);
      $("networkExposure").className = exposure.length ? "network-bars" : "network-unavailable";
      $("networkExposure").innerHTML = exposure.length ? exposure.map((b) => `<div class="network-bar-row"><span>${esc(b.label)}</span><strong>${b.count}</strong></div>`).join("") : `<strong>No classified exposure categories in the available findings</strong><span>Categories are shown only when finding content supports them.</span>`;
      const risks = network.filter(({ finding: f }) => shared.isRiskFinding(f));
      if (risks.length) {
        const dist = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => [sev, risks.filter(({ finding: f }) => severityOf(f) === sev).length]);
        $("networkSeverity").className = "network-severity-list";
        $("networkSeverity").innerHTML = dist.map(([sev, count]) => `<div class="network-severity-row" data-severity="${sev.toLowerCase()}"><span>${sev}</span><i><b style="width:${Math.round(count / risks.length * 100)}%"></b></i><strong>${count}</strong><small>${Math.round(count / risks.length * 100)}%</small></div>`).join("");
      } else { setAvailability("networkSeverity", "No open risk findings in the available Network records", "PASS and INFO records are excluded from risk distribution."); }
      if (resources.length) {
        $("networkResources").className = "network-resource-list";
        $("networkResources").innerHTML = resources.slice(0, 8).map((r) => `<div><strong>${esc(r.type)}</strong><span>${esc(r.id)}</span></div>`).join("");
        const types = [...new Set(resources.map((r) => r.type))].map((type) => [type, resources.filter((r) => r.type === type).length]);
        $("networkResourceTypes").innerHTML = `<h3>Resources by Type</h3>` + types.map(([type, count]) => `<span>${esc(type)} <b>${count}</b></span>`).join("");
      } else { setAvailability("networkResources", "Resource identity is unavailable for these findings.", "Resource counts require both resource_type and resource_id."); }
      const exposed = network.filter(({ finding }) => explicitPublic(finding));
      if (exposed.length) {
        const exposedResources = new Set(exposed.map(({ finding }) => resourceKey(finding)).filter(Boolean)).size;
        const openExposure = exposed.filter(({ finding }) => shared.isOpenFinding(finding)).length;
        const highExposure = exposed.filter(({ finding }) => shared.isOpenFinding(finding) && ["CRITICAL", "HIGH"].includes(severityOf(finding))).length;
        $("networkPublic").className = "network-public-metric";
        $("networkPublic").innerHTML = `<strong>${exposedResources || "—"}</strong><span>Uniquely identified resources with explicit public exposure evidence</span><div class="network-public-breakdown"><span>Open exposure findings <b>${openExposure}</b></span><span>Open critical / high <b>${highExposure}</b></span></div>`;
      }
      else setAvailability("networkPublic", "Public exposure assessment unavailable", "No explicit public exposure assessment is available.");
      const firewall = network.filter(({ finding: f }) => /security.?group|firewall|network acl|inbound rule|outbound rule/i.test(`${f.resource_type || ""} ${f.category || ""} ${f.finding || ""}`));
      if (firewall.length) { $("networkFirewall").className = "network-availability-list"; $("networkFirewall").innerHTML = firewall.slice(0, 4).map(({ finding: f }) => `<div><strong>${esc(f.finding || f.finding_id || "Network access control finding")}</strong><span>${esc(f.evidence ? evidenceText(f.evidence) : "Rule detail unavailable")}</span></div>`).join(""); }
      else setAvailability("networkFirewall", "Awaiting security group/firewall assessment.", "Rule details appear when supported by Network findings.");
      const segmentation = network.filter(({ finding: f }) => /segmentation|isolation|public.private subnet|network path/i.test(`${f.category || ""} ${f.finding || ""} ${evidenceText(f.evidence)}`));
      if (segmentation.length) { $("networkSegmentation").className = "network-availability-list"; $("networkSegmentation").innerHTML = segmentation.slice(0, 3).map(({ finding: f }) => `<div><strong>${esc(f.finding || f.finding_id)}</strong><span>${esc(f.evidence || "No additional evidence recorded")}</span></div>`).join(""); }
      const recommended = network.map(({ finding: f }) => f.recommendation || f.remediation).filter(Boolean);
      if (recommended.length) { $("networkRecommendations").className = "network-availability-list"; $("networkRecommendations").innerHTML = [...new Set(recommended)].slice(0, 5).map((x) => `<div><strong>${esc(x)}</strong></div>`).join(""); }
      else setAvailability("No remediation guidance recorded", "Recommendations require source-provided remediation details.");
    }
    const providers = ["AWS", "Azure", "GCP", "Other"];
    const allClouds = new Set(source.map((f) => shared.normalizeCloud(f.cloud)));
    const providerIds = { AWS: "AWS", Azure: "Azure", GCP: "GCP", Other: "Other" };
    providers.forEach((provider) => {
      const suffix = providerIds[provider];
      const count = network.filter(({ finding: f }) => cloudOf(f) === provider).length;
      const label = count ? "Network findings available" : allClouds.has(provider) ? "General CSPM data; network coverage unavailable" : "No CSPM data";
      $("networkCloud" + suffix).textContent = label;
      const badge = $("networkCount" + suffix);
      badge.textContent = count ? `${count} findings` : "";
      badge.hidden = !count;
    });
    rows = network;
    setOptions("networkCloudFilter", [...new Set(rows.map(({ finding }) => cloudOf(finding)))].sort(), "All clouds");
    setOptions("networkSeverityFilter", [...new Set(rows.map(({ finding }) => severityOf(finding)))].sort((a, b) => (severityRank[b] || 0) - (severityRank[a] || 0)), "All severities");
    setOptions("networkStatusFilter", [...new Set(rows.map(({ finding }) => statusOf(finding)))].sort(), "All statuses");
    setOptions("networkTypeFilter", [...new Set(rows.map(({ finding }) => String(finding.resource_type || "")).filter(Boolean))].sort(), "All resource types");
    renderTable();
  }
  function explicitPublic(f) {
    const hasPublicFlag = (value, depth = 0) => {
      if (!value || typeof value !== "object" || depth > 5) return false;
      return Object.entries(value).some(([key, child]) => {
        if (/^(publicly_exposed|is_public|internet_accessible|public_access)$/i.test(key) && child === true) return true;
        return hasPublicFlag(child, depth + 1);
      });
    };
    if ([f.publicly_exposed, f.is_public, f.internet_accessible].some((v) => v === true) || hasPublicFlag(f.evidence)) return true;
    const raw = `${f.finding || ""} ${evidenceText(f.evidence)}`;
    return /\b(publicly exposed|exposed to the internet|allows?\s+(?:ingress|traffic\s+from)\s+(?:0\.0\.0\.0\/0|::\/0))\b/i.test(raw) && !/\b(?:not|no|never|without|non-|isn't\s+|is\s+not\s+)(?:publicly exposed|exposed to the internet)/i.test(raw);
  }
  function getFiltered() {
    const q = state.search.trim().toLocaleLowerCase();
    return rows.filter(({ finding: f }) => {
      const haystack = [f.finding, f.finding_id, f.cloud, f.domain, f.category, f.resource_type, f.resource_id, evidenceText(f.evidence)].filter(Boolean).join(" ").toLocaleLowerCase();
      return (!q || haystack.includes(q)) && (!state.cloud || cloudOf(f) === state.cloud) && (!state.severity || severityOf(f) === state.severity) && (!state.status || statusOf(f) === state.status) && (!state.type || String(f.resource_type || "") === state.type);
    }).sort((a, b) => {
      const x = a.finding, y = b.finding;
      if (state.sort === "risk") return (Number(y.risk_score) || 0) - (Number(x.risk_score) || 0) || (new Date(y.detected_at) - new Date(x.detected_at));
      if (state.sort === "severity") return (severityRank[severityOf(y)] || 0) - (severityRank[severityOf(x)] || 0);
      if (state.sort === "cloud") return cloudOf(x).localeCompare(cloudOf(y));
      if (state.sort === "resource") return String(x.resource_type || "").localeCompare(String(y.resource_type || ""));
      return (new Date(y.detected_at) - new Date(x.detected_at)) || a.index - b.index;
    });
  }
  function dateLabel(value) { if (!value) return "Not recorded"; const d = new Date(value); return Number.isNaN(d.getTime()) ? String(value) : new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(d); }
  function findingLink(f, index) { const u = new URL("findings.html", location.href); u.searchParams.set("id", f.finding_id); u.searchParams.set("record", String(index)); return u.pathname.split("/").pop() + u.search; }
  function openDetails(row) {
    state.selected = row; state.lastFocus = document.activeElement;
    const f = row.finding;
    $("networkDrawerTitle").textContent = f.finding || f.finding_id || "Network finding";
    const fields = [["Finding ID", f.finding_id], ["Cloud", f.cloud], ["Domain", f.domain || f.category], ["Severity", severityOf(f)], ["Status", statusOf(f)], ["Resource type", f.resource_type], ["Resource ID", f.resource_id], ["Risk score", f.risk_score], ["Detected", dateLabel(f.detected_at)]];
    const resourceUrl = f.resource_type && f.resource_id ? `inventory.html?resource=${encodeURIComponent(JSON.stringify([f.resource_type, f.resource_id]))}` : "";
    $("networkDrawerBody").innerHTML = `<dl class="network-detail-fields">${fields.map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v || "Not recorded")}</dd></div>`).join("")}</dl>${f.evidence ? `<section class="network-detail-section"><h3>Evidence</h3><pre>${esc(evidenceText(f.evidence))}</pre></section>` : ""}<section class="network-detail-section"><h3>Remediation guidance</h3><p>${esc(f.recommendation || f.remediation || "No remediation guidance is recorded for this finding.")}</p></section><div class="network-detail-links"><a class="btn btn-outline" href="${esc(findingLink(f, row.index))}">Open in Findings</a>${resourceUrl ? `<a class="btn btn-outline" href="${esc(resourceUrl)}">View resource in Inventory</a>` : ""}</div>`;
    $("networkDrawer").classList.add("is-open"); $("networkDrawer").setAttribute("aria-hidden", "false"); $("networkDrawer").inert = false; $("networkDrawerBackdrop").hidden = false; document.body.classList.add("network-drawer-open"); $("networkDrawerClose").focus();
  }
  function closeDetails() { if (!$("networkDrawer").classList.contains("is-open")) return; $("networkDrawer").classList.remove("is-open"); $("networkDrawer").setAttribute("aria-hidden", "true"); $("networkDrawer").inert = true; $("networkDrawerBackdrop").hidden = true; document.body.classList.remove("network-drawer-open"); state.selected = null; state.lastFocus?.focus?.(); }
  function renderTable() {
    const filtered = getFiltered();
    const pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE)); state.page = Math.min(state.page, pages);
    const pageRows = filtered.slice((state.page - 1) * PAGE_SIZE, state.page * PAGE_SIZE);
    $("networkFindingsBody").innerHTML = pageRows.map(({ finding: f, index }) => `<tr data-record-index="${index}" tabindex="0"><td><span class="network-severity-pill" data-severity="${esc(severityOf(f).toLowerCase())}">${esc(severityOf(f))}</span></td><td><button class="network-finding-open" type="button" data-index="${index}"><strong>${esc(f.finding || f.finding_id || "Network finding")}</strong><small>${esc(f.finding_id || "ID unavailable")}</small></button></td><td>${esc(cloudOf(f))}</td><td><span class="network-resource-cell"><strong>${esc(f.resource_type || "Type unavailable")}</strong><small>${esc(f.resource_id || "ID unavailable")}</small></span></td><td>${esc(f.risk_score ?? "—")}</td><td>${esc(statusOf(f))}</td><td>${esc(dateLabel(f.detected_at))}</td></tr>`).join("");
    const active = Boolean(state.search || state.cloud || state.severity || state.status || state.type);
    $("networkEmpty").hidden = Boolean(pageRows.length);
    $("networkEmpty").innerHTML = rows.length ? `<strong>${active ? "No findings match these filters" : "No Network findings"}</strong><span>${active ? "Adjust or clear the filters to see other Network findings." : "No Network domain findings are available in the shared data."}</span>` : `<strong>Awaiting Network Scan Data</strong><span>Network findings will appear here when network-related CSPM data becomes available.</span>`;
    $("networkResult").textContent = rows.length ? `${filtered.length} of ${rows.length} Network findings` : "Network assessment data unavailable";
    $("networkFindingsDescription").textContent = rows.length ? "Search, sort, and filter findings in the Network security domain." : "Only findings identified as Network domain data will appear here.";
    $("networkPagination").hidden = filtered.length <= PAGE_SIZE;
    $("networkPageLabel").textContent = `${filtered.length ? (state.page - 1) * PAGE_SIZE + 1 : 0}–${Math.min(state.page * PAGE_SIZE, filtered.length)} of ${filtered.length}`;
    $("networkPageNumber").textContent = `${state.page} / ${pages}`; $("networkPrev").disabled = state.page <= 1; $("networkNext").disabled = state.page >= pages;
    $("networkClearFilters").hidden = !active;
  }
  function clearFilters() { state.search = state.cloud = state.severity = state.status = state.type = ""; state.page = 1; $("networkSearch").value = ""; ["networkCloudFilter", "networkSeverityFilter", "networkStatusFilter", "networkTypeFilter"].forEach((id) => { $(id).value = ""; }); renderTable(); }
  function init() {
    shared = window.CSPMShared;
    if (!shared || !Array.isArray(shared.getFindings())) { $("networkStateTitle").textContent = "Network data unavailable"; return; }
    $("networkSearch").addEventListener("input", (e) => { state.search = e.target.value; state.page = 1; renderTable(); });
    [["networkCloudFilter", "cloud"], ["networkSeverityFilter", "severity"], ["networkStatusFilter", "status"], ["networkTypeFilter", "type"], ["networkSort", "sort"]].forEach(([id, key]) => $(id).addEventListener("change", (e) => { state[key] = e.target.value; state.page = 1; renderTable(); }));
    $("networkClearFilters").addEventListener("click", clearFilters);
    $("networkPrev").addEventListener("click", () => { state.page--; renderTable(); }); $("networkNext").addEventListener("click", () => { state.page++; renderTable(); });
    $("networkRefresh").addEventListener("click", () => { updatePanels(); $("networkLive").textContent = "Network security view refreshed from current shared data."; });
    $("runNetworkScan").addEventListener("click", runLiveNetworkScan);
    $("networkFindingsBody").addEventListener("click", (e) => { const button = e.target.closest("[data-index]"); if (button) { const index = Number(button.dataset.index); const row = rows.find((r) => r.index === index); if (row) openDetails(row); } });
    $("networkFindingsBody").addEventListener("keydown", (e) => { if ((e.key === "Enter" || e.key === " ") && e.target.matches("tr[data-record-index]")) { e.preventDefault(); const row = rows.find((r) => r.index === Number(e.target.dataset.recordIndex)); if (row) openDetails(row); } });
    $("networkDrawerClose").addEventListener("click", closeDetails); $("networkDrawerBackdrop").addEventListener("click", closeDetails); document.addEventListener("keydown", (e) => {
      if (!$("networkDrawer").classList.contains("is-open")) return;
      if (e.key === "Escape") { closeDetails(); return; }
      if (e.key === "Tab") { const items = [...$("networkDrawer").querySelectorAll("button:not([disabled]),a[href],input:not([disabled]),select:not([disabled]),[tabindex='0']")]; if (!items.length) return; const first = items[0], last = items[items.length - 1]; if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); } else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); } }
    });
    updatePanels();
    loadSavedNetworkScan();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init, { once: true }); else init();
  if (typeof window !== "undefined") window.CSPMNetwork = Object.freeze({ getNetworkFindings, getResources });
})();
