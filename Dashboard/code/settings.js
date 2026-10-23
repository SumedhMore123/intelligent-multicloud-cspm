(() => {
  "use strict";
  if (!document.getElementById("settingsContent")) return;

  const $ = (id) => document.getElementById(id);
  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  const categories = [
    { id: "general", label: "General", icon: "total" },
    { id: "appearance", label: "Appearance", icon: "sun" },
    { id: "dashboard", label: "Dashboard", icon: "dashboard", badge: "Limited" },
    { id: "notifications", label: "Notifications", icon: "notifications" },
    { id: "data-display", label: "Data & Display", icon: "data" },
    { id: "reports", label: "Reports", icon: "reports", badge: "Limited" },
    { id: "security", label: "Security", icon: "high", badge: "Backend" },
    { id: "cloud-connections", label: "Cloud Connections", icon: "cloud", badge: "Backend" },
    { id: "advanced", label: "Advanced", icon: "activity" },
  ];
  let selected = "general";
  let settings = window.CSPMSettings?.getCSPMSettings?.() || { theme: "light", tablePageSize: 20, showNotificationBadge: true };
  const labels = { light: "Light", dark: "Dark", system: "System" };

  function icon(name) { return window.CSPM_ICONS?.[name] || ""; }
  function setSaveState(message, error = false) {
    const node = $("settingsSaveState");
    node.textContent = message;
    node.dataset.state = error ? "error" : "saved";
    node.classList.remove("is-updated"); void node.offsetWidth; node.classList.add("is-updated");
  }
  function persist(changes) {
    const saved = window.CSPMSettings?.saveCSPMSettings?.(changes) === true;
    settings = window.CSPMSettings?.getCSPMSettings?.() || { ...settings, ...changes };
    setSaveState(saved ? "Saved automatically" : "Could not save in this browser", !saved);
    return saved;
  }
  function renderNavigation() {
    $("settingsNav").innerHTML = categories.map((category) => `<button class="settings-nav-item${selected === category.id ? " is-current" : ""}" type="button" data-settings-section="${category.id}"${selected === category.id ? ' aria-current="page"' : ""}><span class="settings-nav-icon" aria-hidden="true">${icon(category.icon)}</span><span>${category.label}</span>${category.badge ? `<small data-badge="${category.badge === "Backend" ? "backend" : "limited"}">${category.badge}</small>` : ""}</button>`).join("");
    $("settingsMobileNav").innerHTML = categories.map((category) => `<option value="${category.id}">${category.label}${category.badge ? ` · ${category.badge}` : ""}</option>`).join("");
    $("settingsMobileNav").value = selected;
  }
  function panelHeader(kicker, title, description, status = "") {
    return `<header class="settings-panel-head"><div><span class="settings-eyebrow">${esc(kicker)}</span><h2 id="settingsSectionTitle" tabindex="-1">${esc(title)}</h2><p>${esc(description)}</p></div>${status ? `<span class="settings-status-label" data-state="${status === "Available" ? "available" : status === "Requires Backend" ? "backend" : "limited"}">${esc(status)}</span>` : ""}</header>`;
  }
  function infoRow(title, description, status = "Coming Soon") {
    const state = status === "Requires Backend" ? "backend" : status === "Available" ? "available" : "limited";
    return `<article class="settings-info-row"><span class="settings-info-icon" aria-hidden="true">${icon("activity")}</span><div><strong>${esc(title)}</strong><p>${esc(description)}</p></div><span class="settings-status-label" data-state="${state}">${esc(status)}</span></article>`;
  }
  function themePreview(theme) {
    const active = settings.theme === theme;
    return `<button class="settings-theme-card${active ? " is-selected" : ""}" type="button" data-setting-theme="${theme}" aria-pressed="${active}" aria-label="Use ${labels[theme]} theme"><span class="theme-mini" data-theme-preview="${theme}"><span class="theme-mini-sidebar"></span><span class="theme-mini-main"><i></i><i></i><i></i><b></b></span></span><span class="settings-theme-choice"><span>${icon(theme === "dark" ? "moon" : theme === "system" ? "activity" : "sun")}</span><strong>${labels[theme]}</strong><span class="settings-theme-check" aria-hidden="true">${active ? icon("complianceBadge") : ""}</span></span></button>`;
  }
  function toggleRow(title, description, checked, id) {
    return `<div class="settings-control-row"><div><label for="${id}">${esc(title)}</label><p>${esc(description)}</p></div><button id="${id}" class="settings-switch" type="button" role="switch" aria-checked="${checked}" aria-label="${esc(title)}"><span></span></button></div>`;
  }
  function cloudProviderMark(name) {
    const key = name === "AWS" ? "aws" : name === "Azure" ? "azure" : "gcp";
    return `<span class="settings-provider-mark" data-provider="${name}" role="img" aria-label="${name} logo">${icon(key)}</span>`;
  }
  function cloudConnections() {
    const shared = window.CSPMShared;
    let available = new Set();
    let sourceLoaded = false;
    try {
      sourceLoaded = Boolean(shared?.hasDataSource?.());
      if (sourceLoaded) available = new Set((shared.getFindings() || []).map((finding) => shared.normalizeCloud(finding.cloud)));
    } catch (_) { sourceLoaded = false; }
    const providers = ["AWS", "Azure", "GCP"];
    return providers.map((provider) => {
      const hasData = sourceLoaded && available.has(provider);
      const stateText = hasData ? "Finding data available" : sourceLoaded ? "No finding records" : "No CSPM data source";
      return `<article class="settings-cloud-card">${cloudProviderMark(provider)}<div class="settings-cloud-copy"><h3>${provider}</h3><p>${hasData ? "Present in the current CSPM dataset. This does not indicate a live account connection." : "No records for this provider are present in the current CSPM dataset."}</p><span class="settings-status-label" data-state="${hasData ? "available" : "limited"}"><i aria-hidden="true"></i>${stateText}</span></div><span class="settings-cloud-requirement">Requires Backend</span></article>`;
    }).join("");
  }
  function renderPanel() {
    const panel = $("settingsPanel");
    if (selected === "general") {
      panel.innerHTML = panelHeader("Workspace", "General", "A quick view of this browser workspace and the defaults that are currently active.", "Available") + `<div class="settings-overview-grid"><article><span class="settings-overview-icon">${icon("settings")}</span><span>Workspace</span><strong>CSPM Workspace</strong><small>Local browser session</small></article><article><span class="settings-overview-icon">${icon("dashboard")}</span><span>Entry page</span><strong>Dashboard</strong><small>Application entry is fixed to index.html</small></article><article><span class="settings-overview-icon">${icon("calendar")}</span><span>Date range</span><strong>All available findings</strong><small>Dashboard date picker is not wired to filtering</small></article></div><div class="settings-note"><span aria-hidden="true">${icon("activity")}</span><p>Workspace name, timezone, landing page, and dashboard date range are not configurable in the current application.</p></div>`;
    } else if (selected === "appearance") {
      panel.innerHTML = panelHeader("Interface", "Appearance", "Choose a theme for all CSPM pages. Your choice saves in this browser immediately.", "Auto-saved") + `<section class="settings-section"><div class="settings-section-title"><div><h3>Theme</h3><p>System follows your operating system’s light or dark appearance.</p></div><span class="settings-current-value">Current: ${labels[settings.theme]}</span></div><div class="settings-theme-grid">${["light", "dark", "system"].map(themePreview).join("")}</div></section><div class="settings-note"><span aria-hidden="true">${icon("info")}</span><p>Theme selection is shared across Dashboard, Security, Reports, Alerts, and IAM Security.</p></div>`;
    } else if (selected === "dashboard") {
      panel.innerHTML = panelHeader("View preferences", "Dashboard", "Dashboard controls are shown here only when this application can apply them.", "Limited") + `<div class="settings-limitation-banner"><span aria-hidden="true">${icon("activity")}</span><div><strong>Live refresh and scan scheduling are unavailable</strong><p>This workspace reads the current CSPM findings dataset. There is no live scan source or recurring refresh pipeline to configure.</p></div></div><div class="settings-info-list">${infoRow("Automatic refresh", "Requires a live data source and scheduled refresh support.", "Requires Backend")}${infoRow("Default date range", "The Dashboard date picker is currently a placeholder; it does not filter findings.", "Coming Soon")}${infoRow("Default cloud and severity filters", "Filters are applied interactively on the Dashboard and are not saved as defaults.", "Coming Soon")}</div>`;
    } else if (selected === "notifications") {
      const count = window.CSPMShared?.calcNotificationCount?.(window.CSPMShared.getFindings()) ?? 0;
      panel.innerHTML = panelHeader("On-screen indicators", "Notifications", "Control the existing Dashboard badge. The badge counts open HIGH-severity findings; it is not a delivery system.", "Auto-saved") + `<section class="settings-section settings-control-section"><div class="settings-section-title"><div><h3>Dashboard badge</h3><p>Current count from findings: <strong>${count}</strong></p></div><span class="settings-status-label" data-state="available">In-app only</span></div>${toggleRow("Show high-finding badge", "Display or hide the existing count on the Dashboard bell icon.", settings.showNotificationBadge, "settingsNotificationBadge")}</section><div class="settings-info-list">${infoRow("Email, Slack, Teams, SMS, and push delivery", "No notification delivery or persistent alert routing is configured.", "Requires Backend")}</div>`;
    } else if (selected === "data-display") {
      panel.innerHTML = panelHeader("Table behavior", "Data & Display", "Set the shared default row count for supported finding and resource tables.", "Auto-saved") + `<section class="settings-section"><div class="settings-section-title"><div><h3>Default table page size</h3><p>Applies to Findings, Inventory, Policies, Alerts, and Cloud Security. Individual table changes update this preference.</p></div><span class="settings-current-value">${settings.tablePageSize} rows</span></div><div class="settings-segmented" role="group" aria-label="Default table page size">${[20, 50, 100].map((size) => `<button type="button" data-setting-page-size="${size}" aria-pressed="${settings.tablePageSize === size}">${size}<small>rows</small></button>`).join("")}</div></section><div class="settings-note"><span aria-hidden="true">${icon("info")}</span><p>Dashboard’s compact Latest Findings panel keeps its existing 8-row layout. Timestamp rendering follows browser locale and timezone; no separate format preference is applied.</p></div>`;
    } else if (selected === "reports") {
      panel.innerHTML = panelHeader("Output & retention", "Reports", "Report output options are available on the Reports page.", "Limited") + `<div class="settings-info-list">${infoRow("JSON and CSV exports", "Both scoped export formats are available when generating a report.", "Available")}${infoRow("Print / Save PDF", "Print-to-PDF is available through the browser’s print dialog.", "Available")}${infoRow("Scheduled reports and delivery", "History, scheduling, and distribution require persistent backend support.", "Requires Backend")}</div><div class="settings-note"><span aria-hidden="true">${icon("reports")}</span><p>There is no default export format setting because report downloads are selected explicitly for each report.</p></div>`;
    } else if (selected === "security") {
      panel.innerHTML = panelHeader("Access control", "Security", "Account security controls need an authenticated backend and are not available in this browser-only workspace.", "Requires Backend") + `<div class="settings-info-list">${infoRow("Authentication and SSO", "User identity and single sign-on are not configured.", "Requires Backend")}${infoRow("Role-based access control", "There is no server-enforced user or role model.", "Requires Backend")}${infoRow("MFA and session management", "No authentication sessions or MFA enrollment are managed by this application.", "Requires Backend")}${infoRow("API access", "No user-facing API key management is available.", "Requires Backend")}</div>`;
    } else if (selected === "cloud-connections") {
      panel.innerHTML = panelHeader("Provider visibility", "Cloud Connections", "Provider status reflects records in the current CSPM dataset, not an authenticated cloud account connection.", "Data-derived") + `<div class="settings-cloud-list">${cloudConnections()}</div><div class="settings-note"><span aria-hidden="true">${icon("info")}</span><p>Cloud credential configuration and account connection actions are not available. No credentials are read or displayed here.</p></div>`;
    } else {
      panel.innerHTML = panelHeader("Browser preferences", "Advanced", "Reset the supported interface preferences stored by this application in this browser.", "Available") + `<div class="settings-reset-card"><span class="settings-reset-icon" aria-hidden="true">${icon("reset")}</span><div><h3>Reset preferences</h3><p>Restore the default theme, table page size, notification badge, and collapsed navigation state. CSPM data and findings are not affected.</p></div><button id="openResetDialog" class="btn btn-outline" type="button"><span data-cspm-icon="reset" aria-hidden="true">${icon("reset")}</span> Reset Preferences</button></div><div class="settings-note"><span aria-hidden="true">${icon("info")}</span><p>Only the cspm-settings preference key and its legacy theme/navigation preferences are cleared. Scanner data, findings, and source files are untouched.</p></div>`;
    }
    $("settingsContent").setAttribute("aria-busy", "false");
  }
  function selectSection(id, updateHash = true) {
    if (!categories.some((category) => category.id === id)) id = "general";
    selected = id;
    renderNavigation(); renderPanel();
    if (updateHash && location.hash !== `#${id}`) history.replaceState(null, "", `#${id}`);
  }
  function init() {
    selected = location.hash.slice(1) || "general";
    renderNavigation(); renderPanel();
    $("settingsNav").addEventListener("click", (event) => { const button = event.target.closest("[data-settings-section]"); if (button) selectSection(button.dataset.settingsSection); });
    $("settingsMobileNav").addEventListener("change", (event) => selectSection(event.target.value));
    $("settingsPanel").addEventListener("click", (event) => {
      const themeButton = event.target.closest("[data-setting-theme]");
      if (themeButton) {
        const theme = themeButton.dataset.settingTheme;
        if (!["light", "dark", "system"].includes(theme)) return;
        persist({ theme }); window.CSPMSettings?.applyCSPMTheme?.(theme); renderPanel(); return;
      }
      const sizeButton = event.target.closest("[data-setting-page-size]");
      if (sizeButton) {
        const tablePageSize = Number(sizeButton.dataset.settingPageSize);
        if (![20, 50, 100].includes(tablePageSize)) return;
        persist({ tablePageSize }); renderPanel(); return;
      }
      if (event.target.closest("#settingsNotificationBadge")) {
        persist({ showNotificationBadge: event.target.closest("#settingsNotificationBadge").getAttribute("aria-checked") !== "true" });
        renderPanel(); return;
      }
      if (event.target.closest("#openResetDialog")) $("resetDialog").showModal();
    });
    $("settingsPanel").addEventListener("keydown", (event) => {
      if ((event.key === "Enter" || event.key === " ") && event.target.matches("[role='switch']")) { event.preventDefault(); event.target.click(); }
    });
    window.addEventListener("hashchange", () => selectSection(location.hash.slice(1), false));
    $("cancelReset").addEventListener("click", () => $("resetDialog").close());
    $("confirmReset").addEventListener("click", () => {
      const reset = window.CSPMSettings?.resetCSPMSettings?.() === true;
      settings = window.CSPMSettings?.getCSPMSettings?.() || { theme: "light", tablePageSize: 20, showNotificationBadge: true };
      $("resetDialog").close(); selectSection("advanced");
      setSaveState(reset ? "Preferences reset" : "Could not reset preferences", !reset);
    });
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init, { once: true }); else init();
})();
