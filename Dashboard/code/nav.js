// Shared CSPM navigation and inline SVG icon registry.
(function () {
  const icon = (path) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${path}</svg>`;

  const icons = {
    dashboard: icon('<rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/>'),
    executive: icon('<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M8 13h8M8 17h8"/>'),
    findings: icon('<path d="m10.3 3.9-8.6 14.9A2 2 0 0 0 3.4 22h17.1a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/><path d="M12 9v4M12 17h.01"/>'),
    inventory: icon('<rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>'),
    compliance: icon('<path d="M22 11.1V12a10 10 0 1 1-5.9-9.1"/><path d="m9 11 3 3L22 4"/>'),
    cloudSecurity: icon('<path d="M17.5 19H9a7 7 0 1 1 6.7-9h1.8a4.5 4.5 0 1 1 0 9Z"/>'),
    policies: icon('<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M8 13h8M8 17h8"/>'),
    reports: icon('<path d="M4 19V5M4 19h17"/><path d="m7 15 4-4 3 2 6-7"/>'),
    alerts: icon('<path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9M10 21h4"/>'),
    settings: icon('<circle cx="12" cy="12" r="3"/><path d="m19.4 15 .1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5v.2a2 2 0 1 1-4 0V19a1.7 1.7 0 0 0-1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3.8a2 2 0 1 1 0-4H4a1.7 1.7 0 0 0 1.5-1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3 1.7 1.7 0 0 0 1-1.5V3.2a2 2 0 1 1 4 0V4a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8 1.7 1.7 0 0 0 1.5 1h.2a2 2 0 1 1 0 4H21a1.7 1.7 0 0 0-1.6 1.2Z"/>'),
    iam: icon('<circle cx="12" cy="8" r="4"/><path d="M5 21v-2a7 7 0 0 1 14 0v2"/>'),
    network: icon('<circle cx="5" cy="12" r="2"/><circle cx="19" cy="5" r="2"/><circle cx="19" cy="19" r="2"/><path d="m7 11 10-5M7 13l10 5"/>'),
    data: icon('<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>'),
    ai: icon('<path d="m12 3 1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8L12 3ZM19 16l.9 2.1L22 19l-2.1.9L19 22l-.9-2.1L16 19l2.1-.9L19 16Z"/>'),
    total: icon('<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/><path d="M8 9h8M8 12h8M8 15h5"/>'),
    critical: icon('<circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/>'),
    high: icon('<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/><path d="M12 8v4M12 16h.01"/>'),
    resources: icon('<rect x="2" y="3" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><path d="M6 7h.01M6 18h.01"/>'),
    compliance: icon('<path d="M22 11.1V12a10 10 0 1 1-5.9-9.1"/><path d="m9 11 3 3L22 4"/>'),
    complianceBadge: icon('<path d="M22 11.1V12a10 10 0 1 1-5.9-9.1"/><path d="m9 11 3 3L22 4"/>'),
    cloud: icon('<path d="M17.5 19H9a7 7 0 1 1 6.7-9h1.8a4.5 4.5 0 1 1 0 9Z"/>'),
    activity: icon('<circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/>'),
    info: icon('<circle cx="12" cy="12" r="10"/><path d="M12 11v5M12 8h.01"/>'),
    chevronDown: icon('<path d="m6 9 6 6 6-6"/>'),
    moon: icon('<path d="M20.9 13A8.5 8.5 0 0 1 11 3.1 8.5 8.5 0 1 0 20.9 13Z"/>'),
    sun: icon('<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4m11.4 11.4 1.4 1.4M2 12h2m16 0h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>'),
    reset: icon('<path d="M3 12a9 9 0 1 0 2.6-6.4L3 8"/><path d="M3 3v5h5"/>'),
    upload: icon('<path d="M12 16V4m-5 5 5-5 5 5"/><path d="M4 16v4h16v-4"/>'),
    search: icon('<circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/>'),
    filter: icon('<path d="M4 5h16l-6.5 7.5V19l-3 1v-7.5L4 5Z"/>'),
    export: icon('<path d="M12 3v12m-5-5 5 5 5-5"/><path d="M5 16v4h14v-4"/>'),
    copy: icon('<rect x="8" y="8" width="13" height="13" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/>'),
    sort: icon('<path d="m8 9 4-4 4 4M16 15l-4 4-4-4"/><path d="M12 5v14"/>'),
    sortAsc: icon('<path d="m8 12 4-4 4 4M12 8v11"/>'),
    sortDesc: icon('<path d="m8 12 4 4 4-4M12 5v11"/>'),
    previous: icon('<path d="m15 18-6-6 6-6"/>'),
    next: icon('<path d="m9 18 6-6-6-6"/>'),
    menu: icon('<path d="M4 6h16M4 12h16M4 18h16"/>'),
    close: icon('<path d="m18 6-12 12M6 6l12 12"/>'),
    refresh: icon('<path d="M20 7v5h-5"/><path d="M20 12a8 8 0 1 1-2.3-5.7L20 9"/>'),
    calendar: icon('<rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4M8 2v4M3 10h18"/>'),
    help: icon('<circle cx="12" cy="12" r="10"/><path d="M9.1 9a3 3 0 0 1 5.8 1c0 2-3 3-3 3M12 17h.01"/>'),
    notifications: icon('<path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9M10 21h4"/>'),
    brandMark: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/><path d="m9 12 2 2 4-4"/></svg>',
    // Local provider marks: AWS wordmark/smile, Azure A, and segmented GCP cloud.
    aws: '<svg viewBox="0 0 36 24" aria-hidden="true"><text x="2" y="15" fill="currentColor" font-family="Arial,sans-serif" font-size="13" font-weight="700" letter-spacing="-.5">aws</text><path d="M5 19c7 4 17 4 25-1" fill="none" stroke="#F8991D" stroke-width="1.7" stroke-linecap="round"/><path d="m27 16 3 2-3 2" fill="none" stroke="#F8991D" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    azure: '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M13.1 2.7 5.2 21h4.4l5.2-12 2.6 6.2H13l-1.7 3.8H21L13.1 2.7Z"/></svg>',
    gcp: '<svg viewBox="0 0 24 24" fill="none" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M7 18.5h10a4.5 4.5 0 0 0 .4-9A6 6 0 0 0 6 8.3a5.2 5.2 0 0 0 1 10.2Z" stroke="#4285F4" stroke-width="3.2"/><path d="M6.6 9.3a6 6 0 0 1 7.1-4.7" stroke="#EA4335" stroke-width="3.2"/><path d="M6 8.3a5.3 5.3 0 0 0-1.1 8" stroke="#34A853" stroke-width="3.2"/><path d="M5.4 16.3a5 5 0 0 0 1.6 1.9" stroke="#FBBC04" stroke-width="3.2"/></svg>'
  };

  window.CSPM_ICONS = Object.freeze(icons);

  // Shared, validated browser preferences. Keep the legacy theme key in sync
  // while existing pages migrate to the single namespaced settings object.
  const SETTINGS_KEY = 'cspm-settings';
  const VALID_THEMES = ['light', 'dark', 'system'];
  const VALID_PAGE_SIZES = [20, 50, 100];
  function getCSPMSettings() {
    let stored = {};
    try {
      const parsed = JSON.parse(localStorage.getItem(SETTINGS_KEY) || '{}');
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) stored = parsed;
    } catch (_) {}
    let legacyTheme = 'light';
    try { legacyTheme = localStorage.getItem('cspm-theme') || 'light'; } catch (_) {}
    return {
      theme: VALID_THEMES.includes(stored.theme) ? stored.theme : VALID_THEMES.includes(legacyTheme) ? legacyTheme : 'light',
      tablePageSize: VALID_PAGE_SIZES.includes(Number(stored.tablePageSize)) ? Number(stored.tablePageSize) : 20,
      showNotificationBadge: typeof stored.showNotificationBadge === 'boolean' ? stored.showNotificationBadge : true,
    };
  }
  function saveCSPMSettings(changes) {
    if (!changes || typeof changes !== 'object' || Array.isArray(changes)) return false;
    const current = getCSPMSettings();
    if (Object.hasOwn(changes, 'theme') && VALID_THEMES.includes(changes.theme)) current.theme = changes.theme;
    if (Object.hasOwn(changes, 'tablePageSize') && VALID_PAGE_SIZES.includes(Number(changes.tablePageSize))) current.tablePageSize = Number(changes.tablePageSize);
    if (Object.hasOwn(changes, 'showNotificationBadge') && typeof changes.showNotificationBadge === 'boolean') current.showNotificationBadge = changes.showNotificationBadge;
    try {
      localStorage.setItem(SETTINGS_KEY, JSON.stringify(current));
      if (Object.hasOwn(changes, 'theme') && VALID_THEMES.includes(changes.theme)) localStorage.setItem('cspm-theme', current.theme);
      return true;
    } catch (_) { return false; }
  }
  let systemThemeListenerInstalled = false;
  function applyCSPMTheme(mode) {
    const theme = VALID_THEMES.includes(mode) ? mode : getCSPMSettings().theme;
    const media = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;
    const dark = theme === 'dark' || (theme === 'system' && Boolean(media?.matches));
    document.body.classList.toggle('dark-mode', dark);
    document.documentElement.dataset.cspmTheme = theme;
    document.documentElement.style.colorScheme = dark ? 'dark' : 'light';
    document.querySelectorAll('#themeToggle').forEach((button) => {
      button.innerHTML = (dark ? icons.sun : icons.moon) + `<span>${dark ? 'Light' : 'Dark'}</span>`;
      button.setAttribute('aria-label', `Current theme ${theme}; toggle light and dark appearance`);
    });
    if (!systemThemeListenerInstalled && media) {
      const listener = () => { if (getCSPMSettings().theme === 'system') applyCSPMTheme('system'); };
      if (media.addEventListener) media.addEventListener('change', listener);
      else if (media.addListener) media.addListener(listener);
      systemThemeListenerInstalled = true;
    }
    return theme;
  }
  function resetCSPMSettings() {
    try {
      localStorage.removeItem(SETTINGS_KEY);
      localStorage.removeItem('cspm-theme');
      localStorage.removeItem('cspm-nav-domains');
    } catch (_) { return false; }
    const domainsButton = document.querySelector('#navGroupDomains .nav-group-header');
    const domainsChildren = document.getElementById('domainsSubnav');
    if (domainsButton && domainsChildren) {
      domainsButton.setAttribute('aria-expanded', 'false');
      domainsChildren.setAttribute('aria-hidden', 'true');
      domainsChildren.inert = true;
      domainsChildren.classList.remove('expanded');
    }
    applyCSPMTheme('light');
    return true;
  }
  window.CSPMSettings = Object.freeze({ getCSPMSettings, saveCSPMSettings, resetCSPMSettings, applyCSPMTheme });

  const comingSoon = (name, iconName) => `
    <div class="nav-item nav-soon" aria-disabled="true" title="${name} - coming soon">
      <span class="nav-label">${icons[iconName]} ${name}</span><span class="soon-badge">Soon</span>
    </div>`;

  const sidebarMarkup = `
    <a href="index.html" class="sidebar-header" aria-label="IMCSPM Dashboard home">
      <img class="brand-logo" src="../assets/IMCSPM%20Tech%20Brand%20Board.png" alt="IMCSPM - Intelligent Multi-Cloud Security Posture Management" />
    </a>
    <nav class="sidebar-nav" id="sidebarNav" aria-label="Primary navigation">
      <div class="nav-section-label">Overview</div>
      <a href="index.html" class="nav-item nav-link" data-path="index.html"><span class="nav-label">${icons.dashboard} Dashboard</span></a>
      <a href="executive-summary.html" class="nav-item nav-link" data-path="executive-summary.html"><span class="nav-label">${icons.executive} Executive Summary</span></a>
      <div class="nav-divider" role="separator"></div>
      <div class="nav-section-label">Security</div>
      <a href="findings.html" class="nav-item nav-link" data-path="findings.html"><span class="nav-label">${icons.findings} Findings</span></a>
      <a href="inventory.html" class="nav-item nav-link" data-path="inventory.html"><span class="nav-label">${icons.inventory} Inventory</span></a>
      <a href="compliance.html" class="nav-item nav-link" data-path="compliance.html"><span class="nav-label">${icons.compliance} Compliance</span></a>
      <a href="cloud-security.html" class="nav-item nav-link" data-path="cloud-security.html"><span class="nav-label">${icons.cloudSecurity} Cloud Security</span></a>
      <a href="policies.html" class="nav-item nav-link" data-path="policies.html"><span class="nav-label">${icons.policies} Policies</span></a>
      <a href="reports.html" class="nav-item nav-link" data-path="reports.html"><span class="nav-label">${icons.reports} Reports</span></a>
      <a href="alerts.html" class="nav-item nav-link" data-path="alerts.html"><span class="nav-label">${icons.alerts} Alerts</span></a>
      <div class="nav-divider" role="separator"></div>
      <div class="nav-group" id="navGroupDomains">
        <button class="nav-group-header" type="button" aria-expanded="false" aria-controls="domainsSubnav">
          <span class="nav-label">Security Domains</span><span class="nav-group-icon">${icons.chevronDown}</span>
        </button>
        <div class="nav-group-children" id="domainsSubnav">
          <a href="iam.html" class="nav-item nav-link nav-child" data-path="iam.html"><span class="nav-label">${icons.iam} IAM Security</span></a>
          <a href="network.html" class="nav-item nav-link nav-child" data-path="network.html"><span class="nav-label">${icons.network} Network Security</span></a>
          <a href="data.html" class="nav-item nav-link nav-child" data-path="data.html"><span class="nav-label">${icons.data} Data &amp; Compliance</span></a>
          <a href="ai.html" class="nav-item nav-link nav-child" data-path="ai.html"><span class="nav-label">${icons.ai} AI Intelligence</span></a>
        </div>
      </div>
      <div class="nav-divider" role="separator"></div>
      <div class="nav-section-label">System</div>
      <a href="settings.html" class="nav-item nav-link" data-path="settings.html"><span class="nav-label">${icons.settings} Settings</span></a>
    </nav>
    <div class="sidebar-footer">
      <div class="sidebar-user" aria-label="Admin User, Security Ops">
        <div class="user-avatar">${icons.iam}</div>
        <div class="user-info"><div class="user-name">Admin User</div><div class="user-role">Security Ops</div></div>
      </div>
    </div>`;

  function renderNavigation() {
    const sidebar = document.getElementById('appSidebar');
    if (!sidebar || sidebar.dataset.ready) return;
    sidebar.dataset.ready = 'true';
    sidebar.innerHTML = sidebarMarkup;
    document.querySelectorAll('[data-cspm-icon]').forEach((target) => {
      const svg = icons[target.dataset.cspmIcon];
      if (svg) target.innerHTML = svg;
    });
    sidebar.inert = window.innerWidth <= 768;

    const topbar = document.querySelector('.topbar');
    let menuButton = document.getElementById('mobileNavToggle');
    if (!menuButton && topbar) {
      menuButton = document.createElement('button');
      menuButton.id = 'mobileNavToggle';
      menuButton.className = 'mobile-nav-toggle';
      menuButton.type = 'button';
      menuButton.setAttribute('aria-label', 'Open navigation');
      menuButton.setAttribute('aria-controls', 'appSidebar');
      menuButton.setAttribute('aria-expanded', 'false');
      menuButton.innerHTML = icons.menu;
      topbar.insertBefore(menuButton, topbar.firstChild);
    }

    let scrim = document.getElementById('sidebarScrim');
    if (!scrim) {
      scrim = document.createElement('button');
      scrim.id = 'sidebarScrim';
      scrim.className = 'sidebar-scrim';
      scrim.type = 'button';
      scrim.setAttribute('aria-label', 'Close navigation');
      scrim.tabIndex = -1;
      sidebar.insertAdjacentElement('afterend', scrim);
    }

    const currentPath = window.location.pathname.split('/').pop() || 'index.html';
    let activeChild = false;
    sidebar.querySelectorAll('a.nav-link[data-path]').forEach((link) => {
      if (link.dataset.path === currentPath) {
        link.classList.add('nav-current');
        link.setAttribute('aria-current', 'page');
        activeChild = link.classList.contains('nav-child');
      }
    });

    const groupButton = sidebar.querySelector('.nav-group-header');
    const groupChildren = sidebar.querySelector('#domainsSubnav');
    let expanded = false;
    try { expanded = localStorage.getItem('cspm-nav-domains') === 'true'; } catch (_) {}
    if (activeChild) expanded = true;

    const setExpanded = (value, persist = true) => {
      groupButton.setAttribute('aria-expanded', String(value));
      groupChildren.setAttribute('aria-hidden', String(!value));
      groupChildren.inert = !value;
      groupChildren.classList.toggle('expanded', value);
      if (persist) {
        try { localStorage.setItem('cspm-nav-domains', String(value)); } catch (_) {}
      }
    };
    setExpanded(expanded, activeChild || expanded);
    groupButton.addEventListener('click', () => setExpanded(groupButton.getAttribute('aria-expanded') !== 'true'));

    const closeDrawer = (restoreFocus = false) => {
      document.body.classList.remove('mobile-nav-open');
      sidebar.classList.remove('is-open');
      if (window.innerWidth <= 768) sidebar.inert = true;
      if (menuButton) {
        menuButton.setAttribute('aria-expanded', 'false');
        menuButton.setAttribute('aria-label', 'Open navigation');
        menuButton.innerHTML = icons.menu;
        if (restoreFocus) menuButton.focus();
      }
    };
    if (menuButton) {
      menuButton.addEventListener('click', () => {
        const open = !sidebar.classList.contains('is-open');
        sidebar.classList.toggle('is-open', open);
        sidebar.inert = !open;
        document.body.classList.toggle('mobile-nav-open', open);
        menuButton.setAttribute('aria-expanded', String(open));
        menuButton.setAttribute('aria-label', open ? 'Close navigation' : 'Open navigation');
        menuButton.innerHTML = open ? icons.close : icons.menu;
        if (open) sidebar.querySelector('a.nav-current')?.focus();
      });
    }
    scrim.addEventListener('click', () => closeDrawer(true));
    sidebar.querySelectorAll('a.nav-link').forEach((link) => link.addEventListener('click', () => closeDrawer()));
    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape' && sidebar.classList.contains('is-open')) closeDrawer(true);
      if (event.key === 'Tab' && sidebar.classList.contains('is-open') && window.innerWidth <= 768) {
        const focusable = Array.from(sidebar.querySelectorAll('a[href], button:not(:disabled)')).filter((node) => !node.closest('[inert]'));
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
      }
    });
    window.addEventListener('resize', () => {
      if (window.innerWidth > 768) { sidebar.inert = false; closeDrawer(); }
      else if (!sidebar.classList.contains('is-open')) sidebar.inert = true;
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', renderNavigation, { once: true });
  } else {
    renderNavigation();
  }
})();
