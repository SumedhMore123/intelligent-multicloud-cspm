// ============================================================
// IAM SECURITY PAGE
// Vanilla JavaScript
// No React
// No npm
// No build step
// ============================================================


const SEVERITY_META = {

  CRITICAL: { label: "Critical", color: "#B8323C", bg: "#FCEBED" },

  HIGH: {
    label: "High",
    color: "#C7402F",
    bg: "#FBEAE7"
  },

  MEDIUM: {
    label: "Medium",
    color: "#B4791B",
    bg: "#FBF1E1"
  },

  LOW: { label: "Low", color: "#3376B8", bg: "#EAF2FB" },

  INFO: {
    label: "Info",
    color: "#5B6472",
    bg: "#EEF0F3"
  },

  PASS: {
    label: "Pass",
    color: "#2E8B57",
    bg: "#E7F4EC"
  }

};


const PAGE_SIZE = 8;



// ============================================================
// STATE
// ============================================================

let state = {

  findings: Array.isArray(window.CSPM_LIVE_IAM_META?.findings)
    ? window.CSPM_LIVE_IAM_META.findings
    : SAMPLE_FINDINGS,

  sourceLabel: window.CSPM_LIVE_IAM_META ? "Live IAM scan" : "Sample scan data",

  search: "",

  severityFilter: "ALL",

  categoryFilter: "",

  resourceFilter: "ALL",

  statusFilter: "ALL",

  sortKey: "risk_score",

  sortDir: "desc",

  page: 1,

  selectedFinding: null,

  returnFocus: null

};



// ============================================================
// HELPERS
// ============================================================

function evidenceText(ev) {

  if (typeof ev === "string") {
    return ev;
  }

  try {
    return JSON.stringify(ev);
  }

  catch {
    return String(ev);
  }

}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>\"']/g, char => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;"
  })[char]);
}

function normalizedSeverity(finding) {
  const raw = typeof finding === "string" ? finding : finding?.severity;
  const shared = window.CSPMShared?.normalizeSeverity?.(raw);
  const value = String(shared || raw || "INFO").trim().toUpperCase();
  return Object.hasOwn(SEVERITY_META, value) ? value : "INFO";
}

function normalizedStatus(finding) {
  const raw = typeof finding === "string" ? finding : finding?.status;
  const shared = window.CSPMShared?.normalizeStatus?.(raw);
  return String(shared || raw || "INFO").trim().toUpperCase();
}

function isIAMRiskFinding(finding) {
  if (typeof window.CSPMShared?.isRiskFinding === "function") return window.CSPMShared.isRiskFinding(finding);
  return !["INFO", "PASS"].includes(normalizedSeverity(finding));
}

function isIAMOpenFinding(finding) {
  if (typeof window.CSPMShared?.isOpenFinding === "function") return window.CSPMShared.isOpenFinding(finding);
  return normalizedStatus(finding) === "OPEN";
}

function normalizedCloud(finding) {
  return window.CSPMShared?.normalizeCloud?.(finding?.cloud) || String(finding?.cloud || "Not recorded");
}

function normalizedDomain(finding) {
  return window.CSPMShared?.normalizeDomain?.(finding) || String(finding?.domain || finding?.category || "Not recorded");
}

function uniqueResources(findings) {
  return new Set(findings
    .filter(f => f && String(f.resource_type || "").trim() && String(f.resource_id || "").trim())
    .map(f => JSON.stringify([f.resource_type, f.resource_id])));
}

function matchingText(finding) {
  return `${finding?.finding || ""} ${finding?.evidence || ""} ${finding?.category || ""} ${finding?.finding_id || ""}`.toLowerCase();
}

function subsetMetrics(records) {
  return {
    count: records.length,
    open: records.filter(isIAMOpenFinding).length,
    resources: uniqueResources(records).size,
    highest: records.map(normalizedSeverity).sort((a, b) =>
      ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "PASS"].indexOf(a) - ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "PASS"].indexOf(b)
    )[0] || "—"
  };
}



function riskBand(score) {

  score = Number(score || 0);


  if (score >= 15) {

    return {
      label: "Severe",
      color: "#C7402F"
    };

  }


  if (score >= 7) {

    return {
      label: "Elevated",
      color: "#B4791B"
    };

  }


  if (score > 0) {

    return {
      label: "Low",
      color: "#2E8B57"
    };

  }


  return {
    label: "—",
    color: "#94A3B8"
  };

}



function fmtDate(iso) {

  try {

    const timestamp = Date.parse(iso || "");
    if (!Number.isFinite(timestamp)) return "Not recorded";

    return new Date(timestamp).toLocaleString(
      undefined,
      {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit"
      }
    );

  }

  catch {

    return iso;

  }

}



// ============================================================
// STATISTICS
// ============================================================

function computeStats(findings) {

  const total = findings.length;


  const open = findings.filter(isIAMOpenFinding).length;


  const high = findings.filter(
    f =>
      normalizedSeverity(f) === "HIGH" &&
      isIAMOpenFinding(f)
  ).length;


  const resources = uniqueResources(findings).size;


  const top = findings.reduce(
    (acc, f) => {

      const currentScore = Number(f.risk_score || 0);

      const previousScore =
        Number(acc?.risk_score ?? -1);


      return currentScore > previousScore
        ? f
        : acc;

    },
    null
  );


  return {
    total,
    open,
    high,
    resources,
    top
  };

}



function computeSeverityCounts(findings) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  findings.forEach(f => {
    const severity = normalizedSeverity(f);
    if (Object.hasOwn(counts, severity)) counts[severity] += 1;
  });
  return counts;
}



function computeRuleFrequency(findings) {

  const openFindings =
    findings.filter(isIAMOpenFinding);


  const counts = {};
  const resources = {};


  openFindings.forEach(f => {

    counts[f.finding_id] = (counts[f.finding_id] || 0) + 1;
    if (!resources[f.finding_id]) resources[f.finding_id] = new Set();
    if (f.resource_id) resources[f.finding_id].add(JSON.stringify([f.resource_type, f.resource_id]));

  });


  return Object.entries(counts)

    .map(([id, count]) => {

      const matching =
        openFindings.find(
          f => f.finding_id === id
        );


      return {

        id,

        count,

        finding: matching?.finding || "",
        resources: resources[id]?.size || 0

      };

    })

    .sort(
      (a, b) => b.count - a.count
    )

    .slice(0, 6);

}



function computeResourceTypeData(findings) {
  const resources = new Map();
  findings.filter(f => isIAMOpenFinding(f) && isIAMRiskFinding(f))
    .forEach(f => {
      const type = String(f.resource_type || "Unknown resource");
      if (!resources.has(type)) resources.set(type, new Set());
      if (f.resource_id) resources.get(type).add(JSON.stringify([type, f.resource_id]));
    });
  return [...resources.entries()].map(([name, values]) => ({ name, value: values.size }))
    .sort((a, b) => b.value - a.value || a.name.localeCompare(b.name));
}



function computeTopRisk(findings) {

  return [...findings]

    .filter(
      f => Number(f.risk_score || 0) > 0
    )

    .sort(
      (a, b) =>
        Number(b.risk_score || 0) -
        Number(a.risk_score || 0)
    )

    .slice(0, 5);

}



// ============================================================
// FILTER + SORT
// ============================================================

function applyFiltersAndSort() {

  let rows =
    state.findings.filter(f => {


      if (
        state.severityFilter !== "ALL" &&
        normalizedSeverity(f) !== state.severityFilter
      ) {

        return false;

      }



      if (
        state.resourceFilter !== "ALL" &&
        f.resource_type !== state.resourceFilter
      ) {

        return false;

      }



      if (
        state.statusFilter !== "ALL" &&
        normalizedStatus(f) !== state.statusFilter
      ) {

        return false;

      }



      if (state.search) {

        const q =
          state.search.toLowerCase();


        const hay =

          `${f.resource_id} ` +
          `${f.finding} ` +
          `${f.finding_id} ` +
          `${f.evidence} ` +
          `${f.resource_type} ` +
          `${f.category}`;

        if (
          !hay
            .toLowerCase()
            .includes(q)
        ) {

          return false;

        }

      }

      if (state.categoryFilter) {
        const text = matchingText(f);
        const tests = {
          mfa: /\bmfa\b|multi.factor/,
          keys: /access.key|credential|root key/,
          root: /root account|root user/,
          roles: /\brole\b/,
          policies: /policy|permission/,
          trust: /trust|external account/,
          privilege: /wildcard|excessive|administrator|admin privilege|overly broad|broad permission/
        };
        if (!tests[state.categoryFilter]?.test(text)) return false;
      }


      return true;

    });



  rows.sort((a, b) => {

    let av = a[state.sortKey];

    let bv = b[state.sortKey];


    if (state.sortKey === "detected_at") {

      av =
        new Date(av).getTime();

      bv =
        new Date(bv).getTime();

    }


    if (state.sortKey === "risk_score") {

      av = Number(av || 0);

      bv = Number(bv || 0);

    }

    if (state.sortKey === "severity") {
      const rank = { CRITICAL: 6, HIGH: 5, MEDIUM: 4, LOW: 3, INFO: 2, PASS: 1 };
      av = rank[normalizedSeverity(a)] || 0;
      bv = rank[normalizedSeverity(b)] || 0;
    }

    if (state.sortKey === "finding_id") {
      av = String(av || "").toLowerCase();
      bv = String(bv || "").toLowerCase();
    }

    if (state.sortKey === "detected_at") {
      av = Number.isFinite(av) ? av : -Infinity;
      bv = Number.isFinite(bv) ? bv : -Infinity;
    }


    if (av === undefined) {
      av = 0;
    }


    if (bv === undefined) {
      bv = 0;
    }


    if (av < bv) {

      return state.sortDir === "asc"
        ? -1
        : 1;

    }


    if (av > bv) {

      return state.sortDir === "asc"
        ? 1
        : -1;

    }


    return 0;

  });


  return rows;

}



// ============================================================
// THEME
// ============================================================

function updateThemeButton() {

  const button =
    document.getElementById(
      "themeToggle"
    );


  if (!button) {
    return;
  }


  const dark =
    document.body.classList.contains(
      "dark-mode"
    );


  const icons = window.CSPM_ICONS;
  button.innerHTML = (dark ? icons.sun : icons.moon) + "<span>" + (dark ? "Light" : "Dark") + "</span>";

}



function loadTheme() {
  if (window.CSPMSettings) window.CSPMSettings.applyCSPMTheme(window.CSPMSettings.getCSPMSettings().theme);
  else if (localStorage.getItem("cspm-theme") === "dark") document.body.classList.add("dark-mode");
  updateThemeButton();

}



function toggleTheme() {
  const dark = document.body.classList.contains("dark-mode");
  const theme = dark ? "light" : "dark";
  if (window.CSPMSettings) {
    window.CSPMSettings.saveCSPMSettings({ theme });
    window.CSPMSettings.applyCSPMTheme(theme);
  } else {
    document.body.classList.toggle("dark-mode");
    localStorage.setItem("cspm-theme", theme);
  }
  updateThemeButton();

}



// ============================================================
// SEARCH
// ============================================================

document
  .getElementById("searchInput")
  .addEventListener(
    "input",
    event => {

      state.search =
        event.target.value;

      state.categoryFilter = "";

      state.page = 1;

      renderTable();

    }
  );



// ============================================================
// FILTERS
// ============================================================

document
  .getElementById("severityFilter")
  .addEventListener(
    "change",
    event => {

      state.severityFilter =
        event.target.value;

      state.categoryFilter = "";

      state.page = 1;

      renderTable();

    }
  );



document
  .getElementById("resourceFilter")
  .addEventListener(
    "change",
    event => {

      state.resourceFilter =
        event.target.value;

      state.categoryFilter = "";

      state.page = 1;

      renderTable();

    }
  );



document
  .getElementById("statusFilter")
  .addEventListener(
    "change",
    event => {

      state.statusFilter =
        event.target.value;

      state.categoryFilter = "";

      state.page = 1;

      renderTable();

    }
  );



// ============================================================
// SORTING
// ============================================================

document
  .querySelectorAll(
    "th[data-sort]"
  )
  .forEach(th => {

    th.addEventListener(
      "click",
      () => {

        const key =
          th.dataset.sort;


        if (
          state.sortKey === key
        ) {

          state.sortDir =
            state.sortDir === "asc"
              ? "desc"
              : "asc";

        }

        else {

          state.sortKey = key;

          state.sortDir = "desc";

        }


        state.page = 1;

        renderTable();

      }
    );

  });



// ============================================================
// PAGINATION
// ============================================================

document
  .getElementById("prevPage")
  .addEventListener(
    "click",
    () => {

      state.page =
        Math.max(
          1,
          state.page - 1
        );

      renderTable();

    }
  );



document
  .getElementById("nextPage")
  .addEventListener(
    "click",
    () => {

      const total =
        applyFiltersAndSort()
          .length;


      const totalPages =
        Math.max(
          1,
          Math.ceil(
            total / PAGE_SIZE
          )
        );


      state.page =
        Math.min(
          totalPages,
          state.page + 1
        );


      renderTable();

    }
  );



// ============================================================
// RESET
// ============================================================

document
  .getElementById("resetBtn")
  .addEventListener(
    "click",
    () => {

      state.findings =
        SAMPLE_FINDINGS;

      state.sourceLabel =
        "Sample scan data";

      state.search = "";

      state.categoryFilter = "";

      state.severityFilter =
        "ALL";

      state.resourceFilter =
        "ALL";

      state.statusFilter =
        "ALL";

      closeIAMFinding(false);

      state.sortKey =
        "risk_score";

      state.sortDir =
        "desc";

      state.page = 1;


      document.getElementById(
        "searchInput"
      ).value = "";


      document.getElementById(
        "severityFilter"
      ).value = "ALL";


      document.getElementById(
        "statusFilter"
      ).value = "ALL";

      document.getElementById("resourceFilter").value = "ALL";


      hideUploadError();

      renderAll();

    }
  );



// ============================================================
// UPLOAD
// ============================================================

document
  .getElementById("uploadBtn")
  .addEventListener(
    "click",
    () => {

      document
        .getElementById("fileInput")
        .click();

    }
  );



document
  .getElementById("fileInput")
  .addEventListener(
    "change",
    event => {

      const file =
        event.target.files[0];


      if (!file) {
        return;
      }

      hideUploadError();


      const reader =
        new FileReader();

      document.getElementById("sourceLabel").querySelector("span").textContent = "Reading and validating scan...";
      document.getElementById("uploadBtn").setAttribute("aria-busy", "true");


      reader.onload =
        function(evt) {

          try {

            const parsed =
              JSON.parse(
                evt.target.result
              );


            const arr = Array.isArray(parsed) ? parsed : Array.isArray(parsed?.findings) ? parsed.findings : [parsed];
            if (!arr.length) throw new Error("The JSON contains no findings.");
            const validSeverities = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "PASS"]);
            const validStatuses = new Set(["OPEN", "PASS", "INFO", "RESOLVED"]);
            for (let index = 0; index < arr.length; index += 1) {
              const finding = arr[index];
              const row = index + 1;
              if (!finding || typeof finding !== "object" || Array.isArray(finding)) throw new Error(`Finding ${row} must be a JSON object.`);
              for (const field of ["finding_id", "resource_id", "resource_type", "finding"]) {
                if (typeof finding[field] !== "string" || !finding[field].trim()) throw new Error(`Finding ${row} is missing required text field "${field}".`);
              }
              if (!validSeverities.has(String(finding.severity || "").trim().toUpperCase())) throw new Error(`Finding ${row} has an unsupported or missing severity. Use CRITICAL, HIGH, MEDIUM, LOW, INFO, or PASS.`);
              if (!validStatuses.has(String(finding.status || "").trim().toUpperCase())) throw new Error(`Finding ${row} has an unsupported or missing status. Use OPEN, PASS, INFO, or RESOLVED.`);
              if (finding.risk_score != null && finding.risk_score !== "" && !Number.isFinite(Number(finding.risk_score))) throw new Error(`Finding ${row} has a risk_score that is not numeric.`);
            }


            state.findings =
              arr;

            closeIAMFinding(false);


            state.sourceLabel = `Imported scan · ${file.name}`;


            state.page = 1;


            hideUploadError();

            renderAll();

          }

          catch (error) {
            document.getElementById("sourceLabel").querySelector("span").textContent = state.sourceLabel;
            showUploadError(error instanceof Error ? error.message : "The selected JSON file could not be imported.");

          }

        };

      reader.onloadend = () => document.getElementById("uploadBtn").removeAttribute("aria-busy");
      reader.onerror = () => {
        document.getElementById("sourceLabel").querySelector("span").textContent = state.sourceLabel;
        showUploadError("The selected file could not be read.");
      };


      reader.readAsText(file);

      event.target.value = "";

    }
  );



// ============================================================
// ERROR
// ============================================================

function showUploadError(message) {

  const element =
    document.getElementById(
      "uploadError"
    );


  element.textContent =
    message;


  element.hidden = false;

}



function hideUploadError() {

  const element =
    document.getElementById(
      "uploadError"
    );


  element.hidden = true;

}

function setLiveScanStatus(message, isError) {
  const element = document.getElementById("iamScanStatus");
  if (!element) return;
  element.textContent = message;
  element.dataset.state = isError ? "error" : "ready";
}

function applyLiveIAMResult(payload) {
  if (!payload || payload.source !== "live-iam-scan" || !Array.isArray(payload.findings)) {
    throw new Error("The backend returned an invalid IAM scan result.");
  }
  try {
    window.localStorage.setItem("cspm-live-iam-scan", JSON.stringify(payload));
  } catch (error) {
    console.error("Unable to persist IAM scan in browser storage:", error);
  }
  window.CSPM_LIVE_IAM_META = payload;
  state.findings = payload.findings;
  state.sourceLabel = "Live IAM scan";
  state.page = 1;
  closeIAMFinding(false);
  renderAll();
}

async function refreshLiveIAMResult() {
  try {
    const response = await fetch("http://127.0.0.1:8765/api/iam/results", { cache: "no-store" });
    if (!response.ok) return;
    const payload = await response.json();
    if (payload.source === "live-iam-scan") applyLiveIAMResult(payload);
  } catch (error) {
    setLiveScanStatus("Backend unavailable. Start the local backend to run a live scan.", true);
  }
}

async function runLiveIAMScan() {
  const button = document.getElementById("runIamScanBtn");
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  setLiveScanStatus("IAM scan is running. Waiting for AWS results...");
  try {
    const response = await fetch("http://127.0.0.1:8765/api/iam/scans", { method: "POST" });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || "The IAM scan could not be started.");
    let status = payload.status;
    while (status && status.state === "RUNNING") {
      await new Promise(resolve => setTimeout(resolve, 500));
      const statusResponse = await fetch("http://127.0.0.1:8765/api/iam/status", { cache: "no-store" });
      const statusPayload = await statusResponse.json();
      status = statusPayload.status;
    }
    if (!status || status.state !== "SUCCEEDED") {
      throw new Error(status?.error || "The IAM scan failed. Previous results were preserved.");
    }
    const resultResponse = await fetch("http://127.0.0.1:8765/api/iam/results", { cache: "no-store" });
    const result = await resultResponse.json();
    applyLiveIAMResult(result);
    setLiveScanStatus(`Live IAM scan completed at ${fmtDate(result.completed_at)}. ${result.findings.length} findings recorded.`);
  } catch (error) {
    setLiveScanStatus(error instanceof Error ? error.message : "The IAM scan failed.", true);
  } finally {
    button.disabled = false;
    button.removeAttribute("aria-busy");
  }
}

// ============================================================
// IAM ANALYSIS PRESENTATION
// Keep the original scan data and rank calculation; the views below
// derive identity-specific summaries from the currently loaded records.
// ============================================================

function getIAMSignals() {
  const definitions = [
    ["mfa", "MFA", /\bmfa\b|multi.factor/],
    ["keys", "Access keys & credentials", /access.key|credential|root key/],
    ["root", "Root account", /root account|root user/],
    ["roles", "Roles", /\brole\b/],
    ["policies", "Policies & permissions", /policy|permission/],
    ["trust", "Trust policies", /trust|external account/]
  ];
  return definitions.map(([key, label, pattern]) => ({
    key, label, records: state.findings.filter(f => pattern.test(matchingText(f)))
  })).filter(item => item.records.length);
}

function getPrivilegeRecords() {
  const pattern = /wildcard|excessive|administrator|admin privilege|overly broad|broad permission/;
  return state.findings.filter(f => pattern.test(matchingText(f)));
}

function severityBadge(severity) {
  const value = normalizedSeverity({ severity });
  return `<span class="iam-severity iam-severity-${value.toLowerCase()}">${escapeHtml(SEVERITY_META[value].label)}</span>`;
}

function metricTile(label, value, iconName, note, tone) {
  const icon = window.CSPM_ICONS?.[iconName] || "";
  return `<article class="iam-kpi" data-tone="${tone || "blue"}"><span class="iam-kpi-icon" aria-hidden="true">${icon}</span><div class="iam-kpi-copy"><span class="iam-kpi-label">${escapeHtml(label)}</span><strong class="iam-kpi-value" aria-label="${escapeHtml(value)}">${escapeHtml(value)}</strong><span class="iam-kpi-note">${escapeHtml(note)}</span></div></article>`;
}

function animateIAMCounters() {
  const nodes = document.querySelectorAll(".iam-kpi-value");
  const reduceMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
  nodes.forEach(node => {
    const target = Number(node.textContent);
    if (!Number.isFinite(target)) return;
    if (reduceMotion || typeof window.requestAnimationFrame !== "function") {
      node.textContent = String(target);
      return;
    }
    const started = performance.now();
    const tick = now => {
      const progress = Math.min(1, (now - started) / 360);
      node.textContent = String(Math.round(target * (1 - Math.pow(1 - progress, 3))));
      if (progress < 1 && node.isConnected) window.requestAnimationFrame(tick);
      else node.textContent = String(target);
    };
    node.textContent = "0";
    window.requestAnimationFrame(tick);
  });
}

function renderKpis() {
  const findings = state.findings;
  const stats = computeStats(findings);
  const critical = findings.filter(f => normalizedSeverity(f) === "CRITICAL" && isIAMOpenFinding(f)).length;
  const mfa = findings.filter(f => /\bmfa\b|multi.factor/.test(matchingText(f)));
  document.getElementById("kpiRow").innerHTML = [
    metricTile("Total IAM findings", stats.total, "total", "All recorded IAM checks", "blue"),
    metricTile("Open findings", stats.open, "activity", "Current status is OPEN", stats.open ? "amber" : "green"),
    metricTile("High risk", stats.high, "high", "Open HIGH findings", stats.high ? "red" : "green"),
    metricTile("Critical risk", critical, "critical", "Open CRITICAL findings", critical ? "red" : "green"),
    metricTile("IAM resources", stats.resources, "resources", "Unique type and resource pairs", "indigo"),
    metricTile("MFA observations", mfa.length, "iam", "Recorded checks mentioning MFA", "indigo")
  ].join("");
  animateIAMCounters();

  const privilegeOpen = getPrivilegeRecords().filter(isIAMOpenFinding);
  const trustOpen = state.findings.filter(f => /trust|external account/.test(matchingText(f)) && isIAMOpenFinding(f));
  const phrases = [];
  if (privilegeOpen.length) phrases.push(`${privilegeOpen.length} open broad or excessive permission finding${privilegeOpen.length === 1 ? "" : "s"}`);
  if (trustOpen.length) phrases.push(`${trustOpen.length} open trust-related finding${trustOpen.length === 1 ? "" : "s"}`);
  const summary = phrases.length
    ? `Current scan observations include ${phrases.join(" and ")}. Counts describe recorded findings and do not establish active exploitation.`
    : stats.open
      ? `The current scan contains ${stats.open} open finding${stats.open === 1 ? "" : "s"}. Review the observed controls and their evidence below.`
      : "No open risk findings were recorded in the current scan. This does not establish complete identity coverage.";
  document.getElementById("iamSummary").textContent = summary;
  document.getElementById("iamHeroStatus").dataset.state = stats.open ? "review" : "clear";
  document.getElementById("iamPostureLabel").textContent = stats.open ? "Review required" : "No open risk findings recorded";
  document.getElementById("iamHeroOpen").textContent = String(stats.open);
  document.getElementById("iamHeroRisk").textContent = stats.top && Number.isFinite(Number(stats.top.risk_score)) ? String(stats.top.risk_score) : "Not recorded";
  document.getElementById("iamHeroScope").textContent = `${stats.resources} observed resources · ${findings.length} records`;
}

function renderIdentityPosture() {
  const signals = getIAMSignals();
  document.getElementById("identityPosture").innerHTML = signals.length ? signals.map(signal => {
    const metrics = subsetMetrics(signal.records);
    const severity = signal.records.map(normalizedSeverity).sort((a, b) => ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "PASS"].indexOf(a) - ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "PASS"].indexOf(b))[0];
    return `<button class="iam-signal-row" type="button" data-iam-category="${signal.key}" aria-label="Filter findings for ${escapeHtml(signal.label)}"><span class="iam-signal-main"><strong>${escapeHtml(signal.label)}</strong><small>${metrics.count} observed · ${metrics.open} open · ${metrics.resources} resources</small></span><span class="iam-signal-severity">${severityBadge(severity)}</span><span class="iam-signal-arrow" aria-hidden="true">→</span></button>`;
  }).join("") : `<p class="iam-empty-note">No identity control categories are represented in this scan.</p>`;
}

function renderExposure(targetId, records, kind) {
  const target = document.getElementById(targetId);
  if (!records.length) {
    target.innerHTML = `<p class="iam-empty-note">No ${kind === "privilege" ? "wildcard or excessive permission" : "trust-policy"} observations in this scan.</p>`;
    return;
  }
  const openRecords = records.filter(isIAMOpenFinding);
  const riskRecords = records.filter(isIAMRiskFinding);
  const resources = uniqueResources(openRecords).size;
  const highest = (riskRecords.length ? riskRecords : records).map(normalizedSeverity).sort((a, b) => ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "PASS"].indexOf(a) - ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "PASS"].indexOf(b))[0] || "—";
  target.innerHTML = `<div class="iam-exposure-stats"><div><strong>${openRecords.length}</strong><span>open findings</span></div><div><strong>${resources}</strong><span>affected resources</span></div><div><strong>${severityBadge(highest)}</strong><span>highest recorded severity</span></div></div><button type="button" class="iam-inline-filter" data-iam-category="${kind}">Review matching findings <span aria-hidden="true">→</span></button>`;
}

function renderCredentialPosture() {
  const findings = state.findings;
  const mfa = findings.filter(f => /\bmfa\b|multi.factor/.test(matchingText(f)));
  const keys = findings.filter(f => /access.key|credential|root key/.test(matchingText(f)));
  const root = findings.filter(f => /root account|root user/.test(matchingText(f)));
  const row = (title, records, key, caution = "") => {
    const metrics = subsetMetrics(records);
    return `<button class="iam-control-row" type="button" data-iam-category="${key}"><span><strong>${escapeHtml(title)}</strong><small>${metrics.count} observed · ${metrics.resources} resources observed</small>${caution ? `<em>${escapeHtml(caution)}</em>` : ""}</span><span class="iam-control-open">${metrics.open}<small>open</small></span></button>`;
  };
  const rows = [];
  if (mfa.length) rows.push(row("MFA checks", mfa, "mfa", "Coverage cannot be fully assessed from the current scan."));
  if (keys.length) rows.push(row("Access key & credential checks", keys, "keys"));
  if (root.length) rows.push(row("Root account checks", root, "root", "Observed root checks only; completeness is not established."));
  document.getElementById("credentialPosture").innerHTML = rows.length ? rows.join("") : `<p class="iam-empty-note">No MFA, key, credential, or root account observations in this scan.</p>`;
}

function renderDonut() {
  const counts = computeSeverityCounts(state.findings);
  const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  const total = order.reduce((sum, key) => sum + counts[key], 0);
  let angle = 0;
  const segments = order.filter(key => counts[key]).map(key => {
    const start = angle;
    angle += counts[key] / (total || 1) * 360;
    return `${SEVERITY_META[key].color} ${start}deg ${angle}deg`;
  });
  const donut = document.getElementById("donutChart");
  donut.style.background = total ? `conic-gradient(${segments.join(",")})` : "var(--border-soft)";
  donut.setAttribute("aria-label", `Risk severity distribution: ${order.map(key => `${key} ${counts[key]}`).join(", ")}`);
  document.getElementById("iamRiskTotal").textContent = String(total);
  document.getElementById("severityLegend").innerHTML = total ? order.map(key => {
    const percent = total ? Math.round(counts[key] / total * 100) : 0;
    return `<button type="button" class="iam-legend-row" data-severity="${key}" aria-label="Filter ${counts[key]} ${key} findings"><span class="iam-legend-name"><i class="iam-legend-dot iam-dot-${key.toLowerCase()}"></i>${SEVERITY_META[key].label}</span><strong>${counts[key]}</strong><small>${percent}%</small></button>`;
  }).join("") : `<p class="iam-empty-note">No CRITICAL, HIGH, MEDIUM, or LOW findings recorded.</p>`;
}

function renderResourceBarChart() {
  const data = computeResourceTypeData(state.findings);
  const max = Math.max(1, ...data.map(item => item.value));
  document.getElementById("resourceBarChart").innerHTML = data.length ? data.map(item => { const width = item.value / max * 100; return `<button type="button" class="iam-resource-row" data-resource-type="${escapeHtml(item.name)}"><span class="iam-resource-label">${escapeHtml(item.name)}</span><span class="iam-bar-track"><i style="--iam-bar-width:${width}%;width:${width}%"></i></span><strong>${item.value}</strong></button>`; }).join("") : `<p class="iam-empty-note">No open risk findings are associated with IAM resources.</p>`;
}

function renderRuleFrequency() {
  const rules = computeRuleFrequency(state.findings);
  document.getElementById("ruleCount").textContent = String(rules.length);
  document.getElementById("ruleFrequency").innerHTML = rules.length ? rules.map(rule => `<button type="button" class="iam-rule-row" data-rule-id="${escapeHtml(rule.id)}"><span><code>${escapeHtml(rule.id)}</code><strong>${escapeHtml(rule.finding)}</strong></span><span><b>${rule.count}</b><small>${rule.resources} resources</small></span></button>`).join("") : `<p class="iam-empty-note">No open rule occurrences in this scan.</p>`;
}

function renderTopRisk() {
  const items = computeTopRisk(state.findings);
  document.getElementById("topRiskCount").textContent = String(items.length);
  document.getElementById("topRisk").innerHTML = items.length ? items.map((finding, index) => `<button type="button" class="iam-risk-row ${index === 0 ? "is-top-risk" : ""}" style="animation-delay:${index * 25}ms" data-open-finding="${state.findings.indexOf(finding)}"><span class="iam-risk-rank">${String(index + 1).padStart(2, "0")}</span><span class="iam-risk-copy"><span class="iam-risk-meta">${severityBadge(normalizedSeverity(finding))}<span>${escapeHtml(normalizedStatus(finding))}</span></span><strong>${escapeHtml(finding.finding || "Untitled finding")}</strong><small>${escapeHtml(finding.resource_type || "Resource")}: ${escapeHtml(finding.resource_id || "Not recorded")}</small></span><span class="iam-risk-score"><strong>${escapeHtml(finding.risk_score ?? "—")}</strong><small>risk</small></span></button>`).join("") : `<p class="iam-empty-note">No risk-scored findings in this scan.</p>`;
}

function openIAMFinding(index, opener) {
  const finding = state.findings[index];
  if (!finding) return;
  state.selectedFinding = finding;
  state.returnFocus = opener || document.activeElement;
  const resourceKey = JSON.stringify([String(finding.resource_type || ""), String(finding.resource_id || "")]);
  const resourceMatch = Array.isArray(SAMPLE_FINDINGS) && SAMPLE_FINDINGS.some(item => item.resource_type === finding.resource_type && item.resource_id === finding.resource_id);
  const inventoryUrl = `inventory.html?resource=${encodeURIComponent(resourceKey)}`;
  const policyMatch = Array.isArray(SAMPLE_FINDINGS) && SAMPLE_FINDINGS.some(item => item.finding_id === finding.finding_id && item.finding === finding.finding);
  const policyUrl = `policies.html?id=${encodeURIComponent(String(finding.finding_id || ""))}`;
  const score = finding.risk_score === 0 || finding.risk_score ? finding.risk_score : "Not recorded";
  const guidance = finding.remediation || finding.recommendation || "Remediation guidance not available.";
  const fields = [
    ["Finding ID", finding.finding_id], ["Severity", normalizedSeverity(finding)], ["Status", normalizedStatus(finding)], ["Risk score", score],
    ["Resource", finding.resource_id], ["Resource type", finding.resource_type], ["Category", finding.category], ["Domain", finding.domain || normalizedDomain(finding)],
    ["Cloud", normalizedCloud(finding)], ["Detected at", finding.detected_at]
  ];
  document.getElementById("iamDrawerTitle").textContent = finding.finding || "IAM finding";
  const relatedLinks = `${resourceMatch ? `<a class="btn btn-outline" href="${inventoryUrl}">Open resource in Inventory <span aria-hidden="true">→</span></a>` : ""}${policyMatch ? `<a class="btn btn-outline" href="${policyUrl}">View Policy <span aria-hidden="true">→</span></a>` : ""}`;
  document.getElementById("iamDrawerBody").innerHTML = `<div class="iam-drawer-badges">${severityBadge(normalizedSeverity(finding))}<span class="iam-status-pill">${escapeHtml(normalizedStatus(finding))}</span></div><dl class="iam-drawer-fields">${fields.map(([label, value]) => `<div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value == null || value === "" ? "Not recorded" : value)}</dd></div>`).join("")}</dl><section class="iam-drawer-section"><h3>Evidence</h3><p>${escapeHtml(evidenceText(finding.evidence) || "Evidence not recorded.")}</p></section><section class="iam-drawer-section"><h3>Recommended action</h3><p>${escapeHtml(guidance)}</p></section>${relatedLinks ? `<div class="iam-drawer-links">${relatedLinks}</div>` : ""}`;
  const drawer = document.getElementById("iamFindingDrawer");
  document.getElementById("iamDrawerBackdrop").hidden = false;
  drawer.inert = false;
  drawer.classList.add("is-open");
  drawer.setAttribute("aria-hidden", "false");
  document.body.classList.add("iam-drawer-open");
  document.getElementById("iamDrawerClose").focus();
}

function closeIAMFinding(restore = true) {
  const drawer = document.getElementById("iamFindingDrawer");
  if (!drawer.classList.contains("is-open")) return;
  drawer.classList.remove("is-open");
  drawer.inert = true;
  drawer.setAttribute("aria-hidden", "true");
  document.getElementById("iamDrawerBackdrop").hidden = true;
  document.body.classList.remove("iam-drawer-open");
  state.selectedFinding = null;
  if (restore && state.returnFocus?.isConnected) state.returnFocus.focus();
}

function renderTable() {
  const rows = applyFiltersAndSort();
  const totalPages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
  state.page = Math.min(state.page, totalPages);
  const pageRows = rows.slice((state.page - 1) * PAGE_SIZE, state.page * PAGE_SIZE);
  document.getElementById("findingsTableBody").innerHTML = pageRows.map(finding => {
    const index = state.findings.indexOf(finding);
    const detected = fmtDate(finding.detected_at || "");
    const evidence = evidenceText(finding.evidence);
    const resourceMatch = Array.isArray(SAMPLE_FINDINGS) && SAMPLE_FINDINGS.some(item => item.resource_type === finding.resource_type && item.resource_id === finding.resource_id);
    const resourceContent = resourceMatch
      ? `<a class="iam-resource-link" href="inventory.html?resource=${encodeURIComponent(JSON.stringify([String(finding.resource_type || ""), String(finding.resource_id || "")]))}" aria-label="Open resource ${escapeHtml(finding.resource_id)} in Inventory"><strong>${escapeHtml(finding.resource_id || "Not recorded")}</strong><small>${escapeHtml(finding.resource_type || "Unknown type")}</small></a>`
      : `<span class="iam-resource-link"><strong>${escapeHtml(finding.resource_id || "Not recorded")}</strong><small>${escapeHtml(finding.resource_type || "Unknown type")}</small></span>`;
    return `<tr style="animation-delay:${Math.min(index * 12, 100)}ms" data-open-finding="${index}" tabindex="0" aria-label="Open ${escapeHtml(finding.finding || finding.finding_id)} details"><td><code>${escapeHtml(finding.finding_id || "Not recorded")}</code></td><td>${resourceContent}</td><td><button type="button" class="iam-finding-cell" data-open-finding="${index}" aria-label="View details for ${escapeHtml(finding.finding || finding.finding_id)}"><strong>${escapeHtml(finding.finding || "Untitled finding")}</strong><small title="${escapeHtml(evidence)}">${escapeHtml(evidence || "Evidence not recorded")}</small></button></td><td>${severityBadge(normalizedSeverity(finding))}</td><td><span class="iam-status-pill iam-status-${normalizedStatus(finding).toLowerCase()}">${escapeHtml(normalizedStatus(finding))}</span></td><td><strong class="iam-risk-value">${escapeHtml(finding.risk_score ?? "—")}</strong></td><td><time datetime="${escapeHtml(finding.detected_at || "")}">${escapeHtml(detected || "Not recorded")}</time></td></tr>`;
  }).join("") || `<tr><td colspan="7"><div class="iam-table-empty"><strong>No findings match these filters</strong><span>Adjust search or filters to see more records.</span></div></td></tr>`;
  const from = pageRows.length ? (state.page - 1) * PAGE_SIZE + 1 : 0;
  const to = (state.page - 1) * PAGE_SIZE + pageRows.length;
  document.getElementById("paginationLabel").textContent = `Showing ${from}–${to} of ${rows.length}`;
  document.getElementById("pageIndicator").textContent = `${state.page} / ${totalPages}`;
  document.getElementById("prevPage").disabled = state.page === 1;
  document.getElementById("nextPage").disabled = state.page === totalPages;
  document.querySelectorAll("th[data-sort]").forEach(th => {
    const active = th.dataset.sort === state.sortKey;
    th.classList.toggle("sort-active", active);
    th.setAttribute("aria-sort", active ? (state.sortDir === "asc" ? "ascending" : "descending") : "none");
  });
}

function renderResourceTypeFilterOptions() {
  const select = document.getElementById("resourceFilter");
  const current = state.resourceFilter;
  const types = [...new Set(state.findings.map(f => String(f.resource_type || "")).filter(Boolean))].sort((a, b) => a.localeCompare(b));
  select.innerHTML = `<option value="ALL">All resource types</option>${types.map(type => `<option value="${escapeHtml(type)}">${escapeHtml(type)}</option>`).join("")}`;
  select.value = types.includes(current) ? current : "ALL";
}

function renderAll() {
  const label = document.getElementById("sourceLabel");
  label.querySelector("span").textContent = state.sourceLabel;
  label.dataset.source = state.sourceLabel === "Sample scan data" ? "sample" : "imported";
  renderKpis();
  renderIdentityPosture();
  renderExposure("privilegeExposure", getPrivilegeRecords(), "privilege");
  renderExposure("trustExposure", state.findings.filter(f => /trust|external account/.test(matchingText(f))), "trust");
  renderCredentialPosture();
  renderDonut();
  renderResourceBarChart();
  renderRuleFrequency();
  renderTopRisk();
  renderResourceTypeFilterOptions();
  renderTable();
}

function setCategoryFilter(category) {
  state.categoryFilter = category || "";
  state.search = "";
  state.severityFilter = "ALL";
  state.resourceFilter = "ALL";
  state.statusFilter = ["privilege", "trust"].includes(category) ? "OPEN" : "ALL";
  state.page = 1;
  document.getElementById("searchInput").value = "";
  document.getElementById("severityFilter").value = "ALL";
  document.getElementById("resourceFilter").value = "ALL";
  document.getElementById("statusFilter").value = state.statusFilter;
  renderTable();
}

document.getElementById("findingsTableBody").addEventListener("click", event => {
  const resourceLink = event.target.closest("a.iam-resource-link");
  if (resourceLink) return;
  const opener = event.target.closest("[data-open-finding]");
  if (opener) openIAMFinding(Number(opener.dataset.openFinding), opener);
});
document.getElementById("findingsTableBody").addEventListener("keydown", event => {
  if ((event.key === "Enter" || event.key === " ") && event.target.matches("tr[data-open-finding]")) {
    event.preventDefault(); openIAMFinding(Number(event.target.dataset.openFinding), event.target);
  }
});
document.getElementById("topRisk").addEventListener("click", event => {
  const opener = event.target.closest("[data-open-finding]");
  if (opener) openIAMFinding(Number(opener.dataset.openFinding), opener);
});
document.getElementById("identityPosture").addEventListener("click", event => {
  const control = event.target.closest("[data-iam-category]");
  if (control) setCategoryFilter(control.dataset.iamCategory);
});
document.getElementById("privilegeExposure").addEventListener("click", event => {
  const control = event.target.closest("[data-iam-category]");
  if (control) setCategoryFilter(control.dataset.iamCategory);
});
document.getElementById("trustExposure").addEventListener("click", event => {
  const control = event.target.closest("[data-iam-category]");
  if (control) setCategoryFilter(control.dataset.iamCategory);
});
document.getElementById("credentialPosture").addEventListener("click", event => {
  const control = event.target.closest("[data-iam-category]");
  if (control) setCategoryFilter(control.dataset.iamCategory);
});
document.getElementById("severityLegend").addEventListener("click", event => {
  const control = event.target.closest("[data-severity]");
  if (!control) return;
  state.categoryFilter = ""; state.search = "";
  state.resourceFilter = "ALL"; state.statusFilter = "ALL";
  document.getElementById("searchInput").value = "";
  document.getElementById("resourceFilter").value = "ALL";
  document.getElementById("statusFilter").value = "ALL";
  document.getElementById("severityFilter").value = control.dataset.severity;
  state.severityFilter = control.dataset.severity; state.page = 1; renderTable();
});
document.getElementById("resourceBarChart").addEventListener("click", event => {
  const control = event.target.closest("[data-resource-type]");
  if (!control) return;
  state.categoryFilter = ""; state.search = ""; state.severityFilter = "ALL"; state.statusFilter = "OPEN";
  document.getElementById("searchInput").value = "";
  document.getElementById("severityFilter").value = "ALL";
  document.getElementById("statusFilter").value = "OPEN";
  document.getElementById("resourceFilter").value = control.dataset.resourceType;
  state.resourceFilter = control.dataset.resourceType; state.page = 1; renderTable();
});
document.getElementById("ruleFrequency").addEventListener("click", event => {
  const control = event.target.closest("[data-rule-id]");
  if (!control) return;
  state.categoryFilter = ""; state.search = control.dataset.ruleId; state.statusFilter = "OPEN";
  document.getElementById("searchInput").value = state.search;
  document.getElementById("statusFilter").value = "OPEN";
  state.page = 1; renderTable();
});
document.getElementById("iamDrawerClose").addEventListener("click", () => closeIAMFinding());
document.getElementById("iamDrawerBackdrop").addEventListener("click", () => closeIAMFinding());
document.addEventListener("keydown", event => {
  const drawer = document.getElementById("iamFindingDrawer");
  if (event.key === "Escape" && drawer.classList.contains("is-open")) closeIAMFinding();
  if (event.key === "Tab" && drawer.classList.contains("is-open")) {
    const items = [...drawer.querySelectorAll('button:not(:disabled),a[href],[tabindex]:not([tabindex="-1"])')];
    const first = items[0], last = items[items.length - 1];
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
  }
});
document.getElementById("refreshBtn").addEventListener("click", () => renderAll());
document.getElementById("runIamScanBtn").addEventListener("click", runLiveIAMScan);



// ============================================================
// THEME BUTTON
// ============================================================

document
  .getElementById("themeToggle")
  .addEventListener(
    "click",
    toggleTheme
  );



// ============================================================
// INITIALIZE
// ============================================================

loadTheme();

renderAll();
if (window.CSPM_LIVE_IAM_META) {
  setLiveScanStatus(`Last successful live IAM scan completed at ${fmtDate(window.CSPM_LIVE_IAM_META.completed_at)}.`, false);
} else {
  refreshLiveIAMResult();
}
