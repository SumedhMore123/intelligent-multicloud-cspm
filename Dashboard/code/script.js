// ============================================================
// CSPM MAIN DASHBOARD
// script.js
//
// Responsibilities:
//   1. Theme toggle (preserved from original)
//   2. Data aggregation layer
//   3. KPI calculation functions
//   4. Dashboard KPI card renderer
//   5. Header action button handlers
//   6. Severity distribution calculation + renderer
//   7. Findings Trend chart aggregation + SVG renderer
//   8. Top Findings prioritization + list renderer
//   9. Cloud distribution calculation + bar renderer
//  10. Compliance by Standard processing + renderer
//  11. Recent Activity timeline processing + renderer
//  12. Latest Findings operational table + filters + pagination
//  13. Security Modules dynamic cards
//
// IAM functionality is NOT here.
// IAM functionality is handled by iam.js (iam.html).


// ============================================================
// SHARED SEMANTIC DEFINITIONS & HELPERS
// ============================================================
/*
  Definitions:
  - TOTAL FINDINGS: all actual finding records.
  - RISK FINDINGS: CRITICAL/HIGH/MEDIUM/LOW (excludes PASS and INFO).
  - MONITORED RESOURCES: unique resource_type + resource_id combinations.
  - COMPLIANCE SCORE: passing findings / evaluated checks.
  - OPEN FINDINGS: status === OPEN.
*/

const DASH_SEV_WEIGHT = {
  "CRITICAL": 6,
  "HIGH": 5,
  "MEDIUM": 4,
  "LOW": 3,
  "INFO": 2,
  "PASS": 1
};

function normalizeSeverity(sev) {
  const s = (sev || "").toUpperCase();
  return DASH_SEV_WEIGHT[s] ? s : "MEDIUM";
}

function normalizeStatus(status) {
  const s = (status || "").toUpperCase();
  return ["OPEN", "PASS", "INFO", "RESOLVED"].includes(s) ? s : "OPEN";
}

function normalizeCloud(cloudName) {
  const c = (cloudName || "").trim().toUpperCase();
  if (c.includes("AMAZON") || c === "AWS") return "AWS";
  if (c.includes("MICROSOFT") || c.includes("AZURE")) return "Azure";
  if (c.includes("GOOGLE") || c === "GCP") return "GCP";
  return "Other";
}

function normalizeDomain(finding) {
  return (finding.domain || finding.category || "").toUpperCase();
}

function isRiskFinding(finding) {
  const sev = normalizeSeverity(finding.severity);
  return sev !== "PASS" && sev !== "INFO";
}

function isOpenFinding(finding) {
  return normalizeStatus(finding.status) === "OPEN";
}

// ============================================================





// ============================================================
// DATA SOURCE
//
// SAMPLE_FINDINGS is declared in data.js which is loaded before
// this script. Using a local alias keeps future wiring clean:
// swap CSPM_FINDINGS to any aggregated multi-domain array later.
// ============================================================

const CSPM_DATA_AVAILABLE = typeof SAMPLE_FINDINGS !== "undefined" && Array.isArray(SAMPLE_FINDINGS);
const CSPM_FINDINGS = CSPM_DATA_AVAILABLE ? SAMPLE_FINDINGS : [];

// Table control handlers use the shared browser global; keep it bound to
// the same canonical array used by the dashboard renderers.
window.CSPM_FINDINGS = CSPM_FINDINGS;



// ============================================================
// AGGREGATION HELPERS
// All calculations are case-insensitive on severity/status.
// ============================================================

/**
 * Total number of findings in the current dataset.
 */
function calcTotalFindings(findings) {
  return findings.length;
}

/** Count findings currently marked OPEN using the shared status normalizer. */
function calcOpenFindings(findings) {
  return findings.filter(isOpenFinding).length;
}


/**
 * Count findings where severity === 'CRITICAL' (case-insensitive).
 * IAM-only data has no CRITICAL entries; this will correctly show 0
 * until network/data-security findings are added to CSPM_FINDINGS.
 */
function calcCriticalFindings(findings) {
  return findings.filter(
    f => (f.severity || "").toUpperCase() === "CRITICAL"
  ).length;
}


/**
 * Count findings where severity === 'HIGH' (case-insensitive)
 * and status === 'OPEN'.
 */
function calcHighFindings(findings) {
  return findings.filter(
    f =>
      (f.severity || "").toUpperCase() === "HIGH" &&
      (f.status  || "").toUpperCase() === "OPEN"
  ).length;
}


/**
 * Count unique monitored resources using resource_id.
 * Combines resource_type + resource_id to avoid collisions
 * across different resource types that may share names.
 */
function calcMonitoredResources(findings) {
  const seen = new Set(
    findings.map(f => `${f.resource_type || ""}::${f.resource_id || ""}`)
  );
  return seen.size;
}


/**
 * Compliance Score — proportion of PASS findings as a percentage.
 *
 * Rationale: each IAM check either PASSes (compliant) or produces
 * an OPEN finding (non-compliant). PASS rate across all checks is a
 * meaningful, data-driven proxy for compliance posture.
 *
 * Formula: (PASS findings / total findings) × 100, rounded.
 *
 * Returns 0 when the dataset is empty.
 * Returns a value 0–100 as an integer.
 *
 * This function is intentionally isolated so that future scans
 * (e.g. CIS-benchmark results) can be piped in as the denominator.
 */
function calcComplianceScore(findings) {
  return getComplianceData(findings).generic.score;
}


/**
 * Count OPEN findings that are HIGH severity — used as the
 * notification badge count (capped at 99 for display).
 */
function calcNotificationCount(findings) {
  const count = findings.filter(
    f =>
      (f.status  || "").toUpperCase() === "OPEN" &&
      (f.severity || "").toUpperCase() === "HIGH"
  ).length;

  return Math.min(count, 99);
}



// ============================================================
// SEVERITY DISTRIBUTION
//
// Aggregates CRITICAL / HIGH / MEDIUM / LOW counts from the
// finding dataset. INFO and PASS are intentionally excluded:
// they are compliance metrics, not risk-severity categories,
// and should not appear in the risk donut.
// ============================================================

/**
 * getSeverityDistribution(findings)
 *
 * Returns { critical, high, medium, low, total } where:
 *   total = critical + high + medium + low
 *
 * All severity comparisons are case-insensitive.
 * Unknown/unsupported severities (e.g. INFO, PASS) are silently skipped.
 */
function getSeverityDistribution(findings) {
  let critical = 0, high = 0, medium = 0, low = 0;
  findings.forEach(f => {
    if (isRiskFinding(f)) {
      const sev = normalizeSeverity(f.severity);
      if (sev === "CRITICAL") critical++;
      else if (sev === "HIGH") high++;
      else if (sev === "MEDIUM") medium++;
      else if (sev === "LOW") low++;
    }
  });
  return { critical, high, medium, low, total: critical + high + medium + low };
}



// ============================================================
// SEVERITY COLORS
// Resolved from the CSS custom properties defined in styles.css.
// Kept here so the JS renderer and the CSS variables stay in sync.
// ============================================================

const SEVERITY_COLORS = {
  critical : "#A91E2C",   // var(--critical)
  high     : "#C7402F",   // var(--high)
  medium   : "#B4791B",   // var(--medium)
  low      : "#2E8B57",   // var(--pass) — used by .low-dot in styles.css
};

const SEVERITY_DOT_CLASSES = {
  critical : "critical-dot",
  high     : "high-dot",
  medium   : "medium-dot",
  low      : "low-dot",
};



// ============================================================
// SEVERITY DISTRIBUTION RENDERER
// ============================================================

/**
 * renderSeverityDistribution(findings)
 *
 * Calculates the severity distribution and updates:
 *   #severityDonut      — conic-gradient background
 *   #severityTotal      — center number (risk findings only)
 *   #severityTotalLabel — center label
 *   #severityLegend     — four legend rows with dot / name / count / %
 *
 * Handles edge cases:
 *   - zero risk findings: neutral grey donut, all zeros
 *   - single severity present: full single-color segment
 *   - percentages always sum to 100% (last item absorbs rounding error)
 */
function renderSeverityDistribution(findings) {

  const donutEl  = document.getElementById("severityDonut");
  const totalEl  = document.getElementById("severityTotal");
  const legendEl = document.getElementById("severityLegend");

  if (!donutEl || !totalEl || !legendEl) return;

  const dist = getSeverityDistribution(findings);


  // ---- 1. Update donut center ----

  totalEl.textContent = dist.total;


  // ---- 2. Build conic-gradient for donut ----

  if (dist.total === 0) {

    // No risk findings — render a neutral empty ring
    donutEl.style.background = "var(--border-soft)";

  } else {

    // Each severity gets a proportional arc segment.
    // We accumulate degree positions as we go.
    const segments = [
      { key: "critical", count: dist.critical },
      { key: "high",     count: dist.high     },
      { key: "medium",   count: dist.medium   },
      { key: "low",      count: dist.low      },
    ];

    let cumDeg = 0;
    const stops = [];

    segments.forEach(function(seg) {

      if (seg.count === 0) return;       // zero-count segments get no arc

      const degrees = (seg.count / dist.total) * 360;
      const color   = SEVERITY_COLORS[seg.key];
      const start   = cumDeg;
      cumDeg += degrees;

      stops.push(color + " " + start + "deg " + cumDeg + "deg");

    });

    donutEl.style.background =
      stops.length
        ? "conic-gradient(" + stops.join(", ") + ")"
        : "var(--border-soft)";

  }


  // ---- 3. Build legend rows ----

  // Calculate percentages; last non-zero item absorbs rounding
  // so the displayed values always add to exactly 100%.
  const ROWS = [
    { key: "critical", label: "Critical" },
    { key: "high",     label: "High"     },
    { key: "medium",   label: "Medium"   },
    { key: "low",      label: "Low"      },
  ];

  // Compute raw percentages first
  let sumPct   = 0;
  let lastIdx  = -1;

  const pcts = ROWS.map(function(row, i) {

    if (dist.total === 0) return 0;

    const raw = (dist[row.key] / dist.total) * 100;
    const pct = Math.round(raw);

    if (dist[row.key] > 0) lastIdx = i;

    sumPct += pct;
    return pct;

  });

  // Adjust last non-zero item to absorb rounding drift
  if (lastIdx >= 0 && dist.total > 0) {
    pcts[lastIdx] += (100 - sumPct);
  }

  // Build HTML for each legend row
  legendEl.innerHTML = ROWS.map(function(row, i) {

    const count     = dist[row.key];
    const pct       = pcts[i];
    const dotClass  = SEVERITY_DOT_CLASSES[row.key];
    const pctStr    = dist.total > 0 ? pct + "%" : "0%";

    return [
      '<div class="severity-item">',
      '  <span>',
      '    <span class="severity-dot ' + dotClass + '"></span>',
      '    ' + row.label,
      '  </span>',
      '  <span class="severity-legend-right">',
      '    <strong>' + count + '</strong>',
      '    <span class="severity-pct">' + pctStr + '</span>',
      '  </span>',
      '</div>',
    ].join("\n");

  }).join("\n");


  // ---- 4. Trigger fade-in animation on the donut ----
  // Remove and re-add the animation class so it replays on refresh.
  donutEl.classList.remove("donut-fade-in");


  // Forcing a reflow before re-adding ensures the animation fires again
  void donutEl.offsetWidth;

  donutEl.classList.add("donut-fade-in");

}



// ============================================================
// FINDINGS TREND RENDERER
// ============================================================

/**
 * ISO 8601 Week Number calculation.
 */
function getISOWeekNumber(d) {
  const date = new Date(d.getTime());
  date.setUTCDate(date.getUTCDate() + 4 - (date.getUTCDay() || 7));
  const yearStart = new Date(Date.UTC(date.getUTCFullYear(), 0, 1));
  const weekNo = Math.ceil((((date - yearStart) / 86400000) + 1) / 7);
  return weekNo;
}


/**
 * Aggregates findings by the chosen period ('Daily' or 'Weekly').
 * Only processes CRITICAL, HIGH, MEDIUM, LOW severities.
 */
function aggregateFindingsTrend(findings, period) {
  const aggregated = {};

  findings.forEach(function(f) {
    const sev = (f.severity || "").toUpperCase();
    if (!["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(sev)) return;
    if (!f.detected_at) return;

    const d = new Date(f.detected_at);
    if (isNaN(d.getTime())) return;

    let key, label;
    if (period === "Daily") {
      // e.g. "Sep 10"
      const month = d.toLocaleString("en-US", { month: "short" });
      const day = d.getDate();
      label = month + " " + day;
      key = d.getFullYear() + "-" +
            String(d.getMonth() + 1).padStart(2, "0") + "-" +
            String(d.getDate()).padStart(2, "0");
    } else {
      // e.g. "Wk 36"
      const week = getISOWeekNumber(d);
      label = "Wk " + week;
      key = d.getFullYear() + "-W" + String(week).padStart(2, "0");
    }

    if (!aggregated[key]) {
      aggregated[key] = {
        key: key,
        label: label,
        timestamp: d.getTime(),
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
      };
    }
    aggregated[key][sev.toLowerCase()]++;
  });

  // Return array sorted chronologically
  return Object.values(aggregated).sort(function(a, b) {
    return a.timestamp - b.timestamp;
  });
}


/**
 * Renders an SVG line chart for the aggregated trend data.
 */
function renderFindingsTrend(findings) {
  const wrapper = document.getElementById("trendChartWrapper");
  const periodSelect = document.getElementById("trendPeriodSelect");
  if (!wrapper || !periodSelect) return;

  const period = periodSelect.value || "Daily";
  const data = aggregateFindingsTrend(findings, period);

  // Preserve tooltip element during refresh
  let tooltip = document.getElementById("trendChartTooltip");
  if (!tooltip) {
    tooltip = document.createElement("div");
    tooltip.className = "chart-tooltip";
    tooltip.id = "trendChartTooltip";
    wrapper.appendChild(tooltip);
  }

  // Handle empty data
  if (data.length === 0) {
    wrapper.innerHTML = '<div style="display:flex; height:100%; align-items:center; justify-content:center; color:var(--muted); font-size:14px;">No trend data available</div>';
    wrapper.appendChild(tooltip); // put it back
    return;
  }

  // Chart configuration
  const width = 800;
  const height = 230;
  const padding = { top: 20, right: 30, bottom: 30, left: 40 };
  const chartW = width - padding.left - padding.right;
  const chartH = height - padding.top - padding.bottom;

  // Calculate dynamic scale (max value + 20% headroom, minimum scale of 5)
  let maxVal = 0;
  data.forEach(function(d) {
    maxVal = Math.max(maxVal, d.critical, d.high, d.medium, d.low);
  });
  maxVal = Math.max(5, Math.ceil(maxVal * 1.2));

  // Generate Y-axis grid
  const yTicks = 4;
  let gridLines = "";
  let yLabels = "";
  for (let i = 0; i <= yTicks; i++) {
    const val = Math.round((maxVal / yTicks) * i);
    const y = height - padding.bottom - (val / maxVal) * chartH;
    gridLines += '<line x1="' + padding.left + '" y1="' + y + '" x2="' + (width - padding.right) + '" y2="' + y + '" class="chart-grid-line" />';
    yLabels += '<text x="' + (padding.left - 10) + '" y="' + (y + 4) + '" text-anchor="end" class="chart-axis-text">' + val + '</text>';
  }

  // Calculate X-axis positions
  const pointCount = data.length;
  const xStep = pointCount > 1 ? chartW / (pointCount - 1) : chartW / 2;
  const skip = Math.max(1, Math.ceil(pointCount / 10)); // prevent label overcrowding

  let xLabels = "";
  const points = { critical: [], high: [], medium: [], low: [] };
  let hoverAreas = "";

  data.forEach(function(d, i) {
    const x = padding.left + (pointCount > 1 ? i * xStep : xStep);

    // Label visibility
    if (i % skip === 0 || i === pointCount - 1) {
      xLabels += '<text x="' + x + '" y="' + (height - 10) + '" text-anchor="middle" class="chart-axis-text">' + d.label + '</text>';
    }

    // Coordinates for each severity
    const yC = height - padding.bottom - (d.critical / maxVal) * chartH;
    const yH = height - padding.bottom - (d.high / maxVal) * chartH;
    const yM = height - padding.bottom - (d.medium / maxVal) * chartH;
    const yL = height - padding.bottom - (d.low / maxVal) * chartH;

    points.critical.push(x + "," + yC);
    points.high.push(x + "," + yH);
    points.medium.push(x + "," + yM);
    points.low.push(x + "," + yL);

    // Hover interaction areas (via data attributes to avoid inline JS globals)
    const hoverW = pointCount > 1 ? xStep : chartW;
    const hoverX = pointCount > 1 ? x - xStep / 2 : padding.left;
    
    // Store data nicely for the event listener
    const tooltipData = {
      label: d.label,
      critical: d.critical,
      high: d.high,
      medium: d.medium,
      low: d.low
    };

    hoverAreas += 
      '<g class="chart-hover-group" data-tooltip=\'' + JSON.stringify(tooltipData) + '\'>' +
        '<line x1="' + x + '" y1="' + padding.top + '" x2="' + x + '" y2="' + (height - padding.bottom) + '" class="chart-hover-line" />' +
        '<rect x="' + hoverX + '" y="' + padding.top + '" width="' + hoverW + '" height="' + chartH + '" class="chart-hover-target" />' +
      '</g>';
  });

  // Series rendering helper
  function drawSeries(key, colorVar) {
    if (points[key].length === 0) return "";
    let path = "M " + points[key].join(" L ");
    let circles = points[key].map(function(pt) {
      const parts = pt.split(",");
      return '<circle cx="' + parts[0] + '" cy="' + parts[1] + '" r="4" fill="var(' + colorVar + ')" class="chart-point" />';
    }).join("");

    return '<path d="' + path + '" stroke="var(' + colorVar + ')" class="chart-line" />' + circles;
  }

  // Combine SVG
  const svg = 
    '<svg viewBox="0 0 ' + width + ' ' + height + '" preserveAspectRatio="none" style="width:100%; height:100%; display:block;">' +
      gridLines +
      yLabels +
      xLabels +
      drawSeries("critical", "--critical") +
      drawSeries("high", "--high") +
      drawSeries("medium", "--medium") +
      drawSeries("low", "--pass") +
      hoverAreas +
    '</svg>';

  // Inject SVG but preserve the tooltip node
  wrapper.innerHTML = svg;
  wrapper.appendChild(tooltip);

  // Bind tooltip hover events natively
  const hoverGroups = wrapper.querySelectorAll(".chart-hover-group");
  hoverGroups.forEach(function(group) {
    group.addEventListener("mouseenter", function(e) {
      const td = JSON.parse(this.getAttribute("data-tooltip"));
      tooltip.innerHTML = 
        '<div class="chart-tooltip-date">' + td.label + '</div>' +
        '<div class="chart-tooltip-row"><span style="color:var(--critical)">Critical</span><span>' + td.critical + '</span></div>' +
        '<div class="chart-tooltip-row"><span style="color:var(--high)">High</span><span>' + td.high + '</span></div>' +
        '<div class="chart-tooltip-row"><span style="color:var(--medium)">Medium</span><span>' + td.medium + '</span></div>' +
        '<div class="chart-tooltip-row"><span style="color:var(--pass)">Low</span><span>' + td.low + '</span></div>';
      
      const rect = wrapper.getBoundingClientRect();
      const targetRect = this.querySelector("rect").getBoundingClientRect();
      // Center tooltip over the hover area
      const leftPos = (targetRect.left - rect.left) + (targetRect.width / 2);
      
      tooltip.style.left = leftPos + "px";
      tooltip.style.top = "10px";
      tooltip.style.opacity = "1";
    });

    group.addEventListener("mouseleave", function(e) {
      tooltip.style.opacity = "0";
    });
  });
}



// ============================================================
// TOP FINDINGS
// ============================================================

/**
 * Prioritizes findings based on:
 * 1. Severity (CRITICAL > HIGH > MEDIUM > LOW)
 * 2. Risk Score (Descending)
 * 3. Status (OPEN first)
 * 4. Timestamp (Newer first)
 * Excludes PASS, INFO, and RESOLVED.
 */
function getTopFindings(findings, limit) {
  const filtered = findings.filter(f => isOpenFinding(f) && isRiskFinding(f));

  filtered.sort(function(a, b) {
    // 1. Severity ordering using semantic weights
    const weightA = DASH_SEV_WEIGHT[normalizeSeverity(a.severity)] || 0;
    const weightB = DASH_SEV_WEIGHT[normalizeSeverity(b.severity)] || 0;
    if (weightA !== weightB) {
      return weightB - weightA;
    }

    // 2. Risk Score (descending)
    const riskA = parseFloat(a.risk_score) || 0;
    const riskB = parseFloat(b.risk_score) || 0;
    if (riskA !== riskB) {
      return riskB - riskA;
    }

    // 3. Status OPEN preferred
    const isOpenA = (a.status || "").toUpperCase() === "OPEN";
    const isOpenB = (b.status || "").toUpperCase() === "OPEN";
    if (isOpenA !== isOpenB) {
      return isOpenA ? -1 : 1; // True (-1) before False (1)
    }

    // 4. Newer detected_at first
    const timeA = a.detected_at ? new Date(a.detected_at).getTime() : 0;
    const timeB = b.detected_at ? new Date(b.detected_at).getTime() : 0;
    
    const validTimeA = isNaN(timeA) ? 0 : timeA;
    const validTimeB = isNaN(timeB) ? 0 : timeB;
    
    return validTimeB - validTimeA;
  });

  return filtered.slice(0, limit || 5);
}


/**
 * Renders the top findings list into the DOM.
 */
function renderTopFindings(findings) {
  const listEl = document.getElementById("topFindingsList");
  if (!listEl) return;

  const top = getTopFindings(findings, 5);

  if (top.length === 0) {
    listEl.innerHTML = '<div class="top-findings-empty">No open findings</div>';
    return;
  }

  let html = "";
  
  top.forEach(function(f) {
    const sev = (f.severity || "").toUpperCase();
    const sevLower = sev.toLowerCase();
    
    // Fallback badge class if unknown severity somehow slips through
    let badgeClass = "badge-sev-" + sevLower;
    if (!["critical", "high", "medium", "low"].includes(sevLower)) {
      badgeClass = "badge-sev-medium";
    }

    const title = f.finding || "Unknown Finding";
    const status = (f.status || "").toUpperCase();
    
    // Resource formatting
    let resourceInfo = "";
    if (f.resource_type && f.resource_id) {
      resourceInfo = f.resource_type + " &bull; " + f.resource_id;
    } else if (f.resource_id) {
      resourceInfo = f.resource_id;
    } else if (f.resource_type) {
      resourceInfo = f.resource_type;
    }

    // Cloud / Domain formatting
    let cloudDomainInfo = [];
    if (f.cloud) cloudDomainInfo.push(f.cloud);
    if (f.category || f.domain) cloudDomainInfo.push(f.category || f.domain);
    const cloudMeta = cloudDomainInfo.join(" &bull; ");

    // HTML Structure
    html += '<div class="top-finding-item" title="Click to view details (not yet implemented)">';
    html +=   '<div class="top-finding-left">';
    html +=     '<div class="finding-badge ' + badgeClass + '">' + sev + '</div>';
    html +=     '<div class="top-finding-content">';
    html +=       '<div class="top-finding-title" title="' + title.replace(/"/g, '&quot;') + '">' + title + '</div>';
    if (resourceInfo) {
      html +=     '<div class="top-finding-meta">' + resourceInfo + '</div>';
    }
    if (cloudMeta) {
      html +=     '<div class="top-finding-meta" style="color:var(--muted-light)">' + cloudMeta + '</div>';
    }
    html +=     '</div>';
    html +=   '</div>';
    
    html +=   '<div class="top-finding-right">';
    if (f.risk_score !== undefined && f.risk_score !== null) {
      html +=   '<div class="top-finding-risk">Risk ' + f.risk_score + '</div>';
    }
    if (status === "OPEN") {
      html +=   '<div class="badge-status-open">' + status + '</div>';
    } else if (status) {
      html +=   '<div class="top-finding-meta" style="font-size:10px;text-transform:uppercase;">' + status + '</div>';
    }
    html +=   '</div>';
    
    html += '</div>';
  });

  listEl.innerHTML = html;
}



// ============================================================
// FINDINGS BY CLOUD
// ============================================================

/**
 * Aggregates all findings by Cloud Provider.
 * Preserves AWS, Azure, GCP even if zero. Maps unknowns to 'Other'.
 */
function getFindingsByCloud(findings) {
  const counts = { "AWS": 0, "Azure": 0, "GCP": 0 };
  findings.forEach(f => {
    if (!f.cloud) return;
    const cloud = normalizeCloud(f.cloud);
    if (counts[cloud] === undefined) counts[cloud] = 0;
    counts[cloud]++;
  });
  return counts;
}

/**
 * Renders the Findings by Cloud distribution as horizontal bars.
 */
function renderFindingsByCloud(findings) {
  const container = document.getElementById("cloudFindingsList");
  if (!container) return;

  if (findings.length === 0) {
    container.innerHTML = '<div style="display:flex; height:120px; align-items:center; justify-content:center; color:var(--muted); font-size:13px;">No cloud findings available</div>';
    return;
  }

  const cloudCounts = getFindingsByCloud(findings);
  
  // Find maximum count to scale the bars
  let maxCount = 0;
  for (const key in cloudCounts) {
    if (cloudCounts[key] > maxCount) {
      maxCount = cloudCounts[key];
    }
  }

  let html = "";
  
  // Convert to array to render
  const cloudsToRender = Object.keys(cloudCounts).map(function(key) {
    return { name: key, count: cloudCounts[key] };
  });

  cloudsToRender.forEach(function(item) {
    const width = maxCount > 0 ? (item.count / maxCount) * 100 : 0;
    const provider = (item.name || "").toLowerCase();
    const providerIcon = ICONS[provider] || ICONS.cloud;
    
    html += '<div class="dashboard-bar-row" data-cloud="' + item.name + '">';
    html +=   '<div class="dashboard-bar-header">';
    html +=     '<div class="dashboard-bar-label">';
    html +=       '<span class="cloud-provider-mark" data-provider="' + item.name + '" aria-hidden="true">' + providerIcon + '</span>';
    html +=       '<span>' + item.name + '</span>';
    html +=     '</div>';
    html +=     '<strong class="dashboard-bar-count">' + item.count + '</strong>';
    html +=   '</div>';
    
    html +=   '<div class="dashboard-bar-track">';
    html +=     '<div class="dashboard-bar-fill" style="width: ' + width + '%; background-color: var(--accent);"></div>';
    html +=   '</div>';
    html += '</div>';
  });

  container.innerHTML = html;
}



// ============================================================
// COMPLIANCE BY STANDARD
// ============================================================

/**
 * Extracts generic compliance posture from findings and checks for
 * specific compliance framework data if available.
 */
function getComplianceData(findings) {
  let evaluated = 0;
  let passed = 0;
  let hasFrameworks = false;
  
  findings.forEach(function(f) {
    if (f.framework || f.compliance_standard) {
      hasFrameworks = true;
    }

    const status = (f.status || "").toUpperCase();
    const severity = (f.severity || "").toUpperCase();
    
    // Ignore purely informational records; they are not evaluative checks
    if (status === "INFO" || severity === "INFO") return;
    
    evaluated++;
    if (status === "PASS" || severity === "PASS") {
      passed++;
    }
  });

  const score = evaluated > 0 ? Math.round((passed / evaluated) * 100) : 0;
  
  return {
    hasFrameworks: hasFrameworks,
    frameworks: [], // Reserved for future use when mappings exist
    generic: {
      evaluated: evaluated,
      passed: passed,
      score: score
    }
  };
}

/**
 * Renders the Compliance by Standard panel.
 */
function renderComplianceByStandard(findings) {
  const container = document.getElementById("complianceList");
  if (!container) return;

  const data = getComplianceData(findings);
  let html = "";

  // The current data structure has no framework mappings.
  // We explicitly show the unsupported state for standard frameworks
  // to prepare the UI for future integration without fabricating numbers.
  const standardNames = [
    "CIS AWS Foundations",
    "ISO 27001",
    "SOC 2",
    "NIST CSF"
  ];
  
  if (!data.hasFrameworks || data.frameworks.length === 0) {
    standardNames.forEach(function(name) {
      html += '<div class="dashboard-bar-row" style="opacity:0.6; cursor:default; border-bottom:1px solid var(--border-soft); padding-bottom:10px; margin-bottom:10px;">';
      html +=   '<div class="dashboard-bar-header" style="margin-bottom:6px;">';
      html +=     '<strong style="color:var(--ink); font-size:13px;">' + name + '</strong>';
      html +=     '<span style="color:var(--muted-light); font-size:11px;">No framework data available</span>';
      html +=   '</div>';
      html +=   '<div class="dashboard-bar-track" style="background:var(--surface-soft); height:6px;"></div>';
      html += '</div>';
    });
    
    // Remove the last border
    html = html.replace(/margin-bottom:10px;">$/, 'margin-bottom:0; border-bottom:none; padding-bottom:0;">');
  } else {
    // Future implementation for real framework data would go here
  }

  container.innerHTML = html;
}

/**
 * Renders the Overall Compliance Posture generic generic summary.
 */
function renderOverallPosture(findings) {
  const container = document.getElementById("overallPostureContent");
  if (!container) return;

  const data = getComplianceData(findings);
  
  let html = '<div style="display:flex; align-items:center; gap:20px; padding:20px 10px; width:100%; justify-content:center;">';
  
  // Large percentage circle or text
  html += '<div style="font-size:42px; font-weight:700; color:var(--pass); line-height:1;">' + data.generic.score + '%</div>';
  
  // Explanation
  html += '<div style="display:flex; flex-direction:column; gap:4px;">';
  html +=   '<div style="color:var(--ink-strong); font-size:14px; font-weight:500;">Based on current scan results</div>';
  html +=   '<div style="color:var(--muted); font-size:12.5px;">' + data.generic.passed + ' passed / ' + data.generic.evaluated + ' evaluated findings</div>';
  html +=   '<div style="color:var(--muted-light); font-size:11px; margin-top:2px;">(INFO findings excluded)</div>';
  html += '</div>';
  
  html += '</div>';

  container.innerHTML = html;
}



// ============================================================
// RECENT ACTIVITY
// ============================================================

/**
 * Safely parses and formats a relative time string.
 */
function formatRelativeTime(isoString) {
  if (!isoString) return 'Recently detected';
  
  const timestamp = new Date(isoString).getTime();
  if (isNaN(timestamp)) return 'Recently detected';
  
  const now = new Date().getTime();
  const diffInSeconds = Math.floor((now - timestamp) / 1000);
  
  // Future dates (bad data or time sync issues) shouldn't show negative ago
  if (diffInSeconds < 0) return 'Recently detected';
  
  if (diffInSeconds < 60) return 'Just now';
  
  const minutes = Math.floor(diffInSeconds / 60);
  if (minutes < 60) return minutes + (minutes === 1 ? ' minute ago' : ' minutes ago');
  
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return hours + (hours === 1 ? ' hour ago' : ' hours ago');
  
  const days = Math.floor(hours / 24);
  return days + (days === 1 ? ' day ago' : ' days ago');
}

/**
 * Extracts and sorts the most recent activity events from findings.
 */
function getRecentActivity(findings, limit) {
  // Convert findings into unified event objects to support 
  // future event types beyond just 'finding_detected'
  const events = [];
  
  findings.forEach(function(f) {
    if (!f.detected_at) return;
    
    events.push({
      type: "finding_detected",
      timestamp: f.detected_at,
      title: f.finding || "Unknown Finding",
      cloud: f.cloud,
      domain: normalizeDomain(f),
      severity: f.severity,
      resource_type: f.resource_type,
      resource_id: f.resource_id,
      // For sorting
      _time: new Date(f.detected_at).getTime()
    });
  });
  
  // Sort descending (newest first)
  events.sort(function(a, b) {
    const timeA = isNaN(a._time) ? 0 : a._time;
    const timeB = isNaN(b._time) ? 0 : b._time;
    return timeB - timeA;
  });
  
  return events.slice(0, limit || 5);
}

/**
 * Renders the Recent Activity timeline.
 */
function renderRecentActivity(findings) {
  const container = document.getElementById("recentActivityList");
  if (!container) return;

  const events = getRecentActivity(findings, 5);

  if (events.length === 0) {
    container.innerHTML = '<div class="activity-empty">No recent activity</div>';
    return;
  }

  let html = "";
  
  events.forEach(function(evt) {
    // Resource formatting
    let resourceInfo = "";
    if (evt.resource_type && evt.resource_id) {
      resourceInfo = evt.resource_type + " &bull; " + evt.resource_id;
    } else if (evt.resource_id) {
      resourceInfo = evt.resource_id;
    } else if (evt.resource_type) {
      resourceInfo = evt.resource_type;
    }

    // Cloud / Domain formatting
    let cloudDomainInfo = [];
    if (evt.cloud) cloudDomainInfo.push(evt.cloud);
    if (evt.domain) cloudDomainInfo.push(evt.domain);
    const cloudMeta = cloudDomainInfo.join(" &bull; ");
    
    // Event type label and icon
    let typeLabel = "System Event";
    let iconSvg = ICONS.activity || "";
    if (evt.type === "finding_detected") {
      typeLabel = "Finding detected";
    }
    
    // Severity badge (optional)
    let sevBadgeHtml = "";
    if (evt.severity) {
      const sev = normalizeSeverity(evt.severity);
      const sevLower = sev.toLowerCase();
      const badgeClass = "badge-sev-" + sevLower;
      // Reusing the badge system from Top Findings
      sevBadgeHtml = '<span class="finding-badge ' + badgeClass + '" style="font-size:9px; padding:2px 6px;">' + sev + '</span>';
    }

    html += '<div class="activity-item">';
    
    // Timeline column
    html += '  <div class="activity-timeline">';
    html += '    <div class="activity-marker">' + iconSvg + '</div>';
    html += '    <div class="activity-line"></div>';
    html += '  </div>';
    
    // Content column
    html += '  <div class="activity-content">';
    html += '    <div class="activity-header">';
    html += '      <div style="display:flex; align-items:center; gap:8px;">';
    html += '        <div class="activity-type">' + typeLabel + '</div>';
    html +=          sevBadgeHtml;
    html += '      </div>';
    html += '      <div class="activity-time">' + formatRelativeTime(evt.timestamp) + '</div>';
    html += '    </div>';
    
    html += '    <div class="activity-title" title="' + evt.title.replace(/"/g, '&quot;') + '">' + evt.title + '</div>';
    
    if (resourceInfo) {
      html += '    <div class="activity-meta">' + resourceInfo + '</div>';
    }
    if (cloudMeta) {
      html += '    <div class="activity-meta" style="margin-top:2px;">' + cloudMeta + '</div>';
    }
    
    html += '  </div>';
    html += '</div>';
  });

  container.innerHTML = html;
}




// ============================================================
// LATEST FINDINGS TABLE
// ============================================================

const dashState = {
  search: "",
  cloudFilter: "ALL",
  severityFilter: "ALL",
  statusFilter: "ALL",
  sortKey: "detected_at",
  sortDir: "desc", // "asc" or "desc"
  currentPage: 1,
  itemsPerPage: 8,
  filteredFindings: []
};


function formatDashDate(isoString) {
  if (!isoString) return "-";
  const d = new Date(isoString);
  if (isNaN(d.getTime())) return "-";
  
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const m = months[d.getUTCMonth()];
  const day = d.getUTCDate();
  const hr = String(d.getUTCHours()).padStart(2, '0');
  const min = String(d.getUTCMinutes()).padStart(2, '0');
  
  // Compact absolute date: Sep 5, 11:15
  return m + " " + day + ", " + hr + ":" + min;
}

function processDashFindings(allFindings) {
  // 1. Filter
  let filtered = allFindings.filter(function(f) {
    if (dashState.cloudFilter !== "ALL") {
      let c = normalizeCloud(f.cloud);
      if (dashState.cloudFilter === "Other" && c !== "Other") return false;
      if (dashState.cloudFilter !== "Other" && c.toUpperCase() !== dashState.cloudFilter.toUpperCase()) return false;
    }
    
    if (dashState.severityFilter !== "ALL") {
      if ((f.severity || "").toUpperCase() !== dashState.severityFilter) return false;
    }
    
    if (dashState.statusFilter !== "ALL") {
      if ((f.status || "").toUpperCase() !== dashState.statusFilter) return false;
    }
    
    if (dashState.search) {
      const q = dashState.search.toLowerCase();
      const hay = [
        f.finding,
        f.finding_id,
        f.resource_id,
        f.resource_type,
        f.cloud,
        f.domain,
        f.category
      ].join(" ").toLowerCase();
      
      if (!hay.includes(q)) return false;
    }
    
    return true;
  });
  
  // 2. Sort
  filtered.sort(function(a, b) {
    let av, bv;
    
    if (dashState.sortKey === "detected_at") {
      av = new Date(a.detected_at || 0).getTime();
      bv = new Date(b.detected_at || 0).getTime();
      if (isNaN(av)) av = 0;
      if (isNaN(bv)) bv = 0;
    } else if (dashState.sortKey === "risk_score") {
      av = parseFloat(a.risk_score) || 0;
      bv = parseFloat(b.risk_score) || 0;
    } else if (dashState.sortKey === "severity") {
      av = DASH_SEV_WEIGHT[(a.severity || "").toUpperCase()] || 0;
      bv = DASH_SEV_WEIGHT[(b.severity || "").toUpperCase()] || 0;
    } else {
      // String fallback (though we only have specific sorts)
      av = (a[dashState.sortKey] || "").toString().toLowerCase();
      bv = (b[dashState.sortKey] || "").toString().toLowerCase();
    }
    
    if (av < bv) return dashState.sortDir === "asc" ? -1 : 1;
    if (av > bv) return dashState.sortDir === "asc" ? 1 : -1;
    return 0;
  });
  
  dashState.filteredFindings = filtered;
  
  // Ensure valid page
  const maxPage = Math.ceil(filtered.length / dashState.itemsPerPage) || 1;
  if (dashState.currentPage > maxPage) {
    dashState.currentPage = 1;
  }
}

function renderDashTable() {
  const tbody = document.getElementById("dashTableBody");
  if (!tbody) return;
  
  const rows = dashState.filteredFindings;
  const startIdx = (dashState.currentPage - 1) * dashState.itemsPerPage;
  const pageRows = rows.slice(startIdx, startIdx + dashState.itemsPerPage);
  
  if (rows.length === 0) {
    // Determine if dataset is empty or filtered
    const msg = window.CSPM_FINDINGS && window.CSPM_FINDINGS.length === 0 
      ? "No findings available" 
      : "No findings match the current filters";
      
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; padding:40px; color:var(--muted);">' + msg + '</td></tr>';
  } else {
    let html = "";
    pageRows.forEach(function(f) {
      // Formatting
      const sev = normalizeSeverity(f.severity);
      const sevLower = sev.toLowerCase();
      const badgeClass = "badge-sev-" + sevLower;
      
      const title = f.finding || "-";
      const cloud = f.cloud || "-";
      const domain = f.domain || f.category || "-";
      
      let resource = "-";
      if (f.resource_type && f.resource_id) {
        resource = f.resource_type + " &bull; " + f.resource_id;
      } else if (f.resource_id) {
        resource = f.resource_id;
      }
      
      const risk = (f.risk_score !== undefined && f.risk_score !== null) ? f.risk_score : "-";
      const status = (f.status || "").toUpperCase();
      const dateStr = formatDashDate(f.detected_at);
      
      html += '<tr class="dashboard-table-row" title="' + (f.evidence ? f.evidence.replace(/"/g, '&quot;') : title.replace(/"/g, '&quot;')) + '">';
      html +=   '<td><span class="finding-badge ' + badgeClass + '">' + sev + '</span></td>';
      
      html +=   '<td>';
      html +=     '<div style="font-weight:500; color:var(--ink-strong); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; max-width:300px;">' + title + '</div>';
      if (f.finding_id) {
        html +=   '<div style="font-size:10.5px; color:var(--muted-light); margin-top:2px;">' + f.finding_id + '</div>';
      }
      html +=   '</td>';
      
      html +=   '<td>' + cloud + '</td>';
      html +=   '<td>' + domain + '</td>';
      
      html +=   '<td class="mono" style="max-width:200px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">' + resource + '</td>';
      
      html +=   '<td><span class="' + (risk > 50 ? 'risk-score high-score' : 'risk-score') + '" style="font-size:12px; padding:2px 6px;">' + risk + '</span></td>';
      
      if (status === "OPEN") {
        html += '<td><span class="badge-status-open">' + status + '</span></td>';
      } else {
        html += '<td><span style="font-size:10px; text-transform:uppercase; color:var(--muted);">' + status + '</span></td>';
      }
      
      html +=   '<td style="white-space:nowrap; color:var(--muted); font-size:12px;">' + dateStr + '</td>';
      html += '</tr>';
    });
    tbody.innerHTML = html;
  }
  
  // Pagination Update
  const maxPage = Math.ceil(rows.length / dashState.itemsPerPage) || 1;
  const indicator = document.getElementById("dashPageIndicator");
  const label = document.getElementById("dashPaginationLabel");
  const prevBtn = document.getElementById("dashPrevPage");
  const nextBtn = document.getElementById("dashNextPage");
  
  if (indicator) indicator.textContent = dashState.currentPage + " / " + maxPage;
  if (label) {
    const startRange = rows.length === 0 ? 0 : startIdx + 1;
    const endRange = Math.min(startIdx + dashState.itemsPerPage, rows.length);
    label.textContent = "Showing " + startRange + " - " + endRange + " of " + rows.length;
  }
  
  if (prevBtn) prevBtn.disabled = dashState.currentPage === 1;
  if (nextBtn) nextBtn.disabled = dashState.currentPage === maxPage;
  
  // Sort Arrows Update
  document.querySelectorAll("th[data-dash-sort]").forEach(function(th) {
    th.classList.remove("sort-asc", "sort-desc");
    if (th.getAttribute("data-dash-sort") === dashState.sortKey) {
      th.classList.add(dashState.sortDir === "asc" ? "sort-asc" : "sort-desc");
    }
  });
}

function initDashTableControls() {
  const searchInput = document.getElementById("dashSearchInput");
  const cloudFilter = document.getElementById("dashCloudFilter");
  const sevFilter = document.getElementById("dashSeverityFilter");
  const statusFilter = document.getElementById("dashStatusFilter");
  const prevBtn = document.getElementById("dashPrevPage");
  const nextBtn = document.getElementById("dashNextPage");
  
  // Add listeners only once
  if (searchInput && !searchInput.dataset.initialized) {
    searchInput.dataset.initialized = "true";
    
    searchInput.addEventListener("input", function(e) {
      dashState.search = e.target.value;
      dashState.currentPage = 1;
      processDashFindings(window.CSPM_FINDINGS || []);
      renderDashTable();
    });
    
    cloudFilter.addEventListener("change", function(e) {
      dashState.cloudFilter = e.target.value;
      dashState.currentPage = 1;
      processDashFindings(window.CSPM_FINDINGS || []);
      renderDashTable();
    });
    
    sevFilter.addEventListener("change", function(e) {
      dashState.severityFilter = e.target.value;
      dashState.currentPage = 1;
      processDashFindings(window.CSPM_FINDINGS || []);
      renderDashTable();
    });
    
    statusFilter.addEventListener("change", function(e) {
      dashState.statusFilter = e.target.value;
      dashState.currentPage = 1;
      processDashFindings(window.CSPM_FINDINGS || []);
      renderDashTable();
    });
    
    prevBtn.addEventListener("click", function() {
      if (dashState.currentPage > 1) {
        dashState.currentPage--;
        renderDashTable();
      }
    });
    
    nextBtn.addEventListener("click", function() {
      const maxPage = Math.ceil(dashState.filteredFindings.length / dashState.itemsPerPage) || 1;
      if (dashState.currentPage < maxPage) {
        dashState.currentPage++;
        renderDashTable();
      }
    });
    
    document.querySelectorAll("th[data-dash-sort]").forEach(function(th) {
      th.addEventListener("click", function() {
        const key = th.getAttribute("data-dash-sort");
        if (dashState.sortKey === key) {
          dashState.sortDir = dashState.sortDir === "asc" ? "desc" : "asc";
        } else {
          dashState.sortKey = key;
          dashState.sortDir = key === "detected_at" ? "desc" : "asc"; // Default detected_at to desc, others asc
        }
        processDashFindings(window.CSPM_FINDINGS || []);
        renderDashTable();
      });
    });
  }
}

function refreshDashTable(findings) {
  processDashFindings(findings);
  renderDashTable();
  initDashTableControls();
}



// ============================================================
// SECURITY MODULES
// ============================================================

/**
 * Calculates basic finding statistics for a given domain.
 */
function getModuleStats(findings, targetDomain) {
  let count = 0;
  let openCount = 0;
  
  findings.forEach(f => {
    const domain = normalizeDomain(f);
    if (domain.includes(targetDomain.toUpperCase()) || 
        (targetDomain === "IAM" && domain.includes("IDENTITY"))) {
      count++;
      if (isOpenFinding(f)) openCount++;
    }
  });
  
  return {
    findingCount: count,
    openCount: openCount,
    status: count > 0 ? "Monitoring" : "Awaiting Scan Data"
  };
}

/**
 * Renders the Security Modules cards with dynamic status and metrics.
 */
function renderSecurityModules(findings) {
  const container = document.getElementById("securityModulesList");
  if (!container) return;

  const iam = getModuleStats(findings, "IAM");
  const net = getModuleStats(findings, "NETWORK");
  const dataMod = getModuleStats(findings, "DATA");
  
  // Compliance leverages the robust Step 6 generic calculation
  const compData = getComplianceData(findings);
  const compScore = compData.generic.score;
  const compCount = compData.generic.evaluated;
  
  let html = "";
  
  // 1. IAM Security
  html += '<a href="iam.html" class="module-card">';
  html += '  <div class="module-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M5 21v-2a7 7 0 0 1 14 0v2"/></svg></div>';
  html += '  <div class="module-info">';
  html += '    <strong>IAM Security</strong>';
  html += '    <span>Identity, access and privilege analysis</span>';
  if (iam.findingCount > 0) {
    html += '    <div style="font-size:12.5px; color:var(--ink-soft); margin-top:4px; font-weight:500;">' + iam.openCount + ' open findings</div>';
  }
  html += '  </div>';
  html += '  <div class="module-status ' + (iam.findingCount > 0 ? 'active-module' : '') + '">' + iam.status + '</div>';
  html += '</a>';
  
  // 2. Network Security
  html += '<div class="module-card ' + (net.findingCount > 0 ? '' : 'disabled-module') + '" style="cursor:default;">';
  html += '  <div class="module-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="5" cy="12" r="2"/><circle cx="19" cy="5" r="2"/><circle cx="19" cy="19" r="2"/><path d="m7 11 10-5M7 13l10 5"/></svg></div>';
  html += '  <div class="module-info">';
  html += '    <strong>Network Security</strong>';
  html += '    <span>Compute, firewall and exposure analysis</span>';
  if (net.findingCount > 0) {
    html += '    <div style="font-size:12.5px; color:var(--ink-soft); margin-top:4px; font-weight:500;">' + net.openCount + ' open findings</div>';
  }
  html += '  </div>';
  html += '  <div class="module-status">' + net.status + '</div>';
  html += '</div>';
  
  // 3. Data Security
  html += '<div class="module-card ' + (dataMod.findingCount > 0 ? '' : 'disabled-module') + '" style="cursor:default;">';
  html += '  <div class="module-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/></svg></div>';
  html += '  <div class="module-info">';
  html += '    <strong>Data Security</strong>';
  html += '    <span>Storage, encryption and classification</span>';
  if (dataMod.findingCount > 0) {
    html += '    <div style="font-size:12.5px; color:var(--ink-soft); margin-top:4px; font-weight:500;">' + dataMod.openCount + ' open findings</div>';
  }
  html += '  </div>';
  html += '  <div class="module-status">' + dataMod.status + '</div>';
  html += '</div>';
  
  // 4. Compliance
  html += '<div class="module-card ' + (compCount > 0 ? '' : 'disabled-module') + '" style="cursor:default;">';
  html += '  <div class="module-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M8 4H6a2 2 0 0 0-2 2v14h16V6a2 2 0 0 0-2-2h-2"/><rect x="8" y="2" width="8" height="4" rx="1"/><path d="m8 13 2.5 2.5L16 10"/></svg></div>';
  html += '  <div class="module-info">';
  html += '    <strong>Compliance</strong>';
  html += '    <span>Framework adherence and posture</span>';
  if (compCount > 0) {
    html += '    <div style="font-size:12.5px; color:var(--ink-soft); margin-top:4px; font-weight:500;">Overall Posture: ' + compScore + '%</div>';
  }
  html += '  </div>';
  html += '  <div class="module-status">' + (compCount > 0 ? 'Monitoring' : 'Awaiting Scan Data') + '</div>';
  html += '</div>';
  
  // 5. AI Intelligence
  html += '<div class="module-card disabled-module" style="cursor:default;">';
  html += '  <div class="module-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m12 3 1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8L12 3Z"/><path d="m19 16 .9 2.1L22 19l-2.1.9L19 22l-.9-2.1L16 19l2.1-.9L19 16Z"/></svg></div>';
  html += '  <div class="module-info">';
  html += '    <strong>AI Intelligence</strong>';
  html += '    <span>Risk prioritization and attack-path analysis</span>';
  html += '  </div>';
  html += '  <div class="module-status">Coming soon</div>';
  html += '</div>';

  container.innerHTML = html;
}


// ============================================================
// SVG ICON STRINGS

// Inline SVG keeps zero external dependencies.
// Each returns a full <svg>…</svg> string at 16×16.
// ============================================================

const ICONS = window.CSPM_ICONS;



// ============================================================
// KPI CARD BUILDER
// Returns an HTML string for one KPI card.
// ============================================================

function buildKpiCard({
  iconHtml,
  iconClass,
  label,
  value,
  valueClass,
  trendLabel,
  trendClass,
}) {
  return `
    <div class="dashboard-kpi-card">

      <div class="dashboard-kpi-header">
        <div class="dashboard-kpi-label">${label}</div>
        <div class="kpi-icon-wrap ${iconClass}">
          ${iconHtml}
        </div>
      </div>

      <div class="dashboard-kpi-value ${valueClass || ""}">
        ${value}
      </div>

      <div class="kpi-trend">
        <span class="kpi-trend-label ${trendClass || "kpi-trend-neutral"}">
          ${trendLabel}
        </span>
      </div>

    </div>
  `;
}




// ============================================================
// RENDER DASHBOARD KPIs
//
// Calculates all five metrics, builds card markup, and injects
// into #dashboardKpiRow. Call this whenever the data changes.
// ============================================================

function renderDashboardKPIs() {

  const container = document.getElementById("dashboardKpiRow");
  if (!container) return;

  const findings = window.CSPM_FINDINGS || CSPM_FINDINGS;

  // --- calculations ---
  const total       = calcTotalFindings(findings);
  const critical    = calcCriticalFindings(findings);
  const high        = calcHighFindings(findings);
  const resources   = calcMonitoredResources(findings);
  const compliance  = calcComplianceScore(findings);

  // --- build cards ---
  const cards = [

    buildKpiCard({
      iconHtml   : ICONS.total,
      iconClass  : "kpi-icon-total",
      label      : "Total Findings",
      value      : total,
      valueClass : "",
      trendLabel : "Across all checks",
      trendClass : "kpi-trend-neutral",
    }),

    buildKpiCard({
      iconHtml   : ICONS.critical,
      iconClass  : "kpi-icon-critical",
      label      : "Critical Findings",
      value      : critical,
      valueClass : critical > 0 ? "critical-text" : "",
      trendLabel : "From current scan",
      trendClass : critical > 0 ? "kpi-trend-down" : "kpi-trend-neutral",
    }),

    buildKpiCard({
      iconHtml   : ICONS.high,
      iconClass  : "kpi-icon-high",
      label      : "High Findings",
      value      : high,
      valueClass : high > 0 ? "high-text" : "",
      trendLabel : "Open findings",
      trendClass : high > 0 ? "kpi-trend-down" : "kpi-trend-neutral",
    }),

    buildKpiCard({
      iconHtml   : ICONS.resources,
      iconClass  : "kpi-icon-resources",
      label      : "Monitored Resources",
      value      : resources,
      valueClass : "",
      trendLabel : "Unique resources in scan",
      trendClass : "kpi-trend-neutral",
    }),

    buildKpiCard({
      iconHtml   : ICONS.compliance,
      iconClass  : "kpi-icon-compliance",
      label      : "Compliance Score",
      value      : compliance + "%",
      valueClass : "posture-text",
      trendLabel : "Pass rate · current scan",
      trendClass : compliance >= 70
                     ? "kpi-trend-up"
                     : compliance >= 50
                       ? "kpi-trend-neutral"
                       : "kpi-trend-down",
    }),

  ];

  container.innerHTML = cards.join("");
}



// ============================================================
// NOTIFICATION BADGE
// Reflects count of open HIGH-severity findings.
// ============================================================

function renderNotifBadge() {
  const badge = document.getElementById("notifBadge");
  if (!badge) return;

  const settings = window.CSPMSettings?.getCSPMSettings?.();
  if (settings?.showNotificationBadge === false) {
    badge.style.display = "none";
    return;
  }

  const count = calcNotificationCount(window.CSPM_FINDINGS || CSPM_FINDINGS);
  badge.textContent = count;

  // Hide badge when nothing needs attention
  badge.style.display = count === 0 ? "none" : "flex";
}



// ============================================================
// FULL DASHBOARD REFRESH
// Single entry point to re-render all dynamic sections.
// Later steps can add their own render calls here.
// ============================================================

function refreshDashboard() {
  renderDashboardKPIs();
  renderNotifBadge();
  const findings = window.CSPM_FINDINGS || CSPM_FINDINGS;
  renderSeverityDistribution(findings);
  renderFindingsTrend(findings);
  renderTopFindings(findings);
  renderRecentActivity(findings);
  renderFindingsByCloud(findings);
  renderComplianceByStandard(findings);
  renderOverallPosture(findings);
  renderSecurityModules(findings);
  refreshDashTable(findings);
}



// ============================================================
// THEME
// Preserved exactly from original script.js
// ============================================================

function updateThemeButton() {

  const button = document.getElementById("themeToggle");

  if (!button) {
    return;
  }

  const dark = document.body.classList.contains("dark-mode");

  button.innerHTML = (dark ? ICONS.sun : ICONS.moon) + '<span>' + (dark ? "Light" : "Dark") + '</span>';

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
// HEADER BUTTON EVENTS
// ============================================================

// Theme toggle
const themeButton = document.getElementById("themeToggle");
if (themeButton) {
  themeButton.addEventListener("click", toggleTheme);
}


// Refresh — re-renders all KPIs and plays spin animation
const refreshBtn = document.getElementById("refreshBtn");
if (refreshBtn) {
  refreshBtn.addEventListener("click", () => {
    refreshBtn.classList.add("refreshing");

    // Remove class after animation completes (0.55 s defined in CSS)
    refreshBtn.addEventListener(
      "animationend",
      () => refreshBtn.classList.remove("refreshing"),
      { once: true }
    );

    refreshDashboard();
  });
}


// Settings and Alerts are real page links in the dashboard header.
// Help remains disabled until a help surface is implemented.

const trendSelect = document.getElementById("trendPeriodSelect");
if (trendSelect) {
  trendSelect.addEventListener("change", () => {
    renderFindingsTrend(CSPM_FINDINGS);
  });
}



// ============================================================
// INITIALIZE
// ============================================================

// Public read-only API for pages that share the dashboard data and metrics.
window.CSPMShared = Object.freeze({
  getFindings: () => window.CSPM_FINDINGS || CSPM_FINDINGS,
  hasDataSource: () => CSPM_DATA_AVAILABLE,
  calcTotalFindings,
  calcOpenFindings,
  calcCriticalFindings,
  calcHighFindings,
  calcMonitoredResources,
  calcNotificationCount,
  calcComplianceScore,
  getComplianceData,
  getSeverityDistribution,
  getFindingsByCloud,
  getModuleStats,
  normalizeDomain,
  normalizeCloud,
  normalizeSeverity,
  normalizeStatus,
  isRiskFinding,
  isOpenFinding,
  getCSPMSettings: () => window.CSPMSettings?.getCSPMSettings?.() || { theme: "light", tablePageSize: 20, showNotificationBadge: true },
  saveCSPMSettings: (changes) => window.CSPMSettings?.saveCSPMSettings?.(changes) || false,
  resetCSPMSettings: () => window.CSPMSettings?.resetCSPMSettings?.() || false,
});

loadTheme();
if (document.getElementById("dashboardKpiRow")) refreshDashboard();



// ============================================================
// PREMIUM VISUAL ENHANCEMENTS
// Added by premium upgrade. Does NOT modify any data logic.
// ============================================================


// ------------------------------------------------------------
// COUNT-UP ANIMATION
// Animates numeric KPI values from 0 to their actual value
// on page load and after refresh. Uses CSS custom property
// for duration so reduced-motion is respected via CSS.
// ------------------------------------------------------------

function animateCountUp(el, targetValue, suffix, duration) {
  if (!el) return;

  // Respect reduced-motion preference
  var prefersReduced = window.matchMedia &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  if (prefersReduced || isNaN(targetValue) || targetValue === 0) {
    el.textContent = targetValue + (suffix || '');
    return;
  }

  var start     = 0;
  var startTime = null;
  var dur       = duration || 600;

  function step(timestamp) {
    if (!startTime) startTime = timestamp;
    var progress = Math.min((timestamp - startTime) / dur, 1);
    // Ease-out cubic
    var eased = 1 - Math.pow(1 - progress, 3);
    var current = Math.round(eased * targetValue);
    el.textContent = current + (suffix || '');
    if (progress < 1) {
      requestAnimationFrame(step);
    }
  }

  requestAnimationFrame(step);
}


// Patch renderDashboardKPIs to trigger count-up after injection
var _origRenderKPIs = renderDashboardKPIs;
renderDashboardKPIs = function() {
  _origRenderKPIs();

  // Run count-up on each .dashboard-kpi-value element
  var container = document.getElementById('dashboardKpiRow');
  if (!container) return;

  var valueEls = container.querySelectorAll('.dashboard-kpi-value');
  valueEls.forEach(function(el) {
    var raw = el.textContent.trim();
    var isPercent = raw.indexOf('%') !== -1;
    var numStr = raw.replace('%', '').replace(/,/g, '');
    var num = parseFloat(numStr);

    if (!isNaN(num) && num > 0 && document.visibilityState === "visible") {
      el.textContent = '0' + (isPercent ? '%' : '');
      animateCountUp(el, num, isPercent ? '%' : '', 700);
    }
  });
};


// ------------------------------------------------------------
// CLOUD BAR ACCENT COLORS
// Adds provider-specific gradient class to each bar fill
// after renderFindingsByCloud injects HTML.
// ------------------------------------------------------------

var _origRenderCloud = renderFindingsByCloud;
renderFindingsByCloud = function(findings) {
  _origRenderCloud(findings);

  var container = document.getElementById('cloudFindingsList');
  if (!container) return;

  var fills = container.querySelectorAll('.dashboard-bar-fill');
  fills.forEach(function(fill, i) {
    var row = fill.closest('.dashboard-bar-row');
    if (!row) return;

    var name = (row.dataset.cloud || '').trim().toUpperCase();
    var width = fill.style.width;
    var isEmpty = !width || width === '0%' || width === '0';

    // Remove any existing bar-fill classes
    fill.classList.remove('bar-fill-aws', 'bar-fill-azure', 'bar-fill-gcp', 'bar-fill-other', 'bar-fill-zero');

    if (isEmpty) {
      fill.classList.add('bar-fill-zero');
    } else if (name === 'AWS') {
      fill.classList.add('bar-fill-aws');
    } else if (name === 'AZURE') {
      fill.classList.add('bar-fill-azure');
    } else if (name === 'GCP') {
      fill.classList.add('bar-fill-gcp');
    } else {
      fill.classList.add('bar-fill-other');
    }

    // Animate bar from 0 to its target width
    var target = fill.style.width;
    fill.style.width = '0%';
    requestAnimationFrame(function() {
      requestAnimationFrame(function() {
        fill.style.width = target;
      });
    });
  });
};


// ------------------------------------------------------------
// TOP FINDINGS SEVERITY LEFT INDICATOR
// Adds .finding-left-{severity} to each .top-finding-item
// so the ::before pseudo-element picks up the correct color.
// ------------------------------------------------------------

var _origRenderTopFindings = renderTopFindings;
renderTopFindings = function(findings) {
  _origRenderTopFindings(findings);

  var listEl = document.getElementById('topFindingsList');
  if (!listEl) return;

  var items = listEl.querySelectorAll('.top-finding-item');
  items.forEach(function(item) {
    var badge = item.querySelector('.finding-badge');
    if (!badge) return;

    var sev = badge.textContent.trim().toLowerCase();
    item.classList.remove('finding-left-critical', 'finding-left-high', 'finding-left-medium', 'finding-left-low');

    if (['critical', 'high', 'medium', 'low'].indexOf(sev) !== -1) {
      item.classList.add('finding-left-' + sev);
    }
  });
};


// ------------------------------------------------------------
// OVERALL POSTURE — ENHANCED VISUAL RING
// Replaces the plain percentage text with an SVG arc ring
// that fills to the actual compliance percentage.
// Data comes from the existing getComplianceData() function.
// ------------------------------------------------------------

var _origRenderOverallPosture = renderOverallPosture;
renderOverallPosture = function(findings) {
  var container = document.getElementById('overallPostureContent');
  if (!container) return;

  var data      = getComplianceData(findings);
  var score     = data.generic.score;
  var passed    = data.generic.passed;
  var evaluated = data.generic.evaluated;

  var color = score >= 70 ? 'var(--pass)' : score >= 50 ? 'var(--medium)' : 'var(--high)';

  // Compact inline posture summary — no giant ring
  var html =
    '<div style="display:flex; align-items:center; gap:12px;">' +
      // Small circular score
      '<div style="width:52px; height:52px; border-radius:50%; background:conic-gradient(' + color + ' ' + (score * 3.6) + 'deg, var(--border-soft) 0deg); display:flex; align-items:center; justify-content:center; flex-shrink:0;">' +
        '<div style="width:38px; height:38px; border-radius:50%; background:var(--surface); display:flex; align-items:center; justify-content:center;">' +
          '<span style="font-size:11px; font-weight:750; color:' + color + ';">' + score + '%</span>' +
        '</div>' +
      '</div>' +
      // Text
      '<div style="display:flex; flex-direction:column; gap:2px;">' +
        '<span style="font-size:12.5px; font-weight:700; color:var(--ink-strong);">Overall: ' + score + '% compliant</span>' +
        '<span style="font-size:11px; color:var(--muted);">' + passed + ' passed of ' + evaluated + ' evaluated</span>' +
        '<span style="font-size:10.5px; color:var(--muted-light);">Based on current scan</span>' +
      '</div>' +
    '</div>';

  container.innerHTML = html;
};


// ------------------------------------------------------------
// SEVERITY DONUT MICRO-INTERACTIONS
// Uses the existing severity aggregation and palette. This adds
// hover emphasis and a contextual tooltip without changing data.
// ------------------------------------------------------------
(function initSeverityDonutInteraction() {
  var panel = document.getElementById('severityPanel');
  var donut = document.getElementById('severityDonut');
  var legend = document.getElementById('severityLegend');
  if (!panel || !donut || !legend) return;

  var keys = ['critical', 'high', 'medium', 'low'];
  var names = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
  var tooltip = document.createElement('div');
  tooltip.className = 'severity-tooltip';
  tooltip.setAttribute('role', 'tooltip');
  panel.appendChild(tooltip);
  var originalBackground = '';
  var isEmphasized = false;

  function getCounts() {
    var distribution = getSeverityDistribution(CSPM_FINDINGS);
    return keys.map(function(key) { return distribution[key]; });
  }

  function emphasize(key, event) {
    var counts = getCounts();
    var total = counts.reduce(function(sum, count) { return sum + count; }, 0);
    if (!total) return;
    if (!isEmphasized) {
      originalBackground = donut.style.background;
      isEmphasized = true;
    }

    var activeIndex = keys.indexOf(key);
    var currentAngle = 0;
    var stops = [];
    counts.forEach(function(count, index) {
      if (!count) return;
      var start = currentAngle;
      currentAngle += count / total * 360;
      var color = SEVERITY_COLORS[keys[index]];
      var muted = "color-mix(in srgb, " + color + " 22%, var(--cc-surface) 78%)";
      stops.push((index === activeIndex ? color : muted) + ' ' + start + 'deg ' + currentAngle + 'deg');
    });
    donut.style.background = 'conic-gradient(' + stops.join(', ') + ')';

    var index = keys.indexOf(key);
    var count = counts[index] || 0;
    var pct = total ? Math.round(count / total * 100) : 0;
    tooltip.textContent = names[key] + ' · ' + count + ' findings · ' + pct + '%';
    if (event) {
      var bounds = panel.getBoundingClientRect();
      tooltip.style.left = Math.min(event.clientX - bounds.left + 9, bounds.width - 190) + 'px';
      tooltip.style.top = Math.max(8, event.clientY - bounds.top - 30) + 'px';
    }
    tooltip.classList.add('is-visible');
  }

  function reset() {
    donut.style.background = originalBackground;
    isEmphasized = false;
    tooltip.classList.remove('is-visible');
  }

  legend.addEventListener('mouseover', function(event) {
    var item = event.target.closest('.severity-item');
    if (!item) return;
    var index = Array.prototype.indexOf.call(legend.children, item);
    if (keys[index]) emphasize(keys[index], event);
  });
  donut.addEventListener('mousemove', function(event) {
    var bounds = donut.getBoundingClientRect();
    var dx = event.clientX - (bounds.left + bounds.width / 2);
    var dy = event.clientY - (bounds.top + bounds.height / 2);
    var angle = (Math.atan2(dx, -dy) * 180 / Math.PI + 360) % 360;
    var counts = getCounts();
    var total = counts.reduce(function(sum, count) { return sum + count; }, 0);
    var accumulated = 0;
    for (var i = 0; i < keys.length; i++) {
      accumulated += total ? counts[i] / total * 360 : 0;
      if (counts[i] && angle < accumulated) {
        emphasize(keys[i], event);
        break;
      }
    }
  });
  panel.addEventListener('mouseout', function(event) {
    if (!panel.contains(event.relatedTarget)) reset();
  });
})();

// The enhanced posture renderer is installed after the base initializer.
// Run it once now so the initial load uses the compact gauge presentation.
renderOverallPosture(CSPM_FINDINGS);
