const fs = require('fs');

const analyticsCss = `
/* ============================================================
   SEVERITY DONUT
   ============================================================ */
.severity-overview {
  display: flex;
  align-items: center;
  gap: 24px;
  padding: 10px 0;
}

.severity-chart-wrap {
  position: relative;
  width: 140px;
  height: 140px;
  flex-shrink: 0;
}

.donut {
  width: 100%;
  height: 100%;
  border-radius: 50%;
  position: relative;
  transition: transform 0.3s var(--cc-ease, ease);
}

.donut::after {
  content: "";
  position: absolute;
  inset: 22px; /* controls donut thickness */
  background: var(--bg-panel);
  border-radius: 50%;
  transition: background 0.3s var(--cc-ease, ease);
}

.dashboard-donut-hole {
  position: absolute;
  inset: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  z-index: 2;
  pointer-events: none;
}
.dashboard-donut-hole strong {
  font-size: 28px;
  font-weight: 700;
  color: var(--ink-strong);
  line-height: 1;
}
.dashboard-donut-hole span {
  font-size: 12px;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-top: 4px;
}

.severity-list {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.severity-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 6px 10px;
  border-radius: var(--radius-sm);
  transition: background 0.2s;
  cursor: default;
}
.severity-item:hover {
  background: var(--surface-soft);
}

.severity-item-left {
  display: flex;
  align-items: center;
  gap: 10px;
}

.severity-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
}
.critical-dot { background: var(--critical); }
.high-dot { background: var(--high); }
.medium-dot { background: var(--medium); }
.low-dot { background: var(--pass); }

.severity-label {
  font-size: 13px;
  font-weight: 600;
  color: var(--ink);
}

.severity-item-right {
  display: flex;
  align-items: center;
  gap: 12px;
}

.severity-count {
  font-size: 14px;
  font-weight: 700;
  color: var(--ink-strong);
}

.severity-pct {
  font-size: 12px;
  color: var(--muted);
  width: 32px;
  text-align: right;
}

/* ============================================================
   FINDINGS TREND
   ============================================================ */
.trend-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}

.trend-legend {
  display: flex;
  gap: 16px;
  margin-bottom: 20px;
}
.trend-legend-item {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: var(--muted);
  font-weight: 500;
}

.trend-chart-wrapper {
  position: relative;
  width: 100%;
  height: 200px;
  flex-grow: 1;
}

.chart-line {
  fill: none;
  stroke-width: 2.5;
  stroke-linecap: round;
  stroke-linejoin: round;
}
.chart-point {
  stroke-width: 2;
  stroke: var(--bg-panel);
  transition: r 0.2s;
}
.chart-point:hover {
  r: 6;
}
.chart-grid-line {
  stroke: var(--border-soft);
  stroke-width: 1;
  stroke-dasharray: 4 4;
}
.chart-axis-text {
  font-size: 11px;
  fill: var(--muted-light);
  font-weight: 500;
}

.chart-tooltip {
  position: absolute;
  top: 0;
  left: 0;
  background: var(--ink-strong);
  color: var(--bg-panel);
  padding: 10px 14px;
  border-radius: var(--radius-sm);
  font-size: 12px;
  pointer-events: none;
  opacity: 0;
  transform: translate(-50%, -100%);
  transition: opacity 0.2s, top 0.1s, left 0.1s;
  z-index: 10;
  box-shadow: 0 8px 16px rgba(0,0,0,0.15);
  white-space: nowrap;
}
.chart-tooltip-date {
  font-weight: 600;
  margin-bottom: 8px;
  color: #FFFFFF;
  border-bottom: 1px solid rgba(255,255,255,0.15);
  padding-bottom: 6px;
}
.chart-tooltip-row {
  display: flex;
  justify-content: space-between;
  gap: 20px;
  margin-bottom: 4px;
}
.chart-tooltip-row:last-child { margin-bottom: 0; }
.chart-tooltip-row span:first-child { font-weight: 500; }
.chart-tooltip-row span:last-child { font-weight: 700; color: #FFFFFF; }

/* ============================================================
   TOP FINDINGS
   ============================================================ */
.top-findings-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.top-finding-item {
  display: flex;
  flex-direction: column;
  padding: 12px 14px;
  background: var(--surface-soft);
  border: 1px solid var(--border-soft);
  border-radius: var(--radius-md);
  position: relative;
  overflow: hidden;
  transition: background 0.2s, border-color 0.2s;
  cursor: pointer;
}
.top-finding-item:hover {
  background: var(--bg-panel);
  border-color: var(--border);
  box-shadow: var(--shadow-sm);
}

.finding-left-critical::before { content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 3px; background: var(--critical); }
.finding-left-high::before { content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 3px; background: var(--high); }
.finding-left-medium::before { content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 3px; background: var(--medium); }
.finding-left-low::before { content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 3px; background: var(--pass); }

.top-finding-title-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 12px;
  margin-bottom: 6px;
}

.finding-title {
  font-size: 13px;
  font-weight: 600;
  color: var(--ink-strong);
  line-height: 1.4;
  flex: 1;
}

.finding-badge {
  font-size: 10px;
  font-weight: 700;
  padding: 2px 6px;
  border-radius: 4px;
  text-transform: uppercase;
  flex-shrink: 0;
}
.badge-sev-critical { background: var(--critical-bg); color: var(--critical); }
.badge-sev-high { background: var(--high-bg); color: var(--high); }
.badge-sev-medium { background: var(--medium-bg); color: var(--medium); }
.badge-sev-low { background: var(--pass-bg); color: var(--pass); }

.top-finding-meta {
  display: flex;
  align-items: center;
  gap: 12px;
  font-size: 11px;
  color: var(--muted);
}
.meta-item { display: flex; align-items: center; gap: 4px; }
`;
fs.writeFileSync('analytics.css', analyticsCss);
