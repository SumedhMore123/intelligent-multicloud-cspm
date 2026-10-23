/*
 * Opt-in loader for live scanner results.
 * The static sample remains the fallback when no endpoint is configured or
 * when the endpoint is unavailable, so the dashboard remains usable offline.
 */
(function () {
  "use strict";

  var config = window.CSPM_CONFIG || {};

  function apply(findings, domain) {
    for (var index = window.CSPM_FINDINGS.length - 1; index >= 0; index -= 1) {
      if (String(window.CSPM_FINDINGS[index].domain || window.CSPM_FINDINGS[index].category || "").toUpperCase().includes(domain)) {
        window.CSPM_FINDINGS.splice(index, 1);
      }
    }
    findings.forEach(function (finding) {
      window.CSPM_FINDINGS.push(finding);
    });
    if (typeof window.refreshDashboard === "function") window.refreshDashboard();
  }

  [
    ["cspm-live-iam-scan", "IAM"],
    ["cspm-live-network-scan", "NETWORK"],
    ["cspm-live-data-scan", "DATA"]
  ].forEach(function (entry) {
    var key = entry[0];
    var domain = entry[1];
    try {
      var saved = window.localStorage.getItem(key);
      if (saved) {
        var savedPayload = JSON.parse(saved);
        if (Array.isArray(savedPayload.findings)) apply(savedPayload.findings, domain);
      }
    } catch (error) {
      console.error("Unable to apply saved scanner result:", error);
    }
  });
  if (typeof window.refreshDashboard === "function") {
    window.setTimeout(window.refreshDashboard, 0);
  }
  if (!config.findingsUrl) return;

  function normalize(payload) {
    var findings = Array.isArray(payload) ? payload : payload && payload.findings;
    if (!Array.isArray(findings)) {
      throw new Error("Scanner response must be an array or an object with findings");
    }
    return findings;
  }

  fetch(config.findingsUrl, { cache: "no-store" })
    .then(function (response) {
      if (!response.ok) throw new Error("Scanner endpoint returned HTTP " + response.status);
      return response.json();
    })
    .then(function (payload) {
      var findings = normalize(payload);
      if (!findings.every(function (finding) {
        return finding && finding.finding_id && finding.severity && finding.status;
      })) {
        throw new Error("Scanner response contains an invalid finding");
      }

      apply(findings, "DATA");
    })
    .catch(function (error) {
      console.error("Unable to load live scanner findings:", error);
    });
})();
