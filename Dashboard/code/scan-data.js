/* Applies saved live scanner results over only their matching demo domain. */
(function () {
  "use strict";
  function apply(key, source, domain) {
    var raw = null;
    try { raw = window.localStorage.getItem(key); } catch (error) {
      console.error("Unable to read saved scanner result:", error);
    }
    if (!raw) return;
    try {
      var payload = JSON.parse(raw);
      if (payload && Array.isArray(payload.findings) && payload.source === source) {
      for (var index = SAMPLE_FINDINGS.length - 1; index >= 0; index -= 1) {
        if (String(SAMPLE_FINDINGS[index].domain || SAMPLE_FINDINGS[index].category || "").toUpperCase().includes(domain)) {
          SAMPLE_FINDINGS.splice(index, 1);
        }
      }
      payload.findings.forEach(function (finding) { SAMPLE_FINDINGS.push(finding); });
      window["CSPM_LIVE_" + domain + "_META"] = payload;
      }
    } catch (error) {
      console.error("Unable to load saved scanner result:", error);
    }
  }
  apply("cspm-live-iam-scan", "live-iam-scan", "IAM");
  apply("cspm-live-network-scan", "live-network-scan", "NETWORK");
  apply("cspm-live-data-scan", "live-data-scan", "DATA");
})();
