/*
 * Optional scanner integration settings.
 *
 * Set findingsUrl to an API endpoint that returns either a JSON array of
 * dashboard findings or { "findings": [...] }. An empty value keeps the
 * bundled sample data active.
 */
window.CSPM_CONFIG = window.CSPM_CONFIG || {
  findingsUrl: ""
};
