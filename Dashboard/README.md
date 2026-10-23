# CSPM Dashboard

The dashboard is a static HTML application in [`code/`](./code/). It uses
the sample data in `code/data.js` by default and can be connected to live
scanner output without changing the page renderers.

## Connecting scanner output

1. Open `code/integration-config.js`.
2. Set `findingsUrl` to a same-origin or CORS-enabled endpoint.
3. Return either a JSON array or an object with a `findings` array.
4. Ensure each record contains `finding_id`, `severity`, and `status`, plus
   the fields consumed by the dashboard (`cloud`, `category`, `finding`,
   `resource_id`, and `risk_score`).

The loader is opt-in. If the URL is empty or unavailable, the bundled sample
data remains visible and the error is logged in the browser console.
