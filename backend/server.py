"""Localhost-only HTTP API for explicitly requested IAM scans."""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .iam_service import IAMScanService, load_latest
from .network_service import NetworkScanService, load_latest as load_latest_network
from .data_service import DataScanService, load_latest as load_latest_data


service = IAMScanService()
network_service = NetworkScanService()
data_service = DataScanService()


class Handler(BaseHTTPRequestHandler):
    def _send(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        origin = self.headers.get("Origin")
        if origin in {"http://localhost:8000", "http://127.0.0.1:8000"}:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        if self.path.startswith("/api/"):
            self.send_response(204)
            origin = self.headers.get("Origin")
            if origin in {"http://localhost:8000", "http://127.0.0.1:8000"}:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type")
                self.send_header("Vary", "Origin")
            self.end_headers()
            return
        self._send(404, {"error": "Not found"})

    def do_GET(self):
        if self.path == "/api/health":
            return self._send(200, {"status": "ok"})
        if self.path == "/api/iam/status":
            return self._send(200, {"status": service.status, "latest": load_latest()})
        if self.path == "/api/iam/results":
            latest = load_latest()
            return self._send(200, latest or {"outcome": "NOT_SCANNED", "findings": []})
        if self.path == "/api/network/status":
            return self._send(200, {"status": network_service.status, "latest": load_latest_network()})
        if self.path == "/api/network/results":
            latest = load_latest_network()
            return self._send(200, latest or {"outcome": "NOT_SCANNED", "findings": []})
        if self.path == "/api/data/status":
            return self._send(200, {"status": data_service.status, "latest": load_latest_data()})
        if self.path == "/api/data/results":
            latest = load_latest_data()
            return self._send(200, latest or {"outcome": "NOT_SCANNED", "findings": []})
        self._send(404, {"error": "Not found"})

    def do_POST(self):
        if self.path not in {"/api/iam/scans", "/api/network/scans", "/api/data/scans"}:
            return self._send(404, {"error": "Not found"})
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length) or b"{}") if length else {}
        if not isinstance(body, dict):
            return self._send(400, {"error": "Request body must be an object"})
        if self.path in {"/api/network/scans", "/api/data/scans"}:
            for key in ("profile_name", "region_name"):
                if body.get(key) is not None and (not isinstance(body[key], str) or len(body[key]) > 128):
                    return self._send(400, {"error": f"{key} must be a short text value"})
            service = network_service if self.path == "/api/network/scans" else data_service
            result = service.start(body.get("profile_name"), body.get("region_name"))
        else:
            result = service.start()
        if result is None:
            return self._send(409, {"error": "A scan is already running"})
        self._send(202, {"status": result})

    def log_message(self, *_):
        return


def run(host="127.0.0.1", port=8765):
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    run()
