import json
import time

from backend import iam_service


def test_scan_service_writes_validated_empty_success(tmp_path, monkeypatch):
    monkeypatch.setattr(iam_service, "RESULTS_PATH", tmp_path / "latest.json")
    service = iam_service.IAMScanService(scanner=type("Scanner", (), {"scan_iam": lambda self: []})())

    started = service.start()
    assert started["state"] == "RUNNING"
    deadline = time.time() + 2
    while service.status["state"] == "RUNNING" and time.time() < deadline:
        time.sleep(0.01)

    latest = iam_service.load_latest()
    assert latest["outcome"] == "SUCCESS"
    assert latest["findings"] == []
    assert json.loads((tmp_path / "latest.json").read_text())["summary"]["total"] == 0


def test_failed_scan_preserves_previous_success(tmp_path, monkeypatch):
    monkeypatch.setattr(iam_service, "RESULTS_PATH", tmp_path / "latest.json")
    previous = {
        "source": "live-iam-scan",
        "findings": [],
    }
    iam_service.atomic_write(previous)

    class FailingScanner:
        def scan_iam(self):
            raise RuntimeError("credentials unavailable")

    service = iam_service.IAMScanService(scanner=FailingScanner())
    service.start()
    deadline = time.time() + 2
    while service.status["state"] == "RUNNING" and time.time() < deadline:
        time.sleep(0.01)

    assert service.status["state"] == "FAILED"
    assert iam_service.load_latest() == previous
