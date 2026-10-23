from datetime import datetime, timezone

from backend import data_service
from network_scanner.models.finding import Finding


def test_to_record_normalizes_data_finding():
    finding = Finding(
        "DATA-002",
        "reports",
        "reports",
        "Data Protection",
        "HIGH",
        "S3 bucket does not have default encryption enabled",
        "No encryption rule",
        "Enable encryption",
    )

    record = data_service.to_record(finding, datetime(2026, 1, 1, tzinfo=timezone.utc).isoformat())

    assert record["finding_id"] == "DATA-002:reports"
    assert record["domain"] == "Data"
    assert record["resource_type"] == "S3Bucket"
    assert record["source"] == "live-data-scan"
    assert record["risk_score"] == 8


def test_data_service_preserves_previous_result_on_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(data_service, "RESULTS_PATH", tmp_path / "latest.json")
    previous = {
        "source": "live-data-scan",
        "findings": [],
    }
    data_service.atomic_write(previous)

    class FailingScanner:
        def __call__(self, _client):
            raise RuntimeError("permission denied")

    class FakeSession:
        def client(self, _service):
            return object()

    monkeypatch.setattr(data_service.boto3, "Session", lambda **_kwargs: FakeSession())
    service = data_service.DataScanService(scanner=FailingScanner())
    service.lock.acquire()
    service._run("job", None, None)

    assert data_service.load_latest() == previous
    assert service.status["state"] == "FAILED"