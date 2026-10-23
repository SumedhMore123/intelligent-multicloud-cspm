import importlib.util
from datetime import datetime, timezone


def load_scanner():
    spec = importlib.util.spec_from_file_location("iam_scanner", "iam-scanner/scanner.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeIAM:
    def get_paginator(self, name):
        assert name == "list_users"
        return type("Paginator", (), {"paginate": lambda self: [{"Users": [{"UserName": "alice"}]}]})()

    def list_mfa_devices(self, UserName):
        return {"MFADevices": []}

    def list_access_keys(self, UserName):
        return {"AccessKeyMetadata": []}


def test_scanner_returns_stable_normalized_records():
    scanner = load_scanner()
    records = scanner.scan_iam(FakeIAM(), datetime(2026, 1, 1, tzinfo=timezone.utc))

    assert records[0]["finding_id"] == "IAM-001:iam-user/alice"
    assert records[0]["domain"] == "IAM"
    assert records[0]["status"] == "OPEN"
    assert records[1]["status"] == "PASS"
