from datetime import datetime, timezone

from backend import network_service
from network_scanner.models.finding import Finding


def test_network_finding_is_normalized_for_dashboard():
    finding = Finding(
        "NET-001",
        "public-sg",
        "sg-123",
        "Network Security",
        "HIGH",
        "SSH exposed to the Internet",
        "TCP port 22 allows 0.0.0.0/0",
        "Restrict SSH access.",
    )
    result = network_service.to_record(finding, datetime(2026, 1, 1, tzinfo=timezone.utc).isoformat())

    assert result["finding_id"] == "NET-001:sg-123"
    assert result["domain"] == "Network"
    assert result["source"] == "live-network-scan"
    assert result["risk_score"] == 8
