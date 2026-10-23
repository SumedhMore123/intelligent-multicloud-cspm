from network_scanner.integrations.dashboard import to_dashboard_finding
from network_scanner.models.finding import Finding


def test_dashboard_adapter_preserves_finding_contract():
    finding = Finding(
        rule_id="NET-001",
        resource_name="public-sg",
        resource_id="sg-123",
        category="Network Security",
        severity="HIGH",
        description="SSH exposed to the Internet",
        evidence="TCP port 22 allows 0.0.0.0/0",
        recommendation="Restrict SSH access.",
    )

    result = to_dashboard_finding(finding)

    assert result["finding_id"] == "NET-001"
    assert result["resource_id"] == "sg-123"
    assert result["finding"] == "SSH exposed to the Internet"
    assert result["risk_score"] == 8
