"""Convert canonical scanner findings to the dashboard data contract."""

import json
from pathlib import Path


def to_dashboard_finding(finding, cloud="AWS", detected_at=None):
    """Return a finding shaped for the dashboard's shared data layer."""
    record = finding.to_dict() if hasattr(finding, "to_dict") else dict(finding)
    severity = str(record["severity"]).upper()
    risk_score = {
        "CRITICAL": 10,
        "HIGH": 8,
        "MEDIUM": 5,
        "LOW": 2,
    }.get(severity, 0)

    result = {
        "finding_id": record["rule_id"],
        "cloud": cloud,
        "resource_type": "SecurityGroup",
        "resource_id": record["resource_id"],
        "resource_name": record["resource_name"],
        "category": record["category"],
        "finding": record["description"],
        "severity": severity,
        "evidence": record["evidence"],
        "recommendation": record["recommendation"],
        "status": str(record["status"]).upper(),
        "risk_score": risk_score,
    }
    if detected_at is not None:
        result["detected_at"] = detected_at
    return result


def write_dashboard_findings(findings, output_path, cloud="AWS", detected_at=None):
    """Write scanner findings as a dashboard-compatible JSON array."""
    records = [
        to_dashboard_finding(finding, cloud=cloud, detected_at=detected_at)
        for finding in findings
    ]
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(records, indent=2), encoding="utf-8")
