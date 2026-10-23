"""Data scan orchestration and durable result storage."""

import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

import boto3

from data_scanner.scanner import scan_buckets


ROOT = Path(__file__).resolve().parent.parent
RESULTS_PATH = ROOT / "scan_results" / "latest_data_scan.json"


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def to_record(finding, detected_at):
    record = finding.to_dict()
    severity = str(record["severity"]).upper()
    return {
        "finding_id": f"{record['rule_id']}:{record['resource_id']}",
        "rule_id": record["rule_id"],
        "cloud": "AWS",
        "domain": "Data",
        "category": record["category"],
        "resource_type": "S3Bucket",
        "resource_id": record["resource_id"],
        "resource_name": record["resource_name"],
        "finding": record["description"],
        "severity": severity,
        "evidence": record["evidence"],
        "recommendation": record["recommendation"],
        "status": str(record["status"]).upper(),
        "risk_score": {"CRITICAL": 10, "HIGH": 8, "MEDIUM": 5, "LOW": 2}.get(severity),
        "detected_at": detected_at,
        "source": "live-data-scan",
    }


def validate_findings(findings):
    if not isinstance(findings, list):
        raise ValueError("Data scanner returned a non-list result")
    required = (
        "finding_id", "cloud", "domain", "category", "resource_type",
        "resource_id", "finding", "severity", "status", "detected_at",
    )
    for index, finding in enumerate(findings, 1):
        if not isinstance(finding, dict) or any(not finding.get(field) for field in required):
            raise ValueError(f"Data scanner returned an invalid finding at position {index}")
        if finding.get("source") != "live-data-scan":
            raise ValueError(f"Data scanner returned an unexpected source at position {index}")
    return findings


def load_latest():
    if not RESULTS_PATH.exists():
        return None
    try:
        data = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
        validate_findings(data["findings"])
        return data
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        return None


def atomic_write(data):
    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = RESULTS_PATH.with_name(f".{RESULTS_PATH.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(temporary, RESULTS_PATH)


class DataScanService:
    def __init__(self, scanner=scan_buckets):
        self.scanner = scanner
        self.lock = threading.Lock()
        self.status = {"state": "NOT_SCANNED", "job_id": None, "error": None}

    def start(self, profile_name=None, region_name=None):
        if not self.lock.acquire(blocking=False):
            return None
        job_id = uuid.uuid4().hex
        self.status = {
            "state": "RUNNING",
            "job_id": job_id,
            "profile_name": profile_name,
            "region_name": region_name,
            "started_at": utc_now(),
            "error": None,
        }
        threading.Thread(
            target=self._run,
            args=(job_id, profile_name, region_name),
            daemon=True,
        ).start()
        return self.status.copy()

    def _run(self, job_id, profile_name, region_name):
        try:
            client = boto3.Session(
                profile_name=profile_name or None,
                region_name=region_name or None,
            ).client("s3")
            detected_at = utc_now()
            findings = validate_findings([
                to_record(finding, detected_at)
                for finding in self.scanner(client)
            ])
            completed = utc_now()
            atomic_write({
                "schema_version": 1,
                "scanner": "data",
                "source": "live-data-scan",
                "job_id": job_id,
                "profile_name": profile_name,
                "region_name": region_name,
                "started_at": self.status["started_at"],
                "completed_at": completed,
                "outcome": "SUCCESS",
                "findings": findings,
                "summary": {
                    "total": len(findings),
                    "open": sum(f["status"] == "OPEN" for f in findings),
                },
            })
            self.status.update({"state": "SUCCEEDED", "completed_at": completed})
        except Exception as error:
            self.status.update({
                "state": "FAILED",
                "completed_at": utc_now(),
                "error": str(error)[:300],
            })
        finally:
            self.lock.release()
