"""IAM scan orchestration, validation, and durable result storage."""

import importlib.util
import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RESULTS_PATH = ROOT / "scan_results" / "latest_iam_scan.json"
SCANNER_PATH = ROOT / "iam-scanner" / "scanner.py"


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def load_scanner():
    spec = importlib.util.spec_from_file_location("cspm_iam_scanner", SCANNER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("IAM scanner could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_findings(findings):
    if not isinstance(findings, list):
        raise ValueError("IAM scanner returned a non-list result")
    required = ("finding_id", "cloud", "domain", "category", "resource_type",
                "resource_id", "finding", "severity", "status", "detected_at")
    for index, finding in enumerate(findings, 1):
        if not isinstance(finding, dict) or any(not finding.get(field) for field in required):
            raise ValueError(f"IAM scanner returned an invalid finding at position {index}")
        if finding["source"] != "live-iam-scan":
            raise ValueError(f"IAM scanner returned an unexpected source at position {index}")
        if finding["risk_score"] is not None and not isinstance(finding["risk_score"], (int, float)):
            raise ValueError(f"IAM scanner returned an invalid risk score at position {index}")
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


class IAMScanService:
    def __init__(self, scanner=None):
        self.scanner = scanner
        self.lock = threading.Lock()
        self.status = {"state": "NOT_SCANNED", "job_id": None, "error": None}

    def start(self):
        if not self.lock.acquire(blocking=False):
            return None
        job_id = uuid.uuid4().hex
        self.status = {"state": "RUNNING", "job_id": job_id, "started_at": utc_now(), "error": None}
        threading.Thread(target=self._run, args=(job_id,), daemon=True).start()
        return self.status.copy()

    def _run(self, job_id):
        try:
            scanner = self.scanner or load_scanner()
            findings = validate_findings(scanner.scan_iam())
            completed = utc_now()
            atomic_write({
                "schema_version": 1,
                "scanner": "iam",
                "source": "live-iam-scan",
                "job_id": job_id,
                "started_at": self.status["started_at"],
                "completed_at": completed,
                "outcome": "SUCCESS",
                "findings": findings,
                "summary": {"total": len(findings), "open": sum(f["status"] == "OPEN" for f in findings)},
            })
            self.status.update({"state": "SUCCEEDED", "completed_at": completed})
        except Exception as error:
            self.status.update({"state": "FAILED", "completed_at": utc_now(), "error": _safe_error(error)})
        finally:
            self.lock.release()


def _safe_error(error):
    text = str(error)
    return text if len(text) < 300 else text[:297] + "..."
