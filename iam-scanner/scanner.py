"""Read-only AWS IAM scanner.

The scanner uses boto3's standard credential chain and returns structured
records. It does not change IAM users, credentials, policies, or account
settings.
"""

import json
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound


class IAMScanError(RuntimeError):
    """A readable, actionable IAM scan failure."""


def scan_iam(iam_client=None, now=None):
    """Run the IAM checks and return one normalized record per check."""
    iam = iam_client or boto3.client("iam")
    scan_time = now or datetime.now(timezone.utc)
    findings = []

    try:
        return _scan_users(iam, scan_time)
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "AWS error")
        message = error.response.get("Error", {}).get("Message", "AWS rejected the request")
        raise IAMScanError(
            f"AWS denied IAM scan ({code}): {message}. "
            "Grant the scanner read-only permissions: iam:ListUsers, "
            "iam:ListMFADevices, iam:ListAccessKeys, and iam:GetAccessKeyLastUsed."
        ) from error
    except (NoCredentialsError, ProfileNotFound) as error:
        raise IAMScanError(
            "AWS credentials are unavailable. Configure the standard boto3 credential "
            "chain or AWS profile, then retry the scan."
        ) from error


def _scan_users(iam, scan_time):
    findings = []
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page.get("Users", []):
            username = user["UserName"]
            resource_id = f"iam-user/{username}"
            mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
            findings.append(_record(
                "IAM-001", username, resource_id, "MFA is enabled" if mfa_devices else "MFA is not enabled",
                "PASS" if mfa_devices else "HIGH",
                f"IAM user '{username}' has MFA configured" if mfa_devices else f"IAM user '{username}' has no MFA device configured",
                "No action required" if mfa_devices else "Enable MFA for the IAM user",
                scan_time,
            ))

            active_keys = [
                key for key in iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
                if key.get("Status") == "Active"
            ]
            if not active_keys:
                findings.append(_record(
                    "IAM-002", username, resource_id, "No active access keys found", "PASS",
                    f"IAM user '{username}' has no active access keys", "No action required", scan_time,
                ))
                findings.append(_record(
                    "IAM-003", username, resource_id, "No active credentials to check", "PASS",
                    f"IAM user '{username}' has no active access keys", "No action required", scan_time,
                ))
                continue

            for key in active_keys:
                key_id = key["AccessKeyId"]
                age = (scan_time - _as_utc(key["CreateDate"])).days
                findings.append(_record(
                    "IAM-002", username, f"{resource_id}/access-key/{key_id}",
                    "Access key is older than 90 days" if age > 90 else "Access key is within the 90-day rotation period",
                    "MEDIUM" if age > 90 else "PASS",
                    f"Access key {key_id} is {age} days old",
                    "Rotate the access key" if age > 90 else "No action required",
                    scan_time,
                ))

                last_used = iam.get_access_key_last_used(AccessKeyId=key_id)
                last_used_date = last_used.get("AccessKeyLastUsed", {}).get("LastUsedDate")
                findings.append(_record(
                    "IAM-003", username, f"{resource_id}/access-key/{key_id}",
                    "Access key has never been used" if not last_used_date else "Access key has been used",
                    "MEDIUM" if not last_used_date else "PASS",
                    f"Access key {key_id} has no recorded usage" if not last_used_date
                    else f"Access key {key_id} was last used on {_as_utc(last_used_date).isoformat()}",
                    "Deactivate or delete the unused access key" if not last_used_date else "No action required",
                    scan_time,
                ))

    return findings


def _as_utc(value):
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _record(rule_id, username, resource_id, finding, severity, evidence, recommendation, scan_time):
    risk_score = {"CRITICAL": 10, "HIGH": 8, "MEDIUM": 5, "LOW": 2}.get(severity)
    return {
        "finding_id": f"{rule_id}:{resource_id}",
        "rule_id": rule_id,
        "cloud": "AWS",
        "domain": "IAM",
        "category": "IAM Security",
        "resource_type": "IAMUser",
        "resource_id": resource_id,
        "resource_name": username,
        "finding": finding,
        "severity": severity,
        "evidence": evidence,
        "recommendation": recommendation,
        "status": "OPEN" if severity not in {"PASS", "INFO"} else severity,
        "risk_score": risk_score,
        "detected_at": scan_time.isoformat(),
        "source": "live-iam-scan",
    }


def main():
    try:
        print(json.dumps(scan_iam(), indent=2))
    except IAMScanError as error:
        print(json.dumps({"outcome": "FAILED", "error": str(error)}, indent=2))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
