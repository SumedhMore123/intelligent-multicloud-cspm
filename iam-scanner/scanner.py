import boto3
import json
from datetime import datetime, timezone

# Connect to AWS IAM
iam = boto3.client("iam")

# Get all IAM users
users = iam.list_users()["Users"]

findings = []

# Check each IAM user
for user in users:
    username = user["UserName"]

    user_result = {
        "cloud": "AWS",
        "resource": username,
        "resource_type": "IAM User",
        "checks": {}
    }

    # -------------------------
    # IAM-001: MFA Check
    # -------------------------
    mfa_devices = iam.list_mfa_devices(
        UserName=username
    )["MFADevices"]

    if not mfa_devices:
        user_result["checks"]["IAM-001"] = {
            "finding": "MFA is not enabled",
            "severity": "HIGH",
            "evidence": f"IAM user '{username}' has no MFA device configured",
            "status": "OPEN",
            "recommendation": "Enable MFA for the IAM user"
        }
    else:
        user_result["checks"]["IAM-001"] = {
            "finding": "MFA is enabled",
            "severity": "PASS",
            "evidence": f"IAM user '{username}' has MFA configured",
            "status": "PASS",
            "recommendation": "No action required"
        }

    # -------------------------
    # IAM-002: Access Key Age
    # -------------------------
    access_keys = iam.list_access_keys(
        UserName=username
    )["AccessKeyMetadata"]

    active_keys = [
        key for key in access_keys
        if key["Status"] == "Active"
    ]

    # Store results for each active key
    key_results = []

    for key in active_keys:

        key_age = (
            datetime.now(timezone.utc) - key["CreateDate"]
        ).days

        if key_age > 90:
            key_results.append({
                "finding": "Access key is older than 90 days",
                "severity": "MEDIUM",
                "evidence": f"Access key {key['AccessKeyId']} is {key_age} days old",
                "status": "OPEN",
                "recommendation": "Rotate the access key"
            })
        else:
            key_results.append({
                "finding": "Access key is within the 90-day rotation period",
                "severity": "PASS",
                "evidence": f"Access key {key['AccessKeyId']} is {key_age} days old",
                "status": "PASS",
                "recommendation": "No action required"
            })

    # If no active access keys exist
    if not active_keys:
        key_results.append({
            "finding": "No active access keys found",
            "severity": "PASS",
            "evidence": f"IAM user '{username}' has no active access keys",
            "status": "PASS",
            "recommendation": "No action required"
        })

    user_result["checks"]["IAM-002"] = key_results

    # Add this user's complete result
    findings.append(user_result)

    # -------------------------
    # IAM-003: Unused Credentials
    # -------------------------
    unused_credential_results = []

    for key in active_keys:

        last_used = iam.get_access_key_last_used(
            AccessKeyId=key["AccessKeyId"]
        )

        last_used_date = last_used.get(
            "AccessKeyLastUsed", {}
        ).get("LastUsedDate")

        if not last_used_date:
            unused_credential_results.append({
                "finding": "Access key has never been used",
                "severity": "MEDIUM",
                "evidence": f"Access key {key['AccessKeyId']} has no recorded usage",
                "status": "OPEN",
                "recommendation": "Deactivate or delete the unused access key"
            })
        else:
            unused_credential_results.append({
                "finding": "Access key has been used",
                "severity": "PASS",
                "evidence": f"Access key {key['AccessKeyId']} was last used on {last_used_date.isoformat()}",
                "status": "PASS",
                "recommendation": "No action required"
            })

    # No active access keys
    if not active_keys:
        unused_credential_results.append({
            "finding": "No active credentials to check",
            "severity": "PASS",
            "evidence": f"IAM user '{username}' has no active access keys",
            "status": "PASS",
            "recommendation": "No action required"
        })

    user_result["checks"]["IAM-003"] = unused_credential_results


# Display findings
for finding in findings:
    print(json.dumps(finding, indent=4))