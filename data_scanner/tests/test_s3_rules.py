from data_scanner.rules.s3 import (
    check_bucket_encryption,
    check_public_bucket,
    check_public_bucket_policy,
    check_public_object,
)


def test_public_bucket_acl_creates_critical_finding():
    acl = {
        "Grants": [
            {
                "Grantee": {
                    "Type": "Group",
                    "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                },
                "Permission": "READ",
            }
        ]
    }

    finding = check_public_bucket("customer-data", acl)

    assert finding.rule_id == "DATA-001"
    assert finding.severity == "CRITICAL"


def test_private_bucket_acl_has_no_public_finding():
    acl = {"Grants": [{"Grantee": {"Type": "CanonicalUser"}}]}

    assert check_public_bucket("customer-data", acl) is None


def test_public_bucket_policy_creates_critical_finding():
    finding = check_public_bucket_policy("customer-data", {"PolicyStatus": {"IsPublic": True}})

    assert finding.rule_id == "DATA-003"
    assert finding.severity == "CRITICAL"


def test_private_bucket_policy_has_no_public_finding():
    assert check_public_bucket_policy("customer-data", {"PolicyStatus": {"IsPublic": False}}) is None


def test_public_object_acl_creates_critical_finding():
    acl = {
        "Grants": [
            {
                "Grantee": {
                    "Type": "Group",
                    "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                },
                "Permission": "READ",
            }
        ]
    }

    finding = check_public_object("customer-data", "exports/report.csv", acl)

    assert finding.rule_id == "DATA-004"
    assert finding.resource_id == "customer-data/exports/report.csv"
    assert finding.severity == "CRITICAL"


def test_private_object_acl_has_no_public_finding():
    assert check_public_object("customer-data", "private.txt", {"Grants": []}) is None


def test_missing_encryption_creates_high_finding():
    finding = check_bucket_encryption("customer-data", {})

    assert finding.rule_id == "DATA-002"
    assert finding.severity == "HIGH"


def test_configured_encryption_has_no_finding():
    encryption = {
        "ServerSideEncryptionConfiguration": {
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        }
    }

    assert check_bucket_encryption("customer-data", encryption) is None
