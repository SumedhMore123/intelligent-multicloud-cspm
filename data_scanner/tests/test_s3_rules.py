from data_scanner.rules.s3 import check_bucket_encryption, check_public_bucket


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
