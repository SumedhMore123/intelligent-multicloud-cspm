from .aws_client import get_s3_client
from .rules.s3 import check_bucket_encryption, check_public_bucket


def scan_buckets(s3_client):
    """Scan all accessible S3 buckets for public access and encryption gaps."""
    findings = []
    buckets = s3_client.list_buckets().get("Buckets", [])

    for bucket in buckets:
        bucket_name = bucket["Name"]
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
        public_finding = check_public_bucket(bucket_name, acl)
        if public_finding:
            findings.append(public_finding)

        try:
            encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
        except s3_client.exceptions.ClientError as error:
            if error.response.get("Error", {}).get("Code") != "ServerSideEncryptionConfigurationNotFoundError":
                raise
            encryption = {}

        encryption_finding = check_bucket_encryption(bucket_name, encryption)
        if encryption_finding:
            findings.append(encryption_finding)

    return findings


def main():
    s3 = get_s3_client()
    for finding in scan_buckets(s3):
        print(f"[DATA FINDING] {finding.rule_id}")
        print(f"Resource: {finding.resource_name} ({finding.resource_id})")
        print(f"Description: {finding.description}")
        print(f"Severity: {finding.severity}")
        print(f"Evidence: {finding.evidence}")
        print(f"Recommendation: {finding.recommendation}")
        print(f"Status: {finding.status}")


if __name__ == "__main__":
    main()
