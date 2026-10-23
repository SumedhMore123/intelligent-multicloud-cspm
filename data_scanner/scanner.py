from .aws_client import get_s3_client
from .rules.s3 import (
    check_bucket_encryption,
    check_public_bucket,
    check_public_bucket_policy,
    check_public_object,
)
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound


class DataScanError(RuntimeError):
    """A readable, actionable data scan failure."""


def scan_buckets(s3_client):
    """Scan all accessible S3 buckets for public access and encryption gaps."""
    findings = []
    try:
        buckets = s3_client.list_buckets().get("Buckets", [])
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "AWS error")
        message = error.response.get("Error", {}).get("Message", "AWS rejected the request")
        raise DataScanError(
            f"AWS denied data scan ({code}): {message}. "
            "Grant read-only permissions for s3:ListAllMyBuckets, "
            "s3:GetBucketAcl, s3:GetBucketPolicyStatus, s3:ListBucket, "
            "s3:GetObjectAcl, and s3:GetEncryptionConfiguration."
        ) from error
    except (NoCredentialsError, ProfileNotFound) as error:
        raise DataScanError(
            "AWS credentials are unavailable. Configure an AWS CLI profile or "
            "the standard boto3 credential chain, then retry the scan."
        ) from error

    for bucket in buckets:
        bucket_name = bucket["Name"]
        try:
            acl = s3_client.get_bucket_acl(Bucket=bucket_name)
        except ClientError as error:
            code = error.response.get("Error", {}).get("Code", "AWS error")
            message = error.response.get("Error", {}).get("Message", "AWS rejected the request")
            raise DataScanError(
                f"AWS denied access to S3 bucket {bucket_name} ({code}): {message}. "
                "Grant s3:GetBucketAcl, s3:GetBucketPolicyStatus, and "
                "s3:GetEncryptionConfiguration."
            ) from error
        public_finding = check_public_bucket(bucket_name, acl)

        try:
            policy_status = s3_client.get_bucket_policy_status(Bucket=bucket_name)
        except ClientError as error:
            code = error.response.get("Error", {}).get("Code", "AWS error")
            if code == "NoSuchBucketPolicy":
                policy_status = {}
            else:
                raise DataScanError(
                    f"AWS could not evaluate the policy for S3 bucket {bucket_name} "
                    f"({code}). Grant s3:GetBucketPolicyStatus and retry."
                ) from error
        policy_finding = check_public_bucket_policy(bucket_name, policy_status)

        try:
            public_access_block = s3_client.get_public_access_block(Bucket=bucket_name)
        except ClientError as error:
            code = error.response.get("Error", {}).get("Code", "AWS error")
            if code == "NoSuchPublicAccessBlockConfiguration":
                public_access_block = {}
            else:
                raise DataScanError(
                    f"AWS could not evaluate Public Access Block for S3 bucket "
                    f"{bucket_name} ({code}). Grant s3:GetBucketPublicAccessBlock "
                    "and retry."
                ) from error
        if policy_finding and public_access_block:
            policy_finding.evidence += (
                f"; bucket Public Access Block: "
                f"{public_access_block.get('PublicAccessBlockConfiguration', {})}"
            )

        if public_finding or policy_finding:
            block_context = (
                f"bucket Public Access Block: "
                f"{public_access_block.get('PublicAccessBlockConfiguration', {})}"
            )
            for finding in (public_finding, policy_finding):
                if finding:
                    finding.evidence += block_context
                    findings.append(finding)

        try:
            object_pages = s3_client.get_paginator("list_objects_v2").paginate(
                Bucket=bucket_name
            )
            for page in object_pages:
                for obj in page.get("Contents", []):
                    object_key = obj["Key"]
                    try:
                        object_acl = s3_client.get_object_acl(
                            Bucket=bucket_name,
                            Key=object_key,
                        )
                    except ClientError as error:
                        code = error.response.get("Error", {}).get("Code", "AWS error")
                        raise DataScanError(
                            f"AWS could not evaluate ACL for S3 object "
                            f"{bucket_name}/{object_key} ({code}). Grant "
                            "s3:GetObjectAcl and retry."
                        ) from error
                    object_finding = check_public_object(
                        bucket_name, object_key, object_acl
                    )
                    if object_finding:
                        findings.append(object_finding)
        except ClientError as error:
            code = error.response.get("Error", {}).get("Code", "AWS error")
            raise DataScanError(
                f"AWS could not list objects in S3 bucket {bucket_name} ({code}). "
                "Grant s3:ListBucket and retry."
            ) from error

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
