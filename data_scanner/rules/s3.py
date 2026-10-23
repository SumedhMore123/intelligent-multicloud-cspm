from network_scanner.models.finding import Finding


def check_public_bucket(bucket_name, acl):
    """Return a finding when an S3 bucket ACL grants access to the public."""
    public_groups = {
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    }

    for grant in acl.get("Grants", []):
        grantee = grant.get("Grantee", {})
        if grantee.get("Type") == "Group" and grantee.get("URI") in public_groups:
            return Finding(
                rule_id="DATA-001",
                resource_name=bucket_name,
                resource_id=bucket_name,
                category="Data Protection",
                severity="CRITICAL",
                description="S3 bucket is publicly accessible",
                evidence=f"Bucket ACL grants {grant.get('Permission', 'access')} to {grantee['URI']}",
                recommendation="Remove public ACL grants and restrict bucket access to trusted principals.",
            )

    return None


def check_public_bucket_policy(bucket_name, policy_status):
    """Return a finding when AWS reports the bucket policy as public."""
    if not policy_status.get("PolicyStatus", {}).get("IsPublic", False):
        return None

    return Finding(
        rule_id="DATA-003",
        resource_name=bucket_name,
        resource_id=bucket_name,
        category="Data Protection",
        severity="CRITICAL",
        description="S3 bucket policy allows public access",
        evidence="AWS reports the bucket policy as public",
        recommendation="Remove public bucket-policy principals and restrict access to trusted identities.",
    )


def check_public_object(bucket_name, object_key, acl):
    """Return a finding when an object's ACL grants access to the public."""
    public_groups = {
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    }

    for grant in acl.get("Grants", []):
        grantee = grant.get("Grantee", {})
        if grantee.get("Type") == "Group" and grantee.get("URI") in public_groups:
            return Finding(
                rule_id="DATA-004",
                resource_name=f"{bucket_name}/{object_key}",
                resource_id=f"{bucket_name}/{object_key}",
                category="Data Protection",
                severity="CRITICAL",
                description="S3 object ACL grants public access",
                evidence=(
                    f"Object ACL grants {grant.get('Permission', 'access')} "
                    f"to {grantee['URI']}"
                ),
                recommendation="Remove the public object ACL and restrict access to trusted principals.",
            )

    return None


def check_bucket_encryption(bucket_name, encryption):
    """Return a finding when an S3 bucket has no default encryption."""
    if encryption.get("ServerSideEncryptionConfiguration", {}).get("Rules"):
        return None

    return Finding(
        rule_id="DATA-002",
        resource_name=bucket_name,
        resource_id=bucket_name,
        category="Data Protection",
        severity="HIGH",
        description="S3 bucket does not have default encryption enabled",
        evidence="No server-side encryption rule is configured for the bucket",
        recommendation="Enable default SSE-S3 or SSE-KMS encryption for all new objects.",
    )
