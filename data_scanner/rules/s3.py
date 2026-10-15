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
