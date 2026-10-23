import boto3


def get_ec2_client(profile_name=None, region_name=None):
    """Create an EC2 client from an explicit profile or default chain."""
    if profile_name or region_name:
        return boto3.Session(
            profile_name=profile_name or None,
            region_name=region_name or None,
        ).client("ec2")
    return boto3.client("ec2")