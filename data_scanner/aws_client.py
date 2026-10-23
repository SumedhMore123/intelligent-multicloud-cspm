import boto3


def get_s3_client(profile_name=None, region_name=None):
    """Create an S3 client using the selected AWS profile and region."""
    return boto3.Session(
        profile_name=profile_name or None,
        region_name=region_name or None,
    ).client("s3")
