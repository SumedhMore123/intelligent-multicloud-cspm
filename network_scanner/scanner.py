from .aws_client import get_ec2_client
from .rules.rdp import check_rdp_rule
from .rules.ssh import check_ssh_rule
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound


RULES = (check_ssh_rule, check_rdp_rule)


class NetworkScanError(RuntimeError):
    """A readable, actionable network scan failure."""


def scan_security_groups(ec2_client=None):
    """Scan AWS security groups and return canonical Finding objects."""
    ec2 = ec2_client or get_ec2_client()
    try:
        response = ec2.describe_security_groups()
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "AWS error")
        message = error.response.get("Error", {}).get("Message", "AWS rejected the request")
        raise NetworkScanError(
            f"AWS denied network scan ({code}): {message}. "
            "Grant read-only permission: ec2:DescribeSecurityGroups."
        ) from error
    except (NoCredentialsError, ProfileNotFound) as error:
        raise NetworkScanError(
            "AWS credentials are unavailable. Configure an AWS CLI profile or "
            "the standard boto3 credential chain, then retry the scan."
        ) from error
    findings = []

    for security_group in response.get("SecurityGroups", []):
        for rule in security_group.get("IpPermissions", []):
            for check_rule in RULES:
                finding = check_rule(rule, security_group)
                if finding is not None:
                    findings.append(finding)

    return findings


def print_rule(rule):
    print(f"Protocol: {rule['IpProtocol']}")
    print(f"From Port: {rule.get('FromPort')}")
    print(f"To Port: {rule.get('ToPort')}")

    for ip_range in rule["IpRanges"]:
        print(f"Source IPv4: {ip_range['CidrIp']}")

    for ipv6_range in rule["Ipv6Ranges"]:
        print(f"Source IPv6: {ipv6_range['CidrIpv6']}")

    for group in rule["UserIdGroupPairs"]:
        print(f"Source Security Group: {group['GroupId']}")

    for prefix in rule["PrefixListIds"]:
        print(f"Source Prefix List: {prefix['PrefixListId']}")

    print("---")


def main():
    for finding in scan_security_groups():
        print(f"[SECURITY FINDING] {finding.rule_id}: {finding.description}")
        print(finding.to_dict())


if __name__ == "__main__":
    main()