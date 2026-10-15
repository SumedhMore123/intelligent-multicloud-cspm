from aws_client import get_ec2_client
from rules.ssh import check_ssh_rule


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
    ec2 = get_ec2_client()

    response = ec2.describe_security_groups()

    security_groups = response["SecurityGroups"]

    print(f"Security Groups Found: {len(security_groups)}")

    for sg in security_groups:
        print(f"\nSecurity Group: {sg['GroupName']}")
        print(f"ID: {sg['GroupId']}")

        for rule in sg["IpPermissions"]:
            print_rule(rule)

            finding = check_ssh_rule(rule, sg)

            if finding:
                print("\n[SECURITY FINDING]")
                print(f"Rule ID: {finding.rule_id}")
                print(f"Resource Name: {finding.resource_name}")
                print(f"Resource ID: {finding.resource_id}")
                print(f"Finding: {finding.description}")
                print(f"Category: {finding.category}")
                print(f"Severity: {finding.severity}")
                print(f"Evidence: {finding.evidence}")
                print(f"Recommendation: {finding.recommendation}")
                print(f"Status: {finding.status}")


if __name__ == "__main__":
    main()