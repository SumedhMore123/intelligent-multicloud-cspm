from ..models.finding import Finding


def check_rdp_rule(rule, sg):
    """
    Check whether an inbound rule exposes RDP (TCP port 3389)
    to the entire IPv4 Internet.
    """

    protocol = rule["IpProtocol"]

    # RDP uses TCP.
    if protocol != "tcp":
        return None

    from_port = rule.get("FromPort")
    to_port = rule.get("ToPort")

    # Make sure the rule has a valid port range.
    if from_port is None or to_port is None:
        return None

    # Check whether port 3389 is included in the rule.
    if not (from_port <= 3389 <= to_port):
        return None

    # Check whether RDP is exposed to the entire IPv4 Internet.
    for ip_range in rule["IpRanges"]:
        if ip_range["CidrIp"] == "0.0.0.0/0":
            return Finding(
                rule_id="NET-002",
                resource_name=sg["GroupName"],
                resource_id=sg["GroupId"],
                category="Network Security",
                severity="HIGH",
                description="RDP exposed to the Internet",
                evidence="TCP port 3389 allows 0.0.0.0/0",
                recommendation="Restrict RDP access to trusted IP ranges."
            )

    return None


if __name__ == "__main__":
    test_rule = {
        "IpProtocol": "tcp",
        "FromPort": 3389,
        "ToPort": 3389,
        "IpRanges": [
            {"CidrIp": "0.0.0.0/0"}
        ]
    }

    test_sg = {
        "GroupName": "cspm-test-public-rdp",
        "GroupId": "sg-test123"
    }

    result = check_rdp_rule(test_rule, test_sg)

    if result:
        print(result.to_dict())