from models.finding import Finding


def check_ssh_rule(rule, sg):
    """
    Check whether an inbound rule exposes SSH (TCP port 22)
    to the entire IPv4 Internet.
    """

    protocol = rule["IpProtocol"]

    # We only care about TCP for this rule.
    if protocol != "tcp":
        return None

    from_port = rule.get("FromPort")
    to_port = rule.get("ToPort")

    # Check whether port 22 is included in the allowed range.
    if from_port is None or to_port is None:
        return None

    if not (from_port <= 22 <= to_port):
        return None

    # Check whether the rule allows traffic from anywhere.
    for ip_range in rule["IpRanges"]:
        if ip_range["CidrIp"] == "0.0.0.0/0":
            return Finding(
    rule_id="NET-001",
    resource_name=sg["GroupName"],
    resource_id=sg["GroupId"],
    category="Network Security",
    severity="HIGH",
    description="SSH exposed to the Internet",
    evidence="TCP port 22 allows 0.0.0.0/0",
    recommendation="Restrict SSH access to trusted IP ranges."
)

    return None