class Finding:
    """
    Represents a security finding detected by the CSPM scanner.
    """

    def __init__(
        self,
        rule_id,
        resource_name,
        resource_id,
        category,
        severity,
        description,
        evidence,
        recommendation,
        status="OPEN"
    ):
        self.rule_id = rule_id
        self.resource_name = resource_name
        self.resource_id = resource_id
        self.category = category
        self.severity = severity
        self.description = description
        self.evidence = evidence
        self.recommendation = recommendation
        self.status = status

    def to_dict(self):
        """
        Convert the finding into a dictionary.
        """
        return {
            "rule_id": self.rule_id,
            "resource_name": self.resource_name,
            "resource_id": self.resource_id,
            "category": self.category,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "status": self.status
        }