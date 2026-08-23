# Intelligent Multi-Cloud Security Posture Management Platform

An undergraduate cybersecurity project for building a practical Cloud Security Posture Management (CSPM) platform that discovers cloud resources, detects security misconfigurations, stores findings, and uses AI/ML to analyze and prioritize security issues.

## Project Overview

The platform is designed to monitor cloud environments such as:

- AWS
- Microsoft Azure
- Google Cloud Platform (GCP) — planned/extensible

The system follows this high-level flow:

Cloud Providers → API Connectors → Resource Discovery → Asset Inventory → CSPM Security Scanning → Security Findings → AI/ML Analysis → CSPM Dashboard → Reports & Alerts

## Core Security Areas

### IAM & Access Security
- Excessive permissions
- MFA-related checks
- IAM policy security
- Least-privilege checks
- Credential-related checks

### Infrastructure & Network Security
- Public exposure
- Open ports
- Security Group / NSG misconfigurations
- Network security checks
- Internet-exposed resources

### Data, Monitoring & Compliance
- Public storage
- Encryption configuration
- Logging and monitoring
- CIS-related checks
- Compliance gaps

## AI/ML Intelligence Layer

The AI/ML layer operates on findings produced by the CSPM scanners. Planned capabilities include:

- Finding prioritization
- Finding correlation
- Context-aware remediation recommendations
- Natural-language security summaries

The initial security detection remains rule-based; AI/ML is used to analyze and interpret the resulting findings.

## Current Development Status

The first development milestone is the AWS Infrastructure & Network Security scanner.

Current capabilities:

- Connect to AWS using Boto3
- Discover AWS Security Groups
- Read inbound Security Group rules
- Generate standardized security findings
- Detect `NET-001: SSH exposed to the Internet`
- Identify the affected Security Group by name and ID

## Current Project Structure

```text
intelligent-multicloud-cspm/
│
├── network_scanner/
│   ├── scanner.py
│   ├── aws_client.py
│   │
│   ├── rules/
│   │   ├── __init__.py
│   │   ├── ssh.py
│   │   ├── rdp.py
│   │   ├── unrestricted.py
│   │   ├── port_range.py
│   │   └── database_ports.py
│   │
│   ├── models/
│   │   ├── __init__.py
│   │   └── finding.py
│   │
│   └── tests/
│       └── test_rules.py
│
├── requirements.txt
├── .gitignore
└── README.md
```

## Finding Structure

Security findings are represented using a common structure so that findings from different scanners can later be stored in the same database and consumed by the AI/ML layer.

Example fields:

```text
rule_id
resource_name
resource_id
category
severity
description
evidence
recommendation
status
```

Example:

```text
Rule ID: NET-001
Resource Name: cspm-test-public-ssh
Resource ID: sg-xxxxxxxx
Category: Network Security
Severity: HIGH
Description: SSH exposed to the Internet
Evidence: TCP port 22 allows 0.0.0.0/0
Recommendation: Restrict SSH access to trusted IP ranges.
Status: OPEN
```

## Technology Stack

- Python
- Boto3
- AWS APIs
- Git & GitHub
- Pytest
- AI/ML components — planned
- Dashboard/backend components — planned

## Security Principles

The project follows basic cloud-security engineering principles:

- Least privilege
- Read-only access for scanning where possible
- No hard-coded credentials
- Modular security rules
- Standardized findings
- Test environments for intentionally insecure configurations

## Development Roadmap

1. Complete AWS network-security checks
2. Add EC2/VPC security checks
3. Add IAM security scanner
4. Add data, monitoring, and compliance scanner
5. Integrate a centralized findings database
6. Develop AI/ML analysis
7. Build the centralized CSPM dashboard
8. Add reporting and notifications
9. Extend the platform toward multi-cloud support

## Team

The project is developed by a four-member undergraduate team with responsibilities across:

- Cloud Infrastructure & Network Security
- Cloud IAM Security
- Cloud Data, Monitoring & Compliance
- AI/ML Security Intelligence

## Important

This project is an academic prototype intended to demonstrate CSPM concepts and cloud-security engineering practices. It is not intended to replace commercial CSPM platforms.
