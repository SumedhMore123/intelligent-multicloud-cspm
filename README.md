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
│   ├── __init__.py
│   ├── scanner.py
│   ├── aws_client.py
│   │
│   ├── integrations/
│   │   ├── __init__.py
│   │   └── dashboard.py
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
│       ├── test_rules.py
│       └── test_integration.py
│
├── iam-scanner/
│   └── scanner.py
│
├── data_scanner/
│   ├── scanner.py
│   ├── aws_client.py
│   ├── rules/
│   │   └── s3.py
│   └── tests/
│       └── test_s3_rules.py
│
├── Dashboard/
│   ├── README.md
│   └── code/
│       ├── integration-config.js
│       └── integration-loader.js
│
├── backend/
│   ├── server.py
│   ├── iam_service.py
│   └── tests/
│       ├── test_iam_service.py
│       └── test_scanner.py
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
- Static dashboard available under `Dashboard/code`
- Scanner-to-dashboard serialization adapter available under `network_scanner/integrations`

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
5. Expose scanner results through a centralized findings API
6. Integrate a centralized findings database
7. Develop AI/ML analysis
8. Build the centralized CSPM dashboard
9. Add reporting and notifications
10. Extend the platform toward multi-cloud support

## Dashboard integration contract

`network_scanner.integrations.dashboard.to_dashboard_finding()` converts the
canonical scanner finding into the dashboard record shape. The dashboard
normally uses its bundled sample data, but
`Dashboard/code/integration-config.js` can opt into an endpoint that returns
either a JSON array or `{ "findings": [...] }`. This keeps scanner, API, and
UI responsibilities separate while the findings API is being developed.

## Running a live IAM scan

Start the local API from the repository root:

```powershell
& .venv\Scripts\python.exe -m backend.server
```

Serve `Dashboard/code` from `http://localhost:8000`, open `iam.html`, and
select **Run IAM scan**. The backend binds to `127.0.0.1:8765`, uses boto3's
standard AWS credential chain, and requires only the read operations used by
the scanner: `iam:ListUsers`, `iam:ListMFADevices`, `iam:ListAccessKeys`, and
`iam:GetAccessKeyLastUsed`.

Attach a read-only policy containing these actions to the identity used by
the scanner, for example:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",
        "iam:ListMFADevices",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed"
      ],
      "Resource": "*"
    }
  ]
}
```

The scanner does not create or modify IAM resources. The policy must be
attached by an AWS administrator; the scanner cannot grant itself access.

The Network Security page uses the same backend. Enter an AWS CLI profile
name and optional region, then select **Run network scan**. The network
scanner uses the selected profile to create an EC2 client and requires
`ec2:DescribeSecurityGroups`. Results are stored separately in
`scan_results/latest_network_scan.json` and replace only live Network records
in the shared dashboard collection.

The Data & Compliance page uses the same profile and region inputs. Select
**Run data scan** to scan S3 bucket ACL and bucket-policy exposure, Public
Access Block context, and default encryption. The data scanner requires these
read-only permissions:
`s3:ListAllMyBuckets`, `s3:GetBucketAcl`, `s3:GetBucketPolicyStatus`,
`s3:GetBucketPublicAccessBlock`, `s3:ListBucket`, `s3:GetObjectAcl`, and
`s3:GetEncryptionConfiguration`. A bucket without a policy or Public Access
Block configuration is treated as a normal empty configuration; other
permission errors fail the scan instead of being reported as a clean result.
Object ACL scanning enumerates objects in each bucket, so scan duration and
required API calls increase with bucket size.
Results are stored in
`scan_results/latest_data_scan.json` and replace only live Data records in
the shared dashboard collection. An empty successful result is valid and
means no matching S3 findings were detected.

Successful results are atomically written to the generated
`scan_results/latest_iam_scan.json`; failed scans leave the previous success
untouched. The browser stores the latest successful live result in local
storage so the IAM page and main dashboard use the same live collection after
navigation or refresh. Before a live scan, the existing sample fixture
remains active.

## Scanner sources

The IAM scanner was copied from the repository's `iam-scanner` branch and the
S3/data scanner was copied from `feature/data-compliance`. These scanners are
kept in separate folders so they can be integrated into the common findings
pipeline without changing the existing network scanner.

## AI intelligence source

The repository's current AI intelligence deliverable is the read-only Google
Colab notebook [Security_Intelligence_Copilot_Fridat_Enhanced.ipynb](./Security_Intelligence_Copilot_Fridat_Enhanced.ipynb).
It uses the common scanner findings and related CSV exports as grounded
context for Gemini explanations, validates citations against retrieved
records, and does not connect to or modify AWS, Azure, or GCP environments.
The notebook installs `google-genai` and `ipywidgets` inside its Colab
environment; those packages are intentionally not added to the local scanner
runtime requirements.

The dashboard's [AI Intelligence page](./Dashboard/code/ai.html) remains a
safe, grounded review surface until a provider, credential-management flow,
and backend boundary are approved. It now consumes the same persisted live
IAM, Network, and Data findings as the dashboard, allows analysts to select
findings, and shows their recorded evidence and context. It does not make
provider calls or enable analysis. No API key is stored in this repository or
browser storage.

## Team

The project is developed by a four-member undergraduate team with responsibilities across:

- Cloud Infrastructure & Network Security
- Cloud IAM Security
- Cloud Data, Monitoring & Compliance
- AI/ML Security Intelligence

## Important

This project is an academic prototype intended to demonstrate CSPM concepts and cloud-security engineering practices. It is not intended to replace commercial CSPM platforms.
