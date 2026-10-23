// ============================================================
// CSPM PLATFORM
// IAM Security sample findings
//
// This represents the latest IAM scan data currently being
// used by the interface.
//
// Upload iam_findings.json from the IAM Security page whenever
// you want to replace this sample data with a fresh scan.
// ============================================================

const SAMPLE_FINDINGS = [

  // ============================================================
  // cspm-scanner
  // ============================================================

  {
    finding_id: "IAM-001",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "cspm-scanner",
    category: "IAM Security",
    finding: "MFA is not enabled",
    severity: "HIGH",
    evidence: "IAM user 'cspm-scanner' has no MFA device configured",
    status: "OPEN",
    risk_score: 6,
    detected_at: "2026-09-05T11:15:00Z"
  },

  {
    finding_id: "IAM-002",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "cspm-scanner",
    category: "IAM Security",
    finding: "Access key is within the 90-day rotation period",
    severity: "PASS",
    evidence: "Access key ACCESS_KEY_REDACTED_1 is 12 days old",
    status: "PASS",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:00Z"
  },

  {
    finding_id: "IAM-003",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "cspm-scanner",
    category: "IAM Security",
    finding: "Access key has been used",
    severity: "PASS",
    evidence: "Access key ACCESS_KEY_REDACTED_1 was last used on 2026-09-02T15:21:00Z",
    status: "PASS",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:00Z"
  },

  {
    finding_id: "IAM-005",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "cspm-scanner",
    category: "IAM Security",
    finding: "Policy inventory collected",
    severity: "INFO",
    evidence: {
      direct_managed_policies: [
        "CSPM-IAM-ReadOnly-Policy"
      ]
    },
    status: "INFO",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:00Z"
  },

  {
    finding_id: "IAM-006",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "cspm-scanner",
    category: "IAM Security",
    finding: "Policy grants excessive permissions",
    severity: "HIGH",
    evidence: "Direct policy 'CSPM-IAM-ReadOnly-Policy' grants wildcard Resource '*' for user 'cspm-scanner'",
    status: "OPEN",
    risk_score: 6,
    detected_at: "2026-09-05T11:15:00Z"
  },

  {
    finding_id: "IAM-007",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "cspm-scanner",
    category: "IAM Security",
    finding: "No unused permissions detected",
    severity: "PASS",
    evidence: "All granted service access for 'cspm-scanner' is actively used",
    status: "PASS",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:00Z"
  },

  {
    finding_id: "IAM-011",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "cspm-scanner",
    category: "IAM Security",
    finding: "User does not have dual credential exposure",
    severity: "PASS",
    evidence: "console password: False, active access keys: 1",
    status: "PASS",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:00Z"
  },

  {
    finding_id: "IAM-012",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "cspm-scanner",
    category: "IAM Security",
    finding: "No inverted permission logic detected",
    severity: "PASS",
    evidence: "No NotAction/NotResource statements found for 'cspm-scanner'",
    status: "PASS",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:00Z"
  },

  {
    finding_id: "IAM-013",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "cspm-scanner",
    category: "IAM Security",
    finding: "User does not have multiple active access keys",
    severity: "PASS",
    evidence: "1 active access key(s)",
    status: "PASS",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:00Z"
  },

  {
    finding_id: "IAM-014",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "cspm-scanner",
    category: "IAM Security",
    finding: "Console access (if any) is protected by MFA, or no console access exists",
    severity: "PASS",
    evidence: "console password: False, MFA configured: False",
    status: "PASS",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:00Z"
  },


  // ============================================================
  // test-user-clean
  // ============================================================

  {
    finding_id: "IAM-001",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "test-user-clean",
    category: "IAM Security",
    finding: "MFA is not enabled",
    severity: "HIGH",
    evidence: "IAM user 'test-user-clean' has no MFA device configured",
    status: "OPEN",
    risk_score: 6,
    detected_at: "2026-09-05T11:15:01Z"
  },

  {
    finding_id: "IAM-002",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "test-user-clean",
    category: "IAM Security",
    finding: "Access key is within the 90-day rotation period",
    severity: "PASS",
    evidence: "Access key ACCESS_KEY_REDACTED_2 is 0 days old",
    status: "PASS",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:01Z"
  },

  {
    finding_id: "IAM-002",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "test-user-clean",
    category: "IAM Security",
    finding: "Access key is within the 90-day rotation period",
    severity: "PASS",
    evidence: "Access key ACCESS_KEY_REDACTED_3 is 0 days old",
    status: "PASS",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:01Z"
  },

  {
    finding_id: "IAM-003",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "test-user-clean",
    category: "IAM Security",
    finding: "Access key has never been used",
    severity: "MEDIUM",
    evidence: "Access key ACCESS_KEY_REDACTED_2 has no recorded usage",
    status: "OPEN",
    risk_score: 4,
    detected_at: "2026-09-05T11:15:01Z"
  },

  {
    finding_id: "IAM-003",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "test-user-clean",
    category: "IAM Security",
    finding: "Access key has never been used",
    severity: "MEDIUM",
    evidence: "Access key ACCESS_KEY_REDACTED_3 has no recorded usage",
    status: "OPEN",
    risk_score: 4,
    detected_at: "2026-09-05T11:15:01Z"
  },

  {
    finding_id: "IAM-005",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "test-user-clean",
    category: "IAM Security",
    finding: "Policy inventory collected",
    severity: "INFO",
    evidence: {
      direct_managed_policies: [
        "AmazonS3ReadOnlyAccess"
      ]
    },
    status: "INFO",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:02Z"
  },

  {
    finding_id: "IAM-006",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "test-user-clean",
    category: "IAM Security",
    finding: "Policy grants excessive permissions",
    severity: "HIGH",
    evidence: "Direct policy 'AmazonS3ReadOnlyAccess' grants wildcard Resource '*' for user 'test-user-clean'",
    status: "OPEN",
    risk_score: 6,
    detected_at: "2026-09-05T11:15:03Z"
  },

  {
    finding_id: "IAM-007",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "test-user-clean",
    category: "IAM Security",
    finding: "2 granted service(s) have never been used",
    severity: "MEDIUM",
    evidence: "User 'test-user-clean' has access to 2 AWS services with no recorded usage (e.g. Amazon S3, Amazon S3 Object Lambda)",
    status: "OPEN",
    risk_score: 4,
    detected_at: "2026-09-05T11:15:06Z"
  },

  {
    finding_id: "IAM-011",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "test-user-clean",
    category: "IAM Security",
    finding: "User has both console password and active access keys",
    severity: "MEDIUM",
    evidence: "IAM user 'test-user-clean' has a console login profile AND 2 active access key(s)",
    status: "OPEN",
    risk_score: 4,
    detected_at: "2026-09-05T11:15:06Z"
  },

  {
    finding_id: "IAM-012",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "test-user-clean",
    category: "IAM Security",
    finding: "No inverted permission logic detected",
    severity: "PASS",
    evidence: "No NotAction/NotResource statements found for 'test-user-clean'",
    status: "PASS",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:07Z"
  },

  {
    finding_id: "IAM-013",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "test-user-clean",
    category: "IAM Security",
    finding: "User has multiple active access keys",
    severity: "MEDIUM",
    evidence: "IAM user 'test-user-clean' has 2 active access keys simultaneously",
    status: "OPEN",
    risk_score: 4,
    detected_at: "2026-09-05T11:15:07Z"
  },

  {
    finding_id: "IAM-014",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "test-user-clean",
    category: "IAM Security",
    finding: "User has console access without MFA",
    severity: "HIGH",
    evidence: "IAM user 'test-user-clean' has a console login profile but no MFA device configured",
    status: "OPEN",
    risk_score: 6,
    detected_at: "2026-09-05T11:15:07Z"
  },


  // ============================================================
  // test-user-inverted
  // ============================================================

  {
    finding_id: "IAM-001",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "test-user-inverted",
    category: "IAM Security",
    finding: "MFA is not enabled",
    severity: "HIGH",
    evidence: "IAM user 'test-user-inverted' has no MFA device configured",
    status: "OPEN",
    risk_score: 3,
    detected_at: "2026-09-05T11:15:08Z"
  },

  {
    finding_id: "IAM-002",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "test-user-inverted",
    category: "IAM Security",
    finding: "No active access keys found",
    severity: "PASS",
    evidence: "IAM user 'test-user-inverted' has no active access keys",
    status: "PASS",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:08Z"
  },

  {
    finding_id: "IAM-003",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "test-user-inverted",
    category: "IAM Security",
    finding: "No active access keys to check",
    severity: "PASS",
    evidence: "IAM user 'test-user-inverted' has no active access keys to evaluate",
    status: "PASS",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:08Z"
  },

  {
    finding_id: "IAM-005",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "test-user-inverted",
    category: "IAM Security",
    finding: "Policy inventory collected",
    severity: "INFO",
    evidence: {
      direct_managed_policies: [
        "test-policy-notaction"
      ]
    },
    status: "INFO",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:08Z"
  },

  {
    finding_id: "IAM-006",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "test-user-inverted",
    category: "IAM Security",
    finding: "Policy grants excessive permissions",
    severity: "HIGH",
    evidence: "Direct policy 'test-policy-notaction' grants wildcard Resource '*' for user 'test-user-inverted'",
    status: "OPEN",
    risk_score: 3,
    detected_at: "2026-09-05T11:15:09Z"
  },

  {
    finding_id: "IAM-007",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "test-user-inverted",
    category: "IAM Security",
    finding: "200 granted service(s) have never been used",
    severity: "MEDIUM",
    evidence: "User 'test-user-inverted' has access to 200 AWS services with no recorded usage",
    status: "OPEN",
    risk_score: 2,
    detected_at: "2026-09-05T11:15:17Z"
  },

  {
    finding_id: "IAM-011",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "test-user-inverted",
    category: "IAM Security",
    finding: "User does not have dual credential exposure",
    severity: "PASS",
    evidence: "console password: False, active access keys: 0",
    status: "PASS",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:18Z"
  },

  {
    finding_id: "IAM-012",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "test-user-inverted",
    category: "IAM Security",
    finding: "Policy uses inverted permission logic",
    severity: "HIGH",
    evidence: "Direct policy 'test-policy-notaction' uses NotAction, which allows all actions/resources except those listed",
    status: "OPEN",
    risk_score: 3,
    detected_at: "2026-09-05T11:15:18Z"
  },

  {
    finding_id: "IAM-013",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "test-user-inverted",
    category: "IAM Security",
    finding: "User does not have multiple active access keys",
    severity: "PASS",
    evidence: "0 active access key(s)",
    status: "PASS",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:18Z"
  },

  {
    finding_id: "IAM-014",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "test-user-inverted",
    category: "IAM Security",
    finding: "Console access (if any) is protected by MFA, or no console access exists",
    severity: "PASS",
    evidence: "console password: False, MFA configured: False",
    status: "PASS",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:18Z"
  },


  // ============================================================
  // test-user-overpermissioned
  // ============================================================

  {
    finding_id: "IAM-001",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "test-user-overpermissioned",
    category: "IAM Security",
    finding: "MFA is not enabled",
    severity: "HIGH",
    evidence: "IAM user 'test-user-overpermissioned' has no MFA device configured",
    status: "OPEN",
    risk_score: 6,
    detected_at: "2026-09-05T11:15:19Z"
  },

  {
    finding_id: "IAM-002",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "test-user-overpermissioned",
    category: "IAM Security",
    finding: "Access key is within the 90-day rotation period",
    severity: "PASS",
    evidence: "Access key ACCESS_KEY_REDACTED_4 is 2 days old",
    status: "PASS",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:19Z"
  },

  {
    finding_id: "IAM-003",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "test-user-overpermissioned",
    category: "IAM Security",
    finding: "Access key has been used",
    severity: "PASS",
    evidence: "Access key ACCESS_KEY_REDACTED_4 was last used on 2026-09-05T11:10:00Z",
    status: "PASS",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:19Z"
  },

  {
    finding_id: "IAM-005",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "test-user-overpermissioned",
    category: "IAM Security",
    finding: "Policy inventory collected",
    severity: "INFO",
    evidence: {
      direct_managed_policies: [
        "AdministratorAccess"
      ]
    },
    status: "INFO",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:20Z"
  },

  {
    finding_id: "IAM-006",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "test-user-overpermissioned",
    category: "IAM Security",
    finding: "Policy grants excessive permissions",
    severity: "HIGH",
    evidence: "Direct policy 'AdministratorAccess' grants wildcard Action and Resource '*' for user 'test-user-overpermissioned'",
    status: "OPEN",
    risk_score: 18,
    detected_at: "2026-09-05T11:15:21Z"
  },

  {
    finding_id: "IAM-007",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "test-user-overpermissioned",
    category: "IAM Security",
    finding: "200 granted service(s) have never been used",
    severity: "MEDIUM",
    evidence: "User 'test-user-overpermissioned' has access to 200 AWS services with no recorded usage",
    status: "OPEN",
    risk_score: 12,
    detected_at: "2026-09-05T11:15:29Z"
  },

  {
    finding_id: "IAM-011",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "test-user-overpermissioned",
    category: "IAM Security",
    finding: "User does not have dual credential exposure",
    severity: "PASS",
    evidence: "console password: False, active access keys: 1",
    status: "PASS",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:29Z"
  },

  {
    finding_id: "IAM-012",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "test-user-overpermissioned",
    category: "IAM Security",
    finding: "No inverted permission logic detected",
    severity: "PASS",
    evidence: "No NotAction/NotResource statements found for 'test-user-overpermissioned'",
    status: "PASS",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:30Z"
  },

  {
    finding_id: "IAM-013",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "test-user-overpermissioned",
    category: "IAM Security",
    finding: "User does not have multiple active access keys",
    severity: "PASS",
    evidence: "1 active access key(s)",
    status: "PASS",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:30Z"
  },

  {
    finding_id: "IAM-014",
    cloud: "AWS",
    resource_type: "IAMUser",
    resource_id: "test-user-overpermissioned",
    category: "IAM Security",
    finding: "Console access (if any) is protected by MFA, or no console access exists",
    severity: "PASS",
    evidence: "console password: False, MFA configured: False",
    status: "PASS",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:30Z"
  },


  // ============================================================
  // IAM ROLES
  // ============================================================

  {
    finding_id: "IAM-008",
    cloud: "AWS",
    resource_type: "IAMRole",
    resource_id: "AWSServiceRoleForResourceExplorer",
    category: "IAM Security",
    finding: "No role misconfigurations detected",
    severity: "PASS",
    evidence: "Role has a scoped trust policy and no wildcard permissions",
    status: "PASS",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:32Z"
  },

  {
    finding_id: "IAM-009",
    cloud: "AWS",
    resource_type: "IAMRole",
    resource_id: "AWSServiceRoleForResourceExplorer",
    category: "IAM Security",
    finding: "No external account trust detected",
    severity: "PASS",
    evidence: "Trust policy does not reference any external AWS accounts",
    status: "PASS",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:32Z"
  },

  {
    finding_id: "IAM-008",
    cloud: "AWS",
    resource_type: "IAMRole",
    resource_id: "AWSServiceRoleForSupport",
    category: "IAM Security",
    finding: "No role misconfigurations detected",
    severity: "PASS",
    evidence: "Role has a scoped trust policy and no wildcard permissions",
    status: "PASS",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:34Z"
  },

  {
    finding_id: "IAM-009",
    cloud: "AWS",
    resource_type: "IAMRole",
    resource_id: "AWSServiceRoleForSupport",
    category: "IAM Security",
    finding: "No external account trust detected",
    severity: "PASS",
    evidence: "Trust policy does not reference any external AWS accounts",
    status: "PASS",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:34Z"
  },

  {
    finding_id: "IAM-008",
    cloud: "AWS",
    resource_type: "IAMRole",
    resource_id: "AWSServiceRoleForTrustedAdvisor",
    category: "IAM Security",
    finding: "No role misconfigurations detected",
    severity: "PASS",
    evidence: "Role has a scoped trust policy and no wildcard permissions",
    status: "PASS",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:35Z"
  },

  {
    finding_id: "IAM-009",
    cloud: "AWS",
    resource_type: "IAMRole",
    resource_id: "AWSServiceRoleForTrustedAdvisor",
    category: "IAM Security",
    finding: "No external account trust detected",
    severity: "PASS",
    evidence: "Trust policy does not reference any external AWS accounts",
    status: "PASS",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:35Z"
  },

  {
    finding_id: "IAM-008",
    cloud: "AWS",
    resource_type: "IAMRole",
    resource_id: "test-role-clean",
    category: "IAM Security",
    finding: "No role misconfigurations detected",
    severity: "PASS",
    evidence: "Role has a scoped trust policy and no wildcard permissions",
    status: "PASS",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:36Z"
  },

  {
    finding_id: "IAM-009",
    cloud: "AWS",
    resource_type: "IAMRole",
    resource_id: "test-role-clean",
    category: "IAM Security",
    finding: "No external account trust detected",
    severity: "PASS",
    evidence: "Trust policy does not reference any external AWS accounts",
    status: "PASS",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:36Z"
  },

  {
    finding_id: "IAM-008",
    cloud: "AWS",
    resource_type: "IAMRole",
    resource_id: "test-role-cross-account",
    category: "IAM Security",
    finding: "No role misconfigurations detected",
    severity: "PASS",
    evidence: "Role has a scoped trust policy and no wildcard permissions",
    status: "PASS",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:37Z"
  },

  {
    finding_id: "IAM-009",
    cloud: "AWS",
    resource_type: "IAMRole",
    resource_id: "test-role-cross-account",
    category: "IAM Security",
    finding: "Role trusts an external AWS account",
    severity: "MEDIUM",
    evidence: "Trust policy allows account '630243421920' (not your account '630243421937') to assume it",
    status: "OPEN",
    risk_score: 4,
    detected_at: "2026-09-05T11:15:37Z"
  },

  {
    finding_id: "IAM-008",
    cloud: "AWS",
    resource_type: "IAMRole",
    resource_id: "test-role-overpermissioned",
    category: "IAM Security",
    finding: "Role trust policy allows any AWS account to assume it",
    severity: "HIGH",
    evidence: "Role has Principal '*' in its trust policy",
    status: "OPEN",
    risk_score: 27,
    detected_at: "2026-09-05T11:15:37Z"
  },

  {
    finding_id: "IAM-008",
    cloud: "AWS",
    resource_type: "IAMRole",
    resource_id: "test-role-overpermissioned",
    category: "IAM Security",
    finding: "Role has wildcard permissions",
    severity: "HIGH",
    evidence: "Policy 'AdministratorAccess' attached to role allows Action '*'",
    status: "OPEN",
    risk_score: 18,
    detected_at: "2026-09-05T11:15:38Z"
  },

  {
    finding_id: "IAM-009",
    cloud: "AWS",
    resource_type: "IAMRole",
    resource_id: "test-role-overpermissioned",
    category: "IAM Security",
    finding: "No external account trust detected",
    severity: "PASS",
    evidence: "Trust policy does not reference any external AWS accounts",
    status: "PASS",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:38Z"
  },

  {
    finding_id: "IAM-008",
    cloud: "AWS",
    resource_type: "IAMRole",
    resource_id: "test-role-partially-permissioned",
    category: "IAM Security",
    finding: "Role has wildcard permissions",
    severity: "HIGH",
    evidence: "Policy 'AdministratorAccess' attached to role allows Action '*'",
    status: "OPEN",
    risk_score: 18,
    detected_at: "2026-09-05T11:15:39Z"
  },

  {
    finding_id: "IAM-009",
    cloud: "AWS",
    resource_type: "IAMRole",
    resource_id: "test-role-partially-permissioned",
    category: "IAM Security",
    finding: "No external account trust detected",
    severity: "PASS",
    evidence: "Trust policy does not reference any external AWS accounts",
    status: "PASS",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:39Z"
  },


  // ============================================================
  // ROOT ACCOUNT
  // ============================================================

  {
    finding_id: "IAM-010",
    cloud: "AWS",
    resource_type: "RootAccount",
    resource_id: "root",
    category: "IAM Security",
    finding: "Root account has MFA enabled",
    severity: "PASS",
    evidence: "AccountMFAEnabled is 1 in account summary",
    status: "PASS",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:39Z"
  },

  {
    finding_id: "IAM-010",
    cloud: "AWS",
    resource_type: "RootAccount",
    resource_id: "root",
    category: "IAM Security",
    finding: "Root account has no access keys",
    severity: "PASS",
    evidence: "AccountAccessKeysPresent is 0 in account summary",
    status: "PASS",
    risk_score: 0,
    detected_at: "2026-09-05T11:15:39Z"
  }

];

// ============================================================
// REAL SCANNER DATA LOADER
// Loads iam_findings.json automatically when dashboard starts.
// ============================================================

async function loadRealIAMFindings() {
  const response = await fetch("./iam_findings.json", {
    cache: "no-store"
  });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }

  const data = await response.json();

  // Accept either:
  // 1. JSON array
  // 2. Single finding object
  const findings = Array.isArray(data) ? data : [data];

  if (
    findings.length === 0 ||
    !findings.every((f) => f && f.finding_id)
  ) {
    throw new Error("Invalid finding format");
  }

  return findings;
}

// Make it available to script.js
window.CSPMData = {
  loadRealIAMFindings
};