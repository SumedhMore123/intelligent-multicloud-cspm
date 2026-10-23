import { useState, useMemo, useRef, useEffect  } from "react";
import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip as ReTooltip,
  BarChart, Bar, XAxis, YAxis,
} from "recharts";
import {
  ShieldAlert, ShieldCheck, Users, Search, Upload, RefreshCw,
  ArrowUpDown, Network, Database, Sparkles, LayoutDashboard,
  KeyRound, Lock, ChevronLeft, ChevronRight, X, FileJson,
} from "lucide-react";

// ---------------------------------------------------------------
// Sample dataset â€” this is your actual last IAM scan output, with
// risk_score computed using severity x exposure x privilege.
// Upload a fresh iam_findings.json anytime to replace it.
// ---------------------------------------------------------------
const SAMPLE_FINDINGS = [
  { finding_id: "IAM-001", cloud: "AWS", resource_type: "IAMUser", resource_id: "cspm-scanner", category: "IAM Security", finding: "MFA is not enabled", severity: "HIGH", evidence: "IAM user 'cspm-scanner' has no MFA device configured", status: "OPEN", risk_score: 6, detected_at: "2026-09-05T11:15:00Z" },
  { finding_id: "IAM-002", cloud: "AWS", resource_type: "IAMUser", resource_id: "cspm-scanner", category: "IAM Security", finding: "Access key is within the 90-day rotation period", severity: "PASS", evidence: "Access key ACCESS_KEY_REDACTED_1 is 12 days old", status: "PASS", risk_score: 0, detected_at: "2026-09-05T11:15:00Z" },
  { finding_id: "IAM-003", cloud: "AWS", resource_type: "IAMUser", resource_id: "cspm-scanner", category: "IAM Security", finding: "Access key has been used", severity: "PASS", evidence: "Access key ACCESS_KEY_REDACTED_1 was last used on 2026-09-02T15:21:00Z", status: "PASS", risk_score: 0, detected_at: "2026-09-05T11:15:00Z" },
  { finding_id: "IAM-005", cloud: "AWS", resource_type: "IAMUser", resource_id: "cspm-scanner", category: "IAM Security", finding: "Policy inventory collected", severity: "INFO", evidence: { direct_managed_policies: ["CSPM-IAM-ReadOnly-Policy"] }, status: "INFO", risk_score: 0, detected_at: "2026-09-05T11:15:00Z" },
  { finding_id: "IAM-006", cloud: "AWS", resource_type: "IAMUser", resource_id: "cspm-scanner", category: "IAM Security", finding: "Policy grants excessive permissions", severity: "HIGH", evidence: "Direct policy 'CSPM-IAM-ReadOnly-Policy' grants wildcard Resource '*' for user 'cspm-scanner'", status: "OPEN", risk_score: 6, detected_at: "2026-09-05T11:15:00Z" },
  { finding_id: "IAM-007", cloud: "AWS", resource_type: "IAMUser", resource_id: "cspm-scanner", category: "IAM Security", finding: "No unused permissions detected", severity: "PASS", evidence: "All granted service access for 'cspm-scanner' is actively used", status: "PASS", risk_score: 0, detected_at: "2026-09-05T11:15:00Z" },
  { finding_id: "IAM-011", cloud: "AWS", resource_type: "IAMUser", resource_id: "cspm-scanner", category: "IAM Security", finding: "User does not have dual credential exposure", severity: "PASS", evidence: "console password: False, active access keys: 1", status: "PASS", risk_score: 0, detected_at: "2026-09-05T11:15:00Z" },
  { finding_id: "IAM-012", cloud: "AWS", resource_type: "IAMUser", resource_id: "cspm-scanner", category: "IAM Security", finding: "No inverted permission logic detected", severity: "PASS", evidence: "No NotAction/NotResource statements found for 'cspm-scanner'", status: "PASS", risk_score: 0, detected_at: "2026-09-05T11:15:00Z" },
  { finding_id: "IAM-013", cloud: "AWS", resource_type: "IAMUser", resource_id: "cspm-scanner", category: "IAM Security", finding: "User does not have multiple active access keys", severity: "PASS", evidence: "1 active access key(s)", status: "PASS", risk_score: 0, detected_at: "2026-09-05T11:15:00Z" },
  { finding_id: "IAM-014", cloud: "AWS", resource_type: "IAMUser", resource_id: "cspm-scanner", category: "IAM Security", finding: "Console access (if any) is protected by MFA, or no console access exists", severity: "PASS", evidence: "console password: False, MFA configured: False", status: "PASS", risk_score: 0, detected_at: "2026-09-05T11:15:00Z" },

  { finding_id: "IAM-001", cloud: "AWS", resource_type: "IAMUser", resource_id: "test-user-clean", category: "IAM Security", finding: "MFA is not enabled", severity: "HIGH", evidence: "IAM user 'test-user-clean' has no MFA device configured", status: "OPEN", risk_score: 6, detected_at: "2026-09-05T11:15:01Z" },
  { finding_id: "IAM-002", cloud: "AWS", resource_type: "IAMUser", resource_id: "test-user-clean", category: "IAM Security", finding: "Access key is within the 90-day rotation period", severity: "PASS", evidence: "Access key ACCESS_KEY_REDACTED_2 is 0 days old", status: "PASS", risk_score: 0, detected_at: "2026-09-05T11:15:01Z" },
  { finding_id: "IAM-002", cloud: "AWS", resource_type: "IAMUser", resource_id: "test-user-clean", category: "IAM Security", finding: "Access key is within the 90-day rotation period", severity: "PASS", evidence: "Access key ACCESS_KEY_REDACTED_3 is 0 days old", status: "PASS", risk_score: 0, detected_at: "2026-09-05T11:15:01Z" },
  { finding_id: "IAM-003", cloud: "AWS", resource_type: "IAMUser", resource_id: "test-user-clean", category: "IAM Security", finding: "Access key has never been used", severity: "MEDIUM", evidence: "Access key ACCESS_KEY_REDACTED_2 has no recorded usage", status: "OPEN", risk_score: 4, detected_at: "2026-09-05T11:15:01Z" },
  { finding_id: "IAM-003", cloud: "AWS", resource_type: "IAMUser", resource_id: "test-user-clean", category: "IAM Security", finding: "Access key has never been used", severity: "MEDIUM", evidence: "Access key ACCESS_KEY_REDACTED_3 has no recorded usage", status: "OPEN", risk_score: 4, detected_at: "2026-09-05T11:15:01Z" },
  { finding_id: "IAM-005", cloud: "AWS", resource_type: "IAMUser", resource_id: "test-user-clean", category: "IAM Security", finding: "Policy inventory collected", severity: "INFO", evidence: { direct_managed_policies: ["AmazonS3ReadOnlyAccess"] }, status: "INFO", risk_score: 0, detected_at: "2026-09-05T11:15:02Z" },
  { finding_id: "IAM-006", cloud: "AWS", resource_type: "IAMUser", resource_id: "test-user-clean", category: "IAM Security", finding: "Policy grants excessive permissions", severity: "HIGH", evidence: "Direct policy 'AmazonS3ReadOnlyAccess' grants wildcard Resource '*' for user 'test-user-clean'", status: "OPEN", risk_score: 6, detected_at: "2026-09-05T11:15:03Z" },
  { finding_id: "IAM-007", cloud: "AWS", resource_type: "IAMUser", resource_id: "test-user-clean", category: "IAM Security", finding: "2 granted service(s) have never been used", severity: "MEDIUM", evidence: "User 'test-user-clean' has access to 2 AWS services with no recorded usage (e.g. Amazon S3, Amazon S3 Object Lambda)", status: "OPEN", risk_score: 4, detected_at: "2026-09-05T11:15:06Z" },
  { finding_id: "IAM-011", cloud: "AWS", resource_type: "IAMUser", resource_id: "test-user-clean", category: "IAM Security", finding: "User has both console password and active access keys", severity: "MEDIUM", evidence: "IAM user 'test-user-clean' has a console login profile AND 2 active access key(s)", status: "OPEN", risk_score: 4, detected_at: "2026-09-05T11:15:06Z" },
  { finding_id: "IAM-012", cloud: "AWS", resource_type: "IAMUser", resource_id: "test-user-clean", category: "IAM Security", finding: "No inverted permission logic detected", severity: "PASS", evidence: "No NotAction/NotResource statements found for 'test-user-clean'", status: "PASS", risk_score: 0, detected_at: "2026-09-05T11:15:07Z" },
  { finding_id: "IAM-013", cloud: "AWS", resource_type: "IAMUser", resource_id: "test-user-clean", category: "IAM Security", finding: "User has multiple active access keys", severity: "MEDIUM", evidence: "IAM user 'test-user-clean' has 2 active access keys simultaneously", status: "OPEN", risk_score: 4, detected_at: "2026-09-05T11:15:07Z" },
  { finding_id: "IAM-014", cloud: "AWS", resource_type: "IAMUser", resource_id: "test-user-clean", category: "IAM Security", finding: "User has console access without MFA", severity: "HIGH", evidence: "IAM user 'test-user-clean' has a console login profile but no MFA device configured", status: "OPEN", risk_score: 6, detected_at: "2026-09-05T11:15:07Z" },

  { finding_id: "IAM-001", cloud: "AWS", resource_type: "IAMUser", resource_id: "test-user-inverted", category: "IAM Security", finding: "MFA is not enabled", severity: "HIGH", evidence: "IAM user 'test-user-inverted' has no MFA device configured", status: "OPEN", risk_score: 3, detected_at: "2026-09-05T11:15:08Z" },
  { finding_id: "IAM-002", cloud: "AWS", resource_type: "IAMUser", resource_id: "test-user-inverted", category: "IAM Security", finding: "No active access keys found", severity: "PASS", evidence: "IAM user 'test-user-inverted' has no active access keys", status: "PASS", risk_score: 0, detected_at: "2026-09-05T11:15:08Z" },
  { finding_id: "IAM-003", cloud: "AWS", resource_type: "IAMUser", resource_id: "test-user-inverted", category: "IAM Security", finding: "No active access keys to check", severity: "PASS", evidence: "IAM user 'test-user-inverted' has no active access keys to evaluate", status: "PASS", risk_score: 0, detected_at: "2026-09-05T11:15:08Z" },
  { finding_id: "IAM-005", cloud: "AWS", resource_type: "IAMUser", resource_id: "test-user-inverted", category: "IAM Security", finding: "Policy inventory collected", severity: "INFO", evidence: { direct_managed_policies: ["test-policy-notaction"] }, status: "INFO", risk_score: 0, detected_at: "2026-09-05T11:15:08Z" },
  { finding_id: "IAM-006", cloud: "AWS", resource_type: "IAMUser", resource_id: "test-user-inverted", category: "IAM Security", finding: "Policy grants excessive permissions", severity: "HIGH", evidence: "Direct policy 'test-policy-notaction' grants wildcard Resource '*' for user 'test-user-inverted'", status: "OPEN", risk_score: 3, detected_at: "2026-09-05T11:15:09Z" },
  { finding_id: "IAM-007", cloud: "AWS", resource_type: "IAMUser", resource_id: "test-user-inverted", category: "IAM Security", finding: "200 granted service(s) have never been used", severity: "MEDIUM", evidence: "User 'test-user-inverted' has access to 200 AWS services with no recorded usage", status: "OPEN", risk_score: 2, detected_at: "2026-09-05T11:15:17Z" },
  { finding_id: "IAM-011", cloud: "AWS", resource_type: "IAMUser", resource_id: "test-user-inverted", category: "IAM Security", finding: "User does not have dual credential exposure", severity: "PASS", evidence: "console password: False, active access keys: 0", status: "PASS", risk_score: 0, detected_at: "2026-09-05T11:15:18Z" },
  { finding_id: "IAM-012", cloud: "AWS", resource_type: "IAMUser", resource_id: "test-user-inverted", category: "IAM Security", finding: "Policy uses inverted permission logic", severity: "HIGH", evidence: "Direct policy 'test-policy-notaction' uses NotAction, which allows all actions/resources except those listed", status: "OPEN", risk_score: 3, detected_at: "2026-09-05T11:15:18Z" },
  { finding_id: "IAM-013", cloud: "AWS", resource_type: "IAMUser", resource_id: "test-user-inverted", category: "IAM Security", finding: "User does not have multiple active access keys", severity: "PASS", evidence: "0 active access key(s)", status: "PASS", risk_score: 0, detected_at: "2026-09-05T11:15:18Z" },
  { finding_id: "IAM-014", cloud: "AWS", resource_type: "IAMUser", resource_id: "test-user-inverted", category: "IAM Security", finding: "Console access (if any) is protected by MFA, or no console access exists", severity: "PASS", evidence: "console password: False, MFA configured: False", status: "PASS", risk_score: 0, detected_at: "2026-09-05T11:15:18Z" },

  { finding_id: "IAM-001", cloud: "AWS", resource_type: "IAMUser", resource_id: "test-user-overpermissioned", category: "IAM Security", finding: "MFA is not enabled", severity: "HIGH", evidence: "IAM user 'test-user-overpermissioned' has no MFA device configured", status: "OPEN", risk_score: 6, detected_at: "2026-09-05T11:15:19Z" },
  { finding_id: "IAM-002", cloud: "AWS", resource_type: "IAMUser", resource_id: "test-user-overpermissioned", category: "IAM Security", finding: "Access key is within the 90-day rotation period", severity: "PASS", evidence: "Access key ACCESS_KEY_REDACTED_4 is 2 days old", status: "PASS", risk_score: 0, detected_at: "2026-09-05T11:15:19Z" },
  { finding_id: "IAM-003", cloud: "AWS", resource_type: "IAMUser", resource_id: "test-user-overpermissioned", category: "IAM Security", finding: "Access key has been used", severity: "PASS", evidence: "Access key ACCESS_KEY_REDACTED_4 was last used on 2026-09-05T11:10:00Z", status: "PASS", risk_score: 0, detected_at: "2026-09-05T11:15:19Z" },
  { finding_id: "IAM-005", cloud: "AWS", resource_type: "IAMUser", resource_id: "test-user-overpermissioned", category: "IAM Security", finding: "Policy inventory collected", severity: "INFO", evidence: { direct_managed_policies: ["AdministratorAccess"] }, status: "INFO", risk_score: 0, detected_at: "2026-09-05T11:15:20Z" },
  { finding_id: "IAM-006", cloud: "AWS", resource_type: "IAMUser", resource_id: "test-user-overpermissioned", category: "IAM Security", finding: "Policy grants excessive permissions", severity: "HIGH", evidence: "Direct policy 'AdministratorAccess' grants wildcard Action and Resource '*' for user 'test-user-overpermissioned'", status: "OPEN", risk_score: 18, detected_at: "2026-09-05T11:15:21Z" },
  { finding_id: "IAM-007", cloud: "AWS", resource_type: "IAMUser", resource_id: "test-user-overpermissioned", category: "IAM Security", finding: "200 granted service(s) have never been used", severity: "MEDIUM", evidence: "User 'test-user-overpermissioned' has access to 200 AWS services with no recorded usage", status: "OPEN", risk_score: 12, detected_at: "2026-09-05T11:15:29Z" },
  { finding_id: "IAM-011", cloud: "AWS", resource_type: "IAMUser", resource_id: "test-user-overpermissioned", category: "IAM Security", finding: "User does not have dual credential exposure", severity: "PASS", evidence: "console password: False, active access keys: 1", status: "PASS", risk_score: 0, detected_at: "2026-09-05T11:15:29Z" },
  { finding_id: "IAM-012", cloud: "AWS", resource_type: "IAMUser", resource_id: "test-user-overpermissioned", category: "IAM Security", finding: "No inverted permission logic detected", severity: "PASS", evidence: "No NotAction/NotResource statements found for 'test-user-overpermissioned'", status: "PASS", risk_score: 0, detected_at: "2026-09-05T11:15:30Z" },
  { finding_id: "IAM-013", cloud: "AWS", resource_type: "IAMUser", resource_id: "test-user-overpermissioned", category: "IAM Security", finding: "User does not have multiple active access keys", severity: "PASS", evidence: "1 active access key(s)", status: "PASS", risk_score: 0, detected_at: "2026-09-05T11:15:30Z" },
  { finding_id: "IAM-014", cloud: "AWS", resource_type: "IAMUser", resource_id: "test-user-overpermissioned", category: "IAM Security", finding: "Console access (if any) is protected by MFA, or no console access exists", severity: "PASS", evidence: "console password: False, MFA configured: False", status: "PASS", risk_score: 0, detected_at: "2026-09-05T11:15:30Z" },

  { finding_id: "IAM-008", cloud: "AWS", resource_type: "IAMRole", resource_id: "AWSServiceRoleForResourceExplorer", category: "IAM Security", finding: "No role misconfigurations detected", severity: "PASS", evidence: "Role has a scoped trust policy and no wildcard permissions", status: "PASS", risk_score: 0, detected_at: "2026-09-05T11:15:32Z" },
  { finding_id: "IAM-009", cloud: "AWS", resource_type: "IAMRole", resource_id: "AWSServiceRoleForResourceExplorer", category: "IAM Security", finding: "No external account trust detected", severity: "PASS", evidence: "Trust policy does not reference any external AWS accounts", status: "PASS", risk_score: 0, detected_at: "2026-09-05T11:15:32Z" },
  { finding_id: "IAM-008", cloud: "AWS", resource_type: "IAMRole", resource_id: "AWSServiceRoleForSupport", category: "IAM Security", finding: "No role misconfigurations detected", severity: "PASS", evidence: "Role has a scoped trust policy and no wildcard permissions", status: "PASS", risk_score: 0, detected_at: "2026-09-05T11:15:34Z" },
  { finding_id: "IAM-009", cloud: "AWS", resource_type: "IAMRole", resource_id: "AWSServiceRoleForSupport", category: "IAM Security", finding: "No external account trust detected", severity: "PASS", evidence: "Trust policy does not reference any external AWS accounts", status: "PASS", risk_score: 0, detected_at: "2026-09-05T11:15:34Z" },
  { finding_id: "IAM-008", cloud: "AWS", resource_type: "IAMRole", resource_id: "AWSServiceRoleForTrustedAdvisor", category: "IAM Security", finding: "No role misconfigurations detected", severity: "PASS", evidence: "Role has a scoped trust policy and no wildcard permissions", status: "PASS", risk_score: 0, detected_at: "2026-09-05T11:15:35Z" },
  { finding_id: "IAM-009", cloud: "AWS", resource_type: "IAMRole", resource_id: "AWSServiceRoleForTrustedAdvisor", category: "IAM Security", finding: "No external account trust detected", severity: "PASS", evidence: "Trust policy does not reference any external AWS accounts", status: "PASS", risk_score: 0, detected_at: "2026-09-05T11:15:35Z" },
  { finding_id: "IAM-008", cloud: "AWS", resource_type: "IAMRole", resource_id: "test-role-clean", category: "IAM Security", finding: "No role misconfigurations detected", severity: "PASS", evidence: "Role has a scoped trust policy and no wildcard permissions", status: "PASS", risk_score: 0, detected_at: "2026-09-05T11:15:36Z" },
  { finding_id: "IAM-009", cloud: "AWS", resource_type: "IAMRole", resource_id: "test-role-clean", category: "IAM Security", finding: "No external account trust detected", severity: "PASS", evidence: "Trust policy does not reference any external AWS accounts", status: "PASS", risk_score: 0, detected_at: "2026-09-05T11:15:36Z" },
  { finding_id: "IAM-008", cloud: "AWS", resource_type: "IAMRole", resource_id: "test-role-cross-account", category: "IAM Security", finding: "No role misconfigurations detected", severity: "PASS", evidence: "Role has a scoped trust policy and no wildcard permissions", status: "PASS", risk_score: 0, detected_at: "2026-09-05T11:15:37Z" },
  { finding_id: "IAM-009", cloud: "AWS", resource_type: "IAMRole", resource_id: "test-role-cross-account", category: "IAM Security", finding: "Role trusts an external AWS account", severity: "MEDIUM", evidence: "Trust policy allows account '630243421920' (not your account '630243421937') to assume it", status: "OPEN", risk_score: 4, detected_at: "2026-09-05T11:15:37Z" },
  { finding_id: "IAM-008", cloud: "AWS", resource_type: "IAMRole", resource_id: "test-role-overpermissioned", category: "IAM Security", finding: "Role trust policy allows any AWS account to assume it", severity: "HIGH", evidence: "Role has Principal '*' in its trust policy", status: "OPEN", risk_score: 27, detected_at: "2026-09-05T11:15:37Z" },
  { finding_id: "IAM-008", cloud: "AWS", resource_type: "IAMRole", resource_id: "test-role-overpermissioned", category: "IAM Security", finding: "Role has wildcard permissions", severity: "HIGH", evidence: "Policy 'AdministratorAccess' attached to role allows Action '*'", status: "OPEN", risk_score: 18, detected_at: "2026-09-05T11:15:38Z" },
  { finding_id: "IAM-009", cloud: "AWS", resource_type: "IAMRole", resource_id: "test-role-overpermissioned", category: "IAM Security", finding: "No external account trust detected", severity: "PASS", evidence: "Trust policy does not reference any external AWS accounts", status: "PASS", risk_score: 0, detected_at: "2026-09-05T11:15:38Z" },
  { finding_id: "IAM-008", cloud: "AWS", resource_type: "IAMRole", resource_id: "test-role-partially-permissioned", category: "IAM Security", finding: "Role has wildcard permissions", severity: "HIGH", evidence: "Policy 'AdministratorAccess' attached to role allows Action '*'", status: "OPEN", risk_score: 18, detected_at: "2026-09-05T11:15:39Z" },
  { finding_id: "IAM-009", cloud: "AWS", resource_type: "IAMRole", resource_id: "test-role-partially-permissioned", category: "IAM Security", finding: "No external account trust detected", severity: "PASS", evidence: "Trust policy does not reference any external AWS accounts", status: "PASS", risk_score: 0, detected_at: "2026-09-05T11:15:39Z" },

  { finding_id: "IAM-010", cloud: "AWS", resource_type: "RootAccount", resource_id: "root", category: "IAM Security", finding: "Root account has MFA enabled", severity: "PASS", evidence: "AccountMFAEnabled is 1 in account summary", status: "PASS", risk_score: 0, detected_at: "2026-09-05T11:15:39Z" },
  { finding_id: "IAM-010", cloud: "AWS", resource_type: "RootAccount", resource_id: "root", category: "IAM Security", finding: "Root account has no access keys", severity: "PASS", evidence: "AccountAccessKeysPresent is 0 in account summary", status: "PASS", risk_score: 0, detected_at: "2026-09-05T11:15:39Z" },
];

const SEVERITY_META = {
  HIGH: { label: "High", color: "#C7402F", bg: "#FBEAE7" },
  MEDIUM: { label: "Medium", color: "#B4791B", bg: "#FBF1E1" },
  INFO: { label: "Info", color: "#5B6472", bg: "#EEF0F3" },
  PASS: { label: "Pass", color: "#2E8B57", bg: "#E7F4EC" },
};

function evidenceText(ev) {
  if (typeof ev === "string") return ev;
  try {
    return JSON.stringify(ev);
  } catch {
    return String(ev);
  }
}

function riskBand(score) {
  if (score >= 15) return { label: "Severe", color: "#C7402F" };
  if (score >= 7) return { label: "Elevated", color: "#B4791B" };
  if (score > 0) return { label: "Low", color: "#2E8B57" };
  return { label: "â€”", color: "#B7BCC4" };
}

function fmtDate(iso) {
  try {
    return new Date(iso).toLocaleString(undefined, {
      month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
    });
  } catch {
    return iso;
  }
}

const NAV_ITEMS = [
  { label: "Dashboard", icon: LayoutDashboard, active: true },
  { label: "IAM Security", icon: KeyRound, active: false, current: true },
  { label: "Network Security", icon: Network, active: false, soon: true },
  { label: "Data & Compliance", icon: Database, active: false, soon: true },
  { label: "AI Intelligence", icon: Sparkles, active: false, soon: true },
];

export default function IamSecurityDashboard() {
  const [findings, setFindings] = useState([]);
  const [sourceLabel, setSourceLabel] = useState("Loading scanner data...");
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [resourceFilter, setResourceFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [sortKey, setSortKey] = useState("risk_score");
  const [sortDir, setSortDir] = useState("desc");
  const [page, setPage] = useState(1);
  const [uploadError, setUploadError] = useState("");
  const fileInputRef = useRef(null);
  const PAGE_SIZE = 8;

  function handleUploadClick() {
    fileInputRef.current?.click();
  }

  function handleFile(e) {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploadError("");
    const reader = new FileReader();
    reader.onload = (evt) => {
      try {
        const parsed = JSON.parse(evt.target.result);
        const arr = Array.isArray(parsed) ? parsed : [parsed];
        if (arr.length === 0 || !arr[0].finding_id) {
          throw new Error("shape mismatch");
        }
        setFindings(arr);
        setSourceLabel(`${file.name} Â· loaded ${new Date().toLocaleTimeString()}`);
        setPage(1);
      } catch {
        setUploadError("Couldn't read that file â€” make sure it's the iam_findings.json the scanner produces.");
      }
    };
    reader.readAsText(file);
    e.target.value = "";
  }

  function resetSample() {
    setFindings(SAMPLE_FINDINGS);
    setSourceLabel("Sample scan data");
    setUploadError("");
    setPage(1);
  }

  const stats = useMemo(() => {
    const total = findings.length;
    const open = findings.filter((f) => f.status === "OPEN").length;
    const high = findings.filter((f) => f.severity === "HIGH" && f.status === "OPEN").length;
    const resources = new Set(findings.map((f) => `${f.resource_type}:${f.resource_id}`)).size;
    const top = findings.reduce((acc, f) => ((f.risk_score || 0) > (acc?.risk_score || -1) ? f : acc), null);
    return { total, open, high, resources, top };
  }, [findings]);

  const severityCounts = useMemo(() => {
    const counts = { HIGH: 0, MEDIUM: 0, INFO: 0, PASS: 0 };
    findings.forEach((f) => {
      counts[f.severity] = (counts[f.severity] || 0) + 1;
    });
    return counts;
  }, [findings]);

  const pieData = useMemo(
    () =>
      Object.entries(severityCounts)
        .filter(([, v]) => v > 0)
        .map(([k, v]) => ({ name: SEVERITY_META[k]?.label || k, value: v, color: SEVERITY_META[k]?.color || "#999" })),
    [severityCounts]
  );

  const ruleFrequency = useMemo(() => {
    const openFindings = findings.filter((f) => f.status === "OPEN");
    const counts = {};
    openFindings.forEach((f) => {
      counts[f.finding_id] = (counts[f.finding_id] || 0) + 1;
    });
    // Look up the label from an OPEN finding specifically, not just the
    // first occurrence in the full list (which could be a PASS row with
    // different wording for the same rule ID).
    return Object.entries(counts)
      .map(([id, count]) => ({
        id,
        count,
        finding: openFindings.find((f) => f.finding_id === id)?.finding || "",
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 6);
  }, [findings]);

  const resourceTypeData = useMemo(() => {
    const counts = {};
    findings
      .filter((f) => f.status === "OPEN")
      .forEach((f) => {
        counts[f.resource_type] = (counts[f.resource_type] || 0) + 1;
      });
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  }, [findings]);

  const topRisk = useMemo(
    () =>
      [...findings]
        .filter((f) => (f.risk_score || 0) > 0)
        .sort((a, b) => b.risk_score - a.risk_score)
        .slice(0, 5),
    [findings]
  );

  const filtered = useMemo(() => {
    return findings.filter((f) => {
      if (severityFilter !== "ALL" && f.severity !== severityFilter) return false;
      if (resourceFilter !== "ALL" && f.resource_type !== resourceFilter) return false;
      if (statusFilter !== "ALL" && f.status !== statusFilter) return false;
      if (search) {
        const q = search.toLowerCase();
        const hay = `${f.resource_id} ${f.finding} ${f.finding_id}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [findings, severityFilter, resourceFilter, statusFilter, search]);

  const sorted = useMemo(() => {
    const copy = [...filtered];
    copy.sort((a, b) => {
      let av = a[sortKey];
      let bv = b[sortKey];
      if (sortKey === "detected_at") {
        av = new Date(av).getTime();
        bv = new Date(bv).getTime();
      }
      if (av === undefined) av = 0;
      if (bv === undefined) bv = 0;
      if (av < bv) return sortDir === "asc" ? -1 : 1;
      if (av > bv) return sortDir === "asc" ? 1 : -1;
      return 0;
    });
    return copy;
  }, [filtered, sortKey, sortDir]);

  const totalPages = Math.max(1, Math.ceil(sorted.length / PAGE_SIZE));
  const currentPage = Math.min(page, totalPages);
  const pageRows = sorted.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);

  function toggleSort(key) {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("desc");
    }
    setPage(1);
  }

  const resourceTypes = useMemo(
    () => Array.from(new Set(findings.map((f) => f.resource_type))),
    [findings]
  );

  return (
    <div style={{ fontFamily: "system-ui, -apple-system, sans-serif" }} className="flex min-h-screen w-full text-slate-800">
      {/* ---------------- Sidebar ---------------- */}
      <aside className="w-60 shrink-0 flex flex-col" style={{ backgroundColor: "#0F1B2D" }}>
        <div className="px-5 py-5 border-b" style={{ borderColor: "#1D2C42" }}>
          <div className="flex items-center gap-2">
            <div className="h-8 w-8 rounded-md flex items-center justify-center" style={{ backgroundColor: "#3E63DD" }}>
              <ShieldCheckMark />
            </div>
            <div>
              <div className="text-white font-semibold text-sm leading-tight">CSPM Platform</div>
              <div className="text-[11px]" style={{ color: "#8391A8" }}>Multi-cloud security posture</div>
            </div>
          </div>
        </div>

        <nav className="flex-1 px-3 py-4 space-y-1">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            return (
              <div
                key={item.label}
                className="flex items-center justify-between px-3 py-2 rounded-lg text-sm"
                style={{
                  backgroundColor: item.current ? "#16263D" : "transparent",
                  color: item.soon ? "#5C6B82" : "#D7DEE9",
                  cursor: item.soon ? "default" : "pointer",
                }}
              >
                <span className="flex items-center gap-2.5">
                  <Icon size={16} strokeWidth={2} />
                  {item.label}
                </span>
                {item.soon && (
                  <span
                    className="text-[10px] px-1.5 py-0.5 rounded"
                    style={{ backgroundColor: "#1D2C42", color: "#8391A8" }}
                  >
                    soon
                  </span>
                )}
              </div>
            );
          })}
        </nav>

        <div className="px-4 py-4 border-t text-[11px] leading-relaxed" style={{ borderColor: "#1D2C42", color: "#5C6B82" }}>
          Network, Data &amp; Compliance, and AI modules plug into this same findings format once built â€” nothing here changes when they're added.
        </div>
      </aside>

      {/* ---------------- Main ---------------- */}
      <div className="flex-1 flex flex-col min-w-0" style={{ backgroundColor: "#F6F7F9" }}>
        {/* Topbar */}
        <header className="flex items-center justify-between px-8 py-5 bg-white border-b border-slate-200">
          <div>
            <h1 className="text-xl font-semibold text-slate-900">IAM Security</h1>
            <p className="text-sm text-slate-500 mt-0.5">AWS Â· Identity and Access Management module</p>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-xs text-slate-500">{sourceLabel}</span>
            <button
              onClick={resetSample}
              className="flex items-center gap-1.5 text-sm px-3 py-2 rounded-lg border border-slate-200 text-slate-600 hover:bg-slate-50"
            >
              <RefreshCw size={14} />
              Reset
            </button>
            <button
              onClick={handleUploadClick}
              className="flex items-center gap-1.5 text-sm px-3 py-2 rounded-lg text-white"
              style={{ backgroundColor: "#3E63DD" }}
            >
              <Upload size={14} />
              Upload findings JSON
            </button>
            <input ref={fileInputRef} type="file" accept=".json,application/json" className="hidden" onChange={handleFile} />
          </div>
        </header>

        {uploadError && (
          <div className="mx-8 mt-4 flex items-center justify-between text-sm px-4 py-2.5 rounded-lg" style={{ backgroundColor: "#FBEAE7", color: "#C7402F" }}>
            {uploadError}
            <button onClick={() => setUploadError("")}><X size={14} /></button>
          </div>
        )}

        <main className="flex-1 px-8 py-6 space-y-6">
          {/* KPI row */}
          <div className="grid grid-cols-5 gap-4">
            <KpiCard label="Total findings" value={stats.total} sub="across all checks" />
            <KpiCard label="Open findings" value={stats.open} sub="require attention" accent="#B4791B" />
            <KpiCard label="High severity, open" value={stats.high} sub="review first" accent="#C7402F" />
            <KpiCard label="Resources scanned" value={stats.resources} sub="users, roles, root" />
            <KpiCard
              label="Highest risk score"
              value={stats.top?.risk_score ?? 0}
              sub={stats.top ? `${stats.top.resource_id} Â· ${stats.top.finding_id}` : "â€”"}
              accent="#C7402F"
              mono
            />
          </div>

          {/* Charts row */}
          <div className="grid grid-cols-3 gap-4 min-w-0">
            <Panel title="Findings by severity">
              <div className="flex items-center gap-4">
                <div style={{ width: 130, height: 130 }}>
                  <ResponsiveContainer>
                    <PieChart>
                      <Pie data={pieData} dataKey="value" nameKey="name" innerRadius={38} outerRadius={58} paddingAngle={2}>
                        {pieData.map((entry, i) => (
                          <Cell key={i} fill={entry.color} stroke="none" />
                        ))}
                      </Pie>
                      <ReTooltip />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="space-y-1.5 flex-1">
                  {Object.entries(severityCounts)
                    .filter(([, v]) => v > 0)
                    .map(([k, v]) => (
                      <div key={k} className="flex items-center justify-between text-sm">
                        <span className="flex items-center gap-2">
                          <span className="h-2 w-2 rounded-full" style={{ backgroundColor: SEVERITY_META[k]?.color }} />
                          {SEVERITY_META[k]?.label}
                        </span>
                        <span className="font-mono text-slate-600">{v}</span>
                      </div>
                    ))}
                </div>
              </div>
            </Panel>

            <Panel title="Open findings by resource type">
              <div style={{ width: "100%", height: 150 }}>
                <ResponsiveContainer>
                  <BarChart data={resourceTypeData} layout="vertical" margin={{ left: 8, right: 16 }}>
                    <XAxis type="number" hide />
                    <YAxis type="category" dataKey="name" width={90} tick={{ fontSize: 12, fill: "#5B6472" }} axisLine={false} tickLine={false} />
                    <ReTooltip cursor={{ fill: "#F1F3F6" }} />
                    <Bar dataKey="value" fill="#3E63DD" radius={[0, 4, 4, 0]} barSize={22} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </Panel>

            <Panel title="Most frequent open rules">
              <div className="space-y-2.5">
                {ruleFrequency.map((r) => (
                  <div key={r.id} className="flex items-center justify-between text-sm">
                    <div className="min-w-0">
                      <div className="font-mono text-xs text-slate-500">{r.id}</div>
                      <div className="truncate text-slate-700">{r.finding}</div>
                    </div>
                    <span
                      className="shrink-0 ml-3 text-xs font-mono px-2 py-0.5 rounded-full"
                      style={{ backgroundColor: "#EEF0F3", color: "#3E4C5E" }}
                    >
                      {r.count}
                    </span>
                  </div>
                ))}
                {ruleFrequency.length === 0 && <div className="text-sm text-slate-400">No open findings.</div>}
              </div>
            </Panel>
          </div>

          {/* Top risk + table */}
          <div className="grid grid-cols-4 gap-4 min-w-0">
            <Panel title="Top risk findings" className="col-span-1">
              <div className="space-y-3">
                {topRisk.map((f, i) => {
                  const band = riskBand(f.risk_score);
                  return (
                    <div key={i} className="pb-3 border-b last:border-0 border-slate-100">
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-xs text-slate-500">{f.finding_id}</span>
                        <span className="font-mono text-sm font-semibold" style={{ color: band.color }}>
                          {f.risk_score}
                        </span>
                      </div>
                      <div className="text-sm text-slate-700 truncate">{f.resource_id}</div>
                      <div className="text-xs text-slate-500 truncate">{f.finding}</div>
                    </div>
                  );
                })}
              </div>
            </Panel>

            <Panel title="Findings" className="col-span-3">
              {/* Filters */}
              <div className="flex flex-wrap items-center gap-2 mb-4">
                <div className="flex items-center gap-2 flex-1 min-w-[180px] px-3 py-2 rounded-lg border border-slate-200 bg-white">
                  <Search size={14} className="text-slate-400" />
                  <input
                    value={search}
                    onChange={(e) => {
                      setSearch(e.target.value);
                      setPage(1);
                    }}
                    placeholder="Search resource, finding, or rule ID"
                    className="text-sm outline-none flex-1"
                  />
                </div>
                <SelectFilter
                  value={severityFilter}
                  onChange={(v) => {
                    setSeverityFilter(v);
                    setPage(1);
                  }}
                  options={["ALL", "HIGH", "MEDIUM", "INFO", "PASS"]}
                  labels={{ ALL: "All severities" }}
                />
                <SelectFilter
                  value={resourceFilter}
                  onChange={(v) => {
                    setResourceFilter(v);
                    setPage(1);
                  }}
                  options={["ALL", ...resourceTypes]}
                  labels={{ ALL: "All resource types" }}
                />
                <SelectFilter
                  value={statusFilter}
                  onChange={(v) => {
                    setStatusFilter(v);
                    setPage(1);
                  }}
                  options={["ALL", "OPEN", "PASS", "INFO"]}
                  labels={{ ALL: "All statuses" }}
                />
              </div>

              {/* Table */}
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left text-xs text-slate-500 border-b border-slate-200">
                      <Th onClick={() => toggleSort("finding_id")} active={sortKey === "finding_id"} dir={sortDir}>Rule</Th>
                      <th className="py-2 pr-3 font-medium">Resource</th>
                      <th className="py-2 pr-3 font-medium">Finding</th>
                      <Th onClick={() => toggleSort("severity")} active={sortKey === "severity"} dir={sortDir}>Severity</Th>
                      <Th onClick={() => toggleSort("risk_score")} active={sortKey === "risk_score"} dir={sortDir}>Risk</Th>
                      <Th onClick={() => toggleSort("detected_at")} active={sortKey === "detected_at"} dir={sortDir}>Detected</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {pageRows.map((f, i) => {
                      const sev = SEVERITY_META[f.severity] || SEVERITY_META.INFO;
                      return (
                        <tr key={i} className="border-b border-slate-100 last:border-0 align-top">
                          <td className="py-2.5 pr-3 font-mono text-xs text-slate-500 whitespace-nowrap">{f.finding_id}</td>
                          <td className="py-2.5 pr-3">
                            <div className="text-slate-800">{f.resource_id}</div>
                            <div className="text-[11px] text-slate-400">{f.resource_type}</div>
                          </td>
                          <td className="py-2.5 pr-3 max-w-xs">
                            <div className="text-slate-700">{f.finding}</div>
                            <div className="text-[11px] text-slate-400 truncate" title={evidenceText(f.evidence)}>
                              {evidenceText(f.evidence)}
                            </div>
                          </td>
                          <td className="py-2.5 pr-3 whitespace-nowrap">
                            <span
                              className="text-xs px-2 py-0.5 rounded-full font-medium"
                              style={{ backgroundColor: sev.bg, color: sev.color }}
                            >
                              {sev.label}
                            </span>
                          </td>
                          <td className="py-2.5 pr-3 font-mono whitespace-nowrap" style={{ color: riskBand(f.risk_score).color }}>
                            {f.risk_score ?? 0}
                          </td>
                          <td className="py-2.5 pr-3 text-slate-500 whitespace-nowrap text-xs">{fmtDate(f.detected_at)}</td>
                        </tr>
                      );
                    })}
                    {pageRows.length === 0 && (
                      <tr>
                        <td colSpan={6} className="py-8 text-center text-slate-400 text-sm">
                          No findings match these filters.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>

              {/* Pagination */}
              <div className="flex items-center justify-between pt-4 text-sm text-slate-500">
                <span>
                  Showing {pageRows.length ? (currentPage - 1) * PAGE_SIZE + 1 : 0}â€“
                  {(currentPage - 1) * PAGE_SIZE + pageRows.length} of {sorted.length}
                </span>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                    disabled={currentPage === 1}
                    className="p-1.5 rounded-md border border-slate-200 disabled:opacity-30"
                  >
                    <ChevronLeft size={14} />
                  </button>
                  <span className="font-mono text-xs">{currentPage} / {totalPages}</span>
                  <button
                    onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                    disabled={currentPage === totalPages}
                    className="p-1.5 rounded-md border border-slate-200 disabled:opacity-30"
                  >
                    <ChevronRight size={14} />
                  </button>
                </div>
              </div>
            </Panel>
          </div>
        </main>
      </div>
    </div>
  );
}

function ShieldCheckMark() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z" />
      <path d="m9 12 2 2 4-4" />
    </svg>
  );
}

function KpiCard({ label, value, sub, accent, mono }) {
  return (
    <div className="bg-white rounded-xl border border-slate-200 px-5 py-4">
      <div className="text-xs text-slate-500">{label}</div>
      <div
        className={`text-2xl font-semibold mt-1 ${mono ? "font-mono" : ""}`}
        style={{ color: accent || "#0F1B2D" }}
      >
        {value}
      </div>
      <div className="text-[11px] text-slate-400 mt-1 truncate">{sub}</div>
    </div>
  );
}

function Panel({ title, children, className = "" }) {
  return (
    <div className={`bg-white rounded-xl border border-slate-200 p-5 min-w-0 ${className}`}>
      <div className="text-sm font-semibold text-slate-800 mb-4">{title}</div>
      {children}
    </div>
  );
}

function Th({ children, onClick, active, dir }) {
  return (
    <th className="py-2 pr-3 font-medium cursor-pointer select-none" onClick={onClick}>
      <span className="flex items-center gap-1">
        {children}
        <ArrowUpDown size={11} className={active ? "text-slate-700" : "text-slate-300"} />
      </span>
    </th>
  );
}

function SelectFilter({ value, onChange, options, labels = {} }) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="text-sm px-3 py-2 rounded-lg border border-slate-200 bg-white text-slate-600"
    >
      {options.map((o) => (
        <option key={o} value={o}>
          {labels[o] || o}
        </option>
      ))}
    </select>
  );
}
