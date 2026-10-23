import React, { useMemo } from "react";
import {
  ShieldCheck,
  AlertTriangle,
  ShieldAlert,
  Server,
  Cloud,
  Activity,
  ArrowUpRight,
  Clock3,
  CheckCircle2,
  Network,
  Database,
  KeyRound,
  Sparkles,
} from "lucide-react";
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
} from "recharts";

/*
  MAIN CSPM DASHBOARD

  This page is intentionally different from IAM Security.

  Dashboard = overall CSPM security posture
  IAM Security = detailed IAM findings

  For now the dashboard uses sample data.
  Later, Network/Data/AI modules can feed their findings
  into the same structure.
*/

// --------------------------------------------------
// SAMPLE FINDINGS
// --------------------------------------------------

const FINDINGS = [
  {
    finding_id: "IAM-001",
    cloud: "AWS",
    domain: "IAM",
    resource_id: "cspm-scanner",
    resource_type: "IAM User",
    finding: "MFA is not enabled",
    severity: "HIGH",
    status: "OPEN",
    risk_score: 8,
  },
  {
    finding_id: "IAM-002",
    cloud: "AWS",
    domain: "IAM",
    resource_id: "test-user",
    resource_type: "IAM User",
    finding: "Access key is older than 90 days",
    severity: "MEDIUM",
    status: "OPEN",
    risk_score: 5,
  },
  {
    finding_id: "IAM-003",
    cloud: "AWS",
    domain: "IAM",
    resource_id: "test-user",
    resource_type: "IAM User",
    finding: "Unused access key detected",
    severity: "HIGH",
    status: "OPEN",
    risk_score: 7,
  },
  {
    finding_id: "IAM-004",
    cloud: "AWS",
    domain: "IAM",
    resource_id: "admin-user",
    resource_type: "IAM User",
    finding: "Wildcard permissions detected",
    severity: "CRITICAL",
    status: "OPEN",
    risk_score: 10,
  },
  {
    finding_id: "NET-001",
    cloud: "AWS",
    domain: "NETWORK",
    resource_id: "sg-0abc123",
    resource_type: "Security Group",
    finding: "SSH port 22 is publicly accessible",
    severity: "CRITICAL",
    status: "OPEN",
    risk_score: 10,
  },
  {
    finding_id: "NET-002",
    cloud: "AWS",
    domain: "NETWORK",
    resource_id: "sg-0def456",
    resource_type: "Security Group",
    finding: "Unrestricted inbound traffic detected",
    severity: "HIGH",
    status: "OPEN",
    risk_score: 8,
  },
  {
    finding_id: "DATA-001",
    cloud: "AWS",
    domain: "DATA",
    resource_id: "company-data-bucket",
    resource_type: "S3 Bucket",
    finding: "S3 bucket is publicly accessible",
    severity: "CRITICAL",
    status: "OPEN",
    risk_score: 10,
  },
  {
    finding_id: "DATA-002",
    cloud: "AWS",
    domain: "DATA",
    resource_id: "backup-bucket",
    resource_type: "S3 Bucket",
    finding: "Encryption is not enabled",
    severity: "MEDIUM",
    status: "OPEN",
    risk_score: 5,
  },
  {
    finding_id: "DATA-003",
    cloud: "AWS",
    domain: "MONITORING",
    resource_id: "cloudtrail-main",
    resource_type: "CloudTrail",
    finding: "CloudTrail logging is not enabled",
    severity: "HIGH",
    status: "OPEN",
    risk_score: 8,
  },
];

// --------------------------------------------------
// HELPERS
// --------------------------------------------------

const severityWeight = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};

const severityClass = {
  CRITICAL: "text-red-400 bg-red-500/10 border-red-500/20",
  HIGH: "text-orange-400 bg-orange-500/10 border-orange-500/20",
  MEDIUM: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
  LOW: "text-blue-400 bg-blue-500/10 border-blue-500/20",
};

// --------------------------------------------------
// COMPONENT
// --------------------------------------------------

export default function Dashboard() {
  const stats = useMemo(() => {
    const critical = FINDINGS.filter(
      (item) => item.severity === "CRITICAL"
    ).length;

    const high = FINDINGS.filter(
      (item) => item.severity === "HIGH"
    ).length;

    const medium = FINDINGS.filter(
      (item) => item.severity === "MEDIUM"
    ).length;

    const open = FINDINGS.filter(
      (item) => item.status === "OPEN"
    ).length;

    const resources = new Set(
      FINDINGS.map((item) => item.resource_id)
    ).size;

    return {
      total: FINDINGS.length,
      critical,
      high,
      medium,
      open,
      resources,
    };
  }, []);

  // --------------------------------------------------
  // SEVERITY DATA
  // --------------------------------------------------

  const severityData = [
    {
      name: "Critical",
      value: stats.critical,
      label: "CRITICAL",
    },
    {
      name: "High",
      value: stats.high,
      label: "HIGH",
    },
    {
      name: "Medium",
      value: stats.medium,
      label: "MEDIUM",
    },
    {
      name: "Low",
      value: FINDINGS.filter(
        (item) => item.severity === "LOW"
      ).length,
      label: "LOW",
    },
  ];

  // --------------------------------------------------
  // DOMAIN DATA
  // --------------------------------------------------

  const domainData = ["IAM", "NETWORK", "DATA", "MONITORING"].map(
    (domain) => ({
      name: domain,
      findings: FINDINGS.filter(
        (item) => item.domain === domain
      ).length,
    })
  );

  // --------------------------------------------------
  // CLOUD DATA
  // --------------------------------------------------

  const cloudData = ["AWS", "AZURE", "GCP"].map((cloud) => ({
    name: cloud,
    findings: FINDINGS.filter(
      (item) => item.cloud === cloud
    ).length,
  }));

  // --------------------------------------------------
  // TOP RISKS
  // --------------------------------------------------

  const topRisks = [...FINDINGS]
    .sort((a, b) => {
      if (
        severityWeight[b.severity] !==
        severityWeight[a.severity]
      ) {
        return (
          severityWeight[b.severity] -
          severityWeight[a.severity]
        );
      }

      return b.risk_score - a.risk_score;
    })
    .slice(0, 5);

  // --------------------------------------------------
  // SECURITY SCORE
  // --------------------------------------------------

  const averageRisk =
    FINDINGS.reduce(
      (total, item) => total + item.risk_score,
      0
    ) / FINDINGS.length;

  const securityScore = Math.max(
    0,
    Math.round(100 - averageRisk * 6)
  );

  return (
    <div className="min-h-screen bg-[#07111f] text-slate-100">

      {/* ============================================
          TOP BAR
      ============================================ */}

      <header className="border-b border-slate-800 bg-[#081321] px-8 py-5">

        <div className="flex items-center justify-between">

          <div>
            <p className="text-xs font-medium uppercase tracking-[0.2em] text-blue-400">
              CSPM Platform
            </p>

            <h1 className="mt-1 text-2xl font-semibold">
              Security Dashboard
            </h1>

            <p className="mt-1 text-sm text-slate-400">
              Overall cloud security posture and prioritized risks
            </p>
          </div>

          <div className="flex items-center gap-3">

            <div className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900/60 px-4 py-2 text-sm text-slate-300">
              <Clock3 size={15} />
              Last scan: Today
            </div>

            <button className="rounded-lg border border-slate-700 bg-slate-900/60 px-4 py-2 text-sm text-slate-300 transition hover:border-blue-500 hover:text-white">
              Refresh
            </button>

          </div>

        </div>
      </header>


      {/* ============================================
          MAIN CONTENT
      ============================================ */}

      <main className="p-8">

        {/* ==========================================
            KPI CARDS
        ========================================== */}

        <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-5">

          <MetricCard
            icon={<ShieldAlert size={20} />}
            title="Total Findings"
            value={stats.total}
            description="Across all security domains"
          />

          <MetricCard
            icon={<AlertTriangle size={20} />}
            title="Critical"
            value={stats.critical}
            description="Immediate attention required"
            danger
          />

          <MetricCard
            icon={<ShieldAlert size={20} />}
            title="High"
            value={stats.high}
            description="High-priority security risks"
          />

          <MetricCard
            icon={<Server size={20} />}
            title="Resources"
            value={stats.resources}
            description="Resources currently monitored"
          />

          <MetricCard
            icon={<ShieldCheck size={20} />}
            title="Security Score"
            value={`${securityScore}%`}
            description="Overall posture score"
            positive
          />

        </section>


        {/* ==========================================
            SECOND ROW
        ========================================== */}

        <section className="mt-6 grid grid-cols-1 gap-6 xl:grid-cols-3">

          {/* SEVERITY */}

          <Panel
            title="Findings by Severity"
            subtitle="Current risk distribution"
          >

            <div className="h-[260px]">

              <ResponsiveContainer width="100%" height="100%">

                <PieChart>

                  <Pie
                    data={severityData}
                    dataKey="value"
                    nameKey="name"
                    innerRadius={65}
                    outerRadius={95}
                    paddingAngle={4}
                  >

                    {severityData.map((entry, index) => (
                      <Cell
                        key={`cell-${index}`}
                        fill={
                          entry.label === "CRITICAL"
                            ? "#ef4444"
                            : entry.label === "HIGH"
                            ? "#f97316"
                            : entry.label === "MEDIUM"
                            ? "#eab308"
                            : "#3b82f6"
                        }
                      />
                    ))}

                  </Pie>

                  <Tooltip
                    contentStyle={{
                      background: "#0f1b2d",
                      border: "1px solid #243247",
                      borderRadius: "8px",
                    }}
                  />

                </PieChart>

              </ResponsiveContainer>

            </div>

            <div className="grid grid-cols-2 gap-3">

              {severityData.map((item) => (
                <div
                  key={item.name}
                  className="flex items-center justify-between rounded-lg bg-slate-900/60 px-3 py-2"
                >

                  <span className="text-sm text-slate-400">
                    {item.name}
                  </span>

                  <span className="font-semibold">
                    {item.value}
                  </span>

                </div>
              ))}

            </div>

          </Panel>


          {/* DOMAIN */}

          <Panel
            title="Findings by Security Domain"
            subtitle="Where risks are concentrated"
          >

            <div className="h-[320px]">

              <ResponsiveContainer width="100%" height="100%">

                <BarChart data={domainData}>

                  <CartesianGrid
                    stroke="#1e293b"
                    vertical={false}
                  />

                  <XAxis
                    dataKey="name"
                    tick={{
                      fill: "#94a3b8",
                      fontSize: 12,
                    }}
                    axisLine={false}
                    tickLine={false}
                  />

                  <YAxis
                    allowDecimals={false}
                    tick={{
                      fill: "#64748b",
                      fontSize: 12,
                    }}
                    axisLine={false}
                    tickLine={false}
                  />

                  <Tooltip
                    contentStyle={{
                      background: "#0f1b2d",
                      border: "1px solid #243247",
                      borderRadius: "8px",
                    }}
                  />

                  <Bar
                    dataKey="findings"
                    fill="#6366f1"
                    radius={[6, 6, 0, 0]}
                  />

                </BarChart>

              </ResponsiveContainer>

            </div>

          </Panel>


          {/* SECURITY POSTURE */}

          <Panel
            title="Security Posture"
            subtitle="Current environment health"
          >

            <div className="flex h-[320px] flex-col items-center justify-center">

              <div className="relative flex h-48 w-48 items-center justify-center rounded-full border-[18px] border-slate-800">

                <div className="absolute inset-[-18px] rounded-full border-[18px] border-blue-500 border-b-transparent border-l-transparent rotate-[-35deg]" />

                <div className="text-center">

                  <p className="text-4xl font-bold">
                    {securityScore}
                  </p>

                  <p className="text-sm text-slate-500">
                    / 100
                  </p>

                </div>

              </div>

              <div className="mt-5 flex items-center gap-2 text-sm text-slate-400">

                <Activity size={15} />

                Based on current findings

              </div>

            </div>

          </Panel>

        </section>


        {/* ==========================================
            THIRD ROW
        ========================================== */}

        <section className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-2">

          {/* CLOUD DISTRIBUTION */}

          <Panel
            title="Cloud Distribution"
            subtitle="Findings across cloud providers"
          >

            <div className="space-y-5">

              {cloudData.map((cloud) => {

                const percentage =
                  stats.total === 0
                    ? 0
                    : Math.round(
                        (cloud.findings / stats.total) * 100
                      );

                return (
                  <div key={cloud.name}>

                    <div className="mb-2 flex justify-between text-sm">

                      <span className="flex items-center gap-2 text-slate-300">

                        <Cloud size={16} />

                        {cloud.name}

                      </span>

                      <span className="text-slate-400">
                        {cloud.findings} findings
                      </span>

                    </div>

                    <div className="h-2 overflow-hidden rounded-full bg-slate-800">

                      <div
                        className="h-full rounded-full bg-blue-500"
                        style={{
                          width: `${percentage}%`,
                        }}
                      />

                    </div>

                  </div>
                );

              })}

            </div>

          </Panel>


          {/* MODULE STATUS */}

          <Panel
            title="Security Modules"
            subtitle="Scanner coverage"
          >

            <div className="space-y-3">

              <ModuleRow
                icon={<KeyRound size={18} />}
                name="IAM Security"
                description="Identity and access controls"
                status="ACTIVE"
                count={
                  FINDINGS.filter(
                    (x) => x.domain === "IAM"
                  ).length
                }
              />

              <ModuleRow
                icon={<Network size={18} />}
                name="Network Security"
                description="Infrastructure and network exposure"
                status="ACTIVE"
                count={
                  FINDINGS.filter(
                    (x) => x.domain === "NETWORK"
                  ).length
                }
              />

              <ModuleRow
                icon={<Database size={18} />}
                name="Data & Compliance"
                description="Storage, logging and compliance"
                status="ACTIVE"
                count={
                  FINDINGS.filter(
                    (x) =>
                      x.domain === "DATA" ||
                      x.domain === "MONITORING"
                  ).length
                }
              />

              <ModuleRow
                icon={<Sparkles size={18} />}
                name="AI Intelligence"
                description="Risk correlation and prioritization"
                status="COMING SOON"
                count="-"
              />

            </div>

          </Panel>

        </section>


        {/* ==========================================
            TOP PRIORITIZED RISKS
        ========================================== */}

        <section className="mt-6">

          <Panel
            title="Top Prioritized Risks"
            subtitle="Issues requiring the most attention"
            action={
              <button className="flex items-center gap-1 text-sm text-blue-400 hover:text-blue-300">
                View all
                <ArrowUpRight size={15} />
              </button>
            }
          >

            <div className="overflow-x-auto">

              <table className="w-full">

                <thead>

                  <tr className="border-b border-slate-800 text-left text-xs uppercase tracking-wider text-slate-500">

                    <th className="px-4 py-3">
                      Finding
                    </th>

                    <th className="px-4 py-3">
                      Domain
                    </th>

                    <th className="px-4 py-3">
                      Resource
                    </th>

                    <th className="px-4 py-3">
                      Severity
                    </th>

                    <th className="px-4 py-3">
                      Risk
                    </th>

                    <th className="px-4 py-3">
                      Status
                    </th>

                  </tr>

                </thead>

                <tbody>

                  {topRisks.map((item) => (

                    <tr
                      key={`${item.finding_id}-${item.resource_id}`}
                      className="border-b border-slate-800/70 transition hover:bg-slate-900/60"
                    >

                      <td className="px-4 py-4">

                        <div className="font-medium text-slate-200">
                          {item.finding}
                        </div>

                        <div className="mt-1 text-xs text-slate-500">
                          {item.finding_id}
                        </div>

                      </td>

                      <td className="px-4 py-4 text-sm text-slate-400">
                        {item.domain}
                      </td>

                      <td className="px-4 py-4 text-sm text-slate-400">
                        {item.resource_id}
                      </td>

                      <td className="px-4 py-4">

                        <span
                          className={`rounded-md border px-2 py-1 text-xs font-medium ${
                            severityClass[item.severity]
                          }`}
                        >
                          {item.severity}
                        </span>

                      </td>

                      <td className="px-4 py-4">

                        <span className="font-semibold text-slate-200">
                          {item.risk_score}
                        </span>

                        <span className="text-xs text-slate-600">
                          /10
                        </span>

                      </td>

                      <td className="px-4 py-4">

                        <span className="flex items-center gap-2 text-sm text-orange-400">

                          <span className="h-2 w-2 rounded-full bg-orange-400" />

                          {item.status}

                        </span>

                      </td>

                    </tr>

                  ))}

                </tbody>

              </table>

            </div>

          </Panel>

        </section>


        {/* ==========================================
            AI INTELLIGENCE PREVIEW
        ========================================== */}

        <section className="mt-6">

          <div className="rounded-xl border border-indigo-500/20 bg-gradient-to-r from-indigo-500/10 to-blue-500/5 p-6">

            <div className="flex items-start gap-4">

              <div className="rounded-lg bg-indigo-500/10 p-3 text-indigo-400">
                <Sparkles size={22} />
              </div>

              <div>

                <p className="text-sm font-medium text-indigo-400">
                  AI SECURITY INTELLIGENCE
                </p>

                <h3 className="mt-1 text-lg font-semibold">
                  Intelligent risk correlation coming soon
                </h3>

                <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
                  The AI intelligence layer will correlate findings
                  from IAM, Network, Data and Monitoring scanners
                  to identify higher-risk attack paths and provide
                  prioritized remediation guidance.
                </p>

              </div>

            </div>

          </div>

        </section>

      </main>

    </div>
  );
}


// ==================================================
// REUSABLE COMPONENTS
// ==================================================

function MetricCard({
  icon,
  title,
  value,
  description,
  danger,
  positive,
}) {
  return (
    <div className="rounded-xl border border-slate-800 bg-[#0b1728] p-5">

      <div className="flex items-center justify-between">

        <div className="rounded-lg bg-slate-800/70 p-2.5 text-blue-400">
          {icon}
        </div>

        {positive && (
          <CheckCircle2
            size={17}
            className="text-emerald-400"
          />
        )}

      </div>

      <p className="mt-5 text-sm text-slate-400">
        {title}
      </p>

      <p
        className={`mt-1 text-3xl font-semibold ${
          danger ? "text-red-400" : "text-slate-100"
        }`}
      >
        {value}
      </p>

      <p className="mt-2 text-xs text-slate-500">
        {description}
      </p>

    </div>
  );
}


function Panel({
  title,
  subtitle,
  children,
  action,
}) {
  return (
    <div className="rounded-xl border border-slate-800 bg-[#0b1728] p-5">

      <div className="mb-5 flex items-start justify-between">

        <div>

          <h2 className="font-semibold text-slate-100">
            {title}
          </h2>

          <p className="mt-1 text-xs text-slate-500">
            {subtitle}
          </p>

        </div>

        {action}

      </div>

      {children}

    </div>
  );
}


function ModuleRow({
  icon,
  name,
  description,
  status,
  count,
}) {
  const active = status === "ACTIVE";

  return (
    <div className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-900/40 p-4">

      <div className="flex items-center gap-3">

        <div className="rounded-lg bg-slate-800 p-2 text-blue-400">
          {icon}
        </div>

        <div>

          <p className="text-sm font-medium text-slate-200">
            {name}
          </p>

          <p className="mt-1 text-xs text-slate-500">
            {description}
          </p>

        </div>

      </div>

      <div className="flex items-center gap-4">

        <span className="text-sm font-semibold text-slate-300">
          {count}
        </span>

        <span
          className={`rounded-md px-2 py-1 text-[10px] font-medium ${
            active
              ? "bg-emerald-500/10 text-emerald-400"
              : "bg-slate-800 text-slate-500"
          }`}
        >
          {status}
        </span>

      </div>

    </div>
  );
}