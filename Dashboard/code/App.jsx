import React, { useState } from "react";
import Dashboard from "./dashboard";
import IamSecurityDashboard from "./iam_dashboard";

const APP_ICON_PATHS = {
  dashboard: <><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></>,
  iam: <><circle cx="12" cy="8" r="4"/><path d="M5 21v-2a7 7 0 0 1 14 0v2"/></>,
  network: <><circle cx="5" cy="12" r="2"/><circle cx="19" cy="5" r="2"/><circle cx="19" cy="19" r="2"/><path d="m7 11 10-5M7 13l10 5"/></>,
  data: <><ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/></>,
  ai: <><path d="m12 3 1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8L12 3Z"/></>,
};
function AppIcon({ name, className = "h-4 w-4" }) {
  return <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{APP_ICON_PATHS[name] || APP_ICON_PATHS.dashboard}</svg>;
}

export default function App() {
  const [activePage, setActivePage] = useState("dashboard");

  const handleNavigation = (page) => {
    setActivePage(page);
  };

  return (
    <div className="min-h-screen bg-[#07111f] text-slate-100">

      {/* SIDEBAR */}
      <aside className="fixed left-0 top-0 z-50 flex h-screen w-64 flex-col border-r border-slate-800 bg-[#081321]">

        {/* LOGO */}
        <div className="border-b border-slate-800 px-6 py-6">

          <div className="flex items-center gap-3">

            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-500/10">
              <AppIcon name="dashboard" className="h-5 w-5 text-blue-400" />
            </div>

            <div>
              <h1 className="font-semibold text-white">
                CSPM Platform
              </h1>

              <p className="text-xs text-slate-500">
                Cloud Security
              </p>
            </div>

          </div>

        </div>


        {/* NAVIGATION */}
        <nav className="flex-1 px-3 py-5">

          <SidebarItem
            label="Dashboard"
            active={activePage === "dashboard"}
            onClick={() => handleNavigation("dashboard")}
            icon="dashboard"
          />

          <SidebarItem
            label="IAM Security"
            active={activePage === "iam"}
            onClick={() => handleNavigation("iam")}
            icon="iam"
          />

          <SidebarItem
            label="Network Security"
            active={activePage === "network"}
            onClick={() => handleNavigation("network")}
            icon="network"
          />

          <SidebarItem
            label="Data & Compliance"
            active={activePage === "data"}
            onClick={() => handleNavigation("data")}
            icon="data"
          />

          <SidebarItem
            label="AI Intelligence"
            active={activePage === "ai"}
            onClick={() => handleNavigation("ai")}
            icon="ai"
          />

        </nav>


        {/* BOTTOM */}
        <div className="border-t border-slate-800 p-4">

          <div className="rounded-lg bg-slate-900/60 p-3">

            <p className="text-xs font-medium text-slate-300">
              Security Status
            </p>

            <div className="mt-2 flex items-center gap-2">

              <span className="h-2 w-2 rounded-full bg-emerald-400" />

              <span className="text-xs text-slate-500">
                Monitoring active
              </span>

            </div>

          </div>

        </div>

      </aside>


      {/* MAIN AREA */}
      <main className="ml-64 min-h-screen">

        {activePage === "dashboard" && (
          <Dashboard />
        )}

        {activePage === "iam" && (
          <IamSecurityDashboard />
        )}

        {activePage === "network" && (
          <ComingSoon
            title="Network Security"
            description="Cloud infrastructure and network security module."
          />
        )}

        {activePage === "data" && (
          <ComingSoon
            title="Data & Compliance"
            description="Cloud data security, monitoring and compliance module."
          />
        )}

        {activePage === "ai" && (
          <ComingSoon
            title="AI Intelligence"
            description="AI-powered finding correlation, attack paths and remediation."
          />
        )}

      </main>

    </div>
  );
}


/* =====================================================
   SIDEBAR ITEM
===================================================== */

function SidebarItem({
  label,
  active,
  onClick,
  icon,
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`mb-1 flex w-full items-center gap-3 rounded-lg px-4 py-3 text-left text-sm transition-all ${
        active
          ? "bg-blue-500/10 text-blue-400"
          : "text-slate-400 hover:bg-slate-800/70 hover:text-slate-200"
      }`}
    >

      <span
        className={`flex h-7 w-7 items-center justify-center rounded-md text-sm ${
          active
            ? "bg-blue-500/10"
            : "bg-slate-800/60"
        }`}
      >
        <AppIcon name={icon} />
      </span>

      <span className="flex-1">
        {label}
      </span>

      {active && (
        <span className="h-1.5 w-1.5 rounded-full bg-blue-400" />
      )}

    </button>
  );
}


/* =====================================================
   COMING SOON
===================================================== */

function ComingSoon({
  title,
  description,
}) {
  return (
    <div className="flex min-h-screen items-center justify-center">

      <div className="text-center">

        <div className="mx-auto mb-5 flex h-16 w-16 items-center justify-center rounded-2xl bg-blue-500/10"><AppIcon name="dashboard" className="h-8 w-8 text-blue-400" /></div>

        <h1 className="text-2xl font-semibold">
          {title}
        </h1>

        <p className="mt-2 text-sm text-slate-500">
          {description}
        </p>

        <div className="mt-5 inline-block rounded-lg border border-slate-800 bg-slate-900/50 px-4 py-2 text-xs text-slate-500">
          Module under development
        </div>

      </div>

    </div>
  );
}