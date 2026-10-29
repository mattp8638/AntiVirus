import M365 from "./pages/M365";
import M365Partner from "./pages/M365Partner";
import Network from "./pages/Network";
import NetworkTopology from "./pages/NetworkTopology";
import OutOfBand from "./pages/OutOfBand";
import RemediationPackages from "./pages/rmm/RemediationPackages";
import Governance from "./pages/Governance";
import Assurance from "./pages/grc/Assurance";
import Backup from "./pages/Backup";
import SocWorkflows from "./pages/SocWorkflows";
import { FormEvent, lazy, Suspense, useEffect, useState } from "react";
import { NavLink, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { useApp } from "./app-context";
import { PageBoundary } from "./components/PageBoundary";
import { InstallAppButton, TenantSelect } from "./components/ui";

import Overview from "./pages/Overview";
import Devices from "./pages/Devices";
import DeviceDetail from "./pages/DeviceDetail";
import Policies from "./pages/Policies";
import PolicyEditor from "./pages/PolicyEditor";
import Alerts from "./pages/Alerts";
import Incidents from "./pages/Incidents";
import IncidentDetail from "./pages/IncidentDetail";
import Hunt from "./pages/Hunt";
import Rules from "./pages/Rules";
import Automations from "./pages/Automations";
import Dns from "./pages/Dns";
import Intel from "./pages/Intel";
import Vulnerabilities from "./pages/Vulnerabilities";
import AttackSurface from "./pages/AttackSurface";
import Compliance from "./pages/Compliance";
import Crm from "./pages/Crm";
import CrmAccount from "./pages/CrmAccount";
import Billing from "./pages/Billing";
import Portal from "./pages/Portal";

const RemoteViewer = lazy(() => import("./pages/RemoteViewer"));
import Scripts from "./pages/rmm/Scripts";
import Jobs from "./pages/rmm/Jobs";
import Monitoring from "./pages/rmm/Monitoring";
import Patching from "./pages/rmm/Patching";
import Software from "./pages/rmm/Software";
import ServiceBoard from "./pages/psa/ServiceBoard";
import TicketDetail from "./pages/psa/TicketDetail";
import Time from "./pages/psa/Time";
import Dispatch from "./pages/psa/Dispatch";
import Workload from "./pages/psa/Workload";
import Companies, { CompanyDetail, Configurations } from "./pages/psa/Companies";
import Catalog, { Knowledge } from "./pages/psa/Catalog";
import PsaSettings, { ProjectDetail } from "./pages/psa/PsaSettings";
import Reports from "./pages/Reports";
import Settings from "./pages/Settings";
import Deploy from "./pages/Deploy";
import { EnrollPhonePage } from "./pages/AddPhone";
import Vault from "./pages/Vault";
import ActiveDirectory from "./pages/ActiveDirectory";
import { ProgrammeDetail } from "./pages/grc/Programmes";
import { PolicyEditor as GrcPolicyEditor } from "./pages/grc/Policies";
import ProtectionHealth from "./pages/ProtectionHealth";
import Quarantine from "./pages/Quarantine";
import EdrExclusions from "./pages/EdrExclusions";
import Exposure from "./pages/Exposure";
import Elevation from "./pages/Elevation";
import RecordingPlayer from "./pages/RecordingPlayer";
import { DialogHost } from "./components/dialogs";

const NAV: { group: string; items: { to: string; label: string; icon: string }[] }[] = [
  { group: "Overview", items: [{ to: "/", label: "Dashboard", icon: "◎" }, { to: "/reports", label: "Reports", icon: "▤" }] },
  {
    group: "Devices & RMM",
    items: [
      { to: "/devices", label: "Devices", icon: "▣" },
      { to: "/monitoring", label: "Monitoring", icon: "♥" },
      { to: "/patching", label: "Patching", icon: "⟳" },
      { to: "/scripts", label: "Scripts", icon: "❯" },
      { to: "/remediation-packages", label: "Remediation packages", icon: "✚" },
      { to: "/automation", label: "Automation", icon: "⏱" },
      { to: "/software", label: "Software", icon: "⬇" },
      { to: "/deploy", label: "Deploy agents", icon: "⇩" },
    ],
  },
  {
    group: "Security",
    items: [
      { to: "/protection-health", label: "Protection health", icon: "⛨" },
      { to: "/quarantine", label: "Quarantine", icon: "⊘" },
      { to: "/admin-requests", label: "Admin requests", icon: "⇡" },
      { to: "/incidents", label: "Incidents", icon: "⚑" },
      { to: "/alerts", label: "Alerts", icon: "△" },
      { to: "/policies", label: "Policies", icon: "⚙" },
      { to: "/edr-exclusions", label: "EDR exclusions", icon: "⊜" },
      { to: "/hunt", label: "Threat hunting", icon: "⌕" },
      { to: "/rules", label: "Detection rules", icon: "≡" },
      { to: "/automations", label: "Response rules", icon: "↯" },
      { to: "/dns", label: "DNS protection", icon: "◈" },
      { to: "/intel", label: "Threat intel", icon: "✦" },
      { to: "/vulnerabilities", label: "Vulnerabilities", icon: "⚠" },
      { to: "/exposure", label: "Data & identity exposure", icon: "⚇" },
      { to: "/active-directory", label: "Active Directory", icon: "⌘" },
      { to: "/attack-surface", label: "Attack surface", icon: "◍" },
      { to: "/compliance", label: "Compliance", icon: "✓" },
    ],
  },
  {
    group: "Service (PSA)",
    items: [
      { to: "/service-board", label: "Service board", icon: "✉" },
      { to: "/dispatch", label: "Dispatch", icon: "▦" },
      { to: "/workload", label: "Workload & changes", icon: "⚖" },
      { to: "/time", label: "Time & timesheets", icon: "◷" },
      { to: "/companies", label: "Companies", icon: "⌂" },
      { to: "/configurations", label: "Configurations", icon: "⚿" },
      { to: "/knowledge", label: "Knowledge base", icon: "❏" },
      { to: "/vault", label: "Credential vault", icon: "⚿" },
    ],
  },
  {
    group: "Sales & finance",
    items: [
      { to: "/crm", label: "CRM & projects", icon: "☺" },
      { to: "/quotes", label: "Products & quotes", icon: "❖" },
      { to: "/billing", label: "Agreements & billing", icon: "£" },
    ],
  },
  { group: "MSP operations", items: [{to:"/m365",label:"Microsoft 365",icon:"▦"},{to:"/m365-partner",label:"M365 partner & standards",icon:"⧉"},{to:"/network",label:"Network monitoring",icon:"⌁"},{to:"/network-topology",label:"Network topology",icon:"⧈"},{to:"/out-of-band",label:"Out-of-band (Intel AMT)",icon:"⏻"},{to:"/governance",label:"GRC & compliance",icon:"✓"},{to:"/continuous-compliance",label:"Continuous compliance",icon:"⟲"},{to:"/backup",label:"Backup & recovery",icon:"⟳"},{to:"/soc-workflows",label:"SOC maintenance",icon:"◷"}] },
  { group: "Administration", items: [{ to: "/service-settings", label: "Service settings", icon: "⚙" }, { to: "/settings", label: "Settings", icon: "⚒" }] },
];

function Login() {
  const { login } = useApp();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [needCode, setNeedCode] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(email, password, needCode ? code : undefined);
    } catch (err) {
      const message = (err as Error).message;
      if (message === "MFA code required") { setNeedCode(true); setError(null); }
      else setError(message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="login">
      <form className="card" onSubmit={submit}>
        <div className="brand" style={{ padding: 0, marginBottom: 20 }}>
          <div className="brand-mark">F</div>
          <div><b>Fenrir Console</b><small>Endpoint · SIEM · Exposure · PSA</small></div>
        </div>
        <label className="field">Email<input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoFocus required /></label>
        <label className="field" style={{ marginTop: 12 }}>Password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required /></label>
        {needCode && <label className="field" style={{ marginTop: 12 }}>Authenticator code<input inputMode="numeric" autoComplete="one-time-code" maxLength={6} value={code} onChange={(e) => setCode(e.target.value)} autoFocus required /></label>}
        {error && <p style={{ color: "#fecaca" }}>{error}</p>}
        <button className="primary" style={{ width: "100%", justifyContent: "center", marginTop: 18 }} disabled={busy}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}

// Phones get a bottom tab bar for the pages a technician opens most; everything else is in the menu.
const BOTTOM_NAV = [
  { to: "/", label: "Home", icon: "◎" },
  { to: "/devices", label: "Devices", icon: "▣" },
  { to: "/alerts", label: "Alerts", icon: "△" },
  { to: "/service-board", label: "Tickets", icon: "✉" },
];

function Shell() {
  const { me, tenantId, setTenantId, logout } = useApp();
  const location = useLocation();
  const [navOpen, setNavOpen] = useState(false);
  // Close the phone menu whenever a page is opened from it.
  useEffect(() => { setNavOpen(false); }, [location.pathname]);
  useEffect(() => {
    if (!navOpen) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setNavOpen(false); };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [navOpen]);
  if (!me) return null;
  return (
    <div className={`shell ${navOpen ? "nav-open" : ""}`}>
      <div className="nav-backdrop" onClick={() => setNavOpen(false)} aria-hidden />
      <aside className="sidebar" aria-label="Main menu">
        <div className="brand"><div className="brand-mark">F</div><div><b>Fenrir</b><small>Unified security platform</small></div>
          <button className="ghost nav-close" aria-label="Close menu" onClick={() => setNavOpen(false)}>✕</button></div>
        <div className="nav-account">
          <div className="small">{me.user.email}</div>
          <div className="small muted">{me.user.role.replace(/_/g, " ")}</div>
          <button className="small" onClick={logout}>Sign out</button>
        </div>
        {NAV.map((group) => (
          <div key={group.group}>
            <div className="nav-group">{group.group}</div>
            {group.items.map((item) => (
              <NavLink key={item.to} to={item.to} end={item.to === "/"} className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}>
                <span aria-hidden style={{ width: 16, textAlign: "center" }}>{item.icon}</span>{item.label}
              </NavLink>
            ))}
          </div>
        ))}
      </aside>
      <div className="main">
        <header className="topbar">
          <button className="ghost nav-toggle" aria-label="Open menu" aria-expanded={navOpen} onClick={() => setNavOpen(true)}>☰</button>
          <span className="muted small hide-phone">Viewing</span>
          <TenantSelect value={tenantId} onChange={setTenantId} />
          <span className="spacer" />
          <InstallAppButton />
          <span className="small muted hide-phone">{me.user.email} · {me.user.role.replace(/_/g, " ")}</span>
          <button className="small hide-phone" onClick={logout}>Sign out</button>
        </header>
        <main className="content">
          <PageBoundary resetKey={`${location.pathname}${location.search}`}>
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/devices" element={<Devices />} />
            <Route path="/devices/:id" element={<DeviceDetail />} />
            <Route path="/policies" element={<Policies />} />
            <Route path="/policies/:id" element={<PolicyEditor />} />
            <Route path="/deploy" element={<Deploy />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/protection-health" element={<ProtectionHealth />} />
            <Route path="/quarantine" element={<Quarantine />} />
            <Route path="/edr-exclusions" element={<EdrExclusions />} />
            <Route path="/admin-requests" element={<Elevation />} />
            <Route path="/recordings/:id" element={<RecordingPlayer />} />
            <Route path="/incidents" element={<Incidents />} />
            <Route path="/incidents/:id" element={<IncidentDetail />} />
            <Route path="/hunt" element={<Hunt />} />
            <Route path="/rules" element={<Rules />} />
            <Route path="/automations" element={<Automations />} />
            <Route path="/dns" element={<Dns />} />
            <Route path="/intel" element={<Intel />} />
            <Route path="/vulnerabilities" element={<Vulnerabilities />} />
            <Route path="/exposure" element={<Exposure />} />
            <Route path="/active-directory" element={<ActiveDirectory />} />
            <Route path="/attack-surface" element={<AttackSurface />} />
            <Route path="/compliance" element={<Compliance />} />
            <Route path="/crm" element={<Crm />} />
            <Route path="/crm/accounts/:id" element={<CrmAccount />} />
            <Route path="/service-desk" element={<Navigate to="/service-board" replace />} />
            <Route path="/service-board" element={<ServiceBoard />} />
            <Route path="/tickets/:id" element={<TicketDetail />} />
            <Route path="/dispatch" element={<Dispatch />} />
            <Route path="/workload" element={<Workload />} />
            <Route path="/time" element={<Time />} />
            <Route path="/companies" element={<Companies />} />
            <Route path="/companies/:id" element={<CompanyDetail />} />
            <Route path="/configurations" element={<Configurations />} />
            <Route path="/knowledge" element={<Knowledge />} />
            <Route path="/vault" element={<Vault />} />
            <Route path="/quotes" element={<Catalog />} />
            <Route path="/projects/:id" element={<ProjectDetail />} />
            <Route path="/service-settings" element={<PsaSettings />} />
            <Route path="/monitoring" element={<Monitoring />} />
            <Route path="/patching" element={<Patching />} />
            <Route path="/scripts" element={<Scripts />} />
            <Route path="/automation" element={<Jobs />} />
            <Route path="/software" element={<Software />} />
            <Route path="/billing" element={<Billing />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/m365" element={<M365 />} />
            <Route path="/m365-partner" element={<M365Partner />} />
            <Route path="/network" element={<Network />} />
            <Route path="/network-topology" element={<NetworkTopology />} />
            <Route path="/out-of-band" element={<OutOfBand />} />
            <Route path="/remediation-packages" element={<RemediationPackages />} />
            <Route path="/governance" element={<Governance />} />
            <Route path="/continuous-compliance" element={<Assurance />} />
            <Route path="/governance/policies/:id" element={<GrcPolicyEditor />} />
            <Route path="/governance/:tenantId/:framework" element={<ProgrammeDetail />} />
            <Route path="/backup" element={<Backup />} />
            <Route path="/soc-workflows" element={<SocWorkflows />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
          </PageBoundary>
        </main>
        <nav className="bottom-nav" aria-label="Quick navigation">
          {BOTTOM_NAV.map((item) => (
            <NavLink key={item.to} to={item.to} end={item.to === "/"} className={({ isActive }) => isActive ? "active" : ""}>
              <span aria-hidden>{item.icon}</span>{item.label}
            </NavLink>
          ))}
          <button onClick={() => setNavOpen(true)} className={navOpen ? "active" : ""}><span aria-hidden>☰</span>More</button>
        </nav>
      </div>
    </div>
  );
}

export function Root() {
  return <><RootContent /><DialogHost /></>;
}

function RootContent() {
  const { me, loading } = useApp();
  const location = useLocation();
  // Opened from a phone's camera when it scans an enrolment code: no sign-in.
  if (location.pathname === "/enroll-phone") return <EnrollPhonePage />;
  if (loading) return <div className="empty">Loading…</div>;
  if (!me) return <Login />;
  // The remote viewer is a pop-out window without the console chrome.
  if (location.pathname.startsWith("/remote/")) {
    return <PageBoundary resetKey={`${location.pathname}${location.search}`}><Suspense fallback={<div className="empty">Opening session…</div>}><Routes><Route path="/remote/:id" element={<RemoteViewer />} /></Routes></Suspense></PageBoundary>;
  }
  if (me.user.role === "client" || location.pathname.startsWith("/portal")) return <PageBoundary resetKey={`${location.pathname}${location.search}`}><Portal /></PageBoundary>;
  return <Shell />;
}
