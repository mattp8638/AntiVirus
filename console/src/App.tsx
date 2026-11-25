import M365 from "./pages/M365";
import { BrandHeader, useBrand } from "./brand";
import M365Partner from "./pages/M365Partner";
import M365Tenant from "./pages/M365Tenant";
import Network from "./pages/Network";
import NetworkTopology from "./pages/NetworkTopology";
import OutOfBand from "./pages/OutOfBand";
import RemediationPackages from "./pages/rmm/RemediationPackages";
import Governance from "./pages/Governance";
import AttackPaths from "./pages/AttackPaths";
import WebAssessments from "./pages/WebAssessments";
import FirewallAssessments from "./pages/FirewallAssessments";
import GoogleWorkspace from "./pages/GoogleWorkspace";
import Infrastructure from "./pages/Infrastructure";
import WorkloadProtection from "./pages/WorkloadProtection";
import Assurance from "./pages/grc/Assurance";
import Continuity from "./pages/grc/Continuity";
import Registers from "./pages/grc/Registers";
import Questionnaires from "./pages/grc/Questionnaires";
import Trust from "./pages/grc/Trust";
import Gaps from "./pages/grc/Gaps";
import AiGovernance from "./pages/grc/AiGovernance";
import Agreements from "./pages/grc/Agreements";
import SocWorkflows from "./pages/SocWorkflows";
import { FormEvent, lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { NavLink, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { useApp } from "./app-context";
import { PageBoundary } from "./components/PageBoundary";
import { InstallAppButton, PageHead, TenantSelect } from "./components/ui";
import { GroupsManager } from "./components/Groups";

import Overview from "./pages/Overview";
import Inbox from "./pages/Inbox";
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
import Pentest from "./pages/Pentest";
import PentestEngagement from "./pages/PentestEngagement";
import Compliance from "./pages/Compliance";
import Crm from "./pages/Crm";
import CrmAccount from "./pages/CrmAccount";
import Onboarding from "./pages/Onboarding";
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
import Settings, { MfaCard, PasskeysCard } from "./pages/Settings";
import { passkeysSupported } from "./passkeys";
import Deploy from "./pages/Deploy";
import { EnrollPhonePage } from "./pages/AddPhone";
import Vault from "./pages/Vault";
import ActiveDirectory from "./pages/ActiveDirectory";
import { ProgrammeDetail } from "./pages/grc/Programmes";
import { PolicyEditor as GrcPolicyEditor } from "./pages/grc/Policies";
import ProtectionHealth from "./pages/ProtectionHealth";
import AgentHealth from "./pages/AgentHealth";
import Backups from "./pages/Backups";
import Quarantine from "./pages/Quarantine";
import EmailSecurity from "./pages/EmailSecurity";
import EdrExclusions from "./pages/EdrExclusions";
import Exposure from "./pages/Exposure";
import Elevation from "./pages/Elevation";
import RecordingPlayer from "./pages/RecordingPlayer";
import { DialogHost } from "./components/dialogs";
import { CommandPalette, useSearchShortcut } from "./components/CommandPalette";
import { api, setDefaultCurrency } from "./api";

// `also`: other pages of the same section (they switch with section tabs), so the entry stays highlighted on them.
// Grouped by the job in hand rather than by module: work the queue, look after a client, look after their endpoints,
// their identity and cloud, run the service desk and the business, prove compliance, then administration.
type NavItem = { to: string; label: string; icon: string; also?: string[]; module?: string };
// `flat`: shown as top-level links rather than a sub-menu. A section left with one page also shows as a plain link.
type NavSection = { group: string; icon: string; flat?: boolean; items: NavItem[] };
const NAV: NavSection[] = [
  // Ordered by how often an MSP reaches for each area: today's work first, set-up and administration last.
  {
    group: "Home", icon: "◎", flat: true,
    items: [
      { to: "/", label: "Dashboard", icon: "◎" },
      { to: "/inbox", label: "Inbox", icon: "☰" },
    ],
  },
  {
    group: "Security operations", icon: "⛨",
    items: [
      { to: "/alerts", label: "Alerts", icon: "△" },
      { module: "security", to: "/incidents", label: "Incidents", icon: "⚑" },
      { module: "security", to: "/admin-requests", label: "Admin requests", icon: "⇡" },
      { module: "protection", to: "/quarantine", label: "Quarantine", icon: "⊘" },
      { module: "security", to: "/hunt", label: "Threat hunting", icon: "⌕" },
      { module: "security", to: "/intel", label: "Threat intel", icon: "✦" },
    ],
  },
  {
    group: "Devices", icon: "▣",
    items: [
      { to: "/devices", label: "Devices", icon: "▣" },
      { to: "/groups", label: "Device groups", icon: "⧉" },
      { to: "/monitoring", label: "Monitoring", icon: "♥" },
      { to: "/agent-health", label: "Agent health", icon: "✚" },
      { to: "/backups", label: "Backups", icon: "⛁" },
      { to: "/deploy", label: "Deploy agents", icon: "⇩" },
      { module: "network", to: "/out-of-band", label: "Out-of-band (Intel AMT)", icon: "⏻" },
    ],
  },
  {
    group: "Maintenance", icon: "⟳",
    items: [
      { to: "/patching", label: "Patching", icon: "⟳" },
      { to: "/software", label: "Software", icon: "⬇" },
      { to: "/scripts", label: "Scripts", icon: "❯" },
      { to: "/remediation-packages", label: "Remediation packages", icon: "✚" },
      { to: "/automation", label: "Jobs & schedules", icon: "⏱" },
    ],
  },
  {
    group: "Protection", icon: "◈",
    items: [
      { module: "protection", to: "/policies", label: "Protection policies", icon: "⚙" },
      { module: "protection", to: "/protection-health", label: "Protection health", icon: "⛨" },
      { module: "protection", to: "/workload-protection", label: "Workload protection", icon: "▦" },
      { module: "security", to: "/dns", label: "DNS protection", icon: "◈" },
      { module: "email", to: "/email-security", label: "Email security", icon: "✉" },
    ],
  },
  {
    group: "Exposure & testing", icon: "⚠",
    items: [
      { module: "vulnerabilities", to: "/vulnerabilities", label: "Vulnerabilities", icon: "⚠" },
      { module: "vulnerabilities", to: "/attack-paths", label: "Attack paths", icon: "⇢" },
      { module: "vulnerabilities", to: "/web-assessments", label: "Web app assessment", icon: "⌘" },
      { module: "vulnerabilities", to: "/firewall-assessments", label: "Firewall configuration", icon: "▤" },
      { module: "vulnerabilities", to: "/google-workspace", label: "Google Workspace", icon: "G" },
      { module: "network", to: "/attack-surface", label: "Attack surface", icon: "◍" },
      { module: "pentest", to: "/pentest", label: "Penetration testing", icon: "⚑" },
      { module: "identity", to: "/exposure", label: "Data & identity exposure", icon: "⚇" },
    ],
  },
  {
    group: "Identity & network", icon: "☁",
    items: [
      { module: "identity", to: "/m365", label: "Microsoft 365", icon: "▦", also: ["/m365-partner"] },
      { module: "identity", to: "/active-directory", label: "Active Directory", icon: "⌘" },
      { module: "network", to: "/network", label: "Network", icon: "⌁", also: ["/network-topology"] },
      { module: "network", to: "/infrastructure", label: "Infrastructure", icon: "▥" },
    ],
  },
  {
    group: "Service desk", icon: "✉",
    items: [
      { module: "service", to: "/service-board", label: "Service board", icon: "✉" },
      { module: "service", to: "/dispatch", label: "Dispatch", icon: "▦" },
      { module: "service", to: "/workload", label: "Workload & changes", icon: "⚖" },
      { module: "service", to: "/time", label: "Time & timesheets", icon: "◷" },
    ],
  },
  {
    group: "Customers & business", icon: "⌂",
    items: [
      { to: "/companies", label: "Companies", icon: "⌂" },
      { module: "business", to: "/onboarding", label: "Customer onboarding", icon: "✓" },
      { module: "business", to: "/crm", label: "CRM & projects", icon: "☺" },
      { module: "business", to: "/quotes", label: "Products & quotes", icon: "❖" },
      { module: "business", to: "/billing", label: "Agreements & billing", icon: "£" },
    ],
  },
  {
    group: "Knowledge & reports", icon: "▤",
    items: [
      { to: "/reports", label: "Reports", icon: "▤" },
      { module: "documentation", to: "/configurations", label: "Configurations", icon: "⚿" },
      { module: "documentation", to: "/knowledge", label: "Knowledge base", icon: "❏" },
      { module: "documentation", to: "/vault", label: "Credential vault", icon: "⚿" },
    ],
  },
  { group: "Governance", icon: "✓", items: [{ module: "governance", to: "/governance", label: "Compliance & GRC", icon: "✓", also: ["/continuous-compliance", "/compliance", "/continuity", "/registers", "/questionnaires", "/trust-centre", "/gaps", "/ai-governance", "/agreements"] }] },
  {
    group: "Admin", icon: "⚙",
    items: [
      { to: "/settings", label: "Settings", icon: "⚒" },
      { module: "service", to: "/service-settings", label: "Service settings", icon: "⚙" },
      { module: "security", to: "/rules", label: "Detection rules", icon: "≡" },
      { module: "security", to: "/automations", label: "Response rules", icon: "↯" },
      { module: "protection", to: "/edr-exclusions", label: "EDR exclusions", icon: "⊜" },
      { module: "security", to: "/soc-workflows", label: "SOC maintenance", icon: "◷" },
    ],
  },
];
// Desktop: the menu can shrink to an icon rail (remembered per browser); sections then open as fly-out menus.
const RAIL_KEY = "fenrir.nav.rail";
function readRail(): boolean {
  try { return localStorage.getItem(RAIL_KEY) === "1"; } catch { return false; }
}
function isCurrent(item: { to: string; also?: string[] }, path: string) {
  const prefixes = [item.to, ...(item.also ?? [])];
  return item.to === "/" ? path === "/" : prefixes.some((p) => path === p || path.startsWith(`${p}/`));
}
// Settings > Modules: pages of switched-off modules leave the menu and search (they still open by link).
function visibleNav(enabled: string[] | null): NavSection[] {
  return NAV.map((g) => ({ ...g, items: g.items.filter((i) => !i.module || !enabled || enabled.includes(i.module)) }))
    .filter((g) => g.items.length > 0);
}

function Login() {
  const { login, completeSso, loginWithPasskey } = useApp();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [needCode, setNeedCode] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [sso, setSso] = useState<{ enabled: boolean; required: boolean } | null>(null);
  const [showPassword, setShowPassword] = useState(false);
  useEffect(() => {
    api<{ enabled: boolean; required: boolean }>("auth/sso/info").then(setSso).catch(() => setSso(null));
    // Back from Microsoft: a single-use code to swap for a session, or the reason it failed.
    const params = new URLSearchParams(window.location.search);
    const handoff = params.get("sso");
    const failure = params.get("sso_error");
    if (!handoff && !failure) return;
    params.delete("sso");
    params.delete("sso_error");
    window.history.replaceState(null, "", window.location.pathname + (params.toString() ? `?${params}` : ""));
    if (failure) setError(failure);
    if (handoff) {
      setBusy(true);
      completeSso(handoff).catch((err) => setError((err as Error).message)).finally(() => setBusy(false));
    }
  }, []);  // eslint-disable-line react-hooks/exhaustive-deps
  const microsoft = sso?.enabled && (
    <a className="btn primary" style={{ width: "100%", justifyContent: "center", marginTop: 4, display: "flex", textDecoration: "none" }}
       href={`/api/console/auth/sso/start?returnTo=${encodeURIComponent(window.location.pathname)}`}>Sign in with Microsoft</a>);
  const passwordForm = !sso?.required || showPassword;
  const signInWithPasskey = async () => {
    setBusy(true);
    setError(null);
    try {
      await loginWithPasskey();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };
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
          <BrandHeader size={40} />
        </div>
        <DemoNote signIn />
        {microsoft}
        {sso?.required && !showPassword && <p className="small muted" style={{ marginTop: 12 }}>
          <button type="button" className="ghost small" onClick={() => setShowPassword(true)}>Platform administrator? Use a password</button></p>}
        {sso?.enabled && passwordForm && <p className="small muted" style={{ textAlign: "center", margin: "14px 0 4px" }}>or</p>}
        {passwordForm && <>
        <label className="field">Email<input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoFocus required /></label>
        <label className="field" style={{ marginTop: 12 }}>Password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required /></label>
        {needCode && <label className="field" style={{ marginTop: 12 }}>Authenticator code<input inputMode="numeric" autoComplete="one-time-code" maxLength={6} value={code} onChange={(e) => setCode(e.target.value)} autoFocus required /></label>}
        </>}
        {error && <p style={{ color: "#fecaca" }}>{error}</p>}
        {passwordForm && <button className={sso?.enabled ? "" : "primary"} style={{ width: "100%", justifyContent: "center", marginTop: 18 }} disabled={busy}>
          {busy ? "Signing in…" : "Sign in"}
        </button>}
        {passwordForm && passkeysSupported() && <button type="button" style={{ width: "100%", justifyContent: "center", marginTop: 10 }}
                                                        disabled={busy} onClick={signInWithPasskey}>Sign in with a passkey</button>}
        {!passwordForm && busy && <p className="small muted">Signing in…</p>}
      </form>
    </div>
  );
}

// On a public read-only demo: say so, with the shared login on the sign-in page.
function DemoNote({ signIn = false }: { signIn?: boolean }) {
  const { brand } = useBrand();
  if (!brand.demo) return null;
  const resets = brand.demo.resets ? ` ${brand.demo.resets}` : "";
  return (
    <div role="note" data-testid="demo-note" className="small"
         style={{ background: "var(--warn-bg, rgba(234,179,8,.15))", border: "1px solid rgba(234,179,8,.45)", borderRadius: 8,
                  padding: "8px 12px", margin: signIn ? "0 0 14px" : "8px 12px 0" }}>
      <b>Demo.</b> Everything here is sample data and read-only: changes, agent downloads and remote sessions are turned off.{resets}
      {signIn && brand.demo.login && <div style={{ marginTop: 4 }}>Sign in with <span className="mono">{brand.demo.login}</span></div>}
    </div>
  );
}

// Phones get a bottom tab bar for the pages a technician opens most; everything else is in the menu.
const BOTTOM_NAV = [
  { to: "/", label: "Home", icon: "◎" },
  { to: "/devices", label: "Devices", icon: "▣" },
  { to: "/inbox", label: "Inbox", icon: "☰" },
  { to: "/service-board", label: "Tickets", icon: "✉" },
];

// The side menu: Dashboard and Inbox at the top, then one sub-menu per area. One sub-menu is open at a time (the
// area of the page you are on, until you open another). In the icon rail, an area opens as a fly-out instead.
function SideNav({ nav, rail }: { nav: NavSection[]; rail: boolean }) {
  const location = useLocation();
  const path = location.pathname;
  const currentGroup = nav.find((g) => g.items.some((i) => isCurrent(i, path)))?.group ?? null;
  const [open, setOpen] = useState<string | null>(currentGroup);
  useEffect(() => { setOpen(currentGroup); }, [currentGroup, path]);
  const [flyout, setFlyout] = useState<{ group: string; top: number } | null>(null);
  const closeTimer = useRef<number | undefined>(undefined);
  useEffect(() => { setFlyout(null); }, [path, rail]);
  useEffect(() => {
    if (!flyout) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setFlyout(null); };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [flyout]);
  const showFlyout = (group: string, el: HTMLElement) => {
    window.clearTimeout(closeTimer.current);
    const top = Math.max(8, Math.min(el.getBoundingClientRect().top, window.innerHeight - 80));
    setFlyout({ group, top });
  };
  const hideFlyout = () => { closeTimer.current = window.setTimeout(() => setFlyout(null), 160); };
  const link = (item: NavItem, sub: boolean) => (
    <NavLink key={item.to} to={item.to} end={item.to === "/"} title={rail && !sub ? item.label : undefined}
             className={() => `nav-link ${sub ? "nav-sublink" : ""} ${isCurrent(item, path) ? "active" : ""}`}
             aria-current={isCurrent(item, path) ? "page" : undefined}>
      {!sub && <span aria-hidden className="nav-icon">{item.icon}</span>}<span className="nav-label">{item.label}</span>
    </NavLink>
  );
  return (
    <nav className="side-nav" aria-label="Sections">
      {nav.map((section) => {
        if (section.flat || section.items.length === 1) {
          return <div key={section.group} className="nav-top">{section.items.map((item) => link(item, false))}</div>;
        }
        const id = `nav-${section.group.replace(/\W+/g, "-").toLowerCase()}`;
        const holdsCurrent = section.group === currentGroup;
        const expanded = !rail && open === section.group;
        const flying = rail && flyout?.group === section.group;
        return (
          <div key={section.group} className={`nav-section ${holdsCurrent ? "current" : ""}`}
               onMouseEnter={rail ? (e) => showFlyout(section.group, e.currentTarget) : undefined}
               onMouseLeave={rail ? hideFlyout : undefined}>
            <button type="button" className={`nav-section-head ${expanded || flying ? "open" : ""}`}
                    aria-expanded={expanded || flying} aria-controls={id} title={rail ? section.group : undefined}
                    onClick={(e) => rail
                      ? (flying ? setFlyout(null) : showFlyout(section.group, e.currentTarget))
                      : setOpen(expanded ? null : section.group)}>
              <span aria-hidden className="nav-icon">{section.icon}</span>
              <span className="nav-label">{section.group}</span>
              <span aria-hidden className="nav-chevron">›</span>
            </button>
            {expanded && <div id={id} className="nav-sub">{section.items.map((item) => link(item, true))}</div>}
            {flying && flyout && (
              <div id={id} className="nav-flyout" style={{ top: flyout.top }} role="group" aria-label={section.group}
                   onMouseEnter={() => window.clearTimeout(closeTimer.current)} onMouseLeave={hideFlyout}>
                <div className="nav-flyout-title">{section.group}</div>
                {section.items.map((item) => link(item, true))}
              </div>
            )}
          </div>
        );
      })}
    </nav>
  );
}

function Shell() {
  const { me, tenantId, setTenantId, logout } = useApp();
  const location = useLocation();
  useEffect(() => { api<{ currency: string }>("region").then((r) => setDefaultCurrency(r.currency)).catch(() => undefined); }, [me?.user.id]);
  const [enabledModules, setEnabledModules] = useState<string[] | null>(null);
  useEffect(() => {
    const load = () => api<{ enabled: string[] }>("modules").then((r) => setEnabledModules(r.enabled)).catch(() => setEnabledModules(null));
    load();
    window.addEventListener("fenrir:modules-changed", load);
    return () => window.removeEventListener("fenrir:modules-changed", load);
  }, [me?.user.id]);
  const nav = useMemo(() => visibleNav(enabledModules), [enabledModules]);
  const [railChosen, setRail] = useState(readRail);
  const [narrow, setNarrow] = useState(() => typeof window.matchMedia === "function" && window.matchMedia("(max-width: 900px)").matches);
  useEffect(() => {
    if (typeof window.matchMedia !== "function") return;
    const query = window.matchMedia("(max-width: 900px)");
    const onChange = () => setNarrow(query.matches);
    query.addEventListener?.("change", onChange);
    return () => query.removeEventListener?.("change", onChange);
  }, []);
  const rail = railChosen && !narrow;  // phones and tablets always use the full slide-out menu
  const toggleRail = useCallback(() => setRail((current) => {
    try { localStorage.setItem(RAIL_KEY, current ? "0" : "1"); } catch { /* storage unavailable: lasts until reload */ }
    return !current;
  }), []);
  const pages = useMemo(() => nav.flatMap((g) => g.items.map((i) => ({ to: i.to, label: i.label, group: g.group }))), [nav]);
  const [navOpen, setNavOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const openSearch = useCallback(() => setSearchOpen(true), []);
  useSearchShortcut(openSearch);
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
    <div className={`shell ${navOpen ? "nav-open" : ""} ${rail ? "nav-rail" : ""}`}>
      <div className="nav-backdrop" onClick={() => setNavOpen(false)} aria-hidden />
      <aside className="sidebar" aria-label="Main menu">
        <div className="brand"><BrandHeader />
          <button className="ghost nav-close" aria-label="Close menu" onClick={() => setNavOpen(false)}>✕</button></div>
        <div className="nav-account">
          <div className="small">{me.user.email}</div>
          <div className="small muted">{me.user.role.replace(/_/g, " ")}</div>
          <button className="small" onClick={logout}>Sign out</button>
        </div>
        <SideNav nav={nav} rail={rail} />
        <button type="button" className="ghost nav-rail-toggle" onClick={toggleRail}
                aria-label={rail ? "Expand menu" : "Collapse menu to icons"} title={rail ? "Expand menu" : "Collapse menu to icons"}>
          <span aria-hidden>{rail ? "»" : "«"}</span><span className="nav-label">Collapse menu</span>
        </button>
      </aside>
      <div className="main">
        <DemoNote />
        <header className="topbar">
          <button className="ghost nav-toggle" aria-label="Open menu" aria-expanded={navOpen} onClick={() => setNavOpen(true)}>☰</button>
          <span className="muted small hide-phone">Viewing</span>
          <TenantSelect value={tenantId} onChange={setTenantId} />
          <button className="ghost search-button" onClick={openSearch} aria-label="Search (Ctrl+K)" title="Search everything (Ctrl+K)">
            ⌕ <span className="hide-phone">Search</span> <kbd className="hide-phone small muted">Ctrl K</kbd></button>
          <span className="spacer" />
          <InstallAppButton />
          <span className="small muted hide-phone">{me.user.email} · {me.user.role.replace(/_/g, " ")}</span>
          <button className="small hide-phone" onClick={logout}>Sign out</button>
        </header>
        <main className="content">
          {me.emergencyStop?.active && <div className="card" role="alert" style={{ borderColor: "var(--bad, #c0392b)", marginBottom: 12 }}>
            <b>Emergency stop is on.</b> Nothing but isolation reaches devices. {me.emergencyStop.reason} ({me.emergencyStop.by}). A platform
            administrator can lift it in Settings → Platform.</div>}
          <PageBoundary resetKey={`${location.pathname}${location.search}`}>
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/inbox" element={<Inbox />} />
            <Route path="/devices" element={<Devices />} />
            <Route path="/devices/:id" element={<DeviceDetail />} />
            <Route path="/groups" element={<><PageHead title="Device groups" subtitle="Organise each customer's devices, give groups their own policy, and target them with scripts, patching and monitoring." /><GroupsManager /></>} />
            <Route path="/policies" element={<Policies />} />
            <Route path="/policies/:id" element={<PolicyEditor />} />
            <Route path="/deploy" element={<Deploy />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/protection-health" element={<ProtectionHealth />} />
            <Route path="/agent-health" element={<AgentHealth />} />
            <Route path="/backups" element={<Backups />} />
            <Route path="/quarantine" element={<Quarantine />} />
            <Route path="/email-security" element={<EmailSecurity />} />
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
            <Route path="/attack-paths" element={<AttackPaths />} />
            <Route path="/web-assessments" element={<WebAssessments />} />
            <Route path="/firewall-assessments" element={<FirewallAssessments />} />
            <Route path="/google-workspace" element={<GoogleWorkspace />} />
            <Route path="/exposure" element={<Exposure />} />
            <Route path="/active-directory" element={<ActiveDirectory />} />
            <Route path="/attack-surface" element={<AttackSurface />} />
            <Route path="/pentest" element={<Pentest />} />
            <Route path="/pentest/:id" element={<PentestEngagement />} />
            <Route path="/compliance" element={<Compliance />} />
            <Route path="/crm" element={<Crm />} />
            <Route path="/onboarding" element={<Onboarding />} />
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
            <Route path="/m365/:connectionId" element={<M365Tenant />} />
            <Route path="/m365-partner" element={<M365Partner />} />
            <Route path="/network" element={<Network />} />
            <Route path="/infrastructure" element={<Infrastructure />} />
            <Route path="/workload-protection" element={<WorkloadProtection />} />
            <Route path="/network-topology" element={<NetworkTopology />} />
            <Route path="/out-of-band" element={<OutOfBand />} />
            <Route path="/remediation-packages" element={<RemediationPackages />} />
            <Route path="/governance" element={<Governance />} />
            <Route path="/continuous-compliance" element={<Assurance />} />
            <Route path="/continuity" element={<Continuity />} />
            <Route path="/registers" element={<Registers />} />
            <Route path="/questionnaires" element={<Questionnaires />} />
            <Route path="/trust-centre" element={<Trust />} />
            <Route path="/gaps" element={<Gaps />} />
            <Route path="/ai-governance" element={<AiGovernance />} />
            <Route path="/agreements" element={<Agreements />} />
            <Route path="/governance/policies/:id" element={<GrcPolicyEditor />} />
            <Route path="/governance/:tenantId/:framework" element={<ProgrammeDetail />} />
            <Route path="/soc-workflows" element={<SocWorkflows />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
          </PageBoundary>
        </main>
        {searchOpen && <CommandPalette pages={pages} onClose={() => setSearchOpen(false)} />}
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
  if (me.mfaSetupRequired) return <MfaSetupGate />;
  return <Shell />;
}

// The MSP requires MFA for staff: until this account enrols, this is all it can reach.
function MfaSetupGate() {
  const { me, logout, loginWithPasskey, toast } = useApp();
  // A new passkey is used straight away to sign in again, which replaces this password-only session.
  const signInWithNewPasskey = async () => {
    try {
      await loginWithPasskey();
    } catch (err) {
      toast(`Passkey added. Sign out and choose "Sign in with a passkey" to continue (${(err as Error).message})`, true);
    }
  };
  return (
    <div className="empty" style={{ maxWidth: 560, margin: "40px auto", textAlign: "left" }}>
      <h2 style={{ marginTop: 0 }}>Set up two-step sign-in</h2>
      <p>Your organisation requires multi-factor authentication for everyone who can reach customer devices. Set up an
        authenticator app{passkeysSupported() ? " or a passkey" : ""} now to continue as <b>{me?.user.email}</b>.</p>
      {me?.passkeys ? <p className="small">You already have a passkey: sign out and choose <b>Sign in with a passkey</b>.</p> : null}
      <MfaCard />
      <PasskeysCard onAdded={signInWithNewPasskey} />
      <p style={{ marginTop: 14 }}><button className="small" onClick={logout}>Sign out</button></p>
    </div>
  );
}
