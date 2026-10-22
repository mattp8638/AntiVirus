import { FormEvent, useState } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, NavLink, Navigate, Route, Routes } from "react-router-dom";
import { AppProvider, useApp } from "./app-context";
import { TenantSelect } from "./components/ui";
import "./styles.css";

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
import ServiceDesk from "./pages/ServiceDesk";
import Billing from "./pages/Billing";
import Reports from "./pages/Reports";
import Settings from "./pages/Settings";
import Deploy from "./pages/Deploy";

const NAV: { group: string; items: { to: string; label: string; icon: string }[] }[] = [
  { group: "Overview", items: [{ to: "/", label: "Dashboard", icon: "◎" }, { to: "/reports", label: "Reports", icon: "▤" }] },
  {
    group: "Endpoint protection",
    items: [
      { to: "/devices", label: "Devices", icon: "▣" },
      { to: "/policies", label: "Policies", icon: "⚙" },
      { to: "/deploy", label: "Deploy agents", icon: "⇩" },
    ],
  },
  {
    group: "Detection & response",
    items: [
      { to: "/incidents", label: "Incidents", icon: "⚑" },
      { to: "/alerts", label: "Alerts", icon: "△" },
      { to: "/hunt", label: "Threat hunting", icon: "⌕" },
      { to: "/rules", label: "Detection rules", icon: "≡" },
      { to: "/automations", label: "Automations", icon: "↯" },
    ],
  },
  {
    group: "Network & intel",
    items: [
      { to: "/dns", label: "DNS protection", icon: "◈" },
      { to: "/intel", label: "Threat intel", icon: "✦" },
    ],
  },
  {
    group: "Exposure",
    items: [
      { to: "/vulnerabilities", label: "Vulnerabilities", icon: "⚠" },
      { to: "/attack-surface", label: "Attack surface", icon: "◍" },
      { to: "/compliance", label: "Compliance", icon: "✓" },
    ],
  },
  {
    group: "Business",
    items: [
      { to: "/crm", label: "CRM", icon: "☺" },
      { to: "/service-desk", label: "Service desk", icon: "✉" },
      { to: "/billing", label: "Billing", icon: "£" },
    ],
  },
  { group: "Administration", items: [{ to: "/settings", label: "Settings", icon: "⚒" }] },
];

function Login() {
  const { login } = useApp();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(email, password);
    } catch (err) {
      setError((err as Error).message);
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
        {error && <p style={{ color: "#fecaca" }}>{error}</p>}
        <button className="primary" style={{ width: "100%", justifyContent: "center", marginTop: 18 }} disabled={busy}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}

function Shell() {
  const { me, tenantId, setTenantId, logout } = useApp();
  if (!me) return null;
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand"><div className="brand-mark">F</div><div><b>Fenrir</b><small>Unified security platform</small></div></div>
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
          <span className="muted small">Viewing</span>
          <TenantSelect value={tenantId} onChange={setTenantId} />
          <span className="spacer" />
          <span className="small muted">{me.user.email} · {me.user.role.replace(/_/g, " ")}</span>
          <button className="small" onClick={logout}>Sign out</button>
        </header>
        <main className="content">
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/devices" element={<Devices />} />
            <Route path="/devices/:id" element={<DeviceDetail />} />
            <Route path="/policies" element={<Policies />} />
            <Route path="/policies/:id" element={<PolicyEditor />} />
            <Route path="/deploy" element={<Deploy />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/incidents" element={<Incidents />} />
            <Route path="/incidents/:id" element={<IncidentDetail />} />
            <Route path="/hunt" element={<Hunt />} />
            <Route path="/rules" element={<Rules />} />
            <Route path="/automations" element={<Automations />} />
            <Route path="/dns" element={<Dns />} />
            <Route path="/intel" element={<Intel />} />
            <Route path="/vulnerabilities" element={<Vulnerabilities />} />
            <Route path="/attack-surface" element={<AttackSurface />} />
            <Route path="/compliance" element={<Compliance />} />
            <Route path="/crm" element={<Crm />} />
            <Route path="/service-desk" element={<ServiceDesk />} />
            <Route path="/billing" element={<Billing />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}

function Root() {
  const { me, loading } = useApp();
  if (loading) return <div className="empty">Loading…</div>;
  return me ? <Shell /> : <Login />;
}

createRoot(document.getElementById("root")!).render(
  <AppProvider>
    <BrowserRouter>
      <Root />
    </BrowserRouter>
  </AppProvider>,
);
