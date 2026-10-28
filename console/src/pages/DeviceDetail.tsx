import { displayValue } from "../components/DisplayValue";
import { Fragment, lazy, Suspense, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { ago, api, fmtTime, getToken } from "../api";
import { useApp } from "../app-context";
import { ErrorNote, Modal, Pill, Sev, Table, useAction, useData, useListData } from "../components/ui";
import { ConnectButtons, JobDetail, JobStatus, pct } from "../components/rmm";
import { TimeChart } from "../components/TimeChart";
import { RunScript } from "./rmm/Scripts";
import { SystemTab } from "./DeviceSystem";
import { DeviceVulns } from "./DeviceVulns";
import { DeviceDetails, DeviceOverview, useCommandLabels } from "./DeviceOverview";

// The map (Leaflet) is only downloaded when a phone's Location tab is opened.
const LocationTab = lazy(() => import("./DeviceLocation"));

// Seven sections instead of thirteen tabs; the section and sub-page live in the URL (?tab=&sub=) so a link,
// a refresh or the back button lands on the same place.
const SECTIONS: { key: string; label: string; subs?: string[] }[] = [
  { key: "overview", label: "Overview" },
  { key: "health", label: "Health" },
  { key: "system", label: "System" },
  { key: "security", label: "Security", subs: ["Alerts", "Vulnerabilities", "Local admin"] },
  { key: "software", label: "Software", subs: ["Patches", "Installed"] },
  { key: "activity", label: "Activity", subs: ["Scripts & jobs", "Remote actions", "Remote sessions", "Bundles & recordings"] },
  { key: "settings", label: "Settings", subs: ["Effective policy", "Device details"] },
];
// Phones have no patches, scripts, remote desktop or local admin; they get Location instead.
const PHONE_SECTIONS: { key: string; label: string; subs?: string[] }[] = [
  { key: "overview", label: "Overview" },
  { key: "location", label: "Location" },
  { key: "security", label: "Security", subs: ["Alerts"] },
  { key: "software", label: "Apps", subs: ["Installed"] },
  { key: "activity", label: "Activity", subs: ["Remote actions"] },
  { key: "settings", label: "Settings", subs: ["Effective policy", "Device details"] },
];
const OPEN_ALERT = (a: any) => !["resolved", "closed", "false_positive"].includes(a.status);
const PLATFORM_GLYPH: Record<string, string> = { windows: "⊞", macos: "⌘", linux: "🐧", android: "📱" };

// A small drop-down menu: closes on outside click or Escape.
function Menu({ label, children }: { label: React.ReactNode; children: (close: () => void) => React.ReactNode }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => { if (!ref.current?.contains(e.target as Node)) setOpen(false); };
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => { document.removeEventListener("mousedown", onDown); document.removeEventListener("keydown", onKey); };
  }, [open]);
  return (
    <div className="menu-wrap" ref={ref}>
      <button onClick={() => setOpen(!open)} aria-haspopup="menu" aria-expanded={open}>{label} ▾</button>
      {open && <div className="menu" role="menu">{children(() => setOpen(false))}</div>}
    </div>
  );
}

function StatTile({ label, value, sub, tone, onClick }: { label: string; value: React.ReactNode; sub?: React.ReactNode; tone?: string; onClick?: () => void }) {
  return (
    <button className={`stat-tile ${tone ? `tone-edge-${tone}` : ""}`} onClick={onClick} disabled={!onClick}>
      <span className="stat-label">{label}</span>
      <span className="stat-value">{displayValue(value)}</span>
      {sub && <span className="stat-sub">{displayValue(sub)}</span>}
    </button>
  );
}

const levelTone = (v: number | undefined, warn: number, bad: number, invert = false) => {
  if (v === undefined || v === null || Number.isNaN(v)) return undefined;
  const x = invert ? -v : v;
  return x >= (invert ? -bad : bad) ? "bad" : x >= (invert ? -warn : warn) ? "warn" : "good";
};

export default function DeviceDetail() {
  const { id } = useParams();
  const { tenantName, can } = useApp();
  const { data, error, reload } = useData<any>(`devices/${id}`);
  const { data: policies } = useListData<any>("policies", { tenant_id: data?.device.tenantId }, [data?.device.tenantId]);
  const { data: groups } = useListData<any>("groups", { tenant_id: data?.device.tenantId }, [data?.device.tenantId]);
  const { data: profile } = useData<any>(id ? `devices/${id}/profile` : null);
  const isPhone = data?.device.platform === "android";
  const { data: patches } = useData<any>(id && data && !isPhone ? `rmm/devices/${id}/patches` : null, {}, [isPhone]);
  const { data: whereabouts, reload: reloadWhere } = useData<any>(id && isPhone ? `devices/${id}/locations` : null, { hours: 24 }, [isPhone]);
  const [reinstating, setReinstating] = useState(false);
  const [installerReady, setInstallerReady] = useState(false);
  const [retiring, setRetiring] = useState(false);
  const [retireName, setRetireName] = useState("");
  const [purging, setPurging] = useState(false);
  const [purgeName, setPurgeName] = useState("");
  const goTo = useNavigate();
  const [params, setParams] = useSearchParams();
  const [action, setAction] = useState<string | null>(null);
  const [scriptPicker, setScriptPicker] = useState(false);
  const [jobId, setJobId] = useState<string | null>(null);
  const { run, busy } = useAction();
  const commandLabel = useCommandLabels();

  // Keep the header live (online state, CPU, memory) without a manual refresh.
  useEffect(() => {
    const timer = setInterval(() => { if (document.visibilityState === "visible") { reload(); reloadWhere(); } }, 30000);
    return () => clearInterval(timer);
  }, [reload, reloadWhere]);

  if (error) return <ErrorNote error={error} />;
  if (!data) return <div className="empty">Loading…</div>;
  const d = data.device;
  const isWindows = String(d.platform || "windows").toLowerCase() === "windows";
  const sections = isPhone ? PHONE_SECTIONS : SECTIONS.map((s) => s.key === "security" && !isWindows ? { ...s, subs: s.subs!.filter((x) => x !== "Local admin") } : s);
  const section = sections.find((s) => s.key === params.get("tab")) ?? sections[0];
  const sub = section.subs ? (section.subs.find((s) => s === params.get("sub")) ?? section.subs[0]) : undefined;
  const go = (tab: string, subPage?: string) => {
    const next = new URLSearchParams(params);
    next.set("tab", tab);
    if (subPage) next.set("sub", subPage); else next.delete("sub");
    if (tab === "overview") { next.delete("tab"); next.delete("sub"); }
    setParams(next);
  };

  const patch = async (body: any, message: string) => {
    await run(() => api(`devices/${d.id}`, { method: "PATCH", body }), message);
    reload();
  };
  const queue = async (type: string, label: string, payload: any = {}) => {
    await run(() => api(`devices/${d.id}/commands`, { body: { type, reason: `${label} from the device page`, payload } }), `${label} queued`);
    reload();
  };

  const m = d.metrics || {};
  const openAlerts = (data.alerts || []).filter(OPEN_ALERT);
  const pendingPatches = (patches?.patches || []).filter((x: any) => x.status !== "installed");
  const openVulns = (data.vulnerabilities || []).filter((v: any) => ["open", "patching"].includes(v.status));
  const diskFree = (m.disks || []).length ? Math.min(...m.disks.map((x: any) => x.freePercent ?? 100)) : undefined;
  const counts: Record<string, number> = { security: openAlerts.length, software: pendingPatches.length };
  const subCounts: Record<string, number> = { Alerts: openAlerts.length, Vulnerabilities: openVulns.length, Patches: pendingPatches.length, Installed: (data.software || []).length };
  const user = m.loggedOnUser || d.inventory?.loggedOnUser;
  const groupName = groups?.find((g) => g.id === d.groupId)?.name;

  const management = (
    <div className="form-grid compact">
      <label className="field">Group
        <select value={d.groupId ?? ""} disabled={!can("configure")} onChange={(e) => patch({ groupId: e.target.value || null }, "Group updated")}>
          <option value="">No group</option>
          {groups?.map((g) => <option key={g.id} value={g.id}>{displayValue(g.name)}</option>)}
        </select>
      </label>
      <label className="field">Policy override
        <select value={d.policyId ?? ""} disabled={!can("configure")} onChange={(e) => patch({ policyId: e.target.value || null }, "Policy override updated")}>
          <option value="">Inherit from group/customer</option>
          {policies?.filter((p) => p.tenantId).map((p) => <option key={p.id} value={p.id}>{displayValue(p.name)}</option>)}
        </select>
      </label>
      <label className="field">Business criticality
        <select value={d.criticality ?? "medium"} disabled={!can("configure")} onChange={(e) => patch({ criticality: e.target.value }, "Criticality updated")}>
          {["low", "medium", "high", "critical"].map((c) => <option key={c}>{c}</option>)}
        </select>
      </label>
    </div>
  );

  return (
    <>
      <div className="crumbs small"><Link to="/devices">Devices</Link> <span className="muted">›</span> <span className="muted">{tenantName(d.tenantId)}</span> <span className="muted">›</span> <span>{displayValue(d.hostname)}</span></div>

      <div className="device-hero">
        <div className={`device-glyph ${d.online ? "on" : ""}`} aria-hidden>{PLATFORM_GLYPH[String(d.platform).toLowerCase()] ?? "▣"}</div>
        <div style={{ minWidth: 0, flex: 1 }}>
          <div className="row" style={{ gap: 10 }}>
            <h1 style={{ margin: 0 }}>{displayValue(d.hostname)}</h1>
            {d.retired ? <Pill value="decommissioned" tone="muted" /> :
              <span className={`status-chip ${d.online ? "on" : "off"}`}><span className={`dot ${d.online ? "on" : "off"}`} />{d.online ? "Online" : `Offline · ${ago(d.lastSeenAt)}`}</span>}
            {!d.approved && !d.retired && <Pill value="needs approval" tone="warn" />}
            {d.isolated && <Pill value="isolated" tone="bad" />}
            {d.lostMode?.enabled && <Pill value="lost mode" tone="bad" />}
            {m.rebootPending && <Pill value="restart pending" tone="warn" />}
            {d.healthState && d.healthState !== "healthy" && <Pill value={d.healthState} tone="warn" />}
            {d.inventory?.role === "domain-controller" && <Link to="/active-directory"><Pill value="Domain controller" tone="blue" /></Link>}
            {d.inventory?.role === "server" && <Pill value="Server" tone="muted" />}
          </div>
          <div className="device-meta">
            <span>{displayValue(d.osVersion)}</span>
            {d.inventory?.serverRoles?.length > 0 && <span title="Installed server roles">{displayValue(d.inventory.serverRoles.slice(0, 4).join(", "))}</span>}
            <span>{tenantName(d.tenantId)}{groupName ? ` · ${groupName}` : ""}</span>
            {user && <span title="Signed-in user">👤 {displayValue(user)}</span>}
            {d.ipAddress && <span className="mono">{displayValue(d.ipAddress)}</span>}
          </div>
        </div>
        {!d.retired && can("respond") && isPhone && <div className="device-actions">
          {!d.approved && can("configure") && <button className="primary" onClick={() => patch({ approved: true }, "Device approved")}>Approve</button>}
          <button className="primary" onClick={() => { queue("device.locate", "Locate now"); go("location"); setTimeout(reloadWhere, 8000); }}>⌖ Locate</button>
          <button onClick={() => queue("device.alarm", "Play alarm", { seconds: 60 })}>🔊 Alarm</button>
          <button onClick={() => queue("device.lock", "Lock")}>🔒 Lock</button>
          <Menu label="More">{(close) => <>
            <button role="menuitem" onClick={() => { close(); go("location"); }}>Lost mode, message, erase…</button>
            <button role="menuitem" onClick={() => { close(); run(() => api(`devices/${d.id}/profile/refresh`, { method: "POST" }), "Inventory refresh queued"); }}>Refresh inventory</button>
            <button role="menuitem" onClick={() => { close(); queue("policy.refresh", "Policy refresh"); }}>Refresh policy now</button>
            <button role="menuitem" onClick={() => { close(); navigator.clipboard?.writeText(d.id); }}>Copy device ID</button>
            {can("configure") && <><div className="menu-sep" />
              <button role="menuitem" className="danger-text" onClick={() => { close(); setRetireName(""); setRetiring(true); }}>Decommission device…</button></>}
          </>}</Menu>
        </div>}
        {!d.retired && can("respond") && !isPhone && <div className="device-actions">
          {!d.approved && can("configure") && <button className="primary" onClick={() => patch({ approved: true }, "Device approved")}>Approve</button>}
          <ConnectButtons device={d} />
          {can("configure") && <button onClick={() => setScriptPicker(true)}>Run script</button>}
          <Menu label="Scan">{(close) => <>
            <button role="menuitem" onClick={() => { close(); queue("scan.quick", "Quick scan"); }}>Quick scan</button>
            <button role="menuitem" onClick={() => { close(); queue("scan.full", "Full scan"); }}>Full scan</button>
            <button role="menuitem" onClick={() => { close(); setAction("scan.targeted"); }}>Scan a path…</button>
            <button role="menuitem" onClick={() => { close(); run(() => api("vulnerabilities/scan", { body: { deviceId: d.id } }), "Vulnerability scan queued"); }}>Vulnerability scan</button>
            <button role="menuitem" onClick={() => { close(); queue("patch.scan", "Patch scan"); }}>Patch scan</button>
          </>}</Menu>
          {d.isolated ? <button onClick={() => setAction("device.release")}>Release isolation</button>
                      : <button className="danger" onClick={() => setAction("device.isolate")}>Isolate</button>}
          <Menu label="More">{(close) => <>
            <div className="menu-label">Device</div>
            <button role="menuitem" onClick={() => { close(); setAction("device.reboot"); }}>Restart…</button>
            <button role="menuitem" onClick={() => { close(); setAction("device.message"); }}>Message the user…</button>
            <button role="menuitem" onClick={() => { close(); setAction("service.control"); }}>Start / stop a service…</button>
            <button role="menuitem" onClick={() => { close(); run(() => api(`devices/${d.id}/profile/refresh`, { method: "POST" }), "Inventory refresh queued"); }}>Refresh inventory</button>
            <button role="menuitem" onClick={() => { close(); queue("policy.refresh", "Policy refresh"); }}>Refresh policy now</button>
            <div className="menu-label">Collect</div>
            <button role="menuitem" onClick={() => { close(); queue("support.bundle", "Support bundle"); }}>Support bundle</button>
            <button role="menuitem" onClick={() => { close(); queue("forensics.collect", "Forensic bundle"); }}>Forensic bundle</button>
            <div className="menu-label">Other</div>
            <button role="menuitem" onClick={() => { close(); setAction(""); }}>All remote actions…</button>
            <button role="menuitem" onClick={() => { close(); navigator.clipboard?.writeText(d.id); }}>Copy device ID</button>
            {can("configure") && <><div className="menu-sep" />
              <button role="menuitem" className="danger-text" onClick={() => { close(); setRetireName(""); setRetiring(true); }}>Decommission device…</button></>}
          </>}</Menu>
        </div>}
      </div>

      {d.platform === "macos" && d.inventory?.permissions?.fullDiskAccess === false && (
        <div className="card" role="alert" style={{ borderColor: "rgba(251,191,36,.5)", marginBottom: 12 }}>
          <b>Full Disk Access is not granted on this Mac.</b> Scans and forensic collection cannot read protected folders
          (Mail, Messages, Safari, other users' files). On the Mac, open System Settings › Privacy &amp; Security › Full Disk Access
          and allow <span className="mono">/usr/local/bin/fenrir-agent</span>, or push the permission with an MDM profile.
        </div>)}
      {d.retired && <div className="card" role="status" style={{ marginBottom: 12, borderColor: "rgba(100,116,139,.6)" }}>
        <div className="row">
          <span style={{ flex: 1 }}>Decommissioned: agent access is revoked. History stays available. Reinstate to reconnect the endpoint to this record.</span>
          {can("configure") && <><button className="primary" onClick={() => { setInstallerReady(false); setReinstating(true); }}>Reinstate device</button>
            <button className="danger" onClick={() => { setPurgeName(""); setPurging(true); }}>Delete permanently</button></>}
        </div>
      </div>}

      {!d.retired && isPhone && <div className="stat-strip">
        <StatTile label="Battery" value={typeof m.batteryPercent === "number" ? `${m.batteryPercent}%` : "—"} tone={typeof m.batteryPercent === "number" ? (m.batteryPercent < 15 ? "bad" : m.batteryPercent < 30 ? "warn" : "good") : undefined} sub={m.charging ? "charging" : m.reportedAt ? `reported ${ago(m.reportedAt)}` : "no data yet"} />
        <StatTile label="Last located" value={whereabouts?.latest ? ago(whereabouts.latest.at) : "—"} tone={whereabouts?.latest ? undefined : "warn"} sub={whereabouts?.latest?.accuracy ? `± ${Math.round(whereabouts.latest.accuracy)} m` : "open the map"} onClick={() => go("location")} />
        <StatTile label="Lost mode" value={whereabouts?.lostMode?.enabled ? "On" : "Off"} tone={whereabouts?.lostMode?.enabled ? "bad" : "good"} sub={whereabouts?.lostMode?.enabled ? "reporting every 5 min" : "phone is not lost"} onClick={() => go("location")} />
        <StatTile label="Storage free" value={diskFree === undefined ? "—" : `${Math.round(diskFree)}%`} tone={diskFree === undefined ? undefined : diskFree < 5 ? "bad" : diskFree < 15 ? "warn" : "good"} sub="internal storage" />
        <StatTile label="Network" value={m.network ? String(m.network) : "—"} sub={m.wifiSsid || m.carrier || "connection"} />
        <StatTile label="Screen lock" value={m.screenLockSecure === undefined ? "—" : m.screenLockSecure ? "Set" : "None"} tone={m.screenLockSecure === undefined ? undefined : m.screenLockSecure ? "good" : "bad"} sub={m.securityPatch ? `patch ${m.securityPatch}` : "PIN, pattern or password"} />
        <StatTile label="Open alerts" value={openAlerts.length} tone={openAlerts.length ? "warn" : "good"} sub={`risk score ${d.riskScore}`} onClick={() => go("security", "Alerts")} />
      </div>}
      {!d.retired && !isPhone && <div className="stat-strip">
        <StatTile label="CPU" value={pct(m.cpuPercent)} tone={levelTone(m.cpuPercent, 70, 90)} sub={m.reportedAt ? `reported ${ago(m.reportedAt)}` : "no data yet"} onClick={() => go("health")} />
        <StatTile label="Memory" value={pct(m.memoryPercent)} tone={levelTone(m.memoryPercent, 80, 92)} sub={m.memoryTotalGb ? `of ${Math.round(m.memoryTotalGb)} GB` : undefined} onClick={() => go("health")} />
        <StatTile label="Disk free" value={diskFree === undefined ? "—" : `${Math.round(diskFree)}%`} tone={diskFree === undefined ? undefined : diskFree < 5 ? "bad" : diskFree < 15 ? "warn" : "good"} sub="lowest volume" onClick={() => go("system")} />
        <StatTile label="Up for" value={m.uptimeSeconds ? `${Math.floor(m.uptimeSeconds / 86400)}d ${Math.floor((m.uptimeSeconds % 86400) / 3600)}h` : "—"} tone={m.uptimeSeconds > 30 * 86400 ? "warn" : undefined} sub={m.rebootPending ? "restart pending" : "since last restart"} onClick={() => go("health")} />
        <StatTile label="Open alerts" value={openAlerts.length} tone={openAlerts.length ? (openAlerts.some((a: any) => ["critical", "high"].includes(a.severity)) ? "bad" : "warn") : "good"} sub={`risk score ${d.riskScore}`} onClick={() => go("security", "Alerts")} />
        <StatTile label="Patches" value={patches ? pendingPatches.length : "—"} tone={patches ? (pendingPatches.length ? "warn" : "good") : undefined} sub={patches?.lastScan ? `scanned ${ago(patches.lastScan)}` : "not scanned"} onClick={() => go("software", "Patches")} />
        <StatTile label="Vulnerabilities" value={openVulns.length} tone={openVulns.some((v: any) => v.knownExploited || v.severity === "critical") ? "bad" : openVulns.length ? "warn" : "good"} sub="open" onClick={() => go("security", "Vulnerabilities")} />
      </div>}

      <div className="tabs device-tabs" role="tablist">
        {sections.map((s) => <button key={s.key} role="tab" aria-selected={s.key === section.key} className={s.key === section.key ? "active" : ""} onClick={() => go(s.key)}>
          {s.label}{counts[s.key] ? <span className="tab-count">{counts[s.key]}</span> : null}</button>)}
      </div>
      {section.subs && <div className="subtabs">
        {section.subs.map((s) => <button key={s} className={s === sub ? "active" : ""} onClick={() => go(section.key, s)}>{s}{subCounts[s] ? <span className="sub-count">{subCounts[s]}</span> : null}</button>)}
      </div>}

      {section.key === "overview" && <DeviceOverview data={data} profile={profile} patches={patches} go={go} management={management} whereabouts={whereabouts} />}
      {section.key === "health" && <HealthTab deviceId={d.id} />}
      {section.key === "location" && <Suspense fallback={<div className="empty">Loading map…</div>}><LocationTab device={d} onChanged={() => { reload(); reloadWhere(); }} /></Suspense>}
      {section.key === "system" && <SystemTab deviceId={d.id} />}

      {sub === "Alerts" && (
        <div className="card">
          <Table rows={data.alerts} empty="No alerts for this device."
                 columns={[{ key: "severity", label: "Sev", render: (r) => <Sev level={r.severity} /> }, { key: "title", label: "Alert" },
                           { key: "status", label: "Status", render: (r) => <Pill value={r.status} /> },
                           { key: "mitre", label: "MITRE", render: (r) => r.mitre.filter((x: string) => x.startsWith("T")).join(", ") },
                           { key: "incidentId", label: "Incident", render: (r) => r.incidentId ? <Link to={`/incidents/${r.incidentId}`}>open</Link> : "—" },
                           { key: "createdAt", label: "When", render: (r) => <span title={fmtTime(r.createdAt)}>{ago(r.createdAt)}</span> }]} />
        </div>
      )}
      {sub === "Vulnerabilities" && <DeviceVulns device={d} vulnerabilities={data.vulnerabilities} risk={data.risk} scans={data.vulnScans} onChanged={reload} />}
      {sub === "Local admin" && <LocalAdmin deviceId={d.id} />}
      {sub === "Patches" && <PatchesTab device={d} />}
      {sub === "Installed" && <SoftwareList rows={data.software} />}
      {sub === "Scripts & jobs" && <JobsTab deviceId={d.id} onOpen={setJobId} onRun={can("configure") ? () => setScriptPicker(true) : undefined} />}
      {sub === "Remote actions" && (
        <div className="card">
          <div className="row" style={{ marginBottom: 10 }}>
            <span className="small muted" style={{ flex: 1 }}>The last 25 commands sent to this device.</span>
            {can("respond") && !d.retired && <button onClick={() => setAction("")}>New remote action…</button>}
          </div>
          <Table rows={data.commands} empty="No remote actions yet."
                 columns={[{ key: "type", label: "Action", render: (r) => <span title={r.type}>{displayValue(commandLabel(r.type))}</span> }, { key: "status", label: "Status", render: (r) => <Pill value={r.status} /> },
                           { key: "issuedBy", label: "By" }, { key: "targetPath", label: "Target", render: (r) => <span className="mono small">{displayValue(r.targetPath || r.recordId || "—")}</span> },
                           { key: "reason", label: "Reason" }, { key: "createdAt", label: "Queued", render: (r) => <span title={fmtTime(r.createdAt)}>{ago(r.createdAt)}</span> },
                           { key: "result", label: "Result", render: (r) => Object.keys(r.result || {}).length ? <span className="mono small" title={JSON.stringify(r.result)}>{JSON.stringify(r.result).slice(0, 80)}</span> : "—" }]} />
        </div>
      )}
      {sub === "Remote sessions" && <SessionsTab deviceId={d.id} />}
      {sub === "Bundles & recordings" && <Bundles deviceId={d.id} />}
      {sub === "Effective policy" && <EffectivePolicy policy={data.policy} />}
      {sub === "Device details" && (
        <div className="grid k2">
          <div className="card"><h3>Device</h3><DeviceDetails data={data} /></div>
          <div className="stack">
            <div className="card"><h3>Management</h3>{management}</div>
            {can("configure") && !d.retired && <div className="card danger-zone">
              <h3>Danger zone</h3>
              <p className="small muted">Decommissioning revokes the agent's access and cancels pending commands. History is kept, and the device can be reinstated later.</p>
              <button className="danger" onClick={() => { setRetireName(""); setRetiring(true); }}>Decommission device…</button>
            </div>}
          </div>
        </div>
      )}

      {purging && <Modal title={`Delete ${d.hostname} permanently`} onClose={()=>{if(!busy)setPurging(false);}}>
        <p>This deletes the device record and everything recorded about it: telemetry, alerts and incidents, commands, inventory, patches, vulnerabilities, remote sessions, bundles and recordings. It cannot be undone.</p>
        <p>Tickets and CMDB configurations are kept but no longer linked to the device. The audit log records the deletion. To use this endpoint again later, install the agent with a new installer.</p>
        <label className="field">Type {displayValue(d.hostname)} to confirm<input value={purgeName} onChange={e=>setPurgeName(e.target.value)}/></label>
        <button className="danger" disabled={busy||purgeName!==d.hostname} onClick={async()=>{
          const result=await run(()=>api(`devices/${d.id}/purge`,{method:"POST",body:{confirmHostname:purgeName}}),`${d.hostname} deleted permanently`);
          if(result){setPurging(false);goTo("/devices");}
        }}>Delete permanently</button>
      </Modal>}
      {reinstating && <Modal title={`Reinstate ${d.hostname}`} onClose={()=>{if(!busy)setReinstating(false);}}>
        <p>Generate a replacement installer bound to this device record and customer. Run it on the original endpoint as administrator. The device stays decommissioned until enrollment succeeds; its history, group and policy are retained.</p>
        <p>The installer expires after 24 hours and can be used once. Generating another replaces the previous reinstatement token. Old agent credentials remain revoked.</p>
        <button disabled={busy} onClick={async()=>{
          const ok=await run(async()=>{
            const token=getToken();
            if(!token)throw new Error("Sign in again before generating an installer.");
            const response=await fetch("/api/console/enrollment-installers",{method:"POST",headers:{Authorization:`Bearer ${token}`,"Content-Type":"application/json"},body:JSON.stringify({os:d.platform,tenantId:d.tenantId,reinstateDeviceId:d.id}),cache:"no-store"});
            if(!response.ok){const body=await response.json();throw new Error(typeof body.detail==="string"?body.detail:"Installer generation failed");}
            const file=await response.blob();
            const filename=/filename="([A-Za-z0-9._-]+)"/.exec(response.headers.get("Content-Disposition")||"")?.[1]||"Fenrir-reinstatement-installer";
            const url=URL.createObjectURL(file);
            const link=document.createElement("a");link.href=url;link.download=filename;document.body.appendChild(link);link.click();link.remove();window.setTimeout(()=>URL.revokeObjectURL(url),60000);
            return true;
          });
          if(ok)setInstallerReady(true);
        }}>{busy?"Generating…":"Download reinstatement installer"}</button>
        {installerReady&&<p role="status">Installer downloaded. Run it on the original device, then refresh this page. This does not uninstall or release network isolation.</p>}
        <button onClick={reload}>Refresh device status</button>
      </Modal>}
      {retiring && <Modal title={`Decommission ${d.hostname}`} onClose={()=>{if(!busy)setRetiring(false);}}>
        <p>This removes the device from the active list, revokes its agent credentials and cancels pending commands. Logs, alerts, inventory and command history are retained under the existing retention policy. It does not uninstall the agent or remove network isolation.</p>
        <p>Active remote sessions must be ended and dispatched commands reconciled first.</p>
        <label className="field">Type {displayValue(d.hostname)} to confirm<input value={retireName} onChange={e=>setRetireName(e.target.value)}/></label>
        <button className="danger" disabled={busy||retireName!==d.hostname} onClick={async()=>{const result=await run(()=>api(`devices/${d.id}`,{method:"DELETE"}),"Device decommissioned; history retained");if(result){setRetiring(false);reload();}}}>Decommission and retain history</button>
      </Modal>}

      {action !== null && <CommandModal device={d} initial={action} onClose={() => { setAction(null); reload(); }} />}
      {scriptPicker && <ScriptPicker device={d} onClose={() => setScriptPicker(false)} onStarted={(jid) => { setScriptPicker(false); setJobId(jid); go("activity", "Scripts & jobs"); }} />}
      {jobId && <JobDetail jobId={jobId} onClose={() => setJobId(null)} />}
    </>
  );
}

// Installed software with a search box (a device can have hundreds of entries).
function SoftwareList({ rows }: { rows: any[] }) {
  const [q, setQ] = useState("");
  const filtered = useMemo(() => (rows || []).filter((r) => !q || `${r.name} ${r.vendor} ${r.version}`.toLowerCase().includes(q.toLowerCase())), [rows, q]);
  return (
    <div className="card">
      <div className="row" style={{ marginBottom: 10 }}>
        <input placeholder="Search installed software" value={q} onChange={(e) => setQ(e.target.value)} style={{ minWidth: 260 }} />
        <span className="small muted">{filtered.length} of {(rows || []).length}</span>
      </div>
      <Table rows={filtered} empty={q ? "Nothing matches." : "No inventory yet. The agent reports software on its inventory cycle."}
             columns={[{ key: "name", label: "Name" }, { key: "version", label: "Version" }, { key: "vendor", label: "Vendor" }, { key: "ecosystem", label: "Source" }]} />
    </div>
  );
}

function EffectivePolicy({ policy }: { policy: any }) {
  const { data: schema } = useData<any>("policy-schema");
  const [filter, setFilter] = useState("");
  const blocked = useMemo(() => new Set(policy.overridesBlocked.map((b: any) => b.setting)), [policy]);
  if (!schema) return <div className="empty">Loading…</div>;
  return (
    <div className="card">
      <div className="row" style={{ marginBottom: 12 }}>
        <input placeholder="Filter settings" value={filter} onChange={(e) => setFilter(e.target.value)} />
        <span className="muted small">Each value shows the layer that set it. Locked settings cannot be overridden lower down.</span>
      </div>
      {schema.sections.map((section: any) => {
        const fields = section.fields.filter((f: any) => !filter || f.label.toLowerCase().includes(filter.toLowerCase()) || f.path.includes(filter));
        if (!fields.length) return null;
        return (
          <div key={section.key} style={{ marginBottom: 18 }}>
            <h3>{displayValue(section.title)}</h3>
            <Table rows={fields.map((f: any) => ({ ...f, id: f.path }))}
                   columns={[{ key: "label", label: "Setting" },
                             { key: "value", label: "Value", render: (f) => <span className="mono small">{JSON.stringify(policy.settings[section.key][f.key])}</span> },
                             { key: "origin", label: "Set by", render: (f) => <span className="small">{displayValue(policy.origin[f.path])}</span> },
                             { key: "lock", label: "", render: (f) => <>
                                 {(policy.locked[f.path] || policy.locked[section.key]) && <Pill value={`locked by ${policy.locked[f.path] || policy.locked[section.key]}`} tone="blue" />}
                                 {blocked.has(f.path) && <Pill value="override blocked" tone="warn" />}
                               </> }]} />
          </div>
        );
      })}
    </div>
  );
}

export function CommandModal({ device, initial, onClose, incidentId }: { device: any; initial: string; onClose: () => void; incidentId?: string }) {
  const { can } = useApp();
  const { data: catalog, error: catalogError } = useListData<any>("commands/catalog");
  const [type, setType] = useState(initial || "scan.quick");
  const [targetPath, setTargetPath] = useState("");
  const [recordId, setRecordId] = useState("");
  const [pid, setPid] = useState("");
  const [reason, setReason] = useState("");
  const { run, busy } = useAction();
  const isKill = type === "process.terminate" || type === "process.tree.terminate";
  const available = catalog?.filter((c) => c.platforms.includes(device.platform) && can(c.permission)) ?? [];
  const spec = available.find((c) => c.type === type);
  const valid = !!spec && (!spec.needs.includes("targetPath") || !!targetPath.trim()) &&
    (!spec.needs.includes("recordId") || !!recordId.trim());
  const submit = async () => {
    if (!valid || busy) return;
    const ok = await run(() => api(`devices/${device.id}/commands`, { body: { type, targetPath, recordId, reason, incidentId, payload: isKill && pid ? { pid: Number(pid) } : {} } }), `${spec?.label ?? type} queued`);
    if (ok) onClose();
  };
  return (
    <Modal title={`Remote action · ${device.hostname}`} onClose={onClose}
           footer={<><button onClick={onClose}>Cancel</button><button className={spec?.destructive ? "danger" : "primary"} disabled={busy || !valid} onClick={submit}>Queue action</button></>}>
      <ErrorNote error={catalogError} />
      <div className="form-grid">
        <label className="field">Action
          <select value={type} onChange={(e) => setType(e.target.value)}>
            {available.map((c) => <option key={c.type} value={c.type}>{displayValue(c.group)}: {displayValue(c.label)}</option>)}
          </select>
        </label>
        {spec?.needs.includes("targetPath") && <label className="field">Target path<input value={targetPath} onChange={(e) => setTargetPath(e.target.value)} placeholder="C:\\path\\file.exe" /></label>}
        {isKill && <label className="field">Process ID<input value={pid} onChange={(e) => setPid(e.target.value.replace(/\D/g, ""))} placeholder="from the alert" /></label>}
        {spec?.needs.includes("recordId") && <label className="field">Record ID<input value={recordId} onChange={(e) => setRecordId(e.target.value)} /></label>}
        <label className="field">Reason<input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Recorded in the audit log" /></label>
      </div>
      {spec?.description && <p className="muted">{displayValue(spec.description)}</p>}
      {isKill && !pid && <p style={{ color: "#fde68a" }}>No process ID: every running copy of this program on the device will be killed.</p>}
      {spec?.destructive && <p style={{ color: "#fecaca" }}>This action changes the device and cannot be undone automatically.</p>}
    </Modal>
  );
}


function HealthTab({ deviceId }: { deviceId: string }) {
  const [hours, setHours] = useState(24);
  const { data } = useData<any>(`rmm/devices/${deviceId}/metrics`, { hours }, [hours]);
  if (!data) return <div className="empty">Loading…</div>;
  const c = data.current || {};
  const series = data.series || [];
  const times = series.map((p: any) => p.at);
  return (
    <>
    <div className="card" style={{ marginBottom: 14 }}>
      <div className="row" style={{ marginBottom: 6 }}>
        <h3 style={{ margin: 0 }}>CPU and memory</h3>
        <span style={{ flex: 1 }} />
        {[24, 168].map((h) => <button key={h} className={`small ${hours === h ? "primary" : ""}`} onClick={() => setHours(h)}>{h === 24 ? "24 hours" : "7 days"}</button>)}
      </div>
      <TimeChart times={times} series={[
        { label: "CPU", color: "#38bdf8", values: series.map((p: any) => p.cpu) },
        { label: "CPU peak", color: "rgba(56,189,248,0.35)", values: series.map((p: any) => p.cpuMax) },
        { label: "Memory", color: "#a855f7", values: series.map((p: any) => p.memory) },
      ]} />
      <div className="small muted" style={{ marginTop: 10 }}>Lowest disk free space</div>
      <TimeChart height={90} times={times} series={[{ label: "Disk free", color: "#22c55e", values: series.map((p: any) => p.diskFree) }]} />
    </div>
    {renderHealthCards()}
    </>
  );
  function renderHealthCards() { return (
    <div className="grid k2">
      <div className="card">
        <h3>Now</h3>
        {!c.reportedAt ? <p className="muted">This agent has not reported health metrics yet (needs agent 1.1 or later).</p> : (
          <dl className="kv">
            <dt>CPU</dt><dd>{pct(c.cpuPercent)}</dd>
            <dt>Memory</dt><dd>{pct(c.memoryPercent)} of {c.memoryTotalGb ? `${Math.round(c.memoryTotalGb)} GB` : "?"}</dd>
            {(c.disks || []).map((disk: any) => <Fragment key={disk.mount}><dt>Disk {displayValue(disk.mount)}</dt><dd>{displayValue(disk.freeGb.toFixed(1))} GB free of {displayValue(disk.totalGb.toFixed(0))} GB ({pct(disk.freePercent)})</dd></Fragment>)}
            <dt>Signed in</dt><dd>{displayValue(c.loggedOnUser || "nobody")}</dd>
            <dt>Up since</dt><dd>{fmtTime(c.lastBootAt)} ({c.uptimeSeconds ? `${(c.uptimeSeconds / 86400).toFixed(1)} days` : "?"})</dd>
            <dt>Restart pending</dt><dd>{c.rebootPending ? <Pill value="yes" tone="warn" /> : "No"}</dd>
            <dt>Stopped services</dt><dd className="small">{displayValue((c.stoppedServices || []).join(", ") || "None")}</dd>
            <dt>Hardware</dt><dd>{[c.manufacturer, c.model].filter(Boolean).join(" ") || "—"}</dd>
            <dt>Reported</dt><dd>{ago(c.reportedAt)}</dd>
          </dl>
        )}
      </div>
      <div className="card">
        <h3>Monitors</h3>
        {(data.monitors || []).length === 0 ? <p className="muted small">No monitor has evaluated this device yet.</p> :
          data.monitors.map((m: any, i: number) => <div key={i} className="row small"><Pill value={m.triggered ? "triggered" : "ok"} tone={m.triggered ? "bad" : "good"} /> {displayValue(m.condition)} <span className="muted">{displayValue(m.message)}</span></div>)}
      </div>
    </div>
  ); }
}

function PatchesTab({ device }: { device: any }) {
  const { can } = useApp();
  const { data, reload } = useData<any>(`rmm/devices/${device.id}/patches`);
  const { run, busy } = useAction();
  if (!data) return <div className="empty">Loading…</div>;
  const targets = { deviceIds: [device.id], groupIds: [], tenantIds: [], platforms: [] };
  return (
    <div className="card">
      <div className="row" style={{ marginBottom: 10 }}>
        <span className="small muted">Policy: {displayValue(data.policy?.name || "defaults")} · ring {displayValue(data.ring.name)} (+{displayValue(data.ring.delayDays)} days) · last scan {ago(data.lastScan)}</span>
        {data.rebootPending && <Pill value="restart pending" tone="warn" />}
        <span style={{ flex: 1 }} />
        {can("respond") && <button disabled={busy} onClick={async () => { await run(() => api("rmm/patches/scan", { body: { targets } }), "Patch scan queued"); }}>Scan now</button>}
        {can("configure") && <button className="primary" disabled={busy} onClick={async () => { await run(() => api("rmm/patches/install", { body: { targets } }), "Approved patches queued"); reload(); }}>Install approved</button>}
      </div>
      <Table rows={data.patches} empty="No patches reported yet. Run a scan."
             columns={[{ key: "title", label: "Patch", render: (p) => <><b>{displayValue(p.title)}</b><div className="small muted mono">{displayValue(p.patchKey)}</div></> },
                       { key: "classification", label: "Class", render: (p) => <Pill value={p.classification} tone={["critical", "security"].includes(p.classification) ? "bad" : "muted"} /> },
                       { key: "approval", label: "Approval", render: (p) => <Pill value={p.approval} tone={p.approval === "approved" ? "good" : p.approval === "pending" ? "warn" : "muted"} /> },
                       { key: "status", label: "Status", render: (p) => <><Pill value={p.status} tone={p.status === "installed" ? "good" : p.status === "failed" ? "bad" : p.status === "installing" ? "blue" : "warn"} />{p.error && <div className="small" style={{ color: "#fecaca" }}>{displayValue(p.error)}</div>}</> },
                       { key: "firstSeenAt", label: "First seen", render: (p) => ago(p.firstSeenAt) }]} />
    </div>
  );
}

function JobsTab({ deviceId, onOpen, onRun }: { deviceId: string; onOpen: (id: string) => void; onRun?: () => void }) {
  const { data } = useListData<any>("rmm/jobs", { deviceId });
  return (
    <div className="card">
      <div className="row" style={{ marginBottom: 10 }}>
        <span className="small muted" style={{ flex: 1 }}>Scripts and jobs that included this device. Click one for its output.</span>
        {onRun && <button onClick={onRun}>Run script…</button>}
      </div>
      <Table rows={data} onRow={(j) => onOpen(j.id)} empty="No scripts or jobs have run on this device."
             columns={[{ key: "name", label: "Job" }, { key: "status", label: "Status", render: (j) => <JobStatus job={j} /> },
                       { key: "createdBy", label: "By" }, { key: "createdAt", label: "When", render: (j) => ago(j.createdAt) }]} />
    </div>
  );
}

function SessionsTab({ deviceId }: { deviceId: string }) {
  const { data } = useListData<any>("remote/sessions", { deviceId });
  return (
    <div className="card">
      <Table rows={data} empty="Nobody has connected to this device yet."
             columns={[{ key: "technician", label: "Technician" }, { key: "mode", label: "Mode" },
                       { key: "status", label: "Status", render: (s) => <Pill value={s.status} tone={s.status === "connected" ? "good" : s.status === "denied" || s.status === "failed" ? "bad" : "muted"} /> },
                       { key: "createdAt", label: "Started", render: (s) => fmtTime(s.createdAt) },
                       { key: "connectedMinutes", label: "Duration", render: (s) => s.connectedMinutes ? `${s.connectedMinutes} min` : "—" },
                       { key: "events", label: "Activity", render: (s) => <span className="small muted">{displayValue((s.events || []).filter((e: any) => !["requested", "viewer.connected", "agent.connected"].includes(e.type)).map((e: any) => e.type).join(", ") || "—")}</span> }]} />
    </div>
  );
}

function ScriptPicker({ device, onClose, onStarted }: { device: any; onClose: () => void; onStarted: (jobId: string) => void }) {
  const { data } = useListData<any>("rmm/scripts");
  const [script, setScript] = useState<any>(null);
  const [q, setQ] = useState("");
  if (script) return <RunScript script={script} presetDeviceId={device.id} onClose={onClose} onStarted={onStarted} />;
  const usable = (data || []).filter((s) => s.platforms.includes(device.platform) && (!q || s.name.toLowerCase().includes(q.toLowerCase())));
  return (
    <Modal title={`Run a script on ${device.hostname}`} onClose={onClose}>
      <input placeholder="Search scripts" value={q} onChange={(e) => setQ(e.target.value)} style={{ width: "100%", marginBottom: 8 }} autoFocus />
      <Table rows={usable} onRow={setScript} empty="No scripts for this platform."
             columns={[{ key: "name", label: "Script", render: (s) => <><b>{displayValue(s.name)}</b><div className="small muted">{displayValue(s.description)}</div></> }, { key: "category", label: "Category" }]} />
    </Modal>
  );
}


// LAPS-style local admin passwords: history, reveal (asks to re-enter your password, audited) and rotate now.
function LocalAdmin({ deviceId }: { deviceId: string }) {
  const { can } = useApp();
  const { data, error, reload } = useData<any>(`devices/${deviceId}/local-admin`);
  const { run, busy } = useAction();
  const [shown, setShown] = useState<{ account: string; password: string } | null>(null);
  useEffect(() => { if (!shown) return; const timer = setTimeout(() => setShown(null), 30000); return () => clearTimeout(timer); }, [shown]);
  const reveal = async (row: any) => {
    const result = await run(() => api<{ account: string; password: string }>(`devices/${deviceId}/local-admin/${row.id}/reveal`, { method: "POST" }));
    if (result) setShown(result);
  };
  return (
    <div className="card">
      <ErrorNote error={error} />
      <p className="muted small">
        {data?.enabled ? `The agent rotates this password every ${data.rotationDays} days and stores it here before changing it.`
          : "Rotation is off for this device. Turn on Privilege management → Rotate the local admin password in its policy, or rotate once now."}
        {" "}It never runs on domain controllers.
      </p>
      {can("respond") && <button disabled={busy} onClick={async () => { if (await run(() => api(`devices/${deviceId}/local-admin/rotate`, { method: "POST" }), "Rotation requested; it runs when the device next checks in")) reload(); }}>Rotate now</button>}
      {can("configure") && <>{" "}
        <button disabled={busy} title="Creates or enables the FenrirBreakGlass local administrator for 4 hours; its password appears in this list"
          onClick={async () => { if (await run(() => api(`devices/${deviceId}/commands`, { body: { type: "breakglass.enable", reason: "break-glass from the Local admin tab", payload: { hours: 4 } } }), "Break-glass requested; the password appears here once the device has set it")) reload(); }}>Break-glass admin (4 h)</button>{" "}
        <button disabled={busy} onClick={async () => { if (await run(() => api(`devices/${deviceId}/commands`, { body: { type: "breakglass.disable", reason: "break-glass ended from the Local admin tab", payload: {} } }), "Break-glass account will be disabled")) reload(); }}>End break-glass</button>
      </>}
      {shown && <div className="card" style={{ marginTop: 12 }}>
        <div className="small muted">{shown.account}</div>
        <pre className="mono" style={{ fontSize: 16, userSelect: "all" }}>{shown.password}</pre>
        <button onClick={() => navigator.clipboard?.writeText(shown.password)}>Copy</button>{" "}<button onClick={() => setShown(null)}>Hide now</button>
        <span className="muted small"> Hidden automatically after 30 seconds.</span>
      </div>}
      <Table rows={data?.items ?? []} empty="No password has been set by Fenrir on this device yet."
             columns={[{ key: "account", label: "Account" }, { key: "status", label: "Status", render: (r) => <Pill value={r.status} /> },
                       { key: "createdAt", label: "Set", render: (r) => fmtTime(r.confirmedAt || r.createdAt) },
                       { key: "error", label: "Note", render: (r) => r.error || "" },
                       { key: "reveal", label: "", render: (r) => r.status !== "failed" && can("respond") && <button className="small" disabled={busy} onClick={() => reveal(r)}>Reveal</button> }]} />
    </div>
  );
}

function Bundles({ deviceId }: { deviceId: string }) {
  const { can } = useApp();
  const navigate = useNavigate();
  const { data, error, reload } = useListData<any>(`devices/${deviceId}/artifacts`);
  const { run, busy } = useAction();
  const collect = async (type: string) => {
    if (await run(() => api(`devices/${deviceId}/commands`, { body: { type, reason: "Collected from the device page" } }),
                  "Requested; the bundle appears here after the device next checks in")) reload();
  };
  const download = async (row: any) => {
    await run(async () => {
      const response = await fetch(`/api/console/artifacts/${row.id}/download`, { headers: { Authorization: `Bearer ${getToken() ?? ""}` }, cache: "no-store" });
      if (!response.ok) throw new Error(response.status === 403 ? "Only incident responders can download bundles" : `Download failed (HTTP ${response.status})`);
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement("a");
      link.href = url;
      link.download = row.filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 30000);
    });
  };
  return (
    <div className="card">
      <ErrorNote error={error} />
      <div className="row" style={{ gap: 6, marginBottom: 10 }}>
        <span className="small muted" style={{ flex: 1 }}>Forensic and support bundles the agent uploaded, and recorded remote sessions. They hold process lists, logs and file copies, so downloads are limited to responders and audited. Bundles are deleted after 30 days.</span>
        {can("respond") && <><button disabled={busy} onClick={() => collect("forensics.collect")}>Collect forensic bundle</button>
          <button disabled={busy} onClick={() => collect("support.bundle")}>Collect support bundle</button></>}
      </div>
      <Table rows={data} empty="No bundles yet."
             columns={[{ key: "filename", label: "Bundle", render: (r) => <><b>{displayValue(r.filename)}</b><div className="small muted mono" title={r.sha256}>SHA-256 {String(r.sha256).slice(0, 16)}…</div></> },
                       { key: "kind", label: "Type", render: (r) => ({ "remote.recording": "Remote session recording", "forensics.collect": "Forensic bundle",
                           "support.bundle": "Support bundle", "support.bundle.sanitized": "Support bundle (sanitised)" } as Record<string, string>)[r.kind] ?? r.kind },
                       { key: "size", label: "Size", className: "right", render: (r) => r.size >= 1048576 ? `${(r.size / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(r.size / 1024))} KB` },
                       { key: "createdAt", label: "Uploaded", render: (r) => ago(r.createdAt) },
                       { key: "dl", label: "", className: "right", render: (r) => can("respond") ? <span style={{ display: "inline-flex", gap: 6 }}>
                           {r.kind === "remote.recording" && <button className="small" onClick={() => navigate(`/recordings/${r.id}`)}>Play</button>}
                           <button className="small" disabled={busy} onClick={() => download(r)}>Download</button></span> : null }]} />
    </div>
  );
}
