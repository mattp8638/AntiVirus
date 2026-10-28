import { displayValue } from "../../components/DisplayValue";
import { useState } from "react";
import { Link } from "react-router-dom";
import { ago, api } from "../../api";
import { useApp } from "../../app-context";
import { emptyTargets, JobDetail, TargetPicker } from "../../components/rmm";
import { Modal, PageHead, Pill, Stat, Table, Tabs, TenantSelect, useAction, useData, useListData } from "../../components/ui";

const APPROVAL_TONE: Record<string, string> = { approved: "good", rejected: "muted", pending: "warn" };
const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

export default function Patching() {
  const { tenantId, can } = useApp();
  const [tab, setTab] = useState("Overview");
  const { data: compliance, reload: reloadCompliance } = useData<any>("rmm/patches/compliance", { tenant_id: tenantId });
  const [classification, setClassification] = useState("");
  const [onlyMissing, setOnlyMissing] = useState(true);
  const { data: catalogue, reload } = useListData<any>("rmm/patches", { tenant_id: tenantId, classification, status: onlyMissing ? "missing" : "" });
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [installing, setInstalling] = useState(false);
  const [jobId, setJobId] = useState<string | null>(null);
  const { run, busy } = useAction();
  const decide = async (decision: string) => {
    await run(() => api("rmm/patches/approve", { body: { patchKeys: [...selected], decision, tenantId: tenantId || undefined } }), `Patches ${decision}`);
    setSelected(new Set());
    reload();
  };
  const scanAll = async () => {
    const targets = { ...emptyTargets(), tenantIds: tenantId ? [tenantId] : [] };
    if (!targets.tenantIds.length) { window.alert("Choose a customer in the top bar first, or scan from a device."); return; }
    const job = await run(() => api<any>("rmm/patches/scan", { body: { targets } }), "Patch scan queued");
    if (job) setJobId(job.id);
  };
  return (
    <>
      <PageHead title="Patch management" subtitle="Windows Update, third-party apps (winget) and Linux packages: approvals, rings and maintenance windows."
                actions={can("configure") && <><button onClick={scanAll} disabled={busy}>Scan now</button><button className="primary" onClick={() => setInstalling(true)}>Install now…</button></>} />
      <div className="grid k4">
        <Stat label="Patch compliance" value={compliance ? `${compliance.compliancePercent}%` : "—"} accent={compliance?.compliancePercent >= 90 ? "green" : "amber"}
              hint={compliance && `${compliance.fullyPatched} of ${compliance.devices} devices verified fully patched`} />
        <Stat label="Missing critical/security" value={compliance?.missingCriticalOrSecurity ?? "—"} accent={compliance?.missingCriticalOrSecurity ? "red" : "green"} hint="devices" />
        <Stat label="Pending restart" value={compliance?.pendingReboot ?? "—"} hint="devices" />
        <Stat label="Failed installs" value={compliance?.failedPatches ?? "—"} accent={compliance?.failedPatches ? "red" : undefined} />
      </div>
      {!!compliance?.incompleteScans && <p role="status" className="muted">{compliance.incompleteScans} device(s) have incomplete patch scans. Failed providers retain their outstanding patches and cannot be counted as fully patched.</p>}
      <div style={{ marginTop: 16 }}><Tabs tabs={["Overview", "Patches", "Policies"]} active={tab} onChange={setTab} /></div>
      {tab === "Overview" && (
        <div className="card">
          <Table rows={compliance?.devices_detail} empty="No devices yet."
                 columns={[{ key: "hostname", label: "Device", render: (d) => <Link to={`/devices/${d.id}`}>{displayValue(d.hostname)}</Link> },
                           { key: "account", label: "Customer" }, { key: "platform", label: "Platform" },
                           { key: "missing", label: "Missing", render: (d) => Object.keys(d.missing).length ? Object.entries(d.missing).map(([k, v]) => <span key={k} className="chip">{k} {String(v)}</span>) : ["partial", "failed"].includes(d.scanStatus) ? <Pill value="scan incomplete" tone="warn" /> : d.lastScan ? <Pill value="up to date" tone="good" /> : <span className="muted small">not scanned</span> },
                           { key: "scanStatus", label: "Scan coverage", render: (d) => <span>{d.scanStatus || (d.lastScan ? "completed" : "not scanned")}{Object.entries(d.providers || {}).map(([name, provider]: [string, any]) => provider.success ? null : <div key={name} className="small muted">{name}: {displayValue(provider.error || "unavailable")}</div>)}</span> },
                           { key: "rebootPending", label: "Restart", render: (d) => d.rebootPending ? <Pill value="pending" tone="warn" /> : "—" },
                           { key: "lastScan", label: "Last scan", render: (d) => ago(d.lastScan) }]} />
          <div className="row" style={{ marginTop: 8 }}><button className="small" onClick={reloadCompliance}>Refresh</button></div>
        </div>
      )}
      {tab === "Patches" && (
        <div className="card">
          <div className="row" style={{ marginBottom: 10 }}>
            <select value={classification} onChange={(e) => setClassification(e.target.value)}>
              <option value="">All classifications</option>{["critical", "security", "updates", "feature", "driver", "definition", "third-party"].map((c) => <option key={c}>{c}</option>)}</select>
            <label className="small"><input type="checkbox" checked={onlyMissing} onChange={(e) => setOnlyMissing(e.target.checked)} /> Only patches still needed</label>
            <span style={{ flex: 1 }} />
            {can("configure") && selected.size > 0 && <>
              <span className="small muted">{selected.size} selected</span>
              <button onClick={() => decide("approved")}>Approve</button><button onClick={() => decide("rejected")}>Reject</button><button onClick={() => decide("reset")}>Use policy rule</button>
            </>}
          </div>
          <Table rows={catalogue?.map((p) => ({ ...p, id: p.patchKey }))} empty="No patches reported. Run a scan."
                 columns={[{ key: "sel", label: "", render: (p) => <input type="checkbox" checked={selected.has(p.patchKey)} onChange={() => { const s = new Set(selected); s.has(p.patchKey) ? s.delete(p.patchKey) : s.add(p.patchKey); setSelected(s); }} /> },
                           { key: "title", label: "Patch", render: (p) => <><b>{displayValue(p.title)}</b><div className="small muted mono">{displayValue(p.patchKey)}{p.availableVersion ? ` → ${p.availableVersion}` : ""}</div></> },
                           { key: "classification", label: "Class", render: (p) => <Pill value={p.classification} tone={["critical", "security"].includes(p.classification) ? "bad" : "muted"} /> },
                           { key: "source", label: "Source", render: (p) => <span className="small">{displayValue(p.source)}</span> },
                           { key: "missing", label: "Needed on", render: (p) => <span>{displayValue(p.missing + p.failed)}{p.failed ? <span className="small" style={{ color: "#fecaca" }}> ({displayValue(p.failed)} failed)</span> : ""}</span> },
                           { key: "installed", label: "Installed on" },
                           { key: "approvalState", label: "Approval", render: (p) => <Pill value={p.approvalState} tone={APPROVAL_TONE[p.approvalState]} /> }]} />
        </div>
      )}
      {tab === "Policies" && <PatchPolicies />}
      {installing && <InstallNow onClose={() => setInstalling(false)} onStarted={(id) => { setInstalling(false); setJobId(id); }} />}
      {jobId && <JobDetail jobId={jobId} onClose={() => { setJobId(null); reloadCompliance(); }} />}
    </>
  );
}

function InstallNow({ onClose, onStarted }: { onClose: () => void; onStarted: (id: string) => void }) {
  const [targets, setTargets] = useState(emptyTargets());
  const [reboot, setReboot] = useState("if_required");
  const { run, busy } = useAction();
  return (
    <Modal title="Install approved patches now" onClose={onClose}
           footer={<><button onClick={onClose}>Cancel</button><button className="primary" disabled={busy} onClick={async () => {
             const job = await run(() => api<any>("rmm/patches/install", { body: { targets, reboot: { mode: reboot } } }), "Install queued");
             if (job) onStarted(job.id);
           }}>Install</button></>}>
      <p className="muted">Installs every approved, missing patch on the chosen devices straight away, outside the maintenance window.</p>
      <label className="field" style={{ marginBottom: 10 }}>Restart<select value={reboot} onChange={(e) => setReboot(e.target.value)}>
        <option value="if_required">If an update needs it</option><option value="never">Never (leave pending)</option><option value="always">Always</option></select></label>
      <TargetPicker value={targets} onChange={setTargets} />
    </Modal>
  );
}

function PatchPolicies() {
  const { can } = useApp();
  const { data, reload } = useData<any>("rmm/patch-policies");
  const [editing, setEditing] = useState<any>(null);
  return (
    <>
      <div className="row" style={{ marginBottom: 12 }}>
        <span className="small muted">A device uses its group's policy, then its customer's. Devices without one use the defaults (critical, security and definitions auto-approved; nightly 02:00 window).</span>
        <span style={{ flex: 1 }} />
        {can("configure") && data && <button className="primary" onClick={() => setEditing({ name: "", approvals: { ...data.defaults.approvals }, window: { ...data.defaults.window, tz: Intl.DateTimeFormat().resolvedOptions().timeZone },
                                                                                  reboot: { ...data.defaults.reboot }, rings: [{ name: "Pilot", groupIds: [], delayDays: 0 }, { name: "Broad", groupIds: [], delayDays: 7 }], scanIntervalHours: 12, enabled: true })}>New policy</button>}
      </div>
      <div className="card">
        <Table rows={data?.policies} onRow={setEditing} empty="No patch policies yet."
               columns={[{ key: "name", label: "Policy", render: (p) => <b>{displayValue(p.name)}</b> }, { key: "account", label: "Customer" },
                         { key: "window", label: "Window", render: (p) => `${(p.window.days || []).map((d: number) => DAYS[d]).join(", ")} ${p.window.start} for ${p.window.durationMinutes / 60}h` },
                         { key: "approvals", label: "Auto-approve", render: (p) => <span className="small">{Object.entries(p.approvals).filter(([, v]) => v === "auto").map(([k]) => k).join(", ")}</span> },
                         { key: "rings", label: "Rings", render: (p) => <span className="small">{displayValue(p.rings.map((r: any) => `${r.name} +${r.delayDays}d`).join(" → "))}</span> },
                         { key: "reboot", label: "Restart", render: (p) => p.reboot.mode.replace("_", " ") },
                         { key: "enabled", label: "", render: (p) => <Pill value={p.enabled ? "on" : "off"} tone={p.enabled ? "good" : "muted"} /> }]} />
      </div>
      {editing && data && <PolicyEditor policy={editing} classifications={data.classifications} onClose={() => { setEditing(null); reload(); }} />}
    </>
  );
}

function PolicyEditor({ policy, classifications, onClose }: { policy: any; classifications: string[]; onClose: () => void }) {
  const [form, setForm] = useState<any>({ ...policy, tenantId: policy.tenantId || "" });
  const { data: groups } = useListData<any>("groups", { tenant_id: form.tenantId });
  const { run, busy } = useAction();
  const save = async () => {
    const body = { name: form.name, groupId: form.groupId || null, enabled: form.enabled, approvals: form.approvals, window: form.window, reboot: form.reboot,
                   rings: form.rings, scanIntervalHours: Number(form.scanIntervalHours), ...(form.id ? {} : { tenantId: form.tenantId }) };
    if (await run(() => (form.id ? api(`rmm/patch-policies/${form.id}`, { method: "PATCH", body }) : api("rmm/patch-policies", { body })), "Patch policy saved")) onClose();
  };
  const win = form.window;
  return (
    <Modal title={form.id ? form.name : "New patch policy"} onClose={onClose}
           footer={<>{form.id && <button className="danger" onClick={async () => { if (await run(() => api(`rmm/patch-policies/${form.id}`, { method: "DELETE" }), "Deleted")) onClose(); }}>Delete</button>}
                   <button className="primary" disabled={busy || !form.name || (!form.id && !form.tenantId)} onClick={save}>Save</button></>}>
      <div className="form-grid">
        <label className="field">Name<input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label>
        {!form.id && <label className="field">Customer<TenantSelect value={form.tenantId} onChange={(id) => setForm({ ...form, tenantId: id })} allowAll={false} /></label>}
        <label className="field">Only for group<select value={form.groupId || ""} onChange={(e) => setForm({ ...form, groupId: e.target.value })}><option value="">Whole customer</option>{groups?.map((g) => <option key={g.id} value={g.id}>{displayValue(g.name)}</option>)}</select></label>
        <label className="field">Scan every (hours)<input type="number" value={form.scanIntervalHours} onChange={(e) => setForm({ ...form, scanIntervalHours: e.target.value })} /></label>
      </div>
      <h3 style={{ marginTop: 14 }}>Approval rules</h3>
      <div className="form-grid">
        {classifications.map((c) => (
          <label key={c} className="field">{c}<select value={form.approvals[c] || "manual"} onChange={(e) => setForm({ ...form, approvals: { ...form.approvals, [c]: e.target.value } })}>
            <option value="auto">Approve automatically</option><option value="manual">Wait for approval</option><option value="reject">Never install</option></select></label>
        ))}
      </div>
      <h3 style={{ marginTop: 14 }}>Maintenance window</h3>
      <div className="row">
        {DAYS.map((d, i) => <label key={d} className="small"><input type="checkbox" checked={(win.days || []).includes(i)}
          onChange={() => setForm({ ...form, window: { ...win, days: (win.days || []).includes(i) ? win.days.filter((x: number) => x !== i) : [...(win.days || []), i] } })} /> {d}</label>)}
      </div>
      <div className="form-grid" style={{ marginTop: 8 }}>
        <label className="field">Starts<input type="time" value={win.start} onChange={(e) => setForm({ ...form, window: { ...win, start: e.target.value } })} /></label>
        <label className="field">Length (minutes)<input type="number" value={win.durationMinutes} onChange={(e) => setForm({ ...form, window: { ...win, durationMinutes: Number(e.target.value) } })} /></label>
        <label className="field">Time zone<input value={win.tz || "UTC"} onChange={(e) => setForm({ ...form, window: { ...win, tz: e.target.value } })} /></label>
        <label className="field">Restart<select value={form.reboot.mode} onChange={(e) => setForm({ ...form, reboot: { ...form.reboot, mode: e.target.value } })}>
          <option value="if_required">If required</option><option value="never">Never</option><option value="always">Always</option></select></label>
        <label className="field">Restart delay (minutes)<input type="number" value={form.reboot.deferMinutes} onChange={(e) => setForm({ ...form, reboot: { ...form.reboot, deferMinutes: Number(e.target.value) } })} /></label>
      </div>
      <h3 style={{ marginTop: 14 }}>Rings</h3>
      <p className="small muted">Auto-approved patches reach each ring this many days after release. Manually approved patches install at the next window.</p>
      {form.rings.map((ring: any, i: number) => (
        <div key={i} className="row" style={{ marginBottom: 6 }}>
          <input value={ring.name} onChange={(e) => setForm({ ...form, rings: form.rings.map((r: any, j: number) => (j === i ? { ...r, name: e.target.value } : r)) })} style={{ width: 140 }} />
          <select value={(ring.groupIds || [])[0] || ""} onChange={(e) => setForm({ ...form, rings: form.rings.map((r: any, j: number) => (j === i ? { ...r, groupIds: e.target.value ? [e.target.value] : [] } : r)) })}>
            <option value="">Everyone else</option>{groups?.map((g) => <option key={g.id} value={g.id}>{displayValue(g.name)}</option>)}</select>
          <span className="small">+</span><input type="number" value={ring.delayDays} style={{ width: 70 }} onChange={(e) => setForm({ ...form, rings: form.rings.map((r: any, j: number) => (j === i ? { ...r, delayDays: Number(e.target.value) } : r)) })} /><span className="small">days</span>
          <button className="small ghost" onClick={() => setForm({ ...form, rings: form.rings.filter((_: any, j: number) => j !== i) })}>✕</button>
        </div>
      ))}
      <button className="small" onClick={() => setForm({ ...form, rings: [...form.rings, { name: "Ring", groupIds: [], delayDays: 3 }] })}>Add ring</button>
    </Modal>
  );
}
