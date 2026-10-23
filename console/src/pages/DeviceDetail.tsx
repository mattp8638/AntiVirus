import { Fragment, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ago, api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { ErrorNote, Modal, PageHead, Pill, Sev, Table, Tabs, useAction, useData } from "../components/ui";
import { ConnectButtons, JobDetail, JobStatus, pct, Sparkline } from "../components/rmm";
import { RunScript } from "./rmm/Scripts";

export default function DeviceDetail() {
  const { id } = useParams();
  const { tenantName, can } = useApp();
  const { data, error, reload } = useData<any>(`devices/${id}`);
  const { data: policies } = useData<any[]>("policies", { tenant_id: data?.device.tenantId }, [data?.device.tenantId]);
  const { data: groups } = useData<any[]>("groups", { tenant_id: data?.device.tenantId }, [data?.device.tenantId]);
  const [tab, setTab] = useState("Overview");
  const [action, setAction] = useState<string | null>(null);
  const [scriptPicker, setScriptPicker] = useState(false);
  const [jobId, setJobId] = useState<string | null>(null);
  const { run } = useAction();

  if (error) return <ErrorNote error={error} />;
  if (!data) return <div className="empty">Loading…</div>;
  const d = data.device;

  const patch = async (body: any, message: string) => {
    await run(() => api(`devices/${d.id}`, { method: "PATCH", body }), message);
    reload();
  };

  return (
    <>
      <PageHead title={d.hostname}
                subtitle={<>{d.osVersion} · {tenantName(d.tenantId)} · <span className={`dot ${d.online ? "on" : "off"}`} /> {d.online ? "online" : `last seen ${ago(d.lastSeenAt)}`}</>}
                actions={can("respond") && <>
                  {!d.approved && can("configure") && <button className="primary" onClick={() => patch({ approved: true }, "Device approved")}>Approve</button>}
                  <ConnectButtons device={d} />
                  {can("configure") && <button onClick={() => setScriptPicker(true)}>Run script</button>}
                  <button onClick={() => setAction("scan.quick")}>Scan</button>
                  {d.isolated ? <button onClick={() => setAction("device.release")}>Release isolation</button>
                              : <button className="danger" onClick={() => setAction("device.isolate")}>Isolate</button>}
                  <button onClick={() => setAction("")}>More actions…</button>
                </>} />
      <Tabs tabs={["Overview", "Health", "Patches", "Scripts & jobs", "Remote sessions", "Effective policy", "Alerts", "Actions", "Software", "Vulnerabilities"]} active={tab} onChange={setTab} />
      {tab === "Health" && <HealthTab deviceId={d.id} />}
      {tab === "Patches" && <PatchesTab device={d} />}
      {tab === "Scripts & jobs" && <JobsTab deviceId={d.id} onOpen={setJobId} />}
      {tab === "Remote sessions" && <SessionsTab deviceId={d.id} />}

      {tab === "Overview" && (
        <div className="grid k2">
          <div className="card">
            <h3>Device</h3>
            <dl className="kv">
              <dt>Device ID</dt><dd className="mono">{d.id}</dd>
              <dt>Platform</dt><dd>{d.platform}</dd>
              <dt>Agent</dt><dd>{d.agentVersion || "—"} (platform {d.platformVersion || "—"})</dd>
              <dt>Health</dt><dd><Pill value={d.healthState} tone={d.healthState === "healthy" ? "good" : "warn"} /></dd>
              <dt>Isolated</dt><dd>{d.isolated ? <Pill value="isolated" tone="bad" /> : "No"}</dd>
              <dt>Risk score</dt><dd>{d.riskScore}</dd>
              <dt>IP address</dt><dd>{d.ipAddress || "—"}</dd>
              <dt>Serial</dt><dd>{d.serialNumber || "—"}</dd>
              <dt>Enrolled</dt><dd>{fmtTime(d.enrolledAt)}</dd>
              <dt>Events stored</dt><dd>{data.eventCount}</dd>
              <dt>Encrypted DNS</dt><dd className="mono small">{data.dnsOverHttpsUrl}</dd>
            </dl>
          </div>
          <div className="card">
            <h3>Management</h3>
            <div className="form-grid">
              <label className="field">Group
                <select value={d.groupId ?? ""} disabled={!can("configure")} onChange={(e) => patch({ groupId: e.target.value || null }, "Group updated")}>
                  <option value="">No group</option>
                  {groups?.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
                </select>
              </label>
              <label className="field">Device policy override
                <select value={d.policyId ?? ""} disabled={!can("configure")} onChange={(e) => patch({ policyId: e.target.value || null }, "Policy override updated")}>
                  <option value="">Inherit from group/tenant</option>
                  {policies?.filter((p) => p.tenantId).map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
                </select>
              </label>
              <label className="field">Business criticality
                <select value={d.criticality ?? "medium"} disabled={!can("configure")} onChange={(e) => patch({ criticality: e.target.value }, "Criticality updated")}>
                  {["low", "medium", "high", "critical"].map((c) => <option key={c}>{c}</option>)}
                </select>
              </label>
            </div>
            <p className="small muted" style={{ marginTop: 12 }}>
              Policy revision {data.policy.revision} · {data.policy.applied ? <Pill value="applied" tone="good" /> : <Pill value="waiting for agent" tone="warn" />}
            </p>
            {data.policy.overridesBlocked.length > 0 && (
              <p className="small">{data.policy.overridesBlocked.length} override(s) blocked by locks — see Effective policy.</p>
            )}
            {Object.keys(d.inventory || {}).length > 0 && (
              <><h3 style={{ marginTop: 16 }}>Inventory</h3><pre>{JSON.stringify(d.inventory, null, 2)}</pre></>
            )}
          </div>
        </div>
      )}

      {tab === "Effective policy" && <EffectivePolicy policy={data.policy} />}

      {tab === "Alerts" && (
        <div className="card">
          <Table rows={data.alerts} empty="No alerts for this device."
                 columns={[{ key: "severity", label: "Sev", render: (r) => <Sev level={r.severity} /> }, { key: "title", label: "Alert" },
                           { key: "status", label: "Status", render: (r) => <Pill value={r.status} /> },
                           { key: "mitre", label: "MITRE", render: (r) => r.mitre.filter((m: string) => m.startsWith("T")).join(", ") },
                           { key: "incidentId", label: "Incident", render: (r) => r.incidentId ? <Link to={`/incidents/${r.incidentId}`}>open</Link> : "—" },
                           { key: "createdAt", label: "When", render: (r) => ago(r.createdAt) }]} />
        </div>
      )}

      {tab === "Actions" && (
        <div className="card">
          <Table rows={data.commands} empty="No remote actions yet."
                 columns={[{ key: "type", label: "Action" }, { key: "status", label: "Status", render: (r) => <Pill value={r.status} /> },
                           { key: "issuedBy", label: "By" }, { key: "targetPath", label: "Target", render: (r) => <span className="mono small">{r.targetPath || r.recordId || "—"}</span> },
                           { key: "reason", label: "Reason" }, { key: "createdAt", label: "Queued", render: (r) => ago(r.createdAt) },
                           { key: "result", label: "Result", render: (r) => Object.keys(r.result || {}).length ? <span className="mono small">{JSON.stringify(r.result).slice(0, 80)}</span> : "—" }]} />
        </div>
      )}

      {tab === "Software" && (
        <div className="card">
          <Table rows={data.software} empty="No inventory yet. The agent reports software on its inventory cycle."
                 columns={[{ key: "name", label: "Name" }, { key: "version", label: "Version" }, { key: "vendor", label: "Vendor" }, { key: "ecosystem", label: "Source" }]} />
        </div>
      )}

      {tab === "Vulnerabilities" && (
        <div className="card">
          <div className="row" style={{ marginBottom: 10 }}>
            <button onClick={() => run(() => api("vulnerabilities/scan", { body: { deviceId: d.id } }), "Vulnerability scan queued")}>Scan now</button>
          </div>
          <Table rows={data.vulnerabilities} empty="No open vulnerabilities."
                 columns={[{ key: "vulnId", label: "ID", render: (r) => <a href={`https://osv.dev/vulnerability/${r.vulnId}`} target="_blank" rel="noreferrer">{r.vulnId}</a> },
                           { key: "severity", label: "Sev", render: (r) => <><Sev level={r.severity} /> {r.knownExploited && <Pill value="exploited" tone="bad" />}</> },
                           { key: "package", label: "Package" }, { key: "installedVersion", label: "Installed" }, { key: "fixedVersion", label: "Fixed in" },
                           { key: "status", label: "Status", render: (r) => <Pill value={r.status} /> }]} />
        </div>
      )}

      {action !== null && <CommandModal device={d} initial={action} onClose={() => { setAction(null); reload(); }} />}
      {scriptPicker && <ScriptPicker device={d} onClose={() => setScriptPicker(false)} onStarted={(id) => { setScriptPicker(false); setJobId(id); setTab("Scripts & jobs"); }} />}
      {jobId && <JobDetail jobId={jobId} onClose={() => setJobId(null)} />}
    </>
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
            <h3>{section.title}</h3>
            <Table rows={fields.map((f: any) => ({ ...f, id: f.path }))}
                   columns={[{ key: "label", label: "Setting" },
                             { key: "value", label: "Value", render: (f) => <span className="mono small">{JSON.stringify(policy.settings[section.key][f.key])}</span> },
                             { key: "origin", label: "Set by", render: (f) => <span className="small">{policy.origin[f.path]}</span> },
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
  const { data: catalog } = useData<any[]>("commands/catalog");
  const [type, setType] = useState(initial || "scan.quick");
  const [targetPath, setTargetPath] = useState("");
  const [recordId, setRecordId] = useState("");
  const [pid, setPid] = useState("");
  const [reason, setReason] = useState("");
  const { run, busy } = useAction();
  const isKill = type === "process.terminate" || type === "process.tree.terminate";
  const available = catalog?.filter((c) => c.platforms.includes(device.platform)) ?? [];
  const spec = available.find((c) => c.type === type);
  const submit = async () => {
    const ok = await run(() => api(`devices/${device.id}/commands`, { body: { type, targetPath, recordId, reason, incidentId, payload: isKill && pid ? { pid: Number(pid) } : {} } }), `${spec?.label ?? type} queued`);
    if (ok) onClose();
  };
  return (
    <Modal title={`Remote action · ${device.hostname}`} onClose={onClose}
           footer={<><button onClick={onClose}>Cancel</button><button className={spec?.destructive ? "danger" : "primary"} disabled={busy || !spec} onClick={submit}>Queue action</button></>}>
      <div className="form-grid">
        <label className="field">Action
          <select value={type} onChange={(e) => setType(e.target.value)}>
            {available.map((c) => <option key={c.type} value={c.type}>{c.group}: {c.label}</option>)}
          </select>
        </label>
        {spec?.needs.includes("targetPath") && <label className="field">Target path<input value={targetPath} onChange={(e) => setTargetPath(e.target.value)} placeholder="C:\\path\\file.exe" /></label>}
        {isKill && <label className="field">Process ID<input value={pid} onChange={(e) => setPid(e.target.value.replace(/\D/g, ""))} placeholder="from the alert" /></label>}
        {spec?.needs.includes("recordId") && <label className="field">Record ID<input value={recordId} onChange={(e) => setRecordId(e.target.value)} /></label>}
        <label className="field">Reason<input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Recorded in the audit log" /></label>
      </div>
      {spec?.description && <p className="muted">{spec.description}</p>}
      {isKill && !pid && <p style={{ color: "#fde68a" }}>No process ID: every running copy of this program on the device will be killed.</p>}
      {spec?.destructive && <p style={{ color: "#fecaca" }}>This action changes the device and cannot be undone automatically.</p>}
    </Modal>
  );
}


function HealthTab({ deviceId }: { deviceId: string }) {
  const { data } = useData<any>(`rmm/devices/${deviceId}/metrics`, { hours: 24 });
  if (!data) return <div className="empty">Loading…</div>;
  const c = data.current || {};
  const series = data.series || [];
  return (
    <div className="grid k2">
      <div className="card">
        <h3>Now</h3>
        {!c.reportedAt ? <p className="muted">This agent has not reported health metrics yet (needs agent 1.1 or later).</p> : (
          <dl className="kv">
            <dt>CPU</dt><dd>{pct(c.cpuPercent)}</dd>
            <dt>Memory</dt><dd>{pct(c.memoryPercent)} of {c.memoryTotalGb ? `${Math.round(c.memoryTotalGb)} GB` : "?"}</dd>
            {(c.disks || []).map((disk: any) => <Fragment key={disk.mount}><dt>Disk {disk.mount}</dt><dd>{disk.freeGb.toFixed(1)} GB free of {disk.totalGb.toFixed(0)} GB ({pct(disk.freePercent)})</dd></Fragment>)}
            <dt>Signed in</dt><dd>{c.loggedOnUser || "nobody"}</dd>
            <dt>Up since</dt><dd>{fmtTime(c.lastBootAt)} ({c.uptimeSeconds ? `${(c.uptimeSeconds / 86400).toFixed(1)} days` : "?"})</dd>
            <dt>Restart pending</dt><dd>{c.rebootPending ? <Pill value="yes" tone="warn" /> : "No"}</dd>
            <dt>Stopped services</dt><dd className="small">{(c.stoppedServices || []).join(", ") || "None"}</dd>
            <dt>Hardware</dt><dd>{[c.manufacturer, c.model].filter(Boolean).join(" ") || "—"}</dd>
            <dt>Reported</dt><dd>{ago(c.reportedAt)}</dd>
          </dl>
        )}
      </div>
      <div className="card">
        <h3>Last 24 hours</h3>
        <div className="small muted">CPU %</div><Sparkline points={series.map((p: any) => p.cpu)} color="#38bdf8" />
        <div className="small muted" style={{ marginTop: 8 }}>Memory %</div><Sparkline points={series.map((p: any) => p.memory)} color="#a855f7" />
        <div className="small muted" style={{ marginTop: 8 }}>Lowest disk free %</div><Sparkline points={series.map((p: any) => p.diskFree)} color="#22c55e" />
        <h3 style={{ marginTop: 14 }}>Monitors</h3>
        {(data.monitors || []).length === 0 ? <p className="muted small">No monitor has evaluated this device yet.</p> :
          data.monitors.map((m: any, i: number) => <div key={i} className="row small"><Pill value={m.triggered ? "triggered" : "ok"} tone={m.triggered ? "bad" : "good"} /> {m.condition} <span className="muted">{m.message}</span></div>)}
      </div>
    </div>
  );
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
        <span className="small muted">Policy: {data.policy?.name || "defaults"} · ring {data.ring.name} (+{data.ring.delayDays} days) · last scan {ago(data.lastScan)}</span>
        {data.rebootPending && <Pill value="restart pending" tone="warn" />}
        <span style={{ flex: 1 }} />
        {can("respond") && <button disabled={busy} onClick={async () => { await run(() => api("rmm/patches/scan", { body: { targets } }), "Patch scan queued"); }}>Scan now</button>}
        {can("configure") && <button className="primary" disabled={busy} onClick={async () => { await run(() => api("rmm/patches/install", { body: { targets } }), "Approved patches queued"); reload(); }}>Install approved</button>}
      </div>
      <Table rows={data.patches} empty="No patches reported yet. Run a scan."
             columns={[{ key: "title", label: "Patch", render: (p) => <><b>{p.title}</b><div className="small muted mono">{p.patchKey}</div></> },
                       { key: "classification", label: "Class", render: (p) => <Pill value={p.classification} tone={["critical", "security"].includes(p.classification) ? "bad" : "muted"} /> },
                       { key: "approval", label: "Approval", render: (p) => <Pill value={p.approval} tone={p.approval === "approved" ? "good" : p.approval === "pending" ? "warn" : "muted"} /> },
                       { key: "status", label: "Status", render: (p) => <><Pill value={p.status} tone={p.status === "installed" ? "good" : p.status === "failed" ? "bad" : p.status === "installing" ? "blue" : "warn"} />{p.error && <div className="small" style={{ color: "#fecaca" }}>{p.error}</div>}</> },
                       { key: "firstSeenAt", label: "First seen", render: (p) => ago(p.firstSeenAt) }]} />
    </div>
  );
}

function JobsTab({ deviceId, onOpen }: { deviceId: string; onOpen: (id: string) => void }) {
  const { data } = useData<any[]>("rmm/jobs", { deviceId });
  return (
    <div className="card">
      <Table rows={data} onRow={(j) => onOpen(j.id)} empty="No scripts or jobs have run on this device."
             columns={[{ key: "name", label: "Job" }, { key: "status", label: "Status", render: (j) => <JobStatus job={j} /> },
                       { key: "createdBy", label: "By" }, { key: "createdAt", label: "When", render: (j) => ago(j.createdAt) }]} />
    </div>
  );
}

function SessionsTab({ deviceId }: { deviceId: string }) {
  const { data } = useData<any[]>("remote/sessions", { deviceId });
  return (
    <div className="card">
      <Table rows={data} empty="Nobody has connected to this device yet."
             columns={[{ key: "technician", label: "Technician" }, { key: "mode", label: "Mode" },
                       { key: "status", label: "Status", render: (s) => <Pill value={s.status} tone={s.status === "connected" ? "good" : s.status === "denied" || s.status === "failed" ? "bad" : "muted"} /> },
                       { key: "createdAt", label: "Started", render: (s) => fmtTime(s.createdAt) },
                       { key: "connectedMinutes", label: "Duration", render: (s) => s.connectedMinutes ? `${s.connectedMinutes} min` : "—" },
                       { key: "events", label: "Activity", render: (s) => <span className="small muted">{(s.events || []).filter((e: any) => !["requested", "viewer.connected", "agent.connected"].includes(e.type)).map((e: any) => e.type).join(", ") || "—"}</span> }]} />
    </div>
  );
}

function ScriptPicker({ device, onClose, onStarted }: { device: any; onClose: () => void; onStarted: (jobId: string) => void }) {
  const { data } = useData<any[]>("rmm/scripts");
  const [script, setScript] = useState<any>(null);
  const [q, setQ] = useState("");
  if (script) return <RunScript script={script} presetDeviceId={device.id} onClose={onClose} onStarted={onStarted} />;
  const usable = (data || []).filter((s) => s.platforms.includes(device.platform) && (!q || s.name.toLowerCase().includes(q.toLowerCase())));
  return (
    <Modal title={`Run a script on ${device.hostname}`} onClose={onClose}>
      <input placeholder="Search scripts" value={q} onChange={(e) => setQ(e.target.value)} style={{ width: "100%", marginBottom: 8 }} autoFocus />
      <Table rows={usable} onRow={setScript} empty="No scripts for this platform."
             columns={[{ key: "name", label: "Script", render: (s) => <><b>{s.name}</b><div className="small muted">{s.description}</div></> }, { key: "category", label: "Category" }]} />
    </Modal>
  );
}
