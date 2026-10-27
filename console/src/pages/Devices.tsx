import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ago, api } from "../api";
import { useApp } from "../app-context";
import { ErrorNote, Meter, Modal, PageHead, Pill, Table, useAction, useData } from "../components/ui";
import { ConnectButtons, pct } from "../components/rmm";

export default function Devices() {
  const { tenantId, tenantName, can } = useApp();
  const navigate = useNavigate();
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("");
  const [platform, setPlatform] = useState("");
  const [role, setRole] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulk, setBulk] = useState(false);
  const { data, error, reload } = useData<any[]>("devices", { tenant_id: tenantId, q, status, platform, role });

  useEffect(() => {
    setSelected(new Set());
    setBulk(false);
  }, [tenantId, q, status, platform, role]);

  const toggle = (id: string) => {
    const next = new Set(selected);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setSelected(next);
  };

  return (
    <>
      <PageHead title="Devices" subtitle="Every enrolled endpoint across Windows, Linux and macOS."
                actions={<>
                  {selected.size > 0 && can("respond") && <button onClick={() => setBulk(true)}>Run action on {selected.size}</button>}
                  <button className="primary" onClick={() => navigate("/deploy")}>Deploy agents</button>
                </>} />
      <div className="row" style={{ marginBottom: 12 }}>
        <input placeholder="Search hostname, OS, IP" value={q} onChange={(e) => setQ(e.target.value)} style={{ minWidth: 260 }} />
        <select value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status">
          <option value="">Active devices</option><option value="retired">Decommissioned</option><option value="online">Online</option><option value="offline">Offline</option>
          <option value="isolated">Isolated</option><option value="pending">Awaiting approval</option><option value="at-risk">At risk</option>
        </select>
        <select value={platform} onChange={(e) => setPlatform(e.target.value)} aria-label="Platform">
          <option value="">All platforms</option><option value="windows">Windows</option><option value="linux">Linux</option><option value="macos">macOS</option><option value="android">Android</option>
        </select>
        <select value={role} onChange={(e) => setRole(e.target.value)} aria-label="Role">
          <option value="">All roles</option><option value="workstation">Workstations</option><option value="server">Servers</option><option value="domain-controller">Domain controllers</option>
        </select>
      </div>
      <ErrorNote error={error} />
      <div className="card">
        <Table rows={data} onRow={(r) => navigate(`/devices/${r.id}`)} empty="No devices match. Deploy the agent to get started."
               columns={[
                 { key: "sel", label: "", render: (r) => <input type="checkbox" disabled={r.retired} checked={selected.has(r.id)} onClick={(e) => e.stopPropagation()} onChange={() => toggle(r.id)} aria-label={`Select ${r.hostname}`} /> },
                 { key: "hostname", label: "Device", render: (r) => <><span className={`dot ${r.online ? "on" : "off"}`} /> <b>{r.hostname}</b>{(r.role === "server" || r.role === "domain-controller") && <> <RoleBadge role={r.role} /></>}<div className="small muted">{r.osVersion}{shownWorkloads(r).length ? ` · ${shownWorkloads(r).join(", ")}` : ""}</div></> },
                 { key: "tenantId", label: "Tenant", render: (r) => tenantName(r.tenantId) },
                 { key: "platform", label: "Platform" },
                 { key: "agentVersion", label: "Agent", render: (r) => r.agentVersion || "—" },
                 { key: "state", label: "State", render: (r) => <div className="row">
                     {r.retired && <Pill value="decommissioned" />}
                     {!r.retired && !r.approved && <Pill value="pending approval" tone="warn" />}
                     {r.isolated && <Pill value="isolated" tone="bad" />}
                     <Pill value={r.healthState || "unknown"} tone={r.healthState === "healthy" ? "good" : "muted"} />
                   </div> },
                 { key: "health", label: "CPU · Mem · Disk free", render: (r) => r.metrics?.reportedAt ? <span className="small mono">{pct(r.metrics.cpuPercent)} · {pct(r.metrics.memoryPercent)} · <span style={{ color: r.metrics.diskFreePercent < 10 ? "#fecaca" : undefined }}>{pct(r.metrics.diskFreePercent)}</span></span> : <span className="muted small">—</span> },
                 { key: "user", label: "User", render: (r) => <span className="small">{r.metrics?.loggedOnUser || "—"}{r.metrics?.rebootPending && <> <Pill value="restart" tone="warn" /></>}</span> },
                 { key: "riskScore", label: "Risk", render: (r) => <div style={{ minWidth: 90 }}><Meter value={r.riskScore} /><span className="small muted">{r.riskScore}</span></div> },
                 { key: "lastSeenAt", label: "Last seen", render: (r) => ago(r.lastSeenAt) },
                 { key: "connect", label: "", render: (r) => r.online && <ConnectButtons device={r} compact /> },
               ]} />
      </div>
      {bulk && <BulkAction ids={[...selected]} onClose={() => { setBulk(false); setSelected(new Set()); reload(); }} />}
    </>
  );
}

function BulkAction({ ids, onClose }: { ids: string[]; onClose: () => void }) {
  const { can } = useApp();
  const { data: catalog, error: catalogError } = useData<any[]>("commands/catalog");
  const [type, setType] = useState("scan.quick");
  const [targetPath, setTargetPath] = useState("");
  const [reason, setReason] = useState("");
  const [recordId, setRecordId] = useState("");
  const [outcome, setOutcome] = useState<{ queued: string[]; skipped: { deviceId: string; reason: string }[] } | null>(null);
  const { run, busy } = useAction();
  const available = catalog?.filter((c) => can(c.permission)) ?? [];
  const spec = available.find((c) => c.type === type);
  const valid = !!spec && (!spec.needs.includes("targetPath") || !!targetPath.trim()) &&
    (!spec.needs.includes("recordId") || !!recordId.trim());
  const submit = async () => {
    if (!valid || busy || outcome) return;
    const result = await run(() => api<{ queued: string[]; skipped: { deviceId: string; reason: string }[] }>("commands/bulk", { body: { type, deviceIds: ids, targetPath: targetPath.trim(), recordId: recordId.trim(), reason } }));
    if (result) setOutcome(result);
  };
  return (
    <Modal title={`Run action on ${ids.length} devices`} onClose={onClose}
           footer={<><button onClick={onClose}>{outcome ? "Done" : "Cancel"}</button>{!outcome && <button className={spec?.destructive ? "danger" : "primary"} disabled={busy || !valid} onClick={submit}>Queue</button>}</>}>
      <ErrorNote error={catalogError} />
      {outcome ? <div role="status">
        <p>{outcome.queued.length} queued; {outcome.skipped.length} skipped.</p>
        {outcome.queued.length > 0 && <p className="muted">Queued actions are awaiting endpoint execution. Check command history for completion.</p>}
        {outcome.skipped.length > 0 && <ul>{outcome.skipped.map((item, index) => <li key={`${item.deviceId}-${index}`}><code>{item.deviceId}</code>: {item.reason}</li>)}</ul>}
      </div> : <>
      <div className="form-grid">
        <label className="field">Action
          <select value={type} onChange={(e) => setType(e.target.value)}>
            {available.map((c) => <option key={c.type} value={c.type}>{c.group}: {c.label}</option>)}
          </select>
        </label>
        {spec?.needs.includes("targetPath") && <label className="field">Target path<input value={targetPath} onChange={(e) => setTargetPath(e.target.value)} /></label>}
        {spec?.needs.includes("recordId") && <label className="field">Record ID<input value={recordId} onChange={(e) => setRecordId(e.target.value)} /></label>}
        <label className="field">Reason<input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Shown in the audit log" /></label>
      </div>
      {spec?.description && <p className="muted">{spec.description}</p>}
      </>}
    </Modal>
  );
}

const shownWorkloads = (r: any): string[] => (r.workloads || []).filter((w: string) => !["File sharing", "Print spooler", "Remote Desktop"].includes(w)).slice(0, 3);

export function RoleBadge({ role }: { role?: string }) {
  if (role === "domain-controller") return <span title="Active Directory domain controller"><Pill value="Domain controller" tone="blue" /></span>;
  if (role === "server") return <Pill value="Server" tone="muted" />;
  return null;
}
