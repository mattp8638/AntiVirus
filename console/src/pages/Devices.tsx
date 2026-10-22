import { useState } from "react";
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
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulk, setBulk] = useState(false);
  const { data, error, reload } = useData<any[]>("devices", { tenant_id: tenantId, q, status, platform });

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
          <option value="">Any status</option><option value="online">Online</option><option value="offline">Offline</option>
          <option value="isolated">Isolated</option><option value="pending">Awaiting approval</option><option value="at-risk">At risk</option>
        </select>
        <select value={platform} onChange={(e) => setPlatform(e.target.value)} aria-label="Platform">
          <option value="">All platforms</option><option value="windows">Windows</option><option value="linux">Linux</option><option value="macos">macOS</option>
        </select>
      </div>
      <ErrorNote error={error} />
      <div className="card">
        <Table rows={data} onRow={(r) => navigate(`/devices/${r.id}`)} empty="No devices match. Deploy the agent to get started."
               columns={[
                 { key: "sel", label: "", render: (r) => <input type="checkbox" checked={selected.has(r.id)} onClick={(e) => e.stopPropagation()} onChange={() => toggle(r.id)} aria-label={`Select ${r.hostname}`} /> },
                 { key: "hostname", label: "Device", render: (r) => <><span className={`dot ${r.online ? "on" : "off"}`} /> <b>{r.hostname}</b><div className="small muted">{r.osVersion}</div></> },
                 { key: "tenantId", label: "Tenant", render: (r) => tenantName(r.tenantId) },
                 { key: "platform", label: "Platform" },
                 { key: "agentVersion", label: "Agent", render: (r) => r.agentVersion || "—" },
                 { key: "state", label: "State", render: (r) => <div className="row">
                     {!r.approved && <Pill value="pending approval" tone="warn" />}
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
  const { data: catalog } = useData<any[]>("commands/catalog");
  const [type, setType] = useState("scan.quick");
  const [targetPath, setTargetPath] = useState("");
  const [reason, setReason] = useState("");
  const { run, busy } = useAction();
  const spec = catalog?.find((c) => c.type === type);
  const submit = async () => {
    const result = await run(() => api("commands/bulk", { body: { type, deviceIds: ids, targetPath, reason } }));
    if (result) onClose();
  };
  return (
    <Modal title={`Run action on ${ids.length} devices`} onClose={onClose}
           footer={<><button onClick={onClose}>Cancel</button><button className={spec?.destructive ? "danger" : "primary"} disabled={busy} onClick={submit}>Queue</button></>}>
      <div className="form-grid">
        <label className="field">Action
          <select value={type} onChange={(e) => setType(e.target.value)}>
            {catalog?.map((c) => <option key={c.type} value={c.type}>{c.group}: {c.label}</option>)}
          </select>
        </label>
        {spec?.needs.includes("targetPath") && <label className="field">Target path<input value={targetPath} onChange={(e) => setTargetPath(e.target.value)} /></label>}
        <label className="field">Reason<input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Shown in the audit log" /></label>
      </div>
      {spec?.description && <p className="muted">{spec.description}</p>}
    </Modal>
  );
}
