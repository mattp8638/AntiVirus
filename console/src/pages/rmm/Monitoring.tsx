import { useState } from "react";
import { Link } from "react-router-dom";
import { ago, api } from "../../api";
import { useApp } from "../../app-context";
import { PageHead, Modal, Pill, Sev, Stat, Table, Tabs, TenantSelect, useAction, useData } from "../../components/ui";

export default function Monitoring() {
  const { tenantId, can } = useApp();
  const [tab, setTab] = useState("Triggered");
  const { data: active, reload: reloadActive } = useData<any[]>("rmm/monitoring", { tenant_id: tenantId });
  const { data: overview } = useData<any>("rmm/overview", { tenant_id: tenantId });
  const { data: conditions, reload } = useData<any>("rmm/conditions");
  const [editing, setEditing] = useState<any>(null);
  return (
    <>
      <PageHead title="Monitoring" subtitle="Health conditions evaluated on every heartbeat: CPU, memory, disk, services, offline, patches and more."
                actions={can("configure") && <button className="primary" onClick={() => setEditing({ name: "", metric: "cpu", operator: ">", threshold: 90, durationMinutes: 10, severity: "medium", actions: [], scope: {}, enabled: true, autoResolve: true })}>New condition</button>} />
      <div className="grid k4">
        <Stat label="Devices online" value={overview ? `${overview.online}/${overview.devices}` : "—"} accent="green" />
        <Stat label="Conditions triggered" value={active?.length ?? "—"} accent={active?.length ? "red" : "green"} />
        <Stat label="Low disk" value={overview?.lowDisk.length ?? "—"} accent={overview?.lowDisk.length ? "amber" : undefined} hint={overview?.lowDisk.slice(0, 3).join(", ")} />
        <Stat label="Restart pending" value={overview?.rebootPending.length ?? "—"} hint={overview?.rebootPending.slice(0, 3).join(", ")} />
      </div>
      <div style={{ marginTop: 16 }}><Tabs tabs={["Triggered", "Conditions"]} active={tab} onChange={setTab} /></div>
      {tab === "Triggered" ? (
        <div className="card">
          <Table rows={active} empty="Everything is healthy."
                 columns={[{ key: "severity", label: "Sev", render: (r) => <Sev level={r.severity} /> },
                           { key: "hostname", label: "Device", render: (r) => <Link to={`/devices/${r.deviceId}`}>{r.hostname}</Link> },
                           { key: "account", label: "Customer" },
                           { key: "condition", label: "Condition", render: (r) => <><b>{r.condition}</b><div className="small muted">{r.message}</div></> },
                           { key: "since", label: "Since", render: (r) => ago(r.since) },
                           { key: "ticketId", label: "Ticket", render: (r) => r.ticketId ? <Link to={`/tickets/${r.ticketId}`}>open</Link> : "—" }]} />
          <div className="row" style={{ marginTop: 8 }}><button className="small" onClick={reloadActive}>Refresh</button></div>
        </div>
      ) : (
        <div className="card">
          <Table rows={conditions?.conditions} onRow={setEditing} empty="No conditions."
                 columns={[{ key: "name", label: "Condition", render: (c) => <b>{c.name}</b> },
                           { key: "metric", label: "Rule", render: (c) => <span className="small">{conditions?.metrics[c.metric]} {c.operator} {c.threshold}{c.target ? ` (${c.target})` : ""} for {c.durationMinutes} min</span> },
                           { key: "severity", label: "Sev", render: (c) => <Sev level={c.severity} /> },
                           { key: "actions", label: "Then", render: (c) => <span className="small">{["alert", ...c.actions.map((a: any) => a.type)].join(", ")}</span> },
                           { key: "scope", label: "Applies to", render: (c) => <span className="small">{c.tenantId ? "one customer" : "everyone"}{c.scope?.platforms?.length ? ` · ${c.scope.platforms.join("/")}` : ""}{c.scope?.tags?.length ? ` · tag ${c.scope.tags.join(",")}` : ""}</span> },
                           { key: "triggered", label: "Now", render: (c) => c.triggered ? <Pill value={`${c.triggered} triggered`} tone="bad" /> : <Pill value="ok" tone="good" /> },
                           { key: "enabled", label: "", render: (c) => c.enabled ? <Pill value="on" tone="good" /> : <Pill value="off" tone="muted" /> }]} />
        </div>
      )}
      {editing && conditions && <ConditionEditor condition={editing} metrics={conditions.metrics} onClose={() => { setEditing(null); reload(); }} />}
    </>
  );
}

function ConditionEditor({ condition, metrics, onClose }: { condition: any; metrics: Record<string, string>; onClose: () => void }) {
  const [form, setForm] = useState<any>({ ...condition, scope: { ...condition.scope }, actions: [...condition.actions] });
  const { data: scripts } = useData<any[]>("rmm/scripts");
  const { run, busy } = useAction();
  const needsTarget = ["service_stopped", "process_missing", "disk_free_percent", "disk_free_gb", "pending_patches"].includes(form.metric);
  const save = async () => {
    const body = { name: form.name, metric: form.metric, operator: form.operator, threshold: Number(form.threshold), target: form.target || "",
                   durationMinutes: Number(form.durationMinutes), severity: form.severity, scope: form.scope, actions: form.actions,
                   enabled: form.enabled, autoResolve: form.autoResolve, ...(form.id ? {} : { tenantId: form.tenantId || undefined }) };
    if (await run(() => (form.id ? api(`rmm/conditions/${form.id}`, { method: "PATCH", body }) : api("rmm/conditions", { body })), "Condition saved")) onClose();
  };
  const setAction = (i: number, patch: any) => setForm({ ...form, actions: form.actions.map((a: any, j: number) => (i === j ? { ...a, ...patch } : a)) });
  return (
    <Modal title={form.id ? form.name : "New condition"} onClose={onClose}
           footer={<>{form.id && <button className="danger" onClick={async () => { if (await run(() => api(`rmm/conditions/${form.id}`, { method: "DELETE" }), "Deleted")) onClose(); }}>Delete</button>}
                   <button className="primary" disabled={busy || !form.name} onClick={save}>Save</button></>}>
      <div className="form-grid">
        <label className="field">Name<input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label>
        <label className="field">Metric<select value={form.metric} onChange={(e) => setForm({ ...form, metric: e.target.value })}>{Object.entries(metrics).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
        <label className="field">Is<select value={form.operator} onChange={(e) => setForm({ ...form, operator: e.target.value })}>{[">", ">=", "<", "<=", "==", "!="].map((o) => <option key={o}>{o}</option>)}</select></label>
        <label className="field">Threshold<input type="number" value={form.threshold} onChange={(e) => setForm({ ...form, threshold: e.target.value })} /></label>
        {needsTarget && <label className="field">{form.metric.startsWith("disk") ? "Drive (blank = any)" : form.metric === "pending_patches" ? "Classification (blank = any)" : "Name"}
          <input value={form.target || ""} onChange={(e) => setForm({ ...form, target: e.target.value })} placeholder={form.metric.startsWith("disk") ? "C: or /" : form.metric === "service_stopped" ? "Spooler" : ""} /></label>}
        <label className="field">For at least (minutes)<input type="number" value={form.durationMinutes} onChange={(e) => setForm({ ...form, durationMinutes: e.target.value })} /></label>
        <label className="field">Severity<select value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}>{["low", "medium", "high", "critical"].map((s) => <option key={s}>{s}</option>)}</select></label>
        {!form.id && <label className="field">Customer<TenantSelect value={form.tenantId || ""} onChange={(id) => setForm({ ...form, tenantId: id })} /></label>}
        <label className="field">Only on<select value={(form.scope.platforms || [])[0] || ""} onChange={(e) => setForm({ ...form, scope: { ...form.scope, platforms: e.target.value ? [e.target.value] : [] } })}>
          <option value="">All platforms</option><option value="windows">Windows</option><option value="linux">Linux</option><option value="macos">macOS</option></select></label>
        <label className="field">Only devices tagged<input value={(form.scope.tags || []).join(",")} onChange={(e) => setForm({ ...form, scope: { ...form.scope, tags: e.target.value.split(",").map((t) => t.trim()).filter(Boolean) } })} placeholder="server" /></label>
      </div>
      <div className="row" style={{ marginTop: 8 }}>
        <label className="small"><input type="checkbox" checked={form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} /> Enabled</label>
        <label className="small"><input type="checkbox" checked={form.autoResolve} onChange={(e) => setForm({ ...form, autoResolve: e.target.checked })} /> Resolve the alert and ticket when it clears</label>
      </div>
      <h3 style={{ marginTop: 14 }}>When it triggers (an alert is always raised)</h3>
      {form.actions.map((a: any, i: number) => (
        <div key={i} className="row" style={{ marginBottom: 6 }}>
          <select value={a.type} onChange={(e) => setAction(i, { type: e.target.value })}>
            <option value="ticket">Open a ticket</option><option value="script">Run a self-heal script</option><option value="email">Email someone</option><option value="webhook">Send webhooks</option></select>
          {a.type === "script" && <select value={a.scriptId || ""} onChange={(e) => setAction(i, { scriptId: e.target.value })} style={{ flex: 1 }}>
            <option value="">Choose script</option>{scripts?.map((s) => <option key={s.id} value={s.id}>{s.name} ({s.language})</option>)}</select>}
          {a.type === "email" && <input placeholder="alerts@yourmsp.com" value={a.to || ""} onChange={(e) => setAction(i, { to: e.target.value })} style={{ flex: 1 }} />}
          {a.type === "ticket" && <input placeholder="Board (default Service Desk)" value={a.board || ""} onChange={(e) => setAction(i, { board: e.target.value })} style={{ flex: 1 }} />}
          <button className="small ghost" onClick={() => setForm({ ...form, actions: form.actions.filter((_: any, j: number) => j !== i) })}>✕</button>
        </div>
      ))}
      <button className="small" onClick={() => setForm({ ...form, actions: [...form.actions, { type: "ticket" }] })}>Add action</button>
    </Modal>
  );
}
