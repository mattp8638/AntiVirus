// Cross-tenant Microsoft 365 bulk and scheduled actions (M365-30). Targets are fixed when the job is created;
// every tenant's result is shown on its own, throttled tenants wait for Microsoft's Retry-After, and items whose
// outcome was lost are never resent: reconcile them from the tenant or resolve them by hand.
import { useState } from "react";
import { api, fmtTime } from "../api";
import { ErrorNote, Pill, Table, useAction, useData } from "../components/ui";

const TONE: Record<string, string> = {
  succeeded: "good", completed: "good", skipped: "neutral", pending: "blue", running: "blue", queued: "blue", scheduled: "blue",
  failed: "bad", unknown: "warn", partial: "warn", cancelled: "neutral", cancelling: "neutral",
};

export default function M365Bulk() {
  const [open, setOpen] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const { data: jobs, error, reload } = useData<any[]>("m365/bulk-jobs");
  if (open) return <Job id={open} onBack={() => { setOpen(null); reload(); }} />;
  return (
    <div style={{ marginTop: 12 }}>
      <div className="row"><p className="small muted" style={{ flex: 1 }}>One action across many customers' tenants. Fenrir fixes the target list when you create the job, checks your access and each connection's permissions per tenant, and records every tenant's result separately.</p>
        <button className="primary" onClick={() => setCreating(!creating)}>{creating ? "Close" : "New bulk job"}</button></div>
      {creating && <NewJob onCreated={(id) => { setCreating(false); setOpen(id); }} />}
      <ErrorNote error={error} />
      <Table rows={jobs || []} empty="No bulk jobs yet." onRow={(j: any) => setOpen(j.id)} columns={[
        { key: "name", label: "Job" }, { key: "title", label: "Action" },
        { key: "targets", label: "Targets", render: (j: any) => `${j.targets.length} in ${j.tenantIds.length} customer(s)` },
        { key: "status", label: "Status", render: (j: any) => <Pill value={j.status} tone={TONE[j.status]} /> },
        { key: "createdAt", label: "Created", render: (j: any) => `${fmtTime(j.createdAt)} by ${j.createdBy}` },
        { key: "scheduledFor", label: "Scheduled", render: (j: any) => j.scheduledFor ? fmtTime(j.scheduledFor) : "now" },
      ]} />
    </div>
  );
}

function NewJob({ onCreated }: { onCreated: (id: string) => void }) {
  const { data: ops } = useData<any>("m365/bulk-jobs/operations");
  const { data: connections } = useData<any[]>("m365/connections");
  const { run, busy } = useAction();
  const [operation, setOperation] = useState("standard.evaluate");
  const [standard, setStandard] = useState("mfa.admins");
  const [enabled, setEnabled] = useState(false);
  const [fields, setFields] = useState({ department: "", jobTitle: "", usageLocation: "" });
  const [picked, setPicked] = useState<Record<string, boolean>>({});
  const [users, setUsers] = useState<Record<string, any[]>>({});
  const [userPicked, setUserPicked] = useState<Record<string, string>>({});
  const [preview, setPreview] = useState<any>(null);
  const [name, setName] = useState("");
  const [when, setWhen] = useState("");
  const [count, setCount] = useState("");
  const spec = ops?.operations?.find((o: any) => o.key === operation);
  const parameters = () => operation.startsWith("standard.") ? { standard }
    : operation === "user.signin" ? { accountEnabled: enabled }
    : operation === "user.update" ? Object.fromEntries(Object.entries(fields).filter(([, v]) => v)) : {};
  const targets = () => spec?.target === "tenant"
    ? Object.keys(picked).filter((k) => picked[k]).map((connectionId) => ({ connectionId }))
    : Object.entries(userPicked).map(([key, label]) => { const [connectionId, targetId] = key.split("|"); return { connectionId, targetId, label }; });
  const loadUsers = async (connectionId: string) => {
    const rows = await run(() => api<any[]>(`m365/connections/${connectionId}/inventory/users`));
    if (rows) setUsers({ ...users, [connectionId]: rows });
  };
  return (
    <div className="card" style={{ marginTop: 12 }}>
      <h3>New bulk job</h3>
      <div className="form-grid">
        <label className="field">Action<select value={operation} onChange={(e) => { setOperation(e.target.value); setPreview(null); }}>
          {(ops?.operations || []).map((o: any) => <option key={o.key} value={o.key}>{o.title}{o.write ? "" : " (read-only)"}</option>)}</select></label>
        {operation.startsWith("standard.") && <label className="field">Standard<select value={standard} onChange={(e) => setStandard(e.target.value)}>
          {(ops?.standards || []).map((s: any) => <option key={s.key} value={s.key}>{s.title}</option>)}</select></label>}
        {operation === "user.signin" && <label className="field">Sign-in<select value={String(enabled)} onChange={(e) => setEnabled(e.target.value === "true")}>
          <option value="false">Block sign-in</option><option value="true">Allow sign-in</option></select></label>}
        {operation === "user.update" && (["department", "jobTitle", "usageLocation"] as const).map((k) =>
          <label key={k} className="field">{k}<input value={fields[k]} onChange={(e) => setFields({ ...fields, [k]: e.target.value })} /></label>)}
      </div>
      <h4>Targets</h4>
      {(connections || []).map((c: any) => (
        <div key={c.id} className="small" style={{ marginBottom: 4 }}>
          {spec?.target === "tenant"
            ? <label><input type="checkbox" checked={!!picked[c.id]} onChange={(e) => setPicked({ ...picked, [c.id]: e.target.checked })} /> {c.tenantName || c.name} <span className="muted">({c.status})</span></label>
            : <>
              <b>{c.tenantName || c.name}</b> <button className="link" onClick={() => loadUsers(c.id)}>Choose users</button>
              {(users[c.id] || []).map((u: any) => {
                const key = `${c.id}|${u.id}`;
                return <label key={key} style={{ display: "block", marginLeft: 16 }}><input type="checkbox" checked={key in userPicked} onChange={(e) => {
                  const next = { ...userPicked };
                  if (e.target.checked) next[key] = u.userPrincipalName; else delete next[key];
                  setUserPicked(next);
                }} /> {u.displayName} ({u.userPrincipalName})</label>;
              })}
            </>}
        </div>
      ))}
      <button disabled={busy} onClick={async () => setPreview(await run(() => api<any>("m365/bulk-jobs/preview", { body: { operation, parameters: parameters(), targets: targets() } })))}>Check targets</button>
      {preview && <>
        <p className="small">{preview.eligible.length} target(s) in {preview.tenants.length} customer(s) will be used.</p>
        {preview.excluded.length > 0 && <div className="small"><b>Left out:</b>{preview.excluded.map((x: any, i: number) => <div key={i}>{x.label || x.connectionId}: {x.reason}</div>)}</div>}
        <div className="form-grid">
          <label className="field">Name<input value={name} onChange={(e) => setName(e.target.value)} /></label>
          <label className="field">Start at (empty = now)<input type="datetime-local" value={when} onChange={(e) => setWhen(e.target.value)} /></label>
          <label className="field">Type {preview.eligible.length} to confirm<input value={count} onChange={(e) => setCount(e.target.value)} /></label>
        </div>
        <button className="primary" disabled={busy || count !== String(preview.eligible.length)} onClick={async () => {
          const job = await run(() => api<any>("m365/bulk-jobs", { body: { operation, parameters: parameters(), targets: targets(), name,
            confirmCount: Number(count), scheduledFor: when ? new Date(when).toISOString() : null } }), "Bulk job created");
          if (job) onCreated(job.id);
        }}>{preview.write ? "Create job (changes tenants)" : "Create job"}</button>
      </>}
    </div>
  );
}

function Job({ id, onBack }: { id: string; onBack: () => void }) {
  const { data: job, error, reload } = useData<any>(`m365/bulk-jobs/${id}`);
  const { run, busy } = useAction();
  if (!job) return <ErrorNote error={error} />;
  const act = async (path: string, message: string) => { await run(() => api(`m365/bulk-jobs/${id}/${path}`, { method: "POST" }), message); reload(); };
  const runNow = async () => {
    for (let i = 0; i < 20; i++) {
      const r = await run(() => api<any>(`m365/bulk-jobs/${id}/run`, { method: "POST" }));
      if (!r?.more) break;
    }
    reload();
  };
  const live = !["completed", "partial", "failed", "cancelled"].includes(job.status);
  return (
    <div style={{ marginTop: 12 }}>
      <button className="link" onClick={onBack}>← All bulk jobs</button>
      <div className="card">
        <div className="row" style={{ gap: 8 }}><h3 style={{ margin: 0, flex: 1 }}>{job.name}</h3><Pill value={job.status} tone={TONE[job.status]} /></div>
        <p className="small muted">{job.title} · created {fmtTime(job.createdAt)} by {job.createdBy}{job.scheduledFor && ` · scheduled for ${fmtTime(job.scheduledFor)}`}
          {" · "}target list SHA-256 {job.targetsHash.slice(0, 16)}… {job.summary?.verified ? "(matches)" : <Pill value="does not match" tone="bad" />}</p>
        {job.summary?.error && <p className="small"><Pill value="refused" tone="bad" /> {job.summary.error}</p>}
        <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
          {Object.entries(job.summary?.counts || {}).map(([k, v]) => <Pill key={k} value={`${v} ${k}`} tone={TONE[k]} />)}
        </div>
        <div className="row" style={{ gap: 8, marginTop: 8 }}>
          {live && job.status !== "scheduled" && <button className="primary" disabled={busy} onClick={runNow}>Run now</button>}
          {live && <button disabled={busy} onClick={() => act("cancel", "Cancelled")}>Cancel</button>}
          {job.summary?.counts?.unknown > 0 && <button disabled={busy} onClick={() => act("reconcile", "Checked the tenants")}>Reconcile unknown items</button>}
        </div>
      </div>
      <div className="card">
        <h3>By customer</h3>
        {Object.entries(job.summary?.tenants || {}).map(([tid, t]: any) => (
          <div key={tid} className="small row" style={{ gap: 6 }}><b style={{ minWidth: 180 }}>{t.name || tid}</b>
            {Object.entries(t.counts).map(([k, v]: any) => <Pill key={k} value={`${v} ${k}`} tone={TONE[k]} />)}</div>
        ))}
      </div>
      <Table rows={job.items} columns={[
        { key: "label", label: "Target" },
        { key: "status", label: "Status", render: (i: any) => <Pill value={i.status} tone={TONE[i.status]} /> },
        { key: "attempts", label: "Tries" },
        { key: "result", label: "Result", render: (i: any) => <span className="small">{i.result?.message || i.result?.compliance || ""}{i.notBefore && ` (waits until ${fmtTime(i.notBefore)})`}</span> },
        { key: "id", label: "", render: (i: any) => (i.status === "unknown" || i.status === "failed") && job.status !== "cancelled" ? <span className="row" style={{ gap: 4 }}>
          {i.status === "unknown" && <><button className="link" onClick={() => run(() => api(`m365/bulk-jobs/${id}/items/${i.id}/resolve`, { body: { outcome: "succeeded" } })).then(reload)}>Done</button>
            <button className="link" onClick={() => run(() => api(`m365/bulk-jobs/${id}/items/${i.id}/resolve`, { body: { outcome: "failed" } })).then(reload)}>Not done</button></>}
          <button className="link" onClick={() => run(() => api(`m365/bulk-jobs/${id}/items/${i.id}/resolve`, { body: { outcome: "retry" } })).then(reload)}>Retry</button>
        </span> : null },
      ]} />
    </div>
  );
}
