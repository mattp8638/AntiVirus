// Tenant configuration backup, change history, comparison and restore (M365-14).
import { useState } from "react";
import { api, fmtTime } from "../api";
import { ErrorNote, Pill, Table, useAction, useData } from "../components/ui";

const ACTION_TONE: Record<string, string> = { create: "blue", update: "warn", unchanged: "neutral", blocked: "bad",
  succeeded: "good", failed: "bad", unknown: "warn", skipped: "neutral" };

function Changes({ changes }: { changes: any }) {
  if (!changes || changes.first) return <span className="small muted">First backup</span>;
  const parts = Object.entries(changes).map(([r, c]: any) => c.unavailable ? `${r}: not readable`
    : `${r}: ${[c.added?.length && `${c.added.length} added`, c.removed?.length && `${c.removed.length} removed`, c.changed?.length && `${c.changed.length} changed`].filter(Boolean).join(", ")}`);
  return <span className="small">{parts.join(" · ") || "No change"}</span>;
}

export default function M365Config({ connection }: { connection: any }) {
  const { run, busy } = useAction();
  const { data: history, error, reload } = useData<any[]>(`m365/config/connections/${connection.id}/snapshots`);
  const { data: meta } = useData<any>("m365/config/resources");
  const [open, setOpen] = useState<string | null>(null);
  const [compareWith, setCompareWith] = useState<string | null>(null);
  return (
    <div style={{ marginTop: 12 }}>
      <div className="row"><p className="small muted" style={{ flex: 1 }}>Fenrir backs up this tenant's Conditional Access, named locations, user and guest defaults, security defaults, authentication methods and Intune policies every day, and keeps a new version only when something changed. Restores are planned first and show exactly what they would create or change; Conditional Access is restored report-only unless you keep its state.</p>
        <button className="primary" disabled={busy} onClick={() => run(() => api(`m365/config/connections/${connection.id}/snapshots`, { method: "POST" }), "Backed up").then(reload)}>Back up now</button></div>
      {meta && <details className="small"><summary>What is not restored</summary>{Object.entries(meta.notRestored).map(([k, v]: any) => <p key={k}>{v}</p>)}</details>}
      <ErrorNote error={error} />
      <Table rows={history || []} empty="No backup yet." onRow={(s: any) => setOpen(s.id)} columns={[
        { key: "takenAt", label: "Backed up", render: (s: any) => `${fmtTime(s.takenAt)}${s.checkedAt ? ` (still current ${fmtTime(s.checkedAt)})` : ""}` },
        { key: "changes", label: "Changes since the previous version", render: (s: any) => <Changes changes={s.changes} /> },
        { key: "unavailable", label: "Not readable", render: (s: any) => Object.keys(s.unavailable).length ? <Pill value={Object.keys(s.unavailable).length} tone="warn" /> : "" },
        { key: "id", label: "", render: (s: any) => <button className="link" onClick={(e) => { e.stopPropagation(); setCompareWith(s.id); }}>Compare…</button> },
      ]} />
      {compareWith && <Compare left={compareWith} onClose={() => setCompareWith(null)} />}
      {open && <Snapshot id={open} connection={connection} onClose={() => setOpen(null)} />}
    </div>
  );
}

function Compare({ left, onClose }: { left: string; onClose: () => void }) {
  const { data: connections } = useData<any[]>("m365/connections");
  const [conn, setConn] = useState("");
  const { data: others } = useData<any[]>(conn ? `m365/config/connections/${conn}/snapshots` : null, undefined, [conn]);
  const [right, setRight] = useState("");
  const { data: result, error } = useData<any>(right ? "m365/config/compare" : null, { left, right }, [right]);
  return (
    <div className="card">
      <div className="row"><h3 style={{ flex: 1, margin: 0 }}>Compare with</h3><button className="link" onClick={onClose}>Close</button></div>
      <div className="form-grid">
        <label className="field">Tenant<select value={conn} onChange={(e) => { setConn(e.target.value); setRight(""); }}><option value="">Choose…</option>
          {(connections || []).map((c: any) => <option key={c.id} value={c.id}>{c.tenantName || c.name}</option>)}</select></label>
        <label className="field">Version<select value={right} onChange={(e) => setRight(e.target.value)}><option value="">Choose…</option>
          {(others || []).map((s: any) => <option key={s.id} value={s.id}>{fmtTime(s.takenAt)}</option>)}</select></label>
      </div>
      <ErrorNote error={error} />
      {result && (Object.keys(result.differences).length === 0 ? <p className="small">No differences.</p> :
        Object.entries(result.differences).map(([r, d]: any) => (
          <div key={r} className="small" style={{ marginTop: 8 }}><b>{r}</b>
            {d.unavailable && <div className="muted">Not readable: {d.unavailable}</div>}
            {d.added?.map((n: string) => <div key={"a" + n}><Pill value="only on the right" tone="blue" /> {n}</div>)}
            {d.removed?.map((n: string) => <div key={"r" + n}><Pill value="only on the left" tone="warn" /> {n}</div>)}
            {d.changed?.map((c: any) => <div key={"c" + c.name}><Pill value="differs" tone="warn" /> {c.name}: {c.fields.map((f: any) => `${f.field} ${JSON.stringify(f.before)} → ${JSON.stringify(f.after)}`).join("; ")}</div>)}
          </div>)))}
    </div>
  );
}

function Snapshot({ id, connection, onClose }: { id: string; connection: any; onClose: () => void }) {
  const { data: snap, error } = useData<any>(`m365/config/snapshots/${id}`);
  const { data: connections } = useData<any[]>("m365/connections");
  const { run, busy } = useAction();
  const [picked, setPicked] = useState<Record<string, boolean>>({});
  const [target, setTarget] = useState(connection.id);
  const [keepState, setKeepState] = useState(false);
  const [plan, setPlan] = useState<any>(null);
  const [count, setCount] = useState("");
  if (!snap) return <ErrorNote error={error} />;
  const items = Object.keys(picked).filter((k) => picked[k]).map((k) => { const [resource, ...rest] = k.split("|"); return { resource, name: rest.join("|") }; });
  const writes = plan ? plan.plan.filter((s: any) => s.action === "create" || s.action === "update").length : 0;
  const name = (resource: string, o: any) => o.displayName || resource;
  return (
    <div className="card">
      <div className="row"><h3 style={{ flex: 1, margin: 0 }}>Backup of {fmtTime(snap.takenAt)}</h3>
        <Pill value={snap.verified ? "SHA-256 verified" : "does not match its SHA-256"} tone={snap.verified ? "good" : "bad"} />
        <button className="link" onClick={onClose}>Close</button></div>
      {Object.entries(snap.unavailable || {}).map(([r, why]: any) => <p key={r} className="small"><Pill value="not readable" tone="warn" /> {r}: {why}</p>)}
      <GapAnalysis snapshotId={id} />
      {Object.entries(snap.resources || {}).map(([resource, objs]: any) => (
        <div key={resource} style={{ marginTop: 8 }}><b className="small">{resource}</b>
          {objs.map((o: any) => { const key = `${resource}|${name(resource, o)}`; return (
            <label key={key} className="small" style={{ display: "block", marginLeft: 12 }}>
              <input type="checkbox" checked={!!picked[key]} onChange={(e) => { setPicked({ ...picked, [key]: e.target.checked }); setPlan(null); }} /> {name(resource, o)}
              {o.state && <span className="muted"> ({o.state})</span>}</label>); })}
        </div>
      ))}
      <div className="form-grid" style={{ marginTop: 8 }}>
        <label className="field">Restore into<select value={target} onChange={(e) => { setTarget(e.target.value); setPlan(null); }}>
          {(connections || []).map((c: any) => <option key={c.id} value={c.id}>{c.tenantName || c.name}{c.id === connection.id ? " (this tenant)" : ""}</option>)}</select></label>
        <label className="field"><span><input type="checkbox" checked={keepState} onChange={(e) => { setKeepState(e.target.checked); setPlan(null); }} /> Keep Conditional Access state (otherwise report-only)</span></label>
      </div>
      <button disabled={busy || items.length === 0} onClick={async () => setPlan(await run(() => api<any>("m365/config/restores", { body: { snapshotId: id, connectionId: target, items, keepState } })))}>Plan restore</button>
      {plan && <>
        <Table rows={plan.plan} columns={[
          { key: "name", label: "Object", render: (s: any) => `${s.resource}: ${s.name}` },
          { key: "action", label: "Plan", render: (s: any) => <Pill value={s.action} tone={ACTION_TONE[s.action]} /> },
          { key: "reasons", label: "Details", render: (s: any) => <span className="small">{[...s.reasons, ...s.translations, ...s.fields.map((f: any) => `${f.field}: ${JSON.stringify(f.before)} → ${JSON.stringify(f.after)}`)].join("; ")}</span> },
        ]} />
        {plan.status === "planned" && writes > 0 && <div className="row" style={{ gap: 8 }}>
          <label className="field">Type {writes} to confirm<input value={count} onChange={(e) => setCount(e.target.value)} /></label>
          <button className="primary" disabled={busy || count !== String(writes)} onClick={async () => {
            const done = await run(() => api<any>(`m365/config/restores/${plan.id}/execute`, { body: { confirmCount: writes } }), "Restore finished");
            if (done) setPlan(done);
          }}>Restore {writes} object(s)</button></div>}
        {plan.results?.length > 0 && <Table rows={plan.results} columns={[
          { key: "name", label: "Object", render: (r: any) => `${r.resource}: ${r.name}` },
          { key: "status", label: "Result", render: (r: any) => <Pill value={r.status} tone={ACTION_TONE[r.status]} /> },
          { key: "message", label: "", render: (r: any) => <span className="small">{r.message || ""}</span> },
        ]} />}
      </>}
    </div>
  );
}

const VERDICT_TONE: Record<string, string> = { pass: "good", gap: "bad" };

// M365-15: a modelled evaluation of this backup's Conditional Access policies. Nothing is sent to the tenant.
function GapAnalysis({ snapshotId }: { snapshotId: string }) {
  const { run, busy } = useAction();
  const [result, setResult] = useState<any>(null);
  return (
    <div style={{ margin: "8px 0" }}>
      <button disabled={busy} onClick={async () => setResult(await run(() => api<any>(`m365/config/snapshots/${snapshotId}/simulate`, { body: {} })))}>
        Conditional Access gap analysis (modelled)</button>
      {result && <div className="card">
        <p className="small"><Pill value="modelled, not a real sign-in" tone="blue" /> {result.summary.policies} policies from this backup (SHA-256 {result.snapshotDigest.slice(0, 12)}…) ·
          {" "}{result.summary.gaps.length} gap(s) · lowest confidence: {result.summary.confidence}</p>
        <Table rows={result.results} columns={[
          { key: "title", label: "Scenario" },
          { key: "verdict", label: "Result", render: (r: any) => <Pill value={r.verdict} tone={VERDICT_TONE[r.verdict]} /> },
          { key: "reason", label: "Why", render: (r: any) => <span className="small">{r.reason} · modelled outcome: {r.outcome}
            {r.applied.length > 0 && ` · applied: ${r.applied.map((a: any) => a.policy).join(", ")}`}</span> },
          { key: "confidence", label: "Confidence", render: (r: any) => <span className="small">{r.confidence}{r.uncertain.length > 0 && ` (${[...new Set(r.uncertain.flatMap((u: any) => u.uncertain))].join(", ")})`}</span> },
        ]} />
      </div>}
    </div>
  );
}
