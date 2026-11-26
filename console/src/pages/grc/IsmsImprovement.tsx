import { useState } from "react";
import { api } from "../../api";
import { useApp } from "../../app-context";
import { displayValue } from "../../components/DisplayValue";
import { ErrorNote, Modal, Pill, Table, useAction, useData } from "../../components/ui";
import { safeArray } from "../../data-shapes";

/** ISMS improvement: nonconformities and corrective action (10.2), objectives and measurement (6.2, 9.1), planned changes (6.3). */

const SOURCE_LABEL: Record<string, string> = {
  internal_audit: "Internal audit", external_audit: "External audit", incident: "Incident", management_review: "Management review",
  monitoring: "Monitoring", complaint: "Complaint", other: "Other",
};
const HEALTH: Record<string, [string, string]> = { met: ["on target", "ok"], not_met: ["off target", "bad"], no_data: ["no data yet", "muted"] };
const TREND: Record<string, string> = { improving: "improving", worsening: "getting worse", steady: "steady", unknown: "" };
const DIRECTION: Record<string, string> = { at_least: "at least", at_most: "at most" };
const ddmmyyyy = (iso?: string | null) => iso ? `${iso.slice(8, 10)}/${iso.slice(5, 7)}/${iso.slice(0, 4)}` : "";

function useIsms() {
  const { tenantId } = useApp();
  const { data: me } = useData<any>(tenantId ? "isms/me" : null, { tenant_id: tenantId }, [tenantId]);
  return { tenantId, me, perms: safeArray<string>(me?.permissions) };
}

function People({ tenantId, value, onChange, label, none }: { tenantId: string; value: string; onChange: (v: string) => void; label: string; none: string }) {
  const { data } = useData<any>("isms/members", { tenant_id: tenantId }, [tenantId]);
  return <label className="field">{label}<select value={value} onChange={(e) => onChange(e.target.value)}>
    <option value="">{none}</option>{safeArray<any>(data?.members).map((m) => <option key={m.id} value={m.id}>{m.name ? `${m.name} (${m.email})` : m.email}</option>)}</select></label>;
}

export function IsmsImprovementTab() {
  const { tenantId, me, perms } = useIsms();
  const [view, setView] = useState<"nc" | "objectives" | "changes">("nc");
  if (!tenantId) return <p className="muted">Choose a customer in the tenant picker to see its ISMS improvement records.</p>;
  if (!perms.includes("controls.view")) return me ? <p className="muted">Your ISMS role in this customer ({displayValue(me.role ?? "none")}) cannot see improvement records.</p> : null;
  const manage = perms.includes("programme.manage");
  return <div className="card">
    <label className="field" style={{ maxWidth: 280 }}>Show<select value={view} onChange={(e) => setView(e.target.value as any)}>
      <option value="nc">Nonconformities and improvements</option><option value="objectives">Objectives and measures</option><option value="changes">Planned changes</option></select></label>
    {view === "nc" && <Nonconformities tenantId={tenantId} manage={manage} userId={me?.userId} />}
    {view === "objectives" && <Objectives tenantId={tenantId} manage={manage} userId={me?.userId} />}
    {view === "changes" && <Changes tenantId={tenantId} manage={manage} />}
  </div>;
}

// Nonconformities -----------------------------------------------------------------------------------------------------

function Nonconformities({ tenantId, manage, userId }: { tenantId: string; manage: boolean; userId?: string }) {
  const [status, setStatus] = useState("open");
  const { data, error, reload } = useData<any>("isms/nonconformities", { tenant_id: tenantId, status }, [tenantId, status]);
  const [openId, setOpenId] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const rows = safeArray<any>(data?.nonconformities);
  const open = rows.find((r) => r.id === openId);
  return <>
    <ErrorNote error={error} />
    <div className="row" style={{ gap: 8, alignItems: "end", marginBottom: 8 }}>
      <label className="field">Status<select value={status} onChange={(e) => setStatus(e.target.value)}><option value="open">Open</option><option value="closed">Closed</option><option value="all">All</option></select></label>
      <span style={{ flex: 1 }} />
      {manage && <button className="primary" onClick={() => setAdding(true)}>Raise</button>}
    </div>
    <p className="small muted">A nonconformity needs a root cause and at least one corrective action. When every action is done, check that it worked before closing it. An improvement opportunity closes with a note.</p>
    <Table rows={rows} empty="Nothing open." onRow={(r) => setOpenId(r.id)} columns={[
      { key: "ref", label: "Ref" },
      { key: "title", label: "Title", render: (r) => <><b>{displayValue(r.title)}</b><div className="small muted">{SOURCE_LABEL[r.source] ?? r.source}{r.requirementRef ? `, ${r.requirementRef}` : ""}</div></> },
      { key: "kind", label: "Type", render: (r) => r.kind === "opportunity" ? "Improvement" : <>Nonconformity <Pill value={r.severity} tone={r.severity === "major" ? "bad" : "warn"} /></> },
      { key: "stage", label: "Stage", render: (r) => <>{r.stageText}{r.overdue && <> <Pill value="overdue" tone="bad" /></>}</> },
      { key: "ownerName", label: "Owner", render: (r) => displayValue(r.ownerName ?? "Nobody") },
      { key: "dueOn", label: "Due", render: (r) => ddmmyyyy(r.dueOn) }]} />
    {open && <NcDetail nc={open} tenantId={tenantId} manage={manage} userId={userId} onChange={reload} onClose={() => setOpenId(null)} />}
    {adding && <RaiseNc tenantId={tenantId} sources={safeArray<string>(data?.sources)} onClose={() => { setAdding(false); reload(); }} />}
  </>;
}

function RaiseNc({ tenantId, sources, onClose }: { tenantId: string; sources: string[]; onClose: () => void }) {
  const [f, setF] = useState({ kind: "nonconformity", title: "", source: "", severity: "", requirementRef: "", description: "", correction: "", ownerId: "", dueOn: "" });
  const { run, busy } = useAction();
  const nc = f.kind === "nonconformity";
  const ready = f.title.trim() && f.source && (!nc || f.severity);
  const save = async () => { if (await run(() => api("isms/nonconformities", { body: { tenantId, ...f, ownerId: f.ownerId || null, dueOn: f.dueOn || null, severity: nc ? f.severity : null } }), "Recorded")) onClose(); };
  return <Modal title="Raise a nonconformity or improvement" onClose={onClose} footer={<button className="primary" disabled={busy || !ready} onClick={save}>Raise</button>}>
    <label className="field">Type<select value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value })}><option value="nonconformity">Nonconformity</option><option value="opportunity">Improvement opportunity</option></select></label>
    <label className="field">Title<input value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} /></label>
    <label className="field">Where it came from<select value={f.source} onChange={(e) => setF({ ...f, source: e.target.value })}>
      <option value="">Choose</option>{(sources.length ? sources : Object.keys(SOURCE_LABEL)).map((s) => <option key={s} value={s}>{SOURCE_LABEL[s] ?? s}</option>)}</select></label>
    {nc && <label className="field">Severity<select value={f.severity} onChange={(e) => setF({ ...f, severity: e.target.value })}><option value="">Choose</option><option value="minor">Minor</option><option value="major">Major</option></select></label>}
    <label className="field">Requirement or control (optional)<input value={f.requirementRef} placeholder="For example 9.2 or CC-BKP-01" onChange={(e) => setF({ ...f, requirementRef: e.target.value })} /></label>
    <label className="field">What was found<textarea rows={3} value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></label>
    {nc && <label className="field">Immediate correction (optional)<textarea rows={2} value={f.correction} onChange={(e) => setF({ ...f, correction: e.target.value })} /></label>}
    <People tenantId={tenantId} label="Owner" none="Nobody yet" value={f.ownerId} onChange={(ownerId) => setF({ ...f, ownerId })} />
    <label className="field">Due on (optional)<input type="date" value={f.dueOn} onChange={(e) => setF({ ...f, dueOn: e.target.value })} /></label>
  </Modal>;
}

function NcDetail({ nc, tenantId, manage, userId, onChange, onClose }: { nc: any; tenantId: string; manage: boolean; userId?: string; onChange: () => void; onClose: () => void }) {
  const { run, busy } = useAction();
  const isOpen = nc.status === "open";
  const [rootCause, setRootCause] = useState(nc.rootCause ?? "");
  const [action, setAction] = useState({ description: "", ownerId: "", dueOn: "" });
  const [doneNote, setDoneNote] = useState<Record<string, string>>({});
  const [check, setCheck] = useState("");
  const [closing, setClosing] = useState("");
  const call = async (path: string, body: any, msg: string, method?: string) => { if (await run(() => api(path, { method, body }), msg)) onChange(); };
  const base = `isms/nonconformities/${nc.id}`;
  return <Modal title={`${nc.ref}: ${nc.title}`} wide onClose={onClose}>
    <p className="small">{nc.kind === "opportunity" ? "Improvement opportunity" : `${nc.severity === "major" ? "Major" : "Minor"} nonconformity`}, raised {ddmmyyyy(nc.raisedOn)} from {(SOURCE_LABEL[nc.source] ?? nc.source).toLowerCase()}. Stage: <b>{nc.stageText}</b>.</p>
    {nc.description && <p style={{ whiteSpace: "pre-wrap" }}>{displayValue(nc.description)}</p>}
    {nc.correction && <p className="small"><b>Correction:</b> {displayValue(nc.correction)}</p>}
    {nc.kind === "nonconformity" && <>
      <h3>Root cause</h3>
      {manage && isOpen ? <div className="row" style={{ gap: 8, alignItems: "end" }}>
        <label className="field" style={{ flex: 1 }}>Root cause<textarea rows={2} value={rootCause} onChange={(e) => setRootCause(e.target.value)} /></label>
        <button disabled={busy || rootCause === (nc.rootCause ?? "")} onClick={() => call(base, { title: nc.title, source: nc.source, severity: nc.severity, requirementRef: nc.requirementRef, description: nc.description, correction: nc.correction, ownerId: nc.ownerId, dueOn: nc.dueOn, rootCause }, "Saved", "PATCH")}>Save root cause</button>
      </div> : <p className="small">{displayValue(nc.rootCause || "Not recorded yet.")}</p>}
      <h3>Corrective actions</h3>
      {nc.actions.length === 0 && <p className="small muted">None yet.</p>}
      <ul className="small">{nc.actions.map((a: any) => <li key={a.id}>
        {a.done ? "Done: " : ""}{displayValue(a.description)} ({displayValue(a.ownerName ?? "nobody")}, due {ddmmyyyy(a.dueOn)}){a.overdue && <> <Pill value="overdue" tone="bad" /></>}
        {a.done && a.doneNote && <div className="muted">{displayValue(a.doneNote)}</div>}
        {!a.done && isOpen && (manage || a.ownerId === userId) && <div className="row" style={{ gap: 6, alignItems: "end" }}>
          <label className="field" style={{ flex: 1 }}>What was done<input value={doneNote[a.id] ?? ""} onChange={(e) => setDoneNote({ ...doneNote, [a.id]: e.target.value })} /></label>
          <button disabled={busy || !(doneNote[a.id] ?? "").trim()} onClick={() => call(`isms/corrective-actions/${a.id}/done`, { note: doneNote[a.id] }, "Action done")}>Mark done</button>
        </div>}
      </li>)}</ul>
      {manage && isOpen && <div className="row" style={{ gap: 8, alignItems: "end", flexWrap: "wrap" }}>
        <label className="field" style={{ flex: 2 }}>New action<input value={action.description} onChange={(e) => setAction({ ...action, description: e.target.value })} /></label>
        <People tenantId={tenantId} label="Action owner" none="Nobody yet" value={action.ownerId} onChange={(ownerId) => setAction({ ...action, ownerId })} />
        <label className="field">Action due<input type="date" value={action.dueOn} onChange={(e) => setAction({ ...action, dueOn: e.target.value })} /></label>
        <button disabled={busy || !action.description.trim() || !action.dueOn} onClick={async () => { await call(`${base}/actions`, { ...action, ownerId: action.ownerId || null }, "Action added"); setAction({ description: "", ownerId: "", dueOn: "" }); }}>Add action</button>
      </div>}
      <h3>Effectiveness</h3>
      {nc.effectivenessNote && <p className="small">{nc.effective ? "Effective" : "Not effective yet"}: {displayValue(nc.effectivenessNote)}</p>}
      {manage && isOpen && <>
        {nc.blockers.length > 0 && <p className="small muted">Before checking: {nc.blockers.join(" ")}</p>}
        <label className="field">How you checked it worked<textarea rows={2} value={check} onChange={(e) => setCheck(e.target.value)} /></label>
        <div className="row" style={{ gap: 8 }}>
          <button className="primary" disabled={busy || nc.blockers.length > 0 || !check.trim()} onClick={() => call(`${base}/effectiveness`, { effective: true, note: check }, "Closed as effective")}>Effective, close it</button>
          <button disabled={busy || nc.blockers.length > 0 || !check.trim()} onClick={() => call(`${base}/effectiveness`, { effective: false, note: check }, "Recorded, still open")}>Not effective yet</button>
        </div>
      </>}
    </>}
    {!isOpen && nc.closureNote && <p className="small"><b>Closure:</b> {displayValue(nc.closureNote)}</p>}
    {manage && isOpen && <>
      <h3>{nc.kind === "opportunity" ? "Close" : "Cancel"}</h3>
      <label className="field">{nc.kind === "opportunity" ? "Outcome" : "Why it is being cancelled"}<input value={closing} onChange={(e) => setClosing(e.target.value)} /></label>
      <div className="row" style={{ gap: 8 }}>
        {nc.kind === "opportunity" && <button disabled={busy || !closing.trim()} onClick={() => call(`${base}/close`, { outcome: "closed", note: closing }, "Closed")}>Close</button>}
        <button disabled={busy || !closing.trim()} onClick={() => call(`${base}/close`, { outcome: "cancelled", note: closing }, "Cancelled")}>Cancel it</button>
      </div>
    </>}
  </Modal>;
}

// Objectives ----------------------------------------------------------------------------------------------------------

function Objectives({ tenantId, manage, userId }: { tenantId: string; manage: boolean; userId?: string }) {
  const { data, error, reload } = useData<any>("isms/objectives", { tenant_id: tenantId }, [tenantId]);
  const [openId, setOpenId] = useState<string | null>(null);
  const [editing, setEditing] = useState<any>(null);
  const rows = safeArray<any>(data?.objectives);
  const open = rows.find((r) => r.id === openId);
  return <>
    <ErrorNote error={error} />
    <div className="row" style={{ marginBottom: 8 }}><span style={{ flex: 1 }} />{manage && <button className="primary" onClick={() => setEditing({})}>Add objective</button>}</div>
    <p className="small muted">Each objective has a measure and a target. The owner records a value at the chosen frequency; a measure with no value for longer than that is flagged as stale.</p>
    <Table rows={rows} empty="No objectives yet." onRow={(r) => setOpenId(r.id)} columns={[
      { key: "ref", label: "Ref" },
      { key: "title", label: "Objective", render: (o) => <><b>{displayValue(o.title)}</b><div className="small muted">{displayValue(o.measure)}: {DIRECTION[o.direction]} {o.target}{o.unit ? ` ${o.unit}` : ""}</div></> },
      { key: "latest", label: "Latest", render: (o) => o.summary.latest ? `${o.summary.latest.value}${o.unit ? ` ${o.unit}` : ""} (${ddmmyyyy(o.summary.latest.measuredOn)})` : "None" },
      { key: "health", label: "Health", render: (o) => <><Pill value={HEALTH[o.summary.health]?.[0] ?? o.summary.health} tone={HEALTH[o.summary.health]?.[1]} />{TREND[o.summary.trend] && <span className="small"> {TREND[o.summary.trend]}</span>}{o.summary.stale && <> <Pill value="stale" tone="warn" /></>}</> },
      { key: "ownerName", label: "Owner", render: (o) => displayValue(o.ownerName ?? "Nobody") },
      { key: "status", label: "Status" }]} />
    {open && <ObjectiveDetail o={open} manage={manage} canRecord={open.status === "active" && (manage || open.ownerId === userId)} onEdit={() => { setEditing(open); setOpenId(null); }} onChange={reload} onClose={() => setOpenId(null)} />}
    {editing && <EditObjective tenantId={tenantId} o={editing} onClose={() => { setEditing(null); reload(); }} />}
  </>;
}

function EditObjective({ tenantId, o, onClose }: { tenantId: string; o: any; onClose: () => void }) {
  const [f, setF] = useState({ title: o.title ?? "", measure: o.measure ?? "", unit: o.unit ?? "", direction: o.direction ?? "at_least", target: o.target ?? "", baseline: o.baseline ?? "",
    frequency: o.frequency ?? "monthly", ownerId: o.ownerId ?? "", dueOn: o.dueOn ?? "", plan: o.plan ?? "", resources: o.resources ?? "" });
  const { run, busy } = useAction();
  const body = { ...f, ownerId: f.ownerId || null, dueOn: f.dueOn || null, target: f.target === "" ? null : Number(f.target), baseline: f.baseline === "" ? null : Number(f.baseline) };
  const save = async () => { if (await run(() => o.id ? api(`isms/objectives/${o.id}`, { method: "PATCH", body }) : api("isms/objectives", { body: { tenantId, ...body } }), "Objective saved")) onClose(); };
  const set = (k: string) => (e: any) => setF({ ...f, [k]: e.target.value });
  return <Modal title={o.id ? `Edit ${o.ref}` : "Add an objective"} onClose={onClose} footer={<button className="primary" disabled={busy || !f.title.trim() || !f.measure.trim() || f.target === ""} onClick={save}>Save</button>}>
    <label className="field">Objective<input value={f.title} onChange={set("title")} /></label>
    <label className="field">Measure<input value={f.measure} onChange={set("measure")} placeholder="For example median days to apply critical patches" /></label>
    <div className="row" style={{ gap: 8 }}>
      <label className="field">Target is<select value={f.direction} onChange={set("direction")}><option value="at_least">At least</option><option value="at_most">At most</option></select></label>
      <label className="field">Target<input type="number" value={f.target} onChange={set("target")} /></label>
      <label className="field">Unit<input value={f.unit} onChange={set("unit")} /></label>
      <label className="field">Baseline (optional)<input type="number" value={f.baseline} onChange={set("baseline")} /></label>
    </div>
    <label className="field">Measured<select value={f.frequency} onChange={set("frequency")}><option value="monthly">Monthly</option><option value="quarterly">Quarterly</option><option value="six-monthly">Six-monthly</option><option value="annual">Annually</option></select></label>
    <People tenantId={tenantId} label="Owner" none="Nobody yet" value={f.ownerId} onChange={(ownerId) => setF({ ...f, ownerId })} />
    <label className="field">Achieve by (optional)<input type="date" value={f.dueOn} onChange={set("dueOn")} /></label>
    <label className="field">Plan<textarea rows={2} value={f.plan} onChange={set("plan")} /></label>
    <label className="field">Resources<textarea rows={2} value={f.resources} onChange={set("resources")} /></label>
  </Modal>;
}

function ObjectiveDetail({ o, manage, canRecord, onEdit, onChange, onClose }: { o: any; manage: boolean; canRecord: boolean; onEdit: () => void; onChange: () => void; onClose: () => void }) {
  const { run, busy } = useAction();
  const [v, setV] = useState({ measuredOn: new Date().toISOString().slice(0, 10), value: "", note: "" });
  const [status, setStatus] = useState({ status: "", note: "" });
  return <Modal title={`${o.ref}: ${o.title}`} wide onClose={onClose} footer={manage && o.status === "active" && <button onClick={onEdit}>Edit</button>}>
    <p className="small">{displayValue(o.measure)}: target {DIRECTION[o.direction]} {o.target}{o.unit ? ` ${o.unit}` : ""}{o.baseline != null ? `, baseline ${o.baseline}` : ""}. Measured {o.frequency}{o.dueOn ? `, achieve by ${ddmmyyyy(o.dueOn)}` : ""}.</p>
    {o.plan && <p className="small"><b>Plan:</b> {displayValue(o.plan)}</p>}
    {o.statusNote && <p className="small"><b>{o.status}:</b> {displayValue(o.statusNote)}</p>}
    <h3>Measurements</h3>
    <Table rows={[...safeArray<any>(o.values)].reverse()} empty="No values yet." columns={[
      { key: "measuredOn", label: "Date", render: (x) => ddmmyyyy(x.measuredOn) }, { key: "value", label: "Value" }, { key: "note", label: "Note", render: (x) => displayValue(x.note ?? "") }]} />
    {canRecord && <div className="row" style={{ gap: 8, alignItems: "end", flexWrap: "wrap" }}>
      <label className="field">Measured on<input type="date" value={v.measuredOn} onChange={(e) => setV({ ...v, measuredOn: e.target.value })} /></label>
      <label className="field">Value<input type="number" value={v.value} onChange={(e) => setV({ ...v, value: e.target.value })} /></label>
      <label className="field" style={{ flex: 1 }}>Note (optional)<input value={v.note} onChange={(e) => setV({ ...v, note: e.target.value })} /></label>
      <button className="primary" disabled={busy || v.value === "" || !v.measuredOn} onClick={async () => { if (await run(() => api(`isms/objectives/${o.id}/values`, { body: { ...v, value: Number(v.value) } }), "Value recorded")) { setV({ ...v, value: "", note: "" }); onChange(); } }}>Record value</button>
    </div>}
    {manage && o.status === "active" && <>
      <h3>Finish</h3>
      <div className="row" style={{ gap: 8, alignItems: "end", flexWrap: "wrap" }}>
        <label className="field">Outcome<select value={status.status} onChange={(e) => setStatus({ ...status, status: e.target.value })}><option value="">Choose</option><option value="achieved">Achieved</option><option value="retired">Retired</option></select></label>
        <label className="field" style={{ flex: 1 }}>Why<input value={status.note} onChange={(e) => setStatus({ ...status, note: e.target.value })} /></label>
        <button disabled={busy || !status.status || !status.note.trim()} onClick={async () => { if (await run(() => api(`isms/objectives/${o.id}`, { method: "PATCH", body: status }), "Objective updated")) onChange(); }}>Save</button>
      </div>
    </>}
  </Modal>;
}

// Planned changes -----------------------------------------------------------------------------------------------------

const CHANGE_LABEL: Record<string, string> = { planned: "Planned", in_progress: "In progress", done: "Done", cancelled: "Cancelled" };

function Changes({ tenantId, manage }: { tenantId: string; manage: boolean }) {
  const { data, error, reload } = useData<any>("isms/changes", { tenant_id: tenantId }, [tenantId]);
  const [editing, setEditing] = useState<any>(null);
  return <>
    <ErrorNote error={error} />
    <div className="row" style={{ marginBottom: 8 }}><span style={{ flex: 1 }} />{manage && <button className="primary" onClick={() => setEditing({})}>Log a change</button>}</div>
    <p className="small muted">Changes to the ISMS itself (scope, structure, tools, people) are planned here: why, what could go wrong, and what it needs. A finished change records its outcome.</p>
    <Table rows={safeArray<any>(data?.changes)} empty="No changes logged." onRow={manage ? setEditing : undefined} columns={[
      { key: "ref", label: "Ref" },
      { key: "title", label: "Change", render: (c) => <><b>{displayValue(c.title)}</b><div className="small muted">{displayValue(c.purpose)}</div></> },
      { key: "plannedOn", label: "Planned", render: (c) => ddmmyyyy(c.plannedOn) },
      { key: "status", label: "Status", render: (c) => <>{CHANGE_LABEL[c.status] ?? c.status}{c.completedOn ? ` ${ddmmyyyy(c.completedOn)}` : ""}</> },
      { key: "ownerName", label: "Owner", render: (c) => displayValue(c.ownerName ?? "Nobody") }]} />
    {editing && <EditChange tenantId={tenantId} c={editing} onClose={() => { setEditing(null); reload(); }} />}
  </>;
}

function EditChange({ tenantId, c, onClose }: { tenantId: string; c: any; onClose: () => void }) {
  const [f, setF] = useState({ title: c.title ?? "", purpose: c.purpose ?? "", consequences: c.consequences ?? "", resources: c.resources ?? "", ownerId: c.ownerId ?? "",
    plannedOn: c.plannedOn ?? "", status: c.status ?? "planned", completedOn: c.completedOn ?? "", outcome: c.outcome ?? "" });
  const { run, busy } = useAction();
  const finished = f.status === "done" || f.status === "cancelled";
  const body = { ...f, ownerId: f.ownerId || null, plannedOn: f.plannedOn || null, completedOn: finished ? f.completedOn || null : null };
  const save = async () => { if (await run(() => c.id ? api(`isms/changes/${c.id}`, { method: "PATCH", body }) : api("isms/changes", { body: { tenantId, ...body } }), "Change saved")) onClose(); };
  const set = (k: string) => (e: any) => setF({ ...f, [k]: e.target.value });
  return <Modal title={c.id ? `${c.ref}: ${c.title}` : "Log a change"} onClose={onClose} footer={<button className="primary" disabled={busy || !f.title.trim() || !f.purpose.trim() || (finished && (!f.completedOn || !f.outcome.trim()))} onClick={save}>Save</button>}>
    <label className="field">Change<input value={f.title} onChange={set("title")} /></label>
    <label className="field">Purpose<textarea rows={2} value={f.purpose} onChange={set("purpose")} /></label>
    <label className="field">Possible consequences<textarea rows={2} value={f.consequences} onChange={set("consequences")} /></label>
    <label className="field">Resources needed<textarea rows={2} value={f.resources} onChange={set("resources")} /></label>
    <People tenantId={tenantId} label="Owner" none="Nobody yet" value={f.ownerId} onChange={(ownerId) => setF({ ...f, ownerId })} />
    <label className="field">Planned for<input type="date" value={f.plannedOn} onChange={set("plannedOn")} /></label>
    <label className="field">Status<select value={f.status} onChange={set("status")}>{Object.entries(CHANGE_LABEL).map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></label>
    {finished && <>
      <label className="field">Finished on<input type="date" value={f.completedOn} onChange={set("completedOn")} /></label>
      <label className="field">Outcome<textarea rows={2} value={f.outcome} onChange={set("outcome")} /></label>
    </>}
  </Modal>;
}
