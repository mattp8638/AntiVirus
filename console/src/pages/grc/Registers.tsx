// Contextual registers (GRC-18), objectives with KPIs and management reviews (GRC-13).
import { useState } from "react";
import { api, downloadFile, fmtTime } from "../../api";
import { useApp } from "../../app-context";
import { Modal, PageHead, Pill, Table, Tabs, useAction, useListData } from "../../components/ui";
import { COMPLIANCE_SECTION, SectionTabs } from "../../components/sections";

const LEVEL: Record<string, string> = { high: "bad", medium: "warn", low: "good", unscored: "muted" };
const TABS = ["Business risks", "Opportunities", "Interested parties", "Internal and external issues", "PESTEL analysis", "Improvement register", "Objectives", "Management reviews"];
const KEY: Record<string, string> = { "Business risks": "risk", Opportunities: "opportunity", "Interested parties": "interested_party", "Internal and external issues": "issue", "PESTEL analysis": "pestel", "Improvement register": "improvement" };

export default function Registers() {
  const { tenantId } = useApp();
  const [tab, setTab] = useState(TABS[0]);
  return (
    <>
      <SectionTabs items={COMPLIANCE_SECTION} />
      <PageHead title="Registers & reviews" subtitle="Business risks and opportunities, interested parties, context (issues and PESTEL), improvements, objectives with KPIs, and management reviews built from the current records." />
      <Tabs tabs={TABS} active={tab} onChange={setTab} />
      {!tenantId ? <div className="card empty">Choose a customer.</div>
        : KEY[tab] ? <Register tenantId={tenantId} register={KEY[tab]} key={tab} />
        : tab === "Objectives" ? <Objectives tenantId={tenantId} /> : <Reviews tenantId={tenantId} />}
    </>
  );
}

function Register({ tenantId, register }: { tenantId: string; register: string }) {
  const { can } = useApp();
  const { run } = useAction();
  const { data: meta } = useListData<any>("grc/registers");
  const m = meta?.find((x) => x.key === register);
  const { data: rows, reload } = useListData<any>(`grc/registers/${register}`, { tenantId }, [tenantId, register]);
  const { data: exports, reload: reloadEx } = useListData<any>("grc/register-exports", { register, tenantId }, [tenantId, register]);
  const [edit, setEdit] = useState<any>(null);
  return (
    <>
      <div className="row" style={{ gap: 6, marginBottom: 10 }}>
        {can("grc") && <button className="primary" onClick={() => setEdit({})}>Add</button>}
        <button onClick={() => run(() => api(`grc/registers/${register}/exports`, { body: { tenantId } }), "Export kept with its hash").then(reloadEx)}>Export a version</button>
        {exports?.[0] && <button className="small" onClick={() => downloadFile(`grc/register-exports/${exports[0].id}.csv`)}>Latest export ({fmtTime(exports[0].createdAt)})</button>}
      </div>
      <Table rows={rows} onRow={(r) => setEdit(r)} empty="Nothing recorded yet." columns={[
        { key: "ref", label: "Ref" },
        { key: "title", label: "Title", render: (r) => <><b>{r.title}</b>{r.category && <div className="small muted">{r.category}</div>}</> },
        ...(m?.scored ? [{ key: "score", label: "Score (residual)", render: (r: any) => <><Pill value={r.score ?? "—"} tone={LEVEL[r.level]} /> {r.residualScore != null && <Pill value={r.residualScore} tone={LEVEL[r.residualLevel]} />}</> },
          { key: "treatment", label: "Treatment" }] : []),
        { key: "owner", label: "Owner" },
        { key: "status", label: "Status", render: (r) => <>{r.status}{r.reviewOverdue && <Pill value="review overdue" tone="warn" />}</> },
        { key: "openActions", label: "Open actions" }]} />
      {edit && <EntryEditor register={register} meta={m} tenantId={tenantId} entry={edit} onClose={() => { setEdit(null); reload(); }} />}
    </>
  );
}

function EntryEditor({ register, meta, tenantId, entry, onClose }: { register: string; meta: any; tenantId: string; entry: any; onClose: () => void }) {
  const { can } = useApp();
  const { run, busy } = useAction();
  const [f, setF] = useState<any>({ title: "", description: "", category: "", owner: "", status: "open", likelihood: null, impact: null, residualLikelihood: null, residualImpact: null, treatment: "", treatmentPlan: "", reviewDue: "", actions: [], ...entry });
  const [newAction, setNewAction] = useState("");
  const num = (k: string) => <select value={f[k] ?? ""} onChange={(e) => setF({ ...f, [k]: e.target.value ? Number(e.target.value) : null })}><option value="">—</option>{[1, 2, 3, 4, 5].map((n) => <option key={n}>{n}</option>)}</select>;
  const body = { title: f.title, description: f.description, owner: f.owner, status: f.status, treatmentPlan: f.treatmentPlan, reviewDue: f.reviewDue || null, actions: f.actions,
    ...(meta?.categories?.length ? { category: f.category } : {}),
    ...(meta?.scored ? { likelihood: f.likelihood, impact: f.impact, residualLikelihood: f.residualLikelihood, residualImpact: f.residualImpact, treatment: f.treatment } : {}) };
  const save = (reviewed = false) => run(() => entry.id ? api(`grc/registers/${register}/${entry.id}`, { method: "PATCH", body: { ...body, reviewed } }) : api(`grc/registers/${register}`, { body: { tenantId, ...body } }), "Saved").then((r) => r && onClose());
  return (
    <Modal wide title={entry.id ? `${entry.ref} ${entry.title}` : `Add to ${meta?.name ?? register}`} onClose={onClose}
      footer={can("grc") && <>{entry.id && <button disabled={busy} onClick={() => save(true)}>Save as reviewed</button>}<button className="primary" disabled={busy || f.title.trim().length < 3} onClick={() => save()}>Save</button></>}>
      <div className="form-grid">
        <label className="field">Title<input value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} /></label>
        <label className="field">Owner<input value={f.owner} onChange={(e) => setF({ ...f, owner: e.target.value })} /></label>
        <label className="field">Status<select value={f.status} onChange={(e) => setF({ ...f, status: e.target.value })}>{["open", "treating", "accepted", "closed"].map((s) => <option key={s}>{s}</option>)}</select></label>
        {meta?.categories?.length > 0 && <label className="field">Category<select value={f.category} onChange={(e) => setF({ ...f, category: e.target.value })}><option value="">Choose</option>{meta.categories.map((c: string) => <option key={c}>{c}</option>)}</select></label>}
        <label className="field">Review by<input type="date" value={f.reviewDue ?? ""} onChange={(e) => setF({ ...f, reviewDue: e.target.value })} /></label>
        {meta?.scored && <>
          <label className="field">Likelihood (1-5){num("likelihood")}</label><label className="field">Impact (1-5){num("impact")}</label>
          <label className="field">Residual likelihood{num("residualLikelihood")}</label><label className="field">Residual impact{num("residualImpact")}</label>
          <label className="field">Treatment<select value={f.treatment} onChange={(e) => setF({ ...f, treatment: e.target.value })}><option value="">—</option>{meta.treatments.map((t: string) => <option key={t}>{t}</option>)}</select></label>
        </>}
      </div>
      <label className="field">{register === "interested_party" ? "Needs and expectations" : "Description"}<textarea rows={3} value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></label>
      {meta?.scored && <label className="field">Treatment plan<textarea rows={2} value={f.treatmentPlan} onChange={(e) => setF({ ...f, treatmentPlan: e.target.value })} /></label>}
      <h4>Actions</h4>
      {f.actions.map((a: any, i: number) => <label key={a.id ?? i} className="row small" style={{ gap: 6 }}><input type="checkbox" checked={a.done} onChange={() => setF({ ...f, actions: f.actions.map((x: any, j: number) => j === i ? { ...x, done: !x.done, doneAt: !x.done ? new Date().toISOString() : null } : x) })} /> {a.text}{a.owner && ` (${a.owner})`}</label>)}
      {can("grc") && <div className="row" style={{ gap: 6 }}><input value={newAction} onChange={(e) => setNewAction(e.target.value)} placeholder="New action" /><button className="small" disabled={!newAction.trim()} onClick={() => { setF({ ...f, actions: [...f.actions, { text: newAction.trim(), done: false }] }); setNewAction(""); }}>Add</button></div>}
      {entry.id && <p className="small muted">Version {entry.version}{entry.reviewedAt && ` · last reviewed ${fmtTime(entry.reviewedAt)} by ${entry.reviewedBy}`}</p>}
    </Modal>
  );
}

function Objectives({ tenantId }: { tenantId: string }) {
  const { can } = useApp();
  const { run } = useAction();
  const { data, reload } = useListData<any>("grc/objectives", { tenantId }, [tenantId]);
  const [f, setF] = useState({ title: "", kpi: "", unit: "", target: "", direction: "higher" });
  return (
    <>
      {can("grc") && <div className="card"><div className="form-grid">
        <label className="field">Objective<input value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} /></label>
        <label className="field">KPI<input value={f.kpi} onChange={(e) => setF({ ...f, kpi: e.target.value })} placeholder="Staff trained (%)" /></label>
        <label className="field">Target<input value={f.target} onChange={(e) => setF({ ...f, target: e.target.value })} /></label>
        <label className="field">Better is<select value={f.direction} onChange={(e) => setF({ ...f, direction: e.target.value })}><option value="higher">higher</option><option value="lower">lower</option></select></label>
      </div><button className="primary" disabled={f.title.trim().length < 3} onClick={() => run(() => api("grc/objectives", { body: { tenantId, ...f, target: f.target === "" ? null : Number(f.target) } }), "Objective added").then(() => { setF({ title: "", kpi: "", unit: "", target: "", direction: "higher" }); reload(); })}>Add objective</button></div>}
      <Table rows={data} empty="No objectives yet." columns={[
        { key: "title", label: "Objective", render: (o) => <><b>{o.title}</b><div className="small muted">{o.kpi}</div></> },
        { key: "target", label: "Target", render: (o) => o.target != null ? `${o.direction === "lower" ? "≤" : "≥"} ${o.target} ${o.unit}` : "—" },
        { key: "latest", label: "Latest", render: (o) => o.latest ? <>{o.latest.value} {o.unit} <span className="small muted">{fmtTime(o.latest.at)}</span> {o.onTrack != null && <Pill value={o.onTrack ? "on track" : "off track"} tone={o.onTrack ? "good" : "bad"} />}</> : "—" },
        { key: "id", label: "", render: (o) => can("grc") && <button className="small" onClick={() => { const v = window.prompt(`New measurement of ${o.kpi || o.title}`); if (v && !Number.isNaN(Number(v))) run(() => api(`grc/objectives/${o.id}/measurements`, { body: { value: Number(v) } })).then(reload); }}>Record value</button> }]} />
    </>
  );
}

function Reviews({ tenantId }: { tenantId: string }) {
  const { can } = useApp();
  const { run } = useAction();
  const { data, reload } = useListData<any>("grc/reviews", { tenantId }, [tenantId]);
  const [open, setOpen] = useState<string | null>(null);
  return (
    <>
      {can("grc") && <button className="primary" style={{ marginBottom: 10 }} onClick={() => { const t = window.prompt("Title of the review", "Management review"); if (t) run(() => api("grc/reviews", { body: { tenantId, title: t } })).then(reload); }}>Plan a review</button>}
      <Table rows={data} onRow={(r) => setOpen(r.id)} empty="No reviews yet." columns={[
        { key: "title", label: "Review", render: (r) => <b>{r.title}</b> },
        { key: "status", label: "Status", render: (r) => <Pill value={r.status} tone={r.status === "held" ? "good" : "muted"} /> },
        { key: "heldOn", label: "Held", render: (r) => r.heldOn ? fmtTime(r.heldOn) : "—" },
        { key: "actions", label: "Open actions", render: (r) => r.actions.filter((a: any) => !a.done).length }]} />
      {open && <ReviewDetail id={open} rows={data ?? []} onClose={() => { setOpen(null); reload(); }} />}
    </>
  );
}

function ReviewDetail({ id, rows, onClose }: { id: string; rows: any[]; onClose: () => void }) {
  const { can } = useApp();
  const { run, busy } = useAction();
  const [r, setR] = useState<any>(rows.find((x) => x.id === id));
  const [f, setF] = useState({ attendees: "", decisions: "", actions: "" });
  if (!r) return null;
  const pack = r.pack;
  return (
    <Modal wide title={r.title} onClose={onClose} footer={can("grc") && r.status !== "held" && <>
      <button disabled={busy} onClick={() => run(() => api(`grc/reviews/${id}/pack`, { body: {} })).then((x) => x && setR(x))}>{pack ? "Rebuild the pack" : "Build the input pack"}</button>
      <button className="primary" disabled={busy || !pack || !f.attendees.trim()} onClick={() => run(() => api(`grc/reviews/${id}/held`, { body: {
        attendees: f.attendees.split(",").map((x) => x.trim()).filter(Boolean), decisions: f.decisions.split("\n").filter((x) => x.trim()),
        actions: f.actions.split("\n").filter((x) => x.trim()).map((x) => { const [text, owner] = x.split("|"); return { text: text.trim(), owner: (owner ?? "").trim() }; }) } }), "Review recorded").then((x) => x && setR(x))}>Record the meeting</button></>}>
      {!pack ? <p className="small muted">Build the input pack: it is made from the records as they are now, and kept (with its hash) once the review is held.</p> : <>
        <p className="small muted">Pack generated {fmtTime(pack.generatedAt)} · SHA-256 {r.packSha256.slice(0, 16)}…{pack.since && ` · covers since ${fmtTime(pack.since)}`}</p>
        <div className="grid k3 small">
          <div className="card"><b>Programmes</b>{pack.programmes.map((p: any) => <div key={p.framework}>{p.framework}: {Object.entries(p.requirements).map(([k, v]) => `${v} ${k}`).join(", ")}</div>)}</div>
          <div className="card"><b>Policies</b><div>{pack.policies.approved}/{pack.policies.total} approved; {pack.policies.acknowledgement.current}/{pack.policies.acknowledgement.asked} acknowledgements current</div>{pack.policies.reviewOverdue.length > 0 && <div>Review overdue: {pack.policies.reviewOverdue.join(", ")}</div>}</div>
          <div className="card"><b>Incidents</b><div>{Object.entries(pack.incidents).map(([k, v]) => `${v} ${k}`).join(", ") || "none"}</div></div>
        </div>
        <h4>Top risks</h4>
        <Table rows={pack.topRisks} empty="No open risks." columns={[{ key: "ref", label: "Ref" }, { key: "title", label: "Risk" }, { key: "score", label: "Score" }, { key: "residualScore", label: "Residual" }, { key: "owner", label: "Owner" }]} />
        <h4>Objectives</h4>
        {pack.objectives.map((o: any) => <div key={o.id} className="small">{o.title}: {o.latest ? `${o.latest.value} ${o.unit}` : "not measured"} (target {o.target ?? "—"}) {o.onTrack != null && <Pill value={o.onTrack ? "on track" : "off track"} tone={o.onTrack ? "good" : "bad"} />}</div>)}
        <h4>Business continuity</h4>
        {pack.continuity.map((c: any) => <div key={c.plan} className="small">{c.plan} ({c.status}): {Object.entries(c.services).map(([k, v]) => `${v} ${k}`).join(", ")}</div>)}
        {pack.previousReview && <><h4>Open actions from {pack.previousReview.title}</h4>{pack.previousReview.openActions.map((a: any) => <div key={a.id} className="small">{a.text} ({a.owner})</div>)}</>}
      </>}
      {r.status === "held" ? <>
        <h4>Held {fmtTime(r.heldOn)} · {r.attendees.join(", ")}</h4>
        <b className="small">Decisions</b>{r.decisions.map((d: any) => <div key={d.id} className="small">• {d.text}</div>)}
        <b className="small">Actions</b>{r.actions.map((a: any) => <label key={a.id} className="row small" style={{ gap: 6 }}><input type="checkbox" checked={a.done} disabled={!can("grc")} onChange={() => run(() => api(`grc/reviews/${id}/actions/${a.id}`, { method: "PATCH", body: { done: !a.done } })).then((x) => x && setR(x))} /> {a.text}{a.owner && ` (${a.owner})`}</label>)}
      </> : can("grc") && pack && <>
        <label className="field">Attendees (comma-separated)<input value={f.attendees} onChange={(e) => setF({ ...f, attendees: e.target.value })} /></label>
        <label className="field">Decisions (one per line)<textarea rows={3} value={f.decisions} onChange={(e) => setF({ ...f, decisions: e.target.value })} /></label>
        <label className="field">Actions (one per line, "text | owner")<textarea rows={3} value={f.actions} onChange={(e) => setF({ ...f, actions: e.target.value })} /></label>
      </>}
    </Modal>
  );
}
