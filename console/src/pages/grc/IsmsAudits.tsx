import { useState } from "react";
import { api } from "../../api";
import { useApp } from "../../app-context";
import { displayValue } from "../../components/DisplayValue";
import { ErrorNote, Modal, Pill, Table, useAction, useData } from "../../components/ui";
import { safeArray } from "../../data-shapes";

/** Internal audit (ISO 27001 9.2): programmes, audits, checklists, results, findings and sampling. */

const RESULT_LABEL: Record<string, string> = { conforms: "Conforms", observation: "Observation", minor: "Minor nonconformity", major: "Major nonconformity", not_assessed: "Not assessed" };
const RESULT_TONE: Record<string, string> = { conforms: "ok", observation: "warn", minor: "bad", major: "bad", not_assessed: "muted" };
const STATUS_LABEL: Record<string, string> = { planned: "Planned", in_progress: "In progress", completed: "Completed" };
const ddmmyyyy = (iso?: string | null) => iso ? `${iso.slice(8, 10)}/${iso.slice(5, 7)}/${iso.slice(0, 4)}` : "";

export function IsmsAuditsTab() {
  const { tenantId } = useApp();
  const { data: me } = useData<any>(tenantId ? "isms/me" : null, { tenant_id: tenantId }, [tenantId]);
  const perms = safeArray<string>(me?.permissions);
  const allowed = perms.includes("controls.view");
  const { data, error, reload } = useData<any>(tenantId && allowed ? "isms/audit-programmes" : null, { tenant_id: tenantId }, [tenantId, allowed]);
  const [editProg, setEditProg] = useState<any>(null);
  const [planFor, setPlanFor] = useState<any>(null);
  const [auditId, setAuditId] = useState<string | null>(null);
  const [sampling, setSampling] = useState(false);
  if (!tenantId) return <p className="muted">Choose a customer in the tenant picker to see its internal audits.</p>;
  if (!allowed) return me ? <p className="muted">Your ISMS role in this customer ({displayValue(me.role ?? "none")}) cannot see internal audits.</p> : null;
  const canPlan = !!data?.canPlan, canAudit = !!data?.canAudit;
  const programmes = safeArray<any>(data?.programmes);
  return <div className="card">
    <ErrorNote error={error} />
    <div className="row" style={{ gap: 8, marginBottom: 8 }}>
      <p className="small muted" style={{ flex: 1, margin: 0 }}>An audit programme covers a period. Each audit gets a checklist of every clause and every applicable requirement of the frameworks it covers; coverage shows how much of that the programme's audits have checked.</p>
      {canAudit && <button onClick={() => setSampling(true)}>Draw a sample</button>}
      {canPlan && <button className="primary" onClick={() => setEditProg({})}>Add programme</button>}
    </div>
    {programmes.length === 0 && <p className="muted">No audit programmes yet.</p>}
    {programmes.map((p) => <section key={p.id} style={{ marginBottom: 16 }}>
      <div className="row" style={{ gap: 8, alignItems: "baseline" }}>
        <h3 style={{ margin: 0 }}>{displayValue(p.title)}</h3>
        <span className="small muted">{ddmmyyyy(p.periodStart)} to {ddmmyyyy(p.periodEnd)}</span>
        <span style={{ flex: 1 }} />
        <span className="small" aria-label={`Coverage ${p.coverage.percent} per cent`}>Coverage {p.coverage.covered} of {p.coverage.required} ({p.coverage.percent}%)</span>
        {canPlan && <button onClick={() => setEditProg(p)}>Edit</button>}
        {canPlan && <button onClick={() => setPlanFor(p)}>Plan an audit</button>}
      </div>
      {p.objectives && <p className="small">{displayValue(p.objectives)}</p>}
      <Table rows={p.audits} empty="No audits planned." onRow={(a) => setAuditId(a.id)} columns={[
        { key: "ref", label: "Ref" }, { key: "title", label: "Audit", render: (a) => <b>{displayValue(a.title)}</b> },
        { key: "plannedStart", label: "Dates", render: (a) => `${ddmmyyyy(a.plannedStart)} to ${ddmmyyyy(a.plannedEnd)}` },
        { key: "leadAuditorName", label: "Lead auditor", render: (a) => displayValue(a.leadAuditorName ?? "Not set") },
        { key: "checks", label: "Checklist", render: (a) => `${a.checks} items, ${a.findings} findings` },
        { key: "status", label: "Status", render: (a) => STATUS_LABEL[a.status] ?? a.status }]} />
    </section>)}
    {editProg && <EditProgramme tenantId={tenantId} p={editProg} onClose={() => { setEditProg(null); reload(); }} />}
    {planFor && <EditAudit tenantId={tenantId} programme={planFor} frameworks={safeArray<string>(data?.frameworks)} onClose={(id) => { setPlanFor(null); reload(); if (id) setAuditId(id); }} />}
    {auditId && <AuditDetail id={auditId} tenantId={tenantId} canPlan={canPlan} canAudit={canAudit} groups={safeArray<any>(data?.groups)} frameworks={safeArray<string>(data?.frameworks)} onClose={() => { setAuditId(null); reload(); }} />}
    {sampling && <Sampler tenantId={tenantId} onClose={() => setSampling(false)} />}
  </div>;
}

function EditProgramme({ tenantId, p, onClose }: { tenantId: string; p: any; onClose: () => void }) {
  const [f, setF] = useState({ title: p.title ?? "", periodStart: p.periodStart ?? "", periodEnd: p.periodEnd ?? "", objectives: p.objectives ?? "" });
  const { run, busy } = useAction();
  const save = async () => { if (await run(() => p.id ? api(`isms/audit-programmes/${p.id}`, { method: "PATCH", body: f }) : api("isms/audit-programmes", { body: { tenantId, ...f } }), "Programme saved")) onClose(); };
  return <Modal title={p.id ? "Edit audit programme" : "Add an audit programme"} onClose={onClose} footer={<button className="primary" disabled={busy || !f.title.trim() || !f.periodStart || !f.periodEnd} onClick={save}>Save</button>}>
    <label className="field">Title<input value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} /></label>
    <label className="field">From<input type="date" value={f.periodStart} onChange={(e) => setF({ ...f, periodStart: e.target.value })} /></label>
    <label className="field">To<input type="date" value={f.periodEnd} onChange={(e) => setF({ ...f, periodEnd: e.target.value })} /></label>
    <label className="field">Objectives<textarea rows={3} value={f.objectives} onChange={(e) => setF({ ...f, objectives: e.target.value })} /></label>
  </Modal>;
}

function EditAudit({ tenantId, programme, audit, frameworks, onClose }: { tenantId: string; programme?: any; audit?: any; frameworks: string[]; onClose: (id?: string) => void }) {
  const a = audit ?? {};
  const { data: people } = useData<any>("isms/members", { tenant_id: tenantId }, [tenantId]);
  const [f, setF] = useState({ title: a.title ?? "", scope: a.scope ?? "", frameworks: a.frameworks ?? frameworks.slice(0, 1), plannedStart: a.plannedStart ?? "", plannedEnd: a.plannedEnd ?? "",
    leadAuditorId: a.leadAuditorId ?? "", otherAuditors: a.otherAuditors ?? "", independenceNote: a.independenceNote ?? "" });
  const { run, busy } = useAction();
  const body = { ...f, leadAuditorId: f.leadAuditorId || null };
  const save = async () => {
    const r: any = await run(() => a.id ? api(`isms/audits/${a.id}`, { method: "PATCH", body }) : api(`isms/audit-programmes/${programme.id}/audits`, { body }), "Audit saved");
    if (r) onClose(r.id);
  };
  const toggle = (fw: string) => setF({ ...f, frameworks: f.frameworks.includes(fw) ? f.frameworks.filter((x: string) => x !== fw) : [...f.frameworks, fw] });
  return <Modal title={a.id ? `Edit ${a.ref}` : `Plan an audit in ${programme.title}`} onClose={() => onClose()} footer={<button className="primary" disabled={busy || !f.title.trim() || !f.plannedStart || !f.plannedEnd || !f.frameworks.length} onClick={save}>Save</button>}>
    <label className="field">Title<input value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} /></label>
    <fieldset><legend className="small">Frameworks</legend>{frameworks.map((fw) => <label key={fw} className="small" style={{ marginRight: 12 }}><input type="checkbox" checked={f.frameworks.includes(fw)} onChange={() => toggle(fw)} /> {fw}</label>)}</fieldset>
    <label className="field">Scope<textarea rows={2} value={f.scope} onChange={(e) => setF({ ...f, scope: e.target.value })} /></label>
    <label className="field">Starts<input type="date" value={f.plannedStart} onChange={(e) => setF({ ...f, plannedStart: e.target.value })} /></label>
    <label className="field">Ends<input type="date" value={f.plannedEnd} onChange={(e) => setF({ ...f, plannedEnd: e.target.value })} /></label>
    <label className="field">Lead auditor<select value={f.leadAuditorId} onChange={(e) => setF({ ...f, leadAuditorId: e.target.value })}>
      <option value="">Not set</option>{safeArray<any>(people?.members).map((m) => <option key={m.id} value={m.id}>{m.name ? `${m.name} (${m.email})` : m.email}</option>)}</select></label>
    <label className="field">Other auditors<input value={f.otherAuditors} onChange={(e) => setF({ ...f, otherAuditors: e.target.value })} /></label>
    <label className="field">Independence<textarea rows={2} value={f.independenceNote} placeholder="How the auditors are independent of the areas they audit" onChange={(e) => setF({ ...f, independenceNote: e.target.value })} /></label>
  </Modal>;
}

function AuditDetail({ id, tenantId, canPlan, canAudit, groups, frameworks, onClose }: { id: string; tenantId: string; canPlan: boolean; canAudit: boolean; groups: any[]; frameworks: string[]; onClose: () => void }) {
  const { data: a, error, reload } = useData<any>(`isms/audits/${id}`, {}, [id]);
  const { run, busy } = useAction();
  const [picked, setPicked] = useState<string[]>([]);
  const [editing, setEditing] = useState(false);
  const [checkId, setCheckId] = useState<string | null>(null);
  const [summary, setSummary] = useState("");
  if (!a) return <Modal title="Audit" onClose={onClose}><ErrorNote error={error} /></Modal>;
  const act = async (fn: () => Promise<any>, msg: string) => { if (await run(fn, msg)) reload(); };
  const check = safeArray<any>(a.checks).find((c) => c.id === checkId);
  const own = groups.filter((g) => a.frameworks.includes(g.framework));
  return <Modal title={`${a.ref}: ${a.title}`} wide onClose={onClose}>
    <ErrorNote error={error} />
    <p className="small">{STATUS_LABEL[a.status]}. {ddmmyyyy(a.plannedStart)} to {ddmmyyyy(a.plannedEnd)}, {a.frameworks.join(", ")}. Lead auditor: {displayValue(a.leadAuditorName ?? "not set")}{a.otherAuditors ? `, with ${a.otherAuditors}` : ""}.</p>
    {a.scope && <p className="small">{displayValue(a.scope)}</p>}
    <p className="small"><b>Independence:</b> {displayValue(a.independenceNote || "Not recorded yet.")}</p>
    {canPlan && a.status !== "completed" && <div className="row" style={{ gap: 8, flexWrap: "wrap", alignItems: "end" }}>
      <button onClick={() => setEditing(true)}>Edit details</button>
      <label className="field">Limit the checklist to (optional)<select multiple size={Math.min(6, own.length || 1)} value={picked} onChange={(e) => setPicked(Array.from(e.target.selectedOptions).map((o) => o.value))}>
        {own.map((g) => <option key={`${g.framework}:${g.ref}`} value={g.ref}>{g.framework}: {g.title}</option>)}</select></label>
      <button disabled={busy} onClick={() => act(() => api(`isms/audits/${id}/checklist`, { body: { groups: picked } }), "Checklist ready")}>{a.checks.length ? "Refresh checklist" : "Generate checklist"}</button>
      {a.status === "planned" && <button disabled={busy} onClick={async () => { if (confirm(`Delete ${a.ref}?`) && await run(() => api(`isms/audits/${id}`, { method: "DELETE" }), "Audit deleted")) onClose(); }}>Delete</button>}
    </div>}
    {canAudit && a.status === "planned" && a.checks.length > 0 && <p><button className="primary" disabled={busy} onClick={() => act(() => api(`isms/audits/${id}/start`, { body: {} }), "Audit started")}>Start the audit</button></p>}
    <p className="small">Results: {a.counts.conforms} conform, {a.counts.observation} observations, {a.counts.minor} minor, {a.counts.major} major, {a.counts.notAssessed} not assessed, {a.counts.open} still to check.</p>
    <Table rows={a.checks} empty="No checklist yet." onRow={(c) => setCheckId(c.id)} columns={[
      { key: "ref", label: "Ref", render: (c) => <>{c.ref}{c.mandatory && <span className="small muted"> (clause)</span>}</> },
      { key: "title", label: "Requirement", render: (c) => <>{displayValue(c.title)}<div className="small muted">{displayValue(c.groupTitle)}{c.controls ? `; ${c.controls}` : ""}</div></> },
      { key: "result", label: "Result", render: (c) => c.result ? <Pill value={RESULT_LABEL[c.result]} tone={RESULT_TONE[c.result]} /> : <span className="muted">To check</span> },
      { key: "findings", label: "Finding", render: (c) => c.findings.map((f: any) => f.ref).join(", ") }]} />
    {a.status === "completed" ? <p className="small"><b>Summary:</b> {displayValue(a.summary)}</p> : canAudit && a.status === "in_progress" && <>
      <h3>Complete</h3>
      {a.blockers.length > 0 && <p className="small muted">Before completing: {a.blockers.filter((b: string) => b !== "Write the audit summary.").join(" ")}</p>}
      <label className="field">Audit summary<textarea rows={3} value={summary} onChange={(e) => setSummary(e.target.value)} /></label>
      <button className="primary" disabled={busy || !summary.trim()} onClick={() => act(() => api(`isms/audits/${id}/complete`, { body: { summary } }), "Audit completed")}>Complete the audit</button>
    </>}
    {editing && <EditAudit tenantId={tenantId} audit={a} frameworks={frameworks} onClose={() => { setEditing(false); reload(); }} />}
    {check && <CheckDetail c={check} tenantId={tenantId} editable={canAudit && a.status === "in_progress"} onSaved={reload} onClose={() => setCheckId(null)} />}
  </Modal>;
}

function CheckDetail({ c, tenantId, editable, onSaved, onClose }: { c: any; tenantId: string; editable: boolean; onSaved: () => void; onClose: () => void }) {
  const { data: people } = useData<any>(editable ? "isms/members" : null, { tenant_id: tenantId }, [tenantId]);
  const [f, setF] = useState({ result: c.result ?? "", notes: c.notes ?? "", evidenceSeen: c.evidenceSeen ?? "" });
  const [owner, setOwner] = useState("");
  const { run, busy } = useAction();
  const finding = ["observation", "minor", "major"].includes(c.result) && c.findings.length === 0;
  const save = async () => { if (await run(() => api(`isms/audit-checks/${c.id}`, { method: "PUT", body: f }), "Result saved")) onSaved(); };
  return <Modal title={`${c.ref}: ${c.title}`} onClose={onClose} footer={editable && <button className="primary" disabled={busy || !f.result || (["observation", "minor", "major"].includes(f.result) && !f.notes.trim())} onClick={save}>Save result</button>}>
    {c.controls && <p className="small">Controls: {c.controls}</p>}
    {c.checkedAt && <p className="small muted">Last recorded by {displayValue(c.checkedByName ?? "")}.</p>}
    {editable ? <>
      <label className="field">Result<select value={f.result} onChange={(e) => setF({ ...f, result: e.target.value })}><option value="">Choose</option>{Object.entries(RESULT_LABEL).map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></label>
      <label className="field">What was found<textarea rows={3} value={f.notes} onChange={(e) => setF({ ...f, notes: e.target.value })} /></label>
      <label className="field">Evidence seen<textarea rows={2} value={f.evidenceSeen} onChange={(e) => setF({ ...f, evidenceSeen: e.target.value })} /></label>
    </> : <>
      <p className="small">{c.result ? RESULT_LABEL[c.result] : "Not checked yet."}</p>
      {c.notes && <p className="small">{displayValue(c.notes)}</p>}
      {c.evidenceSeen && <p className="small"><b>Evidence seen:</b> {displayValue(c.evidenceSeen)}</p>}
    </>}
    {c.findings.length > 0 && <p className="small">Raised as {c.findings.map((x: any) => `${x.ref} (${x.status})`).join(", ")}; follow it up on the ISMS improvement tab.</p>}
    {editable && finding && <div className="row" style={{ gap: 8, alignItems: "end" }}>
      <label className="field" style={{ flex: 1 }}>Finding owner<select value={owner} onChange={(e) => setOwner(e.target.value)}><option value="">Nobody yet</option>
        {safeArray<any>(people?.members).map((m) => <option key={m.id} value={m.id}>{m.name ? `${m.name} (${m.email})` : m.email}</option>)}</select></label>
      <button disabled={busy} onClick={async () => { if (await run(() => api(`isms/audit-checks/${c.id}/finding`, { body: { ownerId: owner || null } }), "Finding raised")) onSaved(); }}>{c.result === "observation" ? "Raise as an improvement" : "Raise a nonconformity"}</button>
    </div>}
  </Modal>;
}

function Sampler({ tenantId, onClose }: { tenantId: string; onClose: () => void }) {
  const [population, setPopulation] = useState("");
  const [seed, setSeed] = useState("");
  const [size, setSize] = useState("");
  const [out, setOut] = useState<any>(null);
  const { run, busy } = useAction();
  const draw = async () => {
    const r = await run(() => api("isms/audit-sample", { body: { tenantId, population: population.split("\n"), seed, size: size ? Number(size) : null } }));
    if (r) setOut(r);
  };
  return <Modal title="Draw a sample" onClose={onClose} footer={<button className="primary" disabled={busy || !population.trim() || !seed.trim()} onClick={draw}>Draw</button>}>
    <p className="small muted">The same list, size and seed always give the same sample, so anyone can draw it again to check. Nothing is stored.</p>
    <label className="field">Population, one item per line<textarea rows={6} value={population} onChange={(e) => setPopulation(e.target.value)} /></label>
    <label className="field">Seed<input value={seed} placeholder="For example AUD-001 A.6.5" onChange={(e) => setSeed(e.target.value)} /></label>
    <label className="field">Sample size (blank for the suggested size)<input type="number" min={1} value={size} onChange={(e) => setSize(e.target.value)} /></label>
    {out && <div aria-live="polite"><p className="small">{out.size} of {out.population} (suggested {out.suggested}), seed "{out.seed}":</p><ol className="small">{out.items.map((x: string) => <li key={x}>{x}</li>)}</ol></div>}
  </Modal>;
}
