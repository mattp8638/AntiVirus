import { useState } from "react";
import { api, fmtTime } from "../../api";
import { useApp } from "../../app-context";
import { displayValue } from "../../components/DisplayValue";
import { ErrorNote, Modal, Pill, Table, useAction, useData } from "../../components/ui";
import { safeArray } from "../../data-shapes";

/** Privacy (UK GDPR): records of processing, DPIAs and data subject requests. */

const ddmmyyyy = (iso?: string | null) => iso ? `${iso.slice(8, 10)}/${iso.slice(5, 7)}/${iso.slice(0, 4)}` : "";
const ROLE_LABEL: Record<string, string> = { controller: "Controller", processor: "Processor", joint_controller: "Joint controller" };
const OUTCOME_LABEL: Record<string, string> = { proceed: "Proceed", proceed_with_measures: "Proceed with the measures", do_not_proceed: "Do not proceed" };
const LEVEL_TONE: Record<string, string> = { low: "ok", medium: "warn", high: "bad" };
const splitList = (s: string) => s.split(",").map((x) => x.trim()).filter(Boolean);

export function IsmsPrivacyTab() {
  const { tenantId } = useApp();
  const { data: me } = useData<any>(tenantId ? "isms/me" : null, { tenant_id: tenantId }, [tenantId]);
  const allowed = safeArray<string>(me?.permissions).includes("controls.view");
  const { data, error, reload } = useData<any>(tenantId && allowed ? "isms/privacy" : null, { tenant_id: tenantId }, [tenantId, allowed]);
  const [view, setView] = useState("processing");
  if (!tenantId) return <p className="muted">Choose a customer in the tenant picker to see its privacy records.</p>;
  if (!allowed) return me ? <p className="muted">Your ISMS role in this customer ({displayValue(me.role ?? "none")}) cannot see privacy records.</p> : null;
  const s = data?.summary;
  return <div className="card">
    <ErrorNote error={error} />
    {s && <p className="small">{s.activities} processing activities, {s.withGaps} to fix, {s.dpiasNeeded} needing a DPIA; {s.openRequests} open requests, {s.overdueRequests} overdue, {s.dueThisWeek} due within a week.</p>}
    <label className="field" style={{ maxWidth: 280 }}>Show<select value={view} onChange={(e) => setView(e.target.value)}>
      <option value="processing">Records of processing</option><option value="dpias">DPIAs</option><option value="requests">Data subject requests</option></select></label>
    {view === "processing" && <Processing data={data} tenantId={tenantId} onChange={reload} />}
    {view === "dpias" && <Dpias data={data} onChange={reload} />}
    {view === "requests" && <Requests data={data} tenantId={tenantId} onChange={reload} />}
  </div>;
}

// Records of processing -----------------------------------------------------------------------------------------------

function Processing({ data, tenantId, onChange }: { data: any; tenantId: string; onChange: () => void }) {
  const [editing, setEditing] = useState<any>(null);
  const { run, busy } = useAction();
  const manage = !!data?.canManage;
  return <>
    <div className="row" style={{ marginBottom: 8 }}><p className="small muted" style={{ flex: 1, margin: 0 }}>What personal data the customer processes, why, on what lawful basis, who receives it and how long it is kept. A record is reviewed every year; the DPIA screening says when an impact assessment is needed.</p>
      {manage && <button className="primary" onClick={() => setEditing({})}>Add activity</button>}</div>
    <Table rows={safeArray<any>(data?.processing)} empty="No processing activities recorded." onRow={manage ? setEditing : undefined} columns={[
      { key: "ref", label: "Ref" },
      { key: "name", label: "Activity", render: (p) => <><b>{displayValue(p.name)}</b><div className="small muted">{ROLE_LABEL[p.role]}{p.lawfulBasis ? `, ${safeArray<any>(data?.options?.lawfulBases).find((b) => b.key === p.lawfulBasis)?.label ?? p.lawfulBasis}` : ""}</div></> },
      { key: "gaps", label: "To fix", render: (p) => p.status === "retired" ? "Retired" : p.gaps.length ? <ul className="small" style={{ margin: 0, paddingLeft: 16 }}>{p.gaps.map((g: string) => <li key={g}>{g}</li>)}</ul> : <Pill value="complete" tone="ok" /> },
      { key: "dpias", label: "DPIA", render: (p) => p.dpias.length ? p.dpias.map((d: any) => `${d.ref} (${d.status})`).join(", ") : p.dpiaRequired ? <Pill value="needed" tone="warn" /> : "Not needed" },
      { key: "nextReviewOn", label: "Review", render: (p) => <>{ddmmyyyy(p.nextReviewOn)}{p.reviewOverdue && <> <Pill value="overdue" tone="bad" /></>}</> },
      ...(manage ? [{ key: "id", label: "", render: (p: any) => p.status === "active" && <div className="row" style={{ gap: 4 }}>
        <button className="small" disabled={busy} onClick={async (e) => { e.stopPropagation(); if (await run(() => api(`isms/privacy/processing/${p.id}`, { method: "PATCH", body: { reviewed: true } }), "Marked as reviewed")) onChange(); }}>Reviewed</button>
        {(p.dpiaRequired || p.dpias.length > 0) && !p.dpias.some((d: any) => d.status === "draft") && <button className="small" disabled={busy} onClick={async (e) => { e.stopPropagation(); if (await run(() => api(`isms/privacy/processing/${p.id}/dpia`, { body: {} }), "DPIA started; open it under DPIAs")) onChange(); }}>Start DPIA</button>}
      </div> }] : [])]} />
    {editing && <EditProcessing tenantId={tenantId} p={editing} options={data?.options} onClose={() => { setEditing(null); onChange(); }} />}
  </>;
}

function EditProcessing({ tenantId, p, options, onClose }: { tenantId: string; p: any; options: any; onClose: () => void }) {
  const { data: people } = useData<any>("isms/members", { tenant_id: tenantId }, [tenantId]);
  const { data: sup } = useData<any>("isms/suppliers", { tenant_id: tenantId }, [tenantId]);
  const [f, setF] = useState({ name: p.name ?? "", purpose: p.purpose ?? "", role: p.role ?? "controller", lawfulBasis: p.lawfulBasis ?? "", specialCategory: !!p.specialCategory,
    specialCondition: p.specialCondition ?? "", criminalData: !!p.criminalData, dataSubjects: safeArray<string>(p.dataSubjects).join(", "), dataCategories: safeArray<string>(p.dataCategories).join(", "),
    recipients: p.recipients ?? "", transfers: !!p.transfers, transferCountries: p.transferCountries ?? "", transferSafeguard: p.transferSafeguard ?? "", retention: p.retention ?? "",
    systems: p.systems ?? "", ownerId: p.ownerId ?? "", supplierIds: safeArray<string>(p.supplierIds), screening: (p.screening ?? {}) as Record<string, boolean> });
  const { run, busy } = useAction();
  const set = (k: string) => (e: any) => setF({ ...f, [k]: e.target.type === "checkbox" ? e.target.checked : e.target.value });
  const body = { ...f, lawfulBasis: f.lawfulBasis || null, transferSafeguard: f.transferSafeguard || null, ownerId: f.ownerId || null,
    dataSubjects: splitList(f.dataSubjects), dataCategories: splitList(f.dataCategories) };
  const save = async () => { if (await run(() => p.id ? api(`isms/privacy/processing/${p.id}`, { method: "PATCH", body }) : api("isms/privacy/processing", { body: { tenantId, ...body } }), "Saved")) onClose(); };
  const retire = async () => { if (await run(() => api(`isms/privacy/processing/${p.id}`, { method: "PATCH", body: { status: p.status === "retired" ? "active" : "retired" } }), "Saved")) onClose(); };
  return <Modal title={p.id ? `${p.ref}: ${p.name}` : "Add a processing activity"} wide onClose={onClose} footer={<>{p.id && <button disabled={busy} onClick={retire}>{p.status === "retired" ? "Make active again" : "Retire"}</button>}<button className="primary" disabled={busy || f.name.trim().length < 3} onClick={save}>Save</button></>}>
    <label className="field">Activity<input value={f.name} onChange={set("name")} /></label>
    <label className="field">Purpose<textarea rows={2} value={f.purpose} onChange={set("purpose")} /></label>
    <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
      <label className="field">The customer's role<select value={f.role} onChange={set("role")}>{safeArray<string>(options?.roles).map((r) => <option key={r} value={r}>{ROLE_LABEL[r]}</option>)}</select></label>
      <label className="field">Lawful basis<select value={f.lawfulBasis} onChange={set("lawfulBasis")}><option value="">Not chosen</option>{safeArray<any>(options?.lawfulBases).map((b) => <option key={b.key} value={b.key}>{b.label}</option>)}</select></label>
    </div>
    <label className="small"><input type="checkbox" checked={f.specialCategory} onChange={set("specialCategory")} /> Special category data (health, ethnicity, beliefs and so on)</label>
    {f.specialCategory && <label className="field">Article 9 condition<input value={f.specialCondition} onChange={set("specialCondition")} /></label>}
    <label className="small" style={{ display: "block" }}><input type="checkbox" checked={f.criminalData} onChange={set("criminalData")} /> Criminal offence data</label>
    <label className="field">People (comma separated)<input value={f.dataSubjects} onChange={set("dataSubjects")} placeholder="Staff, customers" /></label>
    <label className="field">Personal data (comma separated)<input value={f.dataCategories} onChange={set("dataCategories")} placeholder="Contact details, bank details" /></label>
    <label className="field">Recipients<input value={f.recipients} onChange={set("recipients")} /></label>
    <fieldset><legend className="small">Suppliers that receive it (from third-party risk)</legend>{safeArray<any>(sup?.suppliers).length === 0 ? <p className="small muted">No suppliers in third-party risk.</p>
      : safeArray<any>(sup?.suppliers).map((s) => <label key={s.id} className="small" style={{ display: "block" }}><input type="checkbox" checked={f.supplierIds.includes(s.id)} onChange={() => setF({ ...f, supplierIds: f.supplierIds.includes(s.id) ? f.supplierIds.filter((x) => x !== s.id) : [...f.supplierIds, s.id] })} /> {s.name}</label>)}</fieldset>
    <label className="small"><input type="checkbox" checked={f.transfers} onChange={set("transfers")} /> Sent outside the UK</label>
    {f.transfers && <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
      <label className="field">Countries<input value={f.transferCountries} onChange={set("transferCountries")} /></label>
      <label className="field">Safeguard<select value={f.transferSafeguard} onChange={set("transferSafeguard")}><option value="">Not chosen</option>{safeArray<any>(options?.safeguards).map((x) => <option key={x.key} value={x.key}>{x.label}</option>)}</select></label>
    </div>}
    <label className="field">Kept for<input value={f.retention} onChange={set("retention")} placeholder="For example 6 years after employment ends" /></label>
    <label className="field">Systems<input value={f.systems} onChange={set("systems")} /></label>
    <label className="field">Owner<select value={f.ownerId} onChange={set("ownerId")}><option value="">Nobody yet</option>{safeArray<any>(people?.members).map((m) => <option key={m.id} value={m.id}>{m.name || m.email}</option>)}</select></label>
    <fieldset><legend className="small">DPIA screening: tick what applies (one marked strong, or any two, means a DPIA is needed)</legend>
      {safeArray<any>(options?.screening).map((q) => <label key={q.key} className="small" style={{ display: "block" }}><input type="checkbox" checked={!!f.screening[q.key]} onChange={(e) => setF({ ...f, screening: { ...f.screening, [q.key]: e.target.checked } })} /> {q.text}{q.strong ? " (strong)" : ""}</label>)}
    </fieldset>
  </Modal>;
}

// DPIAs ---------------------------------------------------------------------------------------------------------------

function Dpias({ data, onChange }: { data: any; onChange: () => void }) {
  const [openId, setOpenId] = useState<string | null>(null);
  const rows = safeArray<any>(data?.dpias);
  const open = rows.find((d) => d.id === openId);
  return <>
    <p className="small muted">Start a DPIA from its processing activity. An approved DPIA is a record and never changes; to review one, start a new DPIA. A high residual risk means consulting the regulator before the processing starts.</p>
    <Table rows={rows} empty="No DPIAs yet." onRow={(d) => setOpenId(d.id)} columns={[
      { key: "ref", label: "Ref" }, { key: "title", label: "DPIA", render: (d) => <><b>{displayValue(d.title)}</b><div className="small muted">{d.processingRef} {displayValue(d.processingName)}</div></> },
      { key: "outcome", label: "Outcome", render: (d) => d.outcome ? OUTCOME_LABEL[d.outcome] : "Not decided" },
      { key: "priorConsultation", label: "Regulator", render: (d) => d.priorConsultation ? <Pill value="consult first" tone="bad" /> : "" },
      { key: "status", label: "Status", render: (d) => d.status === "approved" ? `Approved ${ddmmyyyy(d.approvedAt)}` : "Draft" }]} />
    {open && <DpiaDetail d={open} manage={!!data?.canManage} canApprove={!!data?.canApprove} onChange={onChange} onClose={() => setOpenId(null)} />}
  </>;
}

function DpiaDetail({ d, manage, canApprove, onChange, onClose }: { d: any; manage: boolean; canApprove: boolean; onChange: () => void; onClose: () => void }) {
  const editable = manage && d.status === "draft";
  const [f, setF] = useState({ title: d.title, description: d.description, necessity: d.necessity, consultation: d.consultation, dpoAdvice: d.dpoAdvice, outcome: d.outcome ?? "",
    risks: d.risks.length ? d.risks.map((r: any) => ({ description: r.description, likelihood: r.likelihood, severity: r.severity, measures: r.measures, residual: r.residual })) : [{ description: "", likelihood: "medium", severity: "medium", measures: "", residual: "low" }] });
  const { run, busy } = useAction();
  const save = async () => { if (await run(() => api(`isms/privacy/dpias/${d.id}`, { method: "PUT", body: { ...f, outcome: f.outcome || null } }), "DPIA saved")) onChange(); };
  const approve = async () => { if (await run(() => api(`isms/privacy/dpias/${d.id}/approve`, { body: {} }), "DPIA approved")) onChange(); };
  const setRisk = (i: number, k: string, v: string) => setF({ ...f, risks: f.risks.map((r: any, j: number) => j === i ? { ...r, [k]: v } : r) });
  const level = (k: string, i: number, value: string) => <select aria-label={`Risk ${i + 1} ${k}`} value={value} disabled={!editable} onChange={(e) => setRisk(i, k, e.target.value)}>{["low", "medium", "high"].map((l) => <option key={l} value={l}>{l}</option>)}</select>;
  return <Modal title={`${d.ref}: ${d.title}`} wide onClose={onClose} footer={editable && <><button disabled={busy} onClick={save}>Save</button>{canApprove && <button className="primary" disabled={busy || d.blockers.length > 0} onClick={approve}>Approve</button>}</>}>
    <p className="small">For {d.processingRef} {displayValue(d.processingName)}. {d.status === "approved" ? `Approved by ${displayValue(d.approvedByName ?? "")} on ${fmtTime(d.approvedAt)}; review by ${ddmmyyyy(d.reviewOn)}.` : "Save your changes before approving."}</p>
    {editable && d.blockers.length > 0 && <p className="small muted">Before approval: {d.blockers.join(" ")}</p>}
    <label className="field">Title<input value={f.title} disabled={!editable} onChange={(e) => setF({ ...f, title: e.target.value })} /></label>
    <label className="field">The processing<textarea rows={2} value={f.description} disabled={!editable} onChange={(e) => setF({ ...f, description: e.target.value })} /></label>
    <label className="field">Why it is necessary and proportionate<textarea rows={2} value={f.necessity} disabled={!editable} onChange={(e) => setF({ ...f, necessity: e.target.value })} /></label>
    <label className="field">Who was consulted<textarea rows={2} value={f.consultation} disabled={!editable} onChange={(e) => setF({ ...f, consultation: e.target.value })} /></label>
    <h3>Risks to people</h3>
    {f.risks.map((r: any, i: number) => <div key={i} className="card" style={{ marginBottom: 6 }}>
      <label className="field">Risk {i + 1}<input value={r.description} disabled={!editable} onChange={(e) => setRisk(i, "description", e.target.value)} /></label>
      <div className="row small" style={{ gap: 8, flexWrap: "wrap" }}>Likelihood {level("likelihood", i, r.likelihood)} Severity {level("severity", i, r.severity)} Residual {level("residual", i, r.residual)}
        {d.risks[i]?.level && <Pill value={`${d.risks[i].level} before measures`} tone={LEVEL_TONE[d.risks[i].level]} />}</div>
      <label className="field">Measures<input value={r.measures} disabled={!editable} onChange={(e) => setRisk(i, "measures", e.target.value)} /></label>
    </div>)}
    {editable && <button className="small" onClick={() => setF({ ...f, risks: [...f.risks, { description: "", likelihood: "medium", severity: "medium", measures: "", residual: "low" }] })}>Add a risk</button>}
    <label className="field">Advice from the data protection officer or privacy lead<textarea rows={2} value={f.dpoAdvice} disabled={!editable} onChange={(e) => setF({ ...f, dpoAdvice: e.target.value })} /></label>
    <label className="field">Outcome<select value={f.outcome} disabled={!editable} onChange={(e) => setF({ ...f, outcome: e.target.value })}><option value="">Not decided</option>{Object.entries(OUTCOME_LABEL).map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></label>
    {d.priorConsultation && <p className="small"><b>A residual risk is high:</b> consult the regulator before starting the processing.</p>}
  </Modal>;
}

// Data subject requests -----------------------------------------------------------------------------------------------

function Requests({ data, tenantId, onChange }: { data: any; tenantId: string; onChange: () => void }) {
  const [adding, setAdding] = useState(false);
  const [openId, setOpenId] = useState<string | null>(null);
  const rows = safeArray<any>(data?.requests);
  const open = rows.find((r) => r.id === openId);
  const manage = !!data?.canManage;
  return <>
    <div className="row" style={{ marginBottom: 8 }}><p className="small muted" style={{ flex: 1, margin: 0 }}>A request must be answered within one month of receipt, or of confirming the person's identity if that came later. Complex or numerous requests can be extended by up to two more months, with a reason. Record only what is needed to handle the request.</p>
      {manage && <button className="primary" onClick={() => setAdding(true)}>Log a request</button>}</div>
    <Table rows={rows} empty="No requests." onRow={(r) => setOpenId(r.id)} columns={[
      { key: "ref", label: "Ref" }, { key: "typeLabel", label: "Type" }, { key: "requester", label: "From" },
      { key: "dueOn", label: "Due", render: (r) => r.status !== "open" ? `Closed ${ddmmyyyy(r.closedOn)}` : <>{ddmmyyyy(r.dueOn)} {r.overdue ? <Pill value="overdue" tone="bad" /> : <span className="small muted">({r.daysLeft} days)</span>}</> },
      { key: "status", label: "Status" }]} />
    {adding && <AddRequest tenantId={tenantId} types={safeArray<any>(data?.options?.requestTypes)} onClose={() => { setAdding(false); onChange(); }} />}
    {open && <RequestDetail r={open} manage={manage} onChange={onChange} onClose={() => setOpenId(null)} />}
  </>;
}

function AddRequest({ tenantId, types, onClose }: { tenantId: string; types: any[]; onClose: () => void }) {
  const { data: people } = useData<any>("isms/members", { tenant_id: tenantId }, [tenantId]);
  const [f, setF] = useState({ type: "access", requester: "", details: "", receivedOn: new Date().toISOString().slice(0, 10), identityVerifiedOn: "", ownerId: "" });
  const { run, busy } = useAction();
  const save = async () => { if (await run(() => api("isms/privacy/requests", { body: { tenantId, ...f, identityVerifiedOn: f.identityVerifiedOn || null, ownerId: f.ownerId || null } }), "Request logged")) onClose(); };
  const set = (k: string) => (e: any) => setF({ ...f, [k]: e.target.value });
  return <Modal title="Log a data subject request" onClose={onClose} footer={<button className="primary" disabled={busy || f.requester.trim().length < 2 || !f.receivedOn} onClick={save}>Log</button>}>
    <label className="field">Type<select value={f.type} onChange={set("type")}>{types.map((t) => <option key={t.key} value={t.key}>{t.label}</option>)}</select></label>
    <label className="field">From<input value={f.requester} onChange={set("requester")} /></label>
    <label className="field">What they asked for<textarea rows={2} value={f.details} onChange={set("details")} /></label>
    <label className="field">Received on<input type="date" value={f.receivedOn} onChange={set("receivedOn")} /></label>
    <label className="field">Identity confirmed on (if later)<input type="date" value={f.identityVerifiedOn} onChange={set("identityVerifiedOn")} /></label>
    <label className="field">Owner<select value={f.ownerId} onChange={set("ownerId")}><option value="">Nobody yet</option>{safeArray<any>(people?.members).map((m) => <option key={m.id} value={m.id}>{m.name || m.email}</option>)}</select></label>
  </Modal>;
}

function RequestDetail({ r, manage, onChange, onClose }: { r: any; manage: boolean; onChange: () => void; onClose: () => void }) {
  const { run, busy } = useAction();
  const [verified, setVerified] = useState("");
  const [ext, setExt] = useState({ months: "1", reason: "" });
  const [end, setEnd] = useState({ status: "completed", response: "" });
  const act = async (action: string, body: any, msg: string) => { if (await run(() => api(`isms/privacy/requests/${r.id}/${action}`, { body }), msg)) onChange(); };
  const open = manage && r.status === "open";
  return <Modal title={`${r.ref}: ${r.typeLabel}`} onClose={onClose}>
    <p className="small">From {displayValue(r.requester)}, received {ddmmyyyy(r.receivedOn)}{r.identityVerifiedOn ? `, identity confirmed ${ddmmyyyy(r.identityVerifiedOn)}` : ""}. Due {ddmmyyyy(r.dueOn)}{r.extensionMonths ? ` (extended by ${r.extensionMonths} month${r.extensionMonths > 1 ? "s" : ""}: ${r.extensionReason})` : ""}.</p>
    {r.details && <p className="small">{displayValue(r.details)}</p>}
    {r.status !== "open" && <p className="small"><b>{r.status}:</b> {displayValue(r.response)}</p>}
    {open && <>
      {!r.identityVerifiedOn && <div className="row" style={{ gap: 8, alignItems: "end" }}>
        <label className="field">Identity confirmed on<input type="date" value={verified} onChange={(e) => setVerified(e.target.value)} /></label>
        <button disabled={busy || !verified} onClick={() => act("verify", { on: verified }, "Deadline moved")}>Record</button></div>}
      <div className="row" style={{ gap: 8, alignItems: "end", flexWrap: "wrap" }}>
        <label className="field">Extend by<select value={ext.months} onChange={(e) => setExt({ ...ext, months: e.target.value })}><option value="1">1 month</option><option value="2">2 months</option></select></label>
        <label className="field" style={{ flex: 1 }}>Why it is complex or numerous<input value={ext.reason} onChange={(e) => setExt({ ...ext, reason: e.target.value })} /></label>
        <button disabled={busy || !ext.reason.trim()} onClick={() => act("extend", { months: Number(ext.months), reason: ext.reason }, "Deadline extended")}>Extend</button></div>
      <div className="row" style={{ gap: 8, alignItems: "end", flexWrap: "wrap" }}>
        <label className="field">Outcome<select value={end.status} onChange={(e) => setEnd({ ...end, status: e.target.value })}><option value="completed">Completed</option><option value="refused">Refused</option><option value="withdrawn">Withdrawn</option></select></label>
        <label className="field" style={{ flex: 1 }}>{end.status === "refused" ? "Reason, and that they were told of their right to complain" : "What was done"}<input value={end.response} onChange={(e) => setEnd({ ...end, response: e.target.value })} /></label>
        <button className="primary" disabled={busy || !end.response.trim()} onClick={() => act("close", end, "Request closed")}>Close</button></div>
    </>}
  </Modal>;
}
