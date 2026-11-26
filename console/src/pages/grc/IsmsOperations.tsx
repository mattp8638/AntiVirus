import { useState } from "react";
import { api, fmtTime } from "../../api";
import { useApp } from "../../app-context";
import { displayValue } from "../../components/DisplayValue";
import { ErrorNote, Modal, Pill, Table, useAction, useData } from "../../components/ui";
import { safeArray } from "../../data-shapes";

/** Suppliers (from third-party risk) linked into the ISMS, and the ISMS review of SOC incidents. */

const CATEGORY_LABEL: Record<string, string> = { malware: "Malware", phishing: "Phishing", unauthorized_access: "Unauthorized access", data_loss: "Data loss",
  availability: "Availability", physical: "Physical", supplier: "Supplier", other: "Other" };
const REVIEW: Record<string, [string, string]> = { not_started: ["not started", "muted"], open: ["in progress", "warn"], complete: ["complete", "ok"] };
const TYPE_LABEL: Record<string, string> = { asset: "Asset", risk: "Risk", control: "Control" };

export function IsmsOperationsTab() {
  const { tenantId } = useApp();
  const { data: me } = useData<any>(tenantId ? "isms/me" : null, { tenant_id: tenantId }, [tenantId]);
  const allowed = safeArray<string>(me?.permissions).includes("controls.view");
  const [view, setView] = useState("incidents");
  if (!tenantId) return <p className="muted">Choose a customer in the tenant picker to see its suppliers and incidents.</p>;
  if (!allowed) return me ? <p className="muted">Your ISMS role in this customer ({displayValue(me.role ?? "none")}) cannot see suppliers and incidents.</p> : null;
  return <div className="card">
    <label className="field" style={{ maxWidth: 280 }}>Show<select value={view} onChange={(e) => setView(e.target.value)}><option value="incidents">Incidents</option><option value="suppliers">Suppliers</option></select></label>
    {view === "incidents" ? <Incidents tenantId={tenantId} /> : <Suppliers tenantId={tenantId} />}
  </div>;
}

function Incidents({ tenantId }: { tenantId: string }) {
  const { data, error, reload } = useData<any>("isms/incidents", { tenant_id: tenantId }, [tenantId]);
  const [openId, setOpenId] = useState<string | null>(null);
  const rows = safeArray<any>(data?.incidents);
  const open = rows.find((r) => r.id === openId);
  return <>
    <ErrorNote error={error} />
    <p className="small muted">Incidents are handled by the SOC. The ISMS review records the category, whether personal data was involved and when the regulator was told, the root cause, the lessons learned and the controls involved. Medium and higher incidents need a root cause and lessons learned before the review can be completed.</p>
    <Table rows={rows} empty="No incidents for this customer." onRow={(r) => setOpenId(r.id)} columns={[
      { key: "title", label: "Incident", render: (r) => <><b>{displayValue(r.title)}</b><div className="small muted">{r.category ? CATEGORY_LABEL[r.category] : "Not categorized"}{r.personalData ? ", personal data" : ""}</div></> },
      { key: "severity", label: "Severity", render: (r) => <Pill value={r.severity} tone={r.severity === "critical" || r.severity === "high" ? "bad" : r.severity === "medium" ? "warn" : "muted"} /> },
      { key: "socStatus", label: "SOC status" }, { key: "detectedAt", label: "Detected", render: (r) => fmtTime(r.detectedAt) },
      { key: "status", label: "ISMS review", render: (r) => <Pill value={REVIEW[r.status][0]} tone={REVIEW[r.status][1]} /> }]} />
    {open && <IncidentReview r={open} tenantId={tenantId} categories={safeArray<string>(data?.categories)} manage={!!data?.canManage} onChange={reload} onClose={() => setOpenId(null)} />}
  </>;
}

function IncidentReview({ r, tenantId, categories, manage, onChange, onClose }: { r: any; tenantId: string; categories: string[]; manage: boolean; onChange: () => void; onClose: () => void }) {
  const { data: ctl } = useData<any>(manage ? "isms/controls" : null, { tenant_id: tenantId }, [tenantId]);
  const { data: sup } = useData<any>(manage ? "isms/suppliers" : null, { tenant_id: tenantId }, [tenantId]);
  const [f, setF] = useState({ category: r.category ?? "other", personalData: r.personalData, reportedToAuthorityAt: r.reportedToAuthorityAt ? r.reportedToAuthorityAt.slice(0, 16) : "",
    vendorId: r.vendorId ?? "", rootCause: r.rootCause, lessonsLearned: r.lessonsLearned, controlIds: r.controls.map((c: any) => c.id) as string[] });
  const [pick, setPick] = useState("");
  const { run, busy } = useAction();
  const editable = manage && r.status !== "complete";
  const url = `isms/incidents/${r.id}/review`;
  const save = async () => { if (await run(() => api(url, { method: "PUT", body: { ...f, vendorId: f.vendorId || null, reportedToAuthorityAt: f.reportedToAuthorityAt ? new Date(f.reportedToAuthorityAt).toISOString() : null } }), "Review saved")) onChange(); };
  const controls = safeArray<any>(ctl?.controls);
  return <Modal title={r.title} wide onClose={onClose} footer={manage && <>
    {r.status === "complete" ? <button disabled={busy} onClick={async () => { if (await run(() => api(`${url}/reopen`, { body: {} }), "Review reopened")) onChange(); }}>Reopen</button> : <>
      <button disabled={busy} onClick={save}>Save</button>
      <button className="primary" disabled={busy || r.reviewId === null || r.blockers.length > 0 || !["resolved", "closed"].includes(r.socStatus)} onClick={async () => { if (await run(() => api(`${url}/complete`, { body: {} }), "Review complete")) onChange(); }}>Complete review</button>
    </>}</>}>
    <p className="small">{r.severity} severity, SOC status {r.socStatus}, detected {fmtTime(r.detectedAt)}{r.assignee ? `, handled by ${r.assignee}` : ""}.</p>
    {r.breachDeadline && !r.reportedToAuthorityAt && <p className="small"><b>Personal data:</b> if the breach is likely to put people at risk, the regulator must be told by {fmtTime(r.breachDeadline)} (72 hours after it was detected).</p>}
    {r.blockers.length > 0 && <p className="small muted">Before completing: {r.blockers.join(" ")}{!["resolved", "closed"].includes(r.socStatus) ? " The SOC must resolve the incident." : ""}</p>}
    {editable ? <>
      <label className="field">Category<select value={f.category} onChange={(e) => setF({ ...f, category: e.target.value })}>{categories.map((c) => <option key={c} value={c}>{CATEGORY_LABEL[c] ?? c}</option>)}</select></label>
      <label className="small"><input type="checkbox" checked={f.personalData} onChange={(e) => setF({ ...f, personalData: e.target.checked })} /> Personal data was involved</label>
      {f.personalData && <label className="field">Reported to the regulator at<input type="datetime-local" value={f.reportedToAuthorityAt} onChange={(e) => setF({ ...f, reportedToAuthorityAt: e.target.value })} /></label>}
      <label className="field">Supplier involved<select value={f.vendorId} onChange={(e) => setF({ ...f, vendorId: e.target.value })}><option value="">None</option>{safeArray<any>(sup?.suppliers).map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</select></label>
      <label className="field">Root cause<textarea rows={2} value={f.rootCause} onChange={(e) => setF({ ...f, rootCause: e.target.value })} /></label>
      <label className="field">Lessons learned<textarea rows={3} value={f.lessonsLearned} onChange={(e) => setF({ ...f, lessonsLearned: e.target.value })} /></label>
      <div className="small"><b>Controls involved:</b> {f.controlIds.map((id) => { const c = controls.find((x) => x.id === id); return <span key={id} style={{ marginRight: 8 }}>{c ? c.ref : id} <button className="small" aria-label={`Remove ${c ? c.ref : id}`} onClick={() => setF({ ...f, controlIds: f.controlIds.filter((x) => x !== id) })}>Remove</button></span>; })}</div>
      <div className="row" style={{ gap: 8, alignItems: "end" }}>
        <label className="field" style={{ flex: 1 }}>Add a control<select value={pick} onChange={(e) => setPick(e.target.value)}><option value="">Choose</option>{controls.filter((c) => !f.controlIds.includes(c.id)).map((c) => <option key={c.id} value={c.id}>{c.ref} {c.title}</option>)}</select></label>
        <button disabled={!pick} onClick={() => { setF({ ...f, controlIds: [...f.controlIds, pick] }); setPick(""); }}>Add</button>
      </div>
    </> : <>
      <p className="small">{r.category ? CATEGORY_LABEL[r.category] : "Not categorized"}{r.personalData ? `; personal data${r.reportedToAuthorityAt ? `, reported to the regulator ${fmtTime(r.reportedToAuthorityAt)}` : ""}` : ""}{r.vendorName ? `; supplier ${r.vendorName}` : ""}.</p>
      {r.rootCause && <p className="small"><b>Root cause:</b> {displayValue(r.rootCause)}</p>}
      {r.lessonsLearned && <p className="small"><b>Lessons learned:</b> {displayValue(r.lessonsLearned)}</p>}
      {r.controls.length > 0 && <p className="small"><b>Controls:</b> {r.controls.map((c: any) => c.ref).join(", ")}</p>}
    </>}
  </Modal>;
}

function Suppliers({ tenantId }: { tenantId: string }) {
  const { data, error, reload } = useData<any>("isms/suppliers", { tenant_id: tenantId }, [tenantId]);
  const [linking, setLinking] = useState<any>(null);
  const { run, busy } = useAction();
  const manage = !!data?.canManage;
  return <>
    <ErrorNote error={error} />
    <p className="small muted">Suppliers are kept in third-party risk (Compliance and GRC, Assurance). Here each one is linked to the ISMS assets, risks and controls it touches.</p>
    <Table rows={safeArray<any>(data?.suppliers)} empty="No suppliers in third-party risk for this customer." columns={[
      { key: "name", label: "Supplier", render: (s) => <><b>{displayValue(s.name)}</b><div className="small muted">{displayValue(s.services)}</div></> },
      { key: "criticality", label: "Criticality", render: (s) => <>{s.criticality}, {s.dataAccess} data</> },
      { key: "riskTier", label: "Risk", render: (s) => <>{s.riskTier}{s.reviewOverdue && <> <Pill value="review overdue" tone="bad" /></>}</> },
      { key: "links", label: "Linked to", render: (s) => <>{s.links.map((lk: any) => <div key={lk.id} className="small">{TYPE_LABEL[lk.type]}: {displayValue(lk.label)}{manage && <> <button className="small" disabled={busy} aria-label={`Unlink ${lk.label}`} onClick={async () => { if (await run(() => api(`isms/supplier-links/${lk.id}`, { method: "DELETE" }))) reload(); }}>Unlink</button></>}</div>)}
        {manage && <button className="small" onClick={() => setLinking(s)}>Link</button>}</> }]} />
    {linking && <LinkSupplier tenantId={tenantId} s={linking} onClose={() => { setLinking(null); reload(); }} />}
  </>;
}

function LinkSupplier({ tenantId, s, onClose }: { tenantId: string; s: any; onClose: () => void }) {
  const [type, setType] = useState("asset");
  const [target, setTarget] = useState("");
  const { data: assets } = useData<any>("isms/assets", { tenant_id: tenantId }, [tenantId]);
  const { data: risks } = useData<any>("isms/risks", { tenant_id: tenantId }, [tenantId]);
  const { data: ctl } = useData<any>("isms/controls", { tenant_id: tenantId }, [tenantId]);
  const options = type === "asset" ? safeArray<any>(assets?.items).map((a) => ({ id: a.id, label: a.name }))
    : type === "risk" ? safeArray<any>(risks?.risks).map((r) => ({ id: r.id, label: `${r.ref} ${r.title}` }))
    : safeArray<any>(ctl?.controls).map((c) => ({ id: c.id, label: `${c.ref} ${c.title}` }));
  const { run, busy } = useAction();
  const save = async () => { if (await run(() => api("isms/supplier-links", { body: { tenantId, vendorId: s.id, type, targetId: target } }), "Linked")) onClose(); };
  return <Modal title={`Link ${s.name}`} onClose={onClose} footer={<button className="primary" disabled={busy || !target} onClick={save}>Link</button>}>
    <label className="field">To<select value={type} onChange={(e) => { setType(e.target.value); setTarget(""); }}><option value="asset">An asset</option><option value="risk">A risk</option><option value="control">A control</option></select></label>
    <label className="field">Which<select value={target} onChange={(e) => setTarget(e.target.value)}><option value="">Choose</option>{options.map((o) => <option key={o.id} value={o.id}>{o.label}</option>)}</select></label>
  </Modal>;
}
