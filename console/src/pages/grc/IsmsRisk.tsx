import { useState } from "react";
import { api, fmtTime } from "../../api";
import { useApp } from "../../app-context";
import { displayValue } from "../../components/DisplayValue";
import { ErrorNote, Modal, Pill, Table, useAction, useData } from "../../components/ui";
import { safeArray } from "../../data-shapes";

/** The ISMS risk register (ISO 27001 6.1.2, 6.1.3, 8.2, 8.3). */

const LEVEL_TONE: Record<string, string> = { Low: "good", Medium: "warn", High: "bad", Critical: "bad" };
const STATUS_LABEL: Record<string, string> = { identified: "Identified", assessed: "Assessed", treatment_planned: "Treatment planned", accepted: "Accepted", closed: "Closed" };
const TREATMENT_LABEL: Record<string, string> = { modify: "Reduce (modify)", retain: "Accept (retain)", avoid: "Avoid", share: "Share or transfer" };

function useIsms() {
  const { tenantId } = useApp();
  const { data: me } = useData<any>(tenantId ? "isms/me" : null, { tenant_id: tenantId }, [tenantId]);
  return { tenantId, me, perms: safeArray<string>(me?.permissions) };
}

export function IsmsRiskTab() {
  const { tenantId, me, perms } = useIsms();
  const allowed = perms.includes("risks.view");
  const { data, error, reload } = useData<any>(tenantId && allowed ? "isms/risks" : null, { tenant_id: tenantId }, [tenantId, allowed]);
  const { data: method, reload: reloadMethod } = useData<any>(tenantId && allowed ? "isms/risk/method" : null, { tenant_id: tenantId }, [tenantId, allowed]);
  const [editing, setEditing] = useState<any | "new" | null>(null);
  const [accepting, setAccepting] = useState<any>(null);
  const [methodOpen, setMethodOpen] = useState(false);
  const { run, busy } = useAction();
  if (!tenantId) return <p className="muted">Choose a customer in the tenant picker to see its risk register.</p>;
  if (!allowed) return me ? <p className="muted">Your ISMS role in this customer ({displayValue(me.role ?? "none")}) cannot view risks.</p> : null;
  const risks = safeArray<any>(data?.risks);
  const canEdit = perms.includes("risks.edit");
  const snapshot = async () => { await run(() => api("isms/risks/snapshots", { body: { tenantId, reason: "manual" } }), "Snapshot taken"); };
  return <>
    <div className="card">
      <ErrorNote error={error} />
      <div className="row" style={{ justifyContent: "space-between", marginBottom: 8, flexWrap: "wrap", gap: 6 }}>
        <span className="small muted">{method ? `Risk method version ${method.version || "not saved yet (default)"}: appetite ${method.appetite} of ${method.maxScore}, reviews every ${method.reviewMonths} months.` : ""}</span>
        <span className="row" style={{ gap: 6 }}>
          {perms.includes("programme.manage") && <button onClick={() => setMethodOpen(true)}>Risk method</button>}
          {canEdit && <button disabled={busy} onClick={snapshot}>Take a snapshot</button>}
          {canEdit && <button className="primary" onClick={() => setEditing("new")}>Add risk</button>}
        </span>
      </div>
      <Table rows={risks} empty="No risks recorded yet." onRow={setEditing} columns={[
        { key: "ref", label: "Risk", render: (r) => <><b>{displayValue(r.ref)}</b> {displayValue(r.title)}<div className="small muted">{safeArray<string>(r.assetNames).join(", ")}</div></> },
        { key: "inherentScore", label: "Inherent", render: (r) => r.inherentScore === null ? "Not rated" : <Pill value={`${r.inherentScore} ${r.inherentLevel}`} tone={LEVEL_TONE[r.inherentLevel]} /> },
        { key: "residualScore", label: "Residual", render: (r) => r.residualScore === null ? "Not rated" : <Pill value={`${r.residualScore} ${r.residualLevel}`} tone={LEVEL_TONE[r.residualLevel]} /> },
        { key: "withinAppetite", label: "Appetite", render: (r) => r.inherentScore === null && r.residualScore === null ? "" : r.withinAppetite ? "Within" : <b>Above</b> },
        { key: "status", label: "Status", render: (r) => <>{STATUS_LABEL[r.status] ?? r.status}{r.reviewOverdue && <> <Pill value="review overdue" tone="bad" /></>}</> },
        { key: "ownerName", label: "Owner", render: (r) => displayValue(r.ownerName ?? "None") },
        { key: "id", label: "", render: (r) => r.ownerId === me?.userId && r.status !== "accepted" ? <button className="small" onClick={(e) => { e.stopPropagation(); setAccepting(r); }}>Accept</button> : null }]} />
    </div>
    {data?.heatMap && <HeatMap map={data.heatMap} />}
    {editing && <RiskEditor tenantId={tenantId} risk={editing === "new" ? null : editing} method={method} canEditAll={canEdit} isOwner={editing !== "new" && editing.ownerId === me?.userId}
      treatments={safeArray<string>(data?.treatments)} onClose={() => { setEditing(null); reload(); }} />}
    {accepting && <AcceptRisk risk={accepting} onClose={() => { setAccepting(null); reload(); }} />}
    {methodOpen && method && <MethodEditor tenantId={tenantId} method={method} onClose={() => { setMethodOpen(false); reloadMethod(); reload(); }} />}
  </>;
}

function HeatMap({ map }: { map: any }) {
  const grid: number[][] = safeArray<number[]>(map.grid);
  const likelihood = safeArray<string>(map.likelihood);
  const impact = safeArray<string>(map.impact);
  return <div className="card">
    <h3 style={{ marginTop: 0 }}>Heat map (residual where rated)</h3>
    <table className="small" aria-label="Risk heat map: number of open risks by impact and likelihood">
      <thead><tr><th scope="col">Impact \ Likelihood</th>{likelihood.map((l) => <th key={l} scope="col">{l}</th>)}</tr></thead>
      <tbody>{[...impact].map((label, i) => ({ label, i })).reverse().map(({ label, i }) => <tr key={label}><th scope="row">{label}</th>
        {likelihood.map((_, j) => <td key={j} style={{ textAlign: "center" }}>{grid[i]?.[j] || ""}</td>)}</tr>)}</tbody>
    </table>
    {map.unrated > 0 && <p className="small muted">{map.unrated} risk(s) not rated yet.</p>}
  </div>;
}

function Rating({ label, value, points, onChange, disabled }: { label: string; value: any; points: any[]; onChange: (v: number | null) => void; disabled?: boolean }) {
  return <label className="field">{label}<select disabled={disabled} value={value ?? ""} onChange={(e) => onChange(e.target.value ? Number(e.target.value) : null)}>
    <option value="">Not rated</option>{points.map((p) => <option key={p.value} value={p.value}>{p.value} {p.label}</option>)}</select></label>;
}

function RiskEditor({ tenantId, risk, method, canEditAll, isOwner, treatments, onClose }: { tenantId: string; risk: any; method: any; canEditAll: boolean; isOwner: boolean; treatments: string[]; onClose: () => void }) {
  const { data: people } = useData<any>(canEditAll ? "isms/members" : null, { tenant_id: tenantId }, [tenantId]);
  const { data: assets } = useData<any>(canEditAll ? "isms/assets" : null, { tenant_id: tenantId }, [tenantId]);
  const [form, setForm] = useState<any>(() => ({
    title: risk?.title ?? "", description: risk?.description ?? "", threat: risk?.threat ?? "", vulnerability: risk?.vulnerability ?? "",
    ownerId: risk?.ownerId ?? "", assetIds: risk?.assetIds ?? [], inherentLikelihood: risk?.inherentLikelihood ?? null, inherentImpact: risk?.inherentImpact ?? null,
    treatment: risk?.treatment ?? "", treatmentPlan: risk?.treatmentPlan ?? "", residualLikelihood: risk?.residualLikelihood ?? null, residualImpact: risk?.residualImpact ?? null }));
  const { run, busy } = useAction();
  const editable = canEditAll || isOwner;
  const set = (k: string, v: unknown) => setForm({ ...form, [k]: v });
  const L = safeArray<any>(method?.likelihoodScale), I = safeArray<any>(method?.impactScale);
  const save = async () => {
    const body = { ...form, ownerId: form.ownerId || null, treatment: form.treatment || null };
    const ok = await run(() => risk ? api(`isms/risks/${risk.id}`, { method: "PATCH", body }) : api("isms/risks", { body: { tenantId, ...body } }), "Risk saved");
    if (ok) onClose();
  };
  const text = (k: string, label: string, rows = 2) => <label className="field">{label}<textarea rows={rows} disabled={!editable} value={form[k]} onChange={(e) => set(k, e.target.value)} /></label>;
  return <Modal title={risk ? `${risk.ref} ${risk.title}` : "Add a risk"} wide onClose={onClose} footer={editable && <button className="primary" disabled={busy || !form.title.trim()} onClick={save}>Save</button>}>
    <label className="field">Title<input disabled={!editable} value={form.title} onChange={(e) => set("title", e.target.value)} /></label>
    {text("description", "Description")}
    <div className="grid k2">{text("threat", "Threat")}{text("vulnerability", "Vulnerability")}</div>
    {canEditAll && <label className="field">Owner<select value={form.ownerId} onChange={(e) => set("ownerId", e.target.value)}>
      <option value="">None</option>{safeArray<any>(people?.members).map((m) => <option key={m.id} value={m.id}>{m.name ? `${m.name} (${m.email})` : m.email}</option>)}</select></label>}
    {canEditAll && safeArray<any>(assets?.items).length > 0 && <fieldset className="field"><legend>Assets affected</legend>
      {safeArray<any>(assets?.items).map((a) => <label key={a.id} className="row" style={{ gap: 6 }}><input type="checkbox" checked={form.assetIds.includes(a.id)}
        onChange={(e) => set("assetIds", e.target.checked ? [...form.assetIds, a.id] : form.assetIds.filter((x: string) => x !== a.id))} />{a.name} ({a.type})</label>)}</fieldset>}
    <div className="grid k2">
      <Rating label="Inherent likelihood" value={form.inherentLikelihood} points={L} disabled={!editable} onChange={(v) => set("inherentLikelihood", v)} />
      <Rating label="Inherent impact" value={form.inherentImpact} points={I} disabled={!editable} onChange={(v) => set("inherentImpact", v)} />
    </div>
    <label className="field">Treatment<select disabled={!editable} value={form.treatment} onChange={(e) => set("treatment", e.target.value)}>
      <option value="">Not decided</option>{treatments.map((t) => <option key={t} value={t}>{TREATMENT_LABEL[t] ?? t}</option>)}</select></label>
    {text("treatmentPlan", "Treatment plan", 3)}
    <div className="grid k2">
      <Rating label="Residual likelihood" value={form.residualLikelihood} points={L} disabled={!editable} onChange={(v) => set("residualLikelihood", v)} />
      <Rating label="Residual impact" value={form.residualImpact} points={I} disabled={!editable} onChange={(v) => set("residualImpact", v)} />
    </div>
    {risk?.acceptance && <p className="small"><b>Accepted</b> by {displayValue(risk.acceptance.acceptedBy)} on {fmtTime(risk.acceptance.acceptedAt)} at score {risk.acceptance.residualScore}: {displayValue(risk.acceptance.rationale)}</p>}
    {risk && <p className="small muted">Next review: {risk.nextReview ?? "not set"}. Changing the accepted score or the owner ends an acceptance.</p>}
  </Modal>;
}

function AcceptRisk({ risk, onClose }: { risk: any; onClose: () => void }) {
  const [rationale, setRationale] = useState("");
  const { run, busy } = useAction();
  const minimum = risk.withinAppetite ? 1 : 40;
  const go = async () => { if (await run(() => api(`isms/risks/${risk.id}/accept`, { body: { rationale } }), "Risk accepted")) onClose(); };
  return <Modal title={`Accept ${risk.ref}`} onClose={onClose} footer={<button className="primary" disabled={busy || rationale.trim().length < minimum} onClick={go}>Accept the residual risk</button>}>
    <p className="small">As the risk owner you are accepting a score of {risk.residualScore ?? risk.inherentScore}{risk.withinAppetite ? ", within appetite." : ", which is above appetite: explain in at least 40 characters why it is accepted."} The acceptance is recorded with your name and the date, and lasts until the next review.</p>
    <label className="field">Rationale<textarea rows={4} value={rationale} onChange={(e) => setRationale(e.target.value)} /></label>
  </Modal>;
}

function MethodEditor({ tenantId, method, onClose }: { tenantId: string; method: any; onClose: () => void }) {
  const [m, setM] = useState<any>(() => JSON.parse(JSON.stringify(method)));
  const { run, busy } = useAction();
  const save = async () => {
    const body = { tenantId, likelihoodScale: m.likelihoodScale, impactScale: m.impactScale, levels: m.levels, appetite: Number(m.appetite), acceptanceCriteria: m.acceptanceCriteria, reviewMonths: Number(m.reviewMonths) };
    if (await run(() => api("isms/risk/method", { method: "PUT", body }), "Risk method saved")) onClose();
  };
  const scale = (key: "likelihoodScale" | "impactScale", title: string) => <fieldset className="field"><legend>{title}</legend>
    {safeArray<any>(m[key]).map((p: any, i: number) => <div key={i} className="grid k2">
      <label className="field">{`${p.value}: label`}<input value={p.label} onChange={(e) => { const next = [...m[key]]; next[i] = { ...p, label: e.target.value }; setM({ ...m, [key]: next }); }} /></label>
      <label className="field">{`${p.value}: meaning`}<input value={p.description} onChange={(e) => { const next = [...m[key]]; next[i] = { ...p, description: e.target.value }; setM({ ...m, [key]: next }); }} /></label></div>)}</fieldset>;
  return <Modal title="Risk method" wide onClose={onClose} footer={<button className="primary" disabled={busy} onClick={save}>Save (new version)</button>}>
    <p className="small muted">Score = likelihood x impact (1 to {method.maxScore}). Each saved change makes a new version of the method.</p>
    {scale("likelihoodScale", "Likelihood")}
    {scale("impactScale", "Impact")}
    <fieldset className="field"><legend>Levels (lowest score in each)</legend>
      {safeArray<any>(m.levels).map((lv: any, i: number) => <label key={lv.level} className="field">{lv.label}<input type="number" min={1} value={lv.min}
        onChange={(e) => { const next = [...m.levels]; next[i] = { ...lv, min: Number(e.target.value) }; setM({ ...m, levels: next }); }} /></label>)}</fieldset>
    <div className="grid k2">
      <label className="field">Appetite (highest score accepted without escalation)<input type="number" min={1} max={method.maxScore} value={m.appetite} onChange={(e) => setM({ ...m, appetite: e.target.value })} /></label>
      <label className="field">Review every (months)<input type="number" min={1} max={36} value={m.reviewMonths} onChange={(e) => setM({ ...m, reviewMonths: e.target.value })} /></label>
    </div>
    <label className="field">Acceptance criteria<textarea rows={3} value={m.acceptanceCriteria} onChange={(e) => setM({ ...m, acceptanceCriteria: e.target.value })} /></label>
  </Modal>;
}
