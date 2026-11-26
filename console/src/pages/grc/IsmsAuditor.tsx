import { useState } from "react";
import { api, fmtTime } from "../../api";
import { useApp } from "../../app-context";
import { displayValue } from "../../components/DisplayValue";
import { ErrorNote, Modal, Pill, Table, useAction, useData } from "../../components/ui";
import { safeArray } from "../../data-shapes";

/** Audit workspace: saved samples over live populations, and evidence requests answered by control owners. */

const ddmmyyyy = (iso?: string | null) => iso ? `${iso.slice(8, 10)}/${iso.slice(5, 7)}/${iso.slice(0, 4)}` : "";
const STATUS: Record<string, [string, string]> = { open: ["open", "warn"], answered: ["answered", "ok"], closed: ["closed", "muted"] };

export function IsmsAuditorTab() {
  const { tenantId } = useApp();
  const { data: me } = useData<any>(tenantId ? "isms/me" : null, { tenant_id: tenantId }, [tenantId]);
  const allowed = safeArray<string>(me?.permissions).includes("controls.view");
  const { data, error, reload } = useData<any>(tenantId && allowed ? "isms/auditor" : null, { tenant_id: tenantId }, [tenantId, allowed]);
  const [drawing, setDrawing] = useState(false);
  const [asking, setAsking] = useState(false);
  const [openSample, setOpenSample] = useState<any>(null);
  const [answering, setAnswering] = useState<any>(null);
  const { run, busy } = useAction();
  if (!tenantId) return <p className="muted">Choose a customer in the tenant picker to open its audit workspace.</p>;
  if (!allowed) return me ? <p className="muted">Your ISMS role in this customer ({displayValue(me.role ?? "none")}) has no audit workspace.</p> : null;
  const canAudit = !!data?.canAudit, canManage = !!data?.canManage;
  const requests = safeArray<any>(data?.requests);
  return <div className="card">
    <ErrorNote error={error} />
    {data?.role === "auditor" && <p className="small">You have auditor access to this customer's ISMS: you can read it, draw samples and request evidence. Every page you open here is recorded in the audit log, and your access ends on the date your ISMS manager set.</p>}
    {(canAudit || canManage) && <>
      <div className="row" style={{ marginBottom: 8 }}><h3 style={{ margin: 0, flex: 1 }}>Samples</h3>{canAudit && <button className="primary" onClick={() => setDrawing(true)}>Draw a sample</button>}</div>
      <p className="small muted">A sample is drawn from the live records and saved with its seed, so anyone can check it gives the same items.</p>
      <Table rows={safeArray<any>(data?.samples)} empty="No samples yet." onRow={setOpenSample} columns={[
        { key: "populationLabel", label: "Population" }, { key: "size", label: "Items", render: (s) => `${s.items.length} of ${s.populationSize}` },
        { key: "seed", label: "Seed" }, { key: "createdAt", label: "Drawn", render: (s) => `${fmtTime(s.createdAt)} by ${displayValue(s.createdByName ?? "")}` },
        { key: "note", label: "Note", render: (s) => displayValue(s.note) }]} />
    </>}
    <div className="row" style={{ marginTop: 12, marginBottom: 8 }}><h3 style={{ margin: 0, flex: 1 }}>Evidence requests</h3>{canAudit && <button onClick={() => setAsking(true)}>Request evidence</button>}</div>
    {!canAudit && !canManage && <p className="small muted">Requests for controls you own.</p>}
    <Table rows={requests} empty="No evidence requests." columns={[
      { key: "request", label: "Request", render: (r) => <><b>{displayValue(r.request)}</b><div className="small muted">{r.controlRef ?? "General"}; asked by {displayValue(r.requestedByName ?? "")}</div></> },
      { key: "dueOn", label: "Due", render: (r) => ddmmyyyy(r.dueOn) },
      { key: "status", label: "Status", render: (r) => <Pill value={STATUS[r.status][0]} tone={STATUS[r.status][1]} /> },
      { key: "response", label: "Answer", render: (r) => r.status === "open" ? "" : <>{displayValue(r.response)}{r.evidenceTitle ? ` (evidence: ${r.evidenceTitle})` : ""}<div className="small muted">{displayValue(r.answeredByName ?? "")}</div></> },
      { key: "id", label: "", render: (r) => <div className="row" style={{ gap: 4 }}>
        {r.status !== "closed" && (canManage || r.controlOwnerId === me?.userId) && <button className="small" onClick={() => setAnswering(r)}>{r.status === "open" ? "Answer" : "Change answer"}</button>}
        {r.status !== "closed" && (canAudit || canManage) && <button className="small" disabled={busy} onClick={async () => { if (await run(() => api(`isms/auditor/requests/${r.id}/close`, { body: {} }), "Request closed")) reload(); }}>Close</button>}
      </div> }]} />
    {drawing && <DrawSample tenantId={tenantId} populations={safeArray<any>(data?.populations)} onClose={() => { setDrawing(false); reload(); }} />}
    {asking && <RequestEvidence tenantId={tenantId} onClose={() => { setAsking(false); reload(); }} />}
    {answering && <Answer tenantId={tenantId} r={answering} onClose={() => { setAnswering(null); reload(); }} />}
    {openSample && <Modal title={`${openSample.populationLabel}, seed "${openSample.seed}"`} onClose={() => setOpenSample(null)}>
      <ol className="small">{openSample.items.map((x: any) => <li key={x.id}>{displayValue(x.label)} <span className="muted">({displayValue(x.detail)})</span></li>)}</ol>
    </Modal>}
  </div>;
}

function DrawSample({ tenantId, populations, onClose }: { tenantId: string; populations: any[]; onClose: () => void }) {
  const [f, setF] = useState({ population: populations[0]?.key ?? "controls", size: "10", seed: "", note: "" });
  const { run, busy } = useAction();
  const save = async () => { if (await run(() => api("isms/auditor/samples", { body: { tenantId, ...f, size: Number(f.size) } }), "Sample drawn and saved")) onClose(); };
  return <Modal title="Draw a sample" onClose={onClose} footer={<button className="primary" disabled={busy || !(Number(f.size) >= 1)} onClick={save}>Draw</button>}>
    <label className="field">Population<select value={f.population} onChange={(e) => setF({ ...f, population: e.target.value })}>{populations.map((p) => <option key={p.key} value={p.key}>{p.label}</option>)}</select></label>
    <label className="field">How many (1 to 200)<input type="number" min={1} max={200} value={f.size} onChange={(e) => setF({ ...f, size: e.target.value })} /></label>
    <label className="field">Seed (blank uses the current time)<input value={f.seed} onChange={(e) => setF({ ...f, seed: e.target.value })} /></label>
    <label className="field">Note<input value={f.note} onChange={(e) => setF({ ...f, note: e.target.value })} /></label>
  </Modal>;
}

function RequestEvidence({ tenantId, onClose }: { tenantId: string; onClose: () => void }) {
  const { data } = useData<any>("isms/controls", { tenant_id: tenantId }, [tenantId]);
  const [f, setF] = useState({ controlId: "", request: "", dueOn: "" });
  const { run, busy } = useAction();
  const save = async () => { if (await run(() => api("isms/auditor/requests", { body: { tenantId, ...f, controlId: f.controlId || null, dueOn: f.dueOn || null } }), "Request sent")) onClose(); };
  return <Modal title="Request evidence" onClose={onClose} footer={<button className="primary" disabled={busy || f.request.trim().length < 3} onClick={save}>Send</button>}>
    <label className="field">Control (optional)<select value={f.controlId} onChange={(e) => setF({ ...f, controlId: e.target.value })}><option value="">General request</option>
      {safeArray<any>(data?.controls).filter((c) => c.state !== "not_applicable").map((c) => <option key={c.id} value={c.id}>{c.ref} {c.title}</option>)}</select></label>
    <label className="field">What you need<textarea rows={3} value={f.request} onChange={(e) => setF({ ...f, request: e.target.value })} /></label>
    <label className="field">Needed by (optional)<input type="date" value={f.dueOn} onChange={(e) => setF({ ...f, dueOn: e.target.value })} /></label>
  </Modal>;
}

function Answer({ tenantId, r, onClose }: { tenantId: string; r: any; onClose: () => void }) {
  const { data } = useData<any>("isms/evidence", { tenant_id: tenantId, ...(r.controlId ? { control_id: r.controlId } : {}) }, [tenantId, r.id]);
  const [f, setF] = useState({ response: r.response ?? "", evidenceId: r.evidenceId ?? "" });
  const { run, busy } = useAction();
  const save = async () => { if (await run(() => api(`isms/auditor/requests/${r.id}/answer`, { body: { response: f.response, evidenceId: f.evidenceId || null } }), "Answer sent")) onClose(); };
  return <Modal title={`Answer: ${r.request}`} onClose={onClose} footer={<button className="primary" disabled={busy || (f.response.trim().length < 2 && !f.evidenceId)} onClick={save}>Send answer</button>}>
    <label className="field">Answer<textarea rows={3} value={f.response} onChange={(e) => setF({ ...f, response: e.target.value })} /></label>
    <label className="field">Evidence (optional)<select value={f.evidenceId} onChange={(e) => setF({ ...f, evidenceId: e.target.value })}><option value="">None</option>
      {safeArray<any>(data?.evidence).map((e) => <option key={e.id} value={e.id}>{e.title}</option>)}</select></label>
  </Modal>;
}
