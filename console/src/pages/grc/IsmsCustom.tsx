import { useState } from "react";
import { api } from "../../api";
import { useApp } from "../../app-context";
import { displayValue } from "../../components/DisplayValue";
import { ErrorNote, Modal, Pill, Table, useAction, useData } from "../../components/ui";
import { safeArray } from "../../data-shapes";

/** The customer's own controls beside the library, pushing them to other customers, and the portfolio. */

const ddmmyyyy = (iso?: string | null) => iso ? `${iso.slice(8, 10)}/${iso.slice(5, 7)}/${iso.slice(0, 4)}` : "";

export function IsmsCustomControlsTab() {
  const { tenantId } = useApp();
  const { data: me } = useData<any>(tenantId ? "isms/me" : null, { tenant_id: tenantId }, [tenantId]);
  const allowed = safeArray<string>(me?.permissions).includes("controls.view");
  const { data, error, reload } = useData<any>(tenantId && allowed ? "isms/custom-controls" : null, { tenant_id: tenantId }, [tenantId, allowed]);
  const [editing, setEditing] = useState<any>(null);
  const [pushing, setPushing] = useState(false);
  if (!tenantId) return <p className="muted">Choose a customer in the tenant picker to see its own controls.</p>;
  if (!allowed) return me ? <p className="muted">Your ISMS role in this customer ({displayValue(me.role ?? "none")}) cannot see controls.</p> : null;
  const manage = !!data?.canManage;
  const reqs = safeArray<any>(data?.requirements);
  const label = (k: string) => { const r = reqs.find((x) => x.key === k); return r ? `${r.ref} ${r.title}` : k; };
  return <div className="card">
    <ErrorNote error={error} />
    <div className="row" style={{ marginBottom: 8, gap: 8 }}>
      <p className="small muted" style={{ flex: 1, margin: 0 }}>Controls this customer runs that are not in the library. Link each one to the requirements it meets so it counts in the Statement of Applicability, readiness and audit checklists. Set its state and owner on the ISMS controls tab.</p>
      {manage && safeArray<any>(data?.controls).length > 0 && <button onClick={() => setPushing(true)}>Copy to other customers</button>}
      {manage && <button className="primary" onClick={() => setEditing({})}>Add control</button>}
    </div>
    <Table rows={safeArray<any>(data?.controls)} empty="No controls of this customer's own yet." onRow={manage ? setEditing : undefined} columns={[
      { key: "ref", label: "Ref" }, { key: "title", label: "Control", render: (c) => <><b>{displayValue(c.title)}</b><div className="small muted">{displayValue(c.statement)}</div></> },
      { key: "frequency", label: "Tested", render: (c) => c.frequency ?? "Not set" },
      { key: "requirementKeys", label: "Meets", render: (c) => c.requirementKeys.length ? c.requirementKeys.map(label).join("; ") : <Pill value="not linked" tone="warn" /> }]} />
    {editing && <EditCustom tenantId={tenantId} c={editing} requirements={reqs} frequencies={safeArray<string>(data?.frequencies)} onClose={() => { setEditing(null); reload(); }} />}
    {pushing && <PushControls tenantId={tenantId} controls={safeArray<any>(data?.controls)} onClose={() => setPushing(false)} />}
  </div>;
}

function EditCustom({ tenantId, c, requirements, frequencies, onClose }: { tenantId: string; c: any; requirements: any[]; frequencies: string[]; onClose: () => void }) {
  const [f, setF] = useState({ title: c.title ?? "", statement: c.statement ?? "", testProcedure: c.testProcedure ?? "", frequency: c.frequency ?? "", requirementKeys: (c.requirementKeys ?? []) as string[] });
  const [filter, setFilter] = useState("");
  const { run, busy } = useAction();
  const body = { ...f, frequency: f.frequency || null, ownerId: c.ownerId ?? null };
  const save = async () => { if (await run(() => c.id ? api(`isms/custom-controls/${c.id}`, { method: "PATCH", body }) : api("isms/custom-controls", { body: { tenantId, ...body } }), "Control saved")) onClose(); };
  const remove = async () => { if (confirm(`Delete ${c.ref}?`) && await run(() => api(`isms/custom-controls/${c.id}`, { method: "DELETE" }), "Control deleted")) onClose(); };
  const shown = requirements.filter((r) => !filter || `${r.ref} ${r.title}`.toLowerCase().includes(filter.toLowerCase())).slice(0, 60);
  const toggle = (k: string) => setF({ ...f, requirementKeys: f.requirementKeys.includes(k) ? f.requirementKeys.filter((x) => x !== k) : [...f.requirementKeys, k] });
  return <Modal title={c.id ? `Edit ${c.ref}` : "Add a control"} wide onClose={onClose} footer={<>{c.id && <button disabled={busy} onClick={remove}>Delete</button>}<button className="primary" disabled={busy || f.title.trim().length < 3 || !f.statement.trim()} onClick={save}>Save</button></>}>
    <label className="field">Title<input value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} /></label>
    <label className="field">What it requires<textarea rows={3} value={f.statement} onChange={(e) => setF({ ...f, statement: e.target.value })} /></label>
    <label className="field">How to test it<textarea rows={2} value={f.testProcedure} onChange={(e) => setF({ ...f, testProcedure: e.target.value })} /></label>
    <label className="field">Test frequency<select value={f.frequency} onChange={(e) => setF({ ...f, frequency: e.target.value })}><option value="">Not set</option>{frequencies.map((x) => <option key={x} value={x}>{x}</option>)}</select></label>
    <fieldset><legend className="small">Requirements it meets ({f.requirementKeys.length} chosen)</legend>
      <label className="field">Find<input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Ref or title" /></label>
      <div style={{ maxHeight: 200, overflowY: "auto" }}>{shown.map((r) => <label key={r.key} className="small" style={{ display: "block" }}>
        <input type="checkbox" checked={f.requirementKeys.includes(r.key)} onChange={() => toggle(r.key)} /> {r.frameworkName}: {r.ref} {r.title}</label>)}</div>
    </fieldset>
  </Modal>;
}

function PushControls({ tenantId, controls, onClose }: { tenantId: string; controls: any[]; onClose: () => void }) {
  const { data } = useData<any>("isms/portfolio", {}, []);
  const targets = safeArray<any>(data?.customers).filter((c) => c.tenantId !== tenantId && c.canManage);
  const [picked, setPicked] = useState<string[]>([]);
  const [which, setWhich] = useState<string[]>(controls.map((c) => c.id));
  const [result, setResult] = useState<any>(null);
  const { run, busy } = useAction();
  const push = async () => { const r: any = await run(() => api("isms/custom-controls/push", { body: { sourceTenantId: tenantId, targetTenantIds: picked, controlIds: which } })); if (r) setResult(r.added); };
  const flip = (xs: string[], x: string) => xs.includes(x) ? xs.filter((y) => y !== x) : [...xs, x];
  return <Modal title="Copy controls to other customers" onClose={onClose} footer={!result && <button className="primary" disabled={busy || !picked.length || !which.length} onClick={push}>Copy</button>}>
    <p className="small muted">Copies the chosen controls as new controls of each customer, without owners or requirement links (their frameworks may differ). A customer that already has a control with the same title is skipped. You need to run the programme in each customer.</p>
    <fieldset><legend className="small">Controls</legend>{controls.map((c) => <label key={c.id} className="small" style={{ display: "block" }}><input type="checkbox" checked={which.includes(c.id)} onChange={() => setWhich(flip(which, c.id))} /> {c.ref} {c.title}</label>)}</fieldset>
    <fieldset><legend className="small">To</legend>{targets.length === 0 ? <p className="small muted">You do not run the ISMS of any other customer.</p> : targets.map((c) => <label key={c.tenantId} className="small" style={{ display: "block" }}><input type="checkbox" checked={picked.includes(c.tenantId)} onChange={() => setPicked(flip(picked, c.tenantId))} /> {c.name}</label>)}</fieldset>
    {result && <ul className="small" aria-live="polite">{Object.entries(result).map(([t, n]) => <li key={t}>{targets.find((c) => c.tenantId === t)?.name ?? t}: {String(n)} added</li>)}</ul>}
  </Modal>;
}

export function IsmsPortfolioTab() {
  const { data, error } = useData<any>("isms/portfolio", {}, []);
  const rows = safeArray<any>(data?.customers);
  return <div className="card">
    <ErrorNote error={error} />
    <p className="small muted">Every customer where you hold an ISMS role that can see controls. Choose a customer in the tenant picker to work on it.</p>
    <Table rows={rows} empty="You hold no ISMS role that can see controls in any customer." columns={[
      { key: "name", label: "Customer", render: (c) => <><b>{displayValue(c.name)}</b><div className="small muted">{displayValue(c.role)}</div></> },
      { key: "readiness", label: "Readiness", render: (c) => c.framework ? `${c.readiness == null ? "not scored" : `${c.readiness}%`} (${c.framework})` : "No framework" },
      { key: "overdueTasks", label: "Overdue tasks", render: (c) => c.overdueTasks ? <Pill value={String(c.overdueTasks)} tone="bad" /> : "0" },
      { key: "openNonconformities", label: "Open nonconformities" },
      { key: "risksAboveAppetite", label: "Risks above appetite" },
      { key: "documentsDueForReview", label: "Documents due for review" },
      { key: "openEvidenceRequests", label: "Evidence requests" },
      { key: "nextAudit", label: "Next audit", render: (c) => c.nextAudit ? `${c.nextAudit.ref} ${ddmmyyyy(c.nextAudit.plannedStart)}` : "None planned" }]} />
  </div>;
}
