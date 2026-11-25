// Business continuity (GRC-17): plans of business services with impact and recovery targets, linked to backed-up
// machines and DR runbooks; each service is measured against its targets, and exercises record what was tested.
import { useMemo, useState } from "react";
import { api, fmtTime } from "../../api";
import { useApp } from "../../app-context";
import { Modal, PageHead, Pill, Table, useAction, useData, useListData } from "../../components/ui";
import { COMPLIANCE_SECTION, SectionTabs } from "../../components/sections";

interface Service { id: string; name: string; criticality: string; rtoMinutes: number; rpoMinutes: number; impact?: string; owner?: string; dependsOn: string[]; machines: string[]; runbookId: string | null; manualSteps?: string }
interface Plan { id: string; tenantId: string; name: string; scope: string; owner: string; status: string; version: number; approvedVersion: number | null; approvedBy: string; approvedAt: string | null; reviewDue: string | null; services: Service[]; changedSinceApproval: boolean }
const CAP: Record<string, [string, string]> = {
  exercised: ["exercised", "good"], measured: ["measured, not exercised", "blue"], planned: ["planned only", "muted"], gap: ["gap", "bad"],
};
const mins = (m: number) => (m >= 1440 ? `${Math.round(m / 144) / 10} d` : m >= 60 ? `${Math.round(m / 6) / 10} h` : `${m} min`);

export default function Continuity() {
  const { tenantId, can } = useApp();
  const { data: plans, reload } = useListData<Plan>("grc/continuity/plans", { tenantId: tenantId || undefined }, [tenantId]);
  const [open, setOpen] = useState<string | null>(null);
  const [editing, setEditing] = useState<Plan | "new" | null>(null);
  return (
    <>
      <SectionTabs items={[...COMPLIANCE_SECTION]} />
      <PageHead title="Business continuity" subtitle="Business services, their impact and recovery targets, and what has actually been shown to recover within them: backup age, boot-verified backups and DR runbook runs measured against each target." />
      {!tenantId ? <div className="card empty">Choose a customer to see their continuity plans.</div> : <>
        {can("grc") && <button className="primary" style={{ marginBottom: 12 }} onClick={() => setEditing("new")}>New plan</button>}
        <Table rows={plans} onRow={(p) => setOpen(p.id)} empty="No continuity plan yet." columns={[
          { key: "name", label: "Plan", render: (p) => <><b>{p.name}</b><div className="small muted">{p.owner}</div></> },
          { key: "status", label: "Status", render: (p) => <><Pill value={p.status} tone={p.status === "approved" ? "good" : "muted"} />{p.changedSinceApproval && <Pill value="changed since approval" tone="warn" />}</> },
          { key: "services", label: "Services", render: (p) => p.services.length },
          { key: "approvedAt", label: "Approved", render: (p) => p.approvedAt ? `v${p.approvedVersion}, ${fmtTime(p.approvedAt)} by ${p.approvedBy}` : "—" }]} />
      </>}
      {editing && <PlanEditor tenantId={tenantId!} plan={editing === "new" ? null : editing} onClose={() => { setEditing(null); reload(); }} />}
      {open && <PlanDetail id={open} onEdit={(p) => { setOpen(null); setEditing(p); }} onClose={() => { setOpen(null); reload(); }} />}
    </>
  );
}

function PlanEditor({ tenantId, plan, onClose }: { tenantId: string; plan: Plan | null; onClose: () => void }) {
  const { run, busy } = useAction();
  const { data: devices } = useData<any>("backup/image-devices", { tenantId }, [tenantId]);
  const { data: runbooks } = useListData<any>("backup/runbooks", { tenantId }, [tenantId]);
  const machines: { key: string; name: string }[] = useMemo(() => (Array.isArray(devices) ? devices : devices?.devices ?? []).filter((d: any) => !d.source).map((d: any) => ({ key: d.key, name: d.name })), [devices]);
  const [f, setF] = useState({ name: plan?.name ?? "", owner: plan?.owner ?? "", scope: plan?.scope ?? "", reviewDue: plan?.reviewDue?.slice(0, 10) ?? "" });
  const [services, setServices] = useState<Service[]>(plan?.services ?? []);
  const set = (i: number, p: Partial<Service>) => setServices(services.map((s, j) => (j === i ? { ...s, ...p } : s)));
  const add = () => setServices([...services, { id: Math.random().toString(36).slice(2, 10), name: "", criticality: "high", rtoMinutes: 240, rpoMinutes: 1440, dependsOn: [], machines: [], runbookId: null }]);
  const save = () => run(() => plan
    ? api(`grc/continuity/plans/${plan.id}`, { method: "PATCH", body: { scope: f.scope, owner: f.owner, reviewDue: f.reviewDue || null, services } })
    : api("grc/continuity/plans", { body: { tenantId, ...f, reviewDue: f.reviewDue || null, services } }), "Plan saved").then((r) => r && onClose());
  return (
    <Modal wide title={plan ? `Edit ${plan.name}` : "New continuity plan"} onClose={onClose} footer={<button className="primary" disabled={busy || (!plan && f.name.trim().length < 3)} onClick={save}>Save</button>}>
      <div className="form-grid">
        {!plan && <label className="field">Name<input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></label>}
        <label className="field">Owner<input value={f.owner} onChange={(e) => setF({ ...f, owner: e.target.value })} /></label>
        <label className="field">Review by<input type="date" value={f.reviewDue} onChange={(e) => setF({ ...f, reviewDue: e.target.value })} /></label>
      </div>
      <label className="field">Scope<textarea rows={2} value={f.scope} onChange={(e) => setF({ ...f, scope: e.target.value })} /></label>
      <h4>Business services</h4>
      <p className="small muted">For each service: how critical it is, how long the business can be without it (RTO) and how much recent data it can afford to lose (RPO), what it depends on, and the backed-up machines and DR runbook that recover it.</p>
      {services.map((s, i) => (
        <div key={s.id} className="card" style={{ padding: 10, marginBottom: 8 }}>
          <div className="form-grid">
            <label className="field">Service<input value={s.name} onChange={(e) => set(i, { name: e.target.value })} placeholder="Payroll" /></label>
            <label className="field">Criticality<select value={s.criticality} onChange={(e) => set(i, { criticality: e.target.value })}>{["critical", "high", "medium", "low"].map((c) => <option key={c}>{c}</option>)}</select></label>
            <label className="field">RTO (minutes)<input type="number" min={1} value={s.rtoMinutes} onChange={(e) => set(i, { rtoMinutes: Number(e.target.value) })} /></label>
            <label className="field">RPO (minutes)<input type="number" min={1} value={s.rpoMinutes} onChange={(e) => set(i, { rpoMinutes: Number(e.target.value) })} /></label>
            <label className="field">DR runbook<select value={s.runbookId ?? ""} onChange={(e) => set(i, { runbookId: e.target.value || null })}><option value="">None</option>{(runbooks ?? []).map((r: any) => <option key={r.id} value={r.id}>{r.name}</option>)}</select></label>
          </div>
          <label className="field">Impact of losing it<input value={s.impact ?? ""} onChange={(e) => set(i, { impact: e.target.value })} placeholder="Staff not paid; statutory deadline" /></label>
          <div className="row small" style={{ gap: 10, flexWrap: "wrap" }}>
            <span className="muted">Depends on:</span>
            {services.filter((o) => o.id !== s.id).map((o) => <label key={o.id} className="row" style={{ gap: 4 }}><input type="checkbox" checked={s.dependsOn.includes(o.id)} onChange={(e) => set(i, { dependsOn: e.target.checked ? [...s.dependsOn, o.id] : s.dependsOn.filter((d) => d !== o.id) })} /> {o.name || "(unnamed)"}</label>)}
          </div>
          <div className="row small" style={{ gap: 10, flexWrap: "wrap", marginTop: 4 }}>
            <span className="muted">Machines:</span>
            {machines.map((m) => <label key={m.key} className="row" style={{ gap: 4 }}><input type="checkbox" checked={s.machines.includes(m.key)} onChange={(e) => set(i, { machines: e.target.checked ? [...s.machines, m.key] : s.machines.filter((x) => x !== m.key) })} /> {m.name}</label>)}
          </div>
          <button className="small danger" style={{ marginTop: 6 }} onClick={() => setServices(services.filter((_, j) => j !== i).map((o) => ({ ...o, dependsOn: o.dependsOn.filter((d) => d !== s.id) })))}>Remove service</button>
        </div>
      ))}
      <button className="small" onClick={add}>Add a service</button>
    </Modal>
  );
}

function PlanDetail({ id, onEdit, onClose }: { id: string; onEdit: (p: Plan) => void; onClose: () => void }) {
  const { can } = useApp();
  const { run, busy } = useAction();
  const { data: plan, reload } = useData<Plan>(`grc/continuity/plans/${id}`);
  const { data: a, reload: reassess } = useData<any>(`grc/continuity/plans/${id}/assessment`);
  const { data: exercises, reload: reloadEx } = useListData<any>(`grc/continuity/plans/${id}/exercises`);
  const [recording, setRecording] = useState(false);
  if (!plan) return null;
  const names = Object.fromEntries(plan.services.map((s) => [s.id, s.name]));
  const downloadReport = async () => {
    const r = await api<any>(`grc/continuity/plans/${id}/report`);
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([JSON.stringify(r, null, 2)], { type: "application/json" }));
    a.download = `continuity-${plan.name.replace(/[^A-Za-z0-9]+/g, "-")}.json`;
    a.click();
  };
  return (
    <Modal wide title={plan.name} onClose={onClose} footer={<>
      <button onClick={downloadReport}>Review pack</button>
      {can("grc") && <button onClick={() => onEdit(plan)}>Edit</button>}
      {can("grc") && (plan.status !== "approved" || plan.changedSinceApproval) && <button className="primary" disabled={busy} onClick={() => run(() => api(`grc/continuity/plans/${id}/approve`, { body: {} }), `Version ${plan.version} approved`).then(() => { reload(); reassess(); })}>Approve version {plan.version}</button>}
    </>}>
      <p className="small"><Pill value={plan.status} tone={plan.status === "approved" ? "good" : "muted"} /> {plan.approvedAt ? `Version ${plan.approvedVersion} approved by ${plan.approvedBy}, ${fmtTime(plan.approvedAt)}` : "Not approved yet"}{plan.changedSinceApproval && " · changed since approval"}{plan.reviewDue && ` · review by ${plan.reviewDue.slice(0, 10)}`}</p>
      <p className="small muted">An approved plan is what the business intends; "exercised" means a recent technical exercise met the targets and nothing has slipped since. Recovery order: {(a?.order ?? []).map((w: string[]) => w.map((x) => names[x]).join(" + ")).join(" → ")}</p>
      <Table rows={a?.services ?? []} columns={[
        { key: "name", label: "Service", render: (s) => <><b>{s.name}</b><div className="small muted">{s.criticality}</div></> },
        { key: "capability", label: "Shown", render: (s) => <Pill value={CAP[s.capability]?.[0] ?? s.capability} tone={CAP[s.capability]?.[1]} /> },
        { key: "rtoMinutes", label: "RTO target / measured", render: (s) => `${mins(s.rtoMinutes)} / ${s.measuredRtoSeconds != null ? mins(Math.ceil(s.measuredRtoSeconds / 60)) : "—"}` },
        { key: "rpoMinutes", label: "RPO target / backup age", render: (s) => `${mins(s.rpoMinutes)} / ${s.evidence.backupAgeMinutes != null ? mins(s.evidence.backupAgeMinutes) : "—"}` },
        { key: "findings", label: "Findings", render: (s) => <span className="small">{s.findings.join("; ") || "—"}{s.evidence.bootVerified ? " · backups boot-verified" : ""}</span> }]} />
      <h4 style={{ marginTop: 14 }}>Exercises</h4>
      {can("grc") && <button className="small" onClick={() => setRecording(true)}>Record an exercise</button>}
      <Table rows={exercises ?? []} empty="No exercises yet." columns={[
        { key: "title", label: "Exercise", render: (e) => <><b>{e.title}</b><div className="small muted">{e.kind}, {fmtTime(e.heldOn)}, plan v{e.planVersion}</div></> },
        { key: "outcome", label: "Outcome", render: (e) => <Pill value={e.outcome} tone={e.outcome === "passed" ? "good" : e.outcome === "failed" ? "bad" : "warn"} /> },
        { key: "results", label: "Measured", render: (e) => <span className="small">{Object.values(e.results ?? {}).map((r: any) => `${r.name}: ${r.measuredSeconds != null ? mins(Math.ceil(r.measuredSeconds / 60)) : "not up"} / ${mins(r.rtoMinutes)}`).join("; ") || "—"}</span> },
        { key: "actions", label: "Actions", render: (e) => <span className="small">{(e.actions ?? []).map((x: any) => (
          <label key={x.id} className="row" style={{ gap: 4 }}><input type="checkbox" checked={x.done} disabled={!can("grc")} onChange={() => run(() => api(`grc/continuity/exercises/${e.id}/actions/${x.id}`, { method: "PATCH", body: { done: !x.done } })).then(reloadEx)} /> {x.text}{x.owner && ` (${x.owner})`}</label>))}</span> }]} />
      {recording && <RecordExercise plan={plan} onClose={() => { setRecording(false); reloadEx(); reassess(); }} />}
    </Modal>
  );
}

function RecordExercise({ plan, onClose }: { plan: Plan; onClose: () => void }) {
  const { run, busy } = useAction();
  const runbookIds = [...new Set(plan.services.map((s) => s.runbookId).filter(Boolean))] as string[];
  const [rb, setRb] = useState(runbookIds[0] ?? "");
  const { data: runs } = useListData<any>(rb ? `backup/runbooks/${rb}/runs` : null, {}, [rb]);
  const [f, setF] = useState({ kind: runbookIds.length ? "technical" : "tabletop", title: "", scenario: "", outcome: "passed", drRunId: "", lessons: "", participants: "", actions: "" });
  const [svc, setSvc] = useState<string[]>(plan.services.map((s) => s.id));
  const save = () => run(() => api(`grc/continuity/plans/${plan.id}/exercises`, { body: {
    kind: f.kind, title: f.title, scenario: f.scenario, outcome: f.outcome, drRunId: f.drRunId, lessons: f.lessons, services: svc,
    participants: f.participants.split(",").map((x) => x.trim()).filter(Boolean),
    actions: f.actions.split("\n").map((x) => x.trim()).filter(Boolean).map((text) => ({ text })) } }), "Exercise recorded").then((r) => r && onClose());
  return (
    <Modal title="Record an exercise" onClose={onClose} footer={<button className="primary" disabled={busy || !f.title.trim() || (f.kind === "technical" && !f.drRunId)} onClick={save}>Record</button>}>
      <div className="form-grid">
        <label className="field">Kind<select value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value })}><option value="technical">Technical (a DR runbook run)</option><option value="tabletop">Tabletop (walk-through)</option></select></label>
        <label className="field">Title<input value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} placeholder="Q4 recovery test" /></label>
        {f.kind === "technical" ? <>
          <label className="field">Runbook<select value={rb} onChange={(e) => { setRb(e.target.value); setF({ ...f, drRunId: "" }); }}>{runbookIds.map((r) => <option key={r} value={r}>{r.slice(0, 8)}</option>)}</select></label>
          <label className="field">Run<select value={f.drRunId} onChange={(e) => setF({ ...f, drRunId: e.target.value })}><option value="">Choose a finished run</option>{(runs ?? []).filter((r: any) => r.state !== "running").map((r: any) => <option key={r.id} value={r.id}>{fmtTime(r.startedAt)} · {r.mode} · {r.state}</option>)}</select></label>
        </> : <label className="field">Outcome<select value={f.outcome} onChange={(e) => setF({ ...f, outcome: e.target.value })}><option value="passed">Passed</option><option value="partial">Partial</option><option value="failed">Failed</option></select></label>}
      </div>
      {f.kind === "technical" && <p className="small muted">The outcome is taken from the run: each service's machines must have come up within its RTO.</p>}
      <div className="row small" style={{ gap: 10, flexWrap: "wrap" }}>{plan.services.map((s) => <label key={s.id} className="row" style={{ gap: 4 }}><input type="checkbox" checked={svc.includes(s.id)} onChange={(e) => setSvc(e.target.checked ? [...svc, s.id] : svc.filter((x) => x !== s.id))} /> {s.name}</label>)}</div>
      <label className="field">Scenario<textarea rows={2} value={f.scenario} onChange={(e) => setF({ ...f, scenario: e.target.value })} /></label>
      <label className="field">Participants (comma-separated)<input value={f.participants} onChange={(e) => setF({ ...f, participants: e.target.value })} /></label>
      <label className="field">Lessons<textarea rows={2} value={f.lessons} onChange={(e) => setF({ ...f, lessons: e.target.value })} /></label>
      <label className="field">Actions (one per line)<textarea rows={2} value={f.actions} onChange={(e) => setF({ ...f, actions: e.target.value })} /></label>
    </Modal>
  );
}
