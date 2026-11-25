// AI governance (GRC-21): inventory of AI systems and use-cases, risk and impact assessment, human oversight,
// approval. The answers suggest a risk tier; a person confirms it.
import { useState } from "react";
import { api } from "../../api";
import { useApp } from "../../app-context";
import { Modal, PageHead, Pill, Table, useAction, useData, useListData } from "../../components/ui";
import { COMPLIANCE_SECTION, SectionTabs } from "../../components/sections";

const TIER: Record<string, string> = { unacceptable: "bad", high: "warn", limited: "blue", minimal: "good" };

export default function AiGovernance() {
  const { tenantId, can } = useApp();
  const { run } = useAction();
  const { data, reload } = useListData<any>("grc/ai/systems", { tenantId: tenantId || undefined }, [tenantId]);
  const [open, setOpen] = useState<any>(null);
  return (
    <>
      <SectionTabs items={COMPLIANCE_SECTION} />
      <PageHead title="AI governance" subtitle="Every AI system and use-case: what it does, the model and supplier, the data it uses, a risk and impact assessment, the human oversight around it, and its approval. The suggested risk tier is guidance, not a legal classification." />
      {!tenantId ? <div className="card empty">Choose a customer.</div> : <>
        {can("grc") && <button className="primary" style={{ marginBottom: 10 }} onClick={() => { const n = window.prompt("Name of the AI system or use-case"); if (n) run(() => api("grc/ai/systems", { body: { tenantId, name: n } })).then((r: any) => { reload(); if (r) setOpen(r); }); }}>Add an AI system</button>}
        <Table rows={data} onRow={(s) => setOpen(s)} empty="No AI systems recorded." columns={[
          { key: "name", label: "System", render: (s) => <><b>{s.name}</b><div className="small muted">{s.provider} · {s.deployment}</div></> },
          { key: "tier", label: "Risk tier", render: (s) => s.tier ? <Pill value={s.tier} tone={TIER[s.tier]} /> : s.suggestedTier ? <Pill value={`suggested ${s.suggestedTier}`} tone="muted" /> : "—" },
          { key: "status", label: "Status", render: (s) => <Pill value={s.status} tone={s.status === "approved" || s.status === "in_use" ? "good" : s.status === "rejected" ? "bad" : "muted"} /> },
          { key: "findings", label: "Open points", render: (s) => s.findings.length || "—" }]} />
      </>}
      {open && <SystemDetail initial={open} onClose={() => { setOpen(null); reload(); }} />}
    </>
  );
}

function SystemDetail({ initial, onClose }: { initial: any; onClose: () => void }) {
  const { can } = useApp();
  const { run, busy } = useAction();
  const { data: meta } = useData<any>("grc/ai/questions");
  const [s, setS] = useState(initial);
  const [f, setF] = useState({ purpose: s.purpose, owner: s.owner, provider: s.provider, deployment: s.deployment, impacts: s.impacts, tier: s.tier, tierRationale: s.tierRationale, answers: s.answers as Record<string, boolean>, oversight: s.oversight as any[] });
  const save = () => run(() => api(`grc/ai/systems/${s.id}`, { method: "PATCH", body: { ...f, tier: f.tier || undefined } }), "Saved").then((r: any) => r && setS(r));
  const decide = (action: string) => run(() => api(`grc/ai/systems/${s.id}/decision`, { body: { action } }), action).then((r: any) => r && setS(r));
  return (
    <Modal wide title={s.name} onClose={onClose} footer={can("grc") && <>
      <button disabled={busy} onClick={save}>Save</button>
      {s.status === "proposed" && <button className="primary" disabled={busy || s.findings.length > 0} onClick={() => decide("approve")}>Approve</button>}
      {s.status === "approved" && <button onClick={() => decide("in_use")}>Mark in use</button>}
      {s.status !== "retired" && <button className="danger" onClick={() => decide(s.status === "proposed" ? "reject" : "retire")}>{s.status === "proposed" ? "Reject" : "Retire"}</button>}
    </>}>
      <p className="small"><Pill value={s.status} /> {s.suggestedTier && <>Answers suggest <Pill value={s.suggestedTier} tone={TIER[s.suggestedTier]} /></>} {s.approvedBy && ` · approved by ${s.approvedBy}`}</p>
      {s.findings.length > 0 && <div className="card small" style={{ borderColor: "#f59e0b" }}>{s.findings.map((x: string) => <div key={x}>• {x}</div>)}</div>}
      <div className="form-grid">
        <label className="field">Owner<input value={f.owner} onChange={(e) => setF({ ...f, owner: e.target.value })} /></label>
        <label className="field">Model and supplier<input value={f.provider} onChange={(e) => setF({ ...f, provider: e.target.value })} /></label>
        <label className="field">Deployment<select value={f.deployment} onChange={(e) => setF({ ...f, deployment: e.target.value })}><option value="internal">Internal</option><option value="customer-facing">Customer-facing</option><option value="embedded">Embedded in a product</option></select></label>
      </div>
      <label className="field">Purpose<textarea rows={2} value={f.purpose} onChange={(e) => setF({ ...f, purpose: e.target.value })} /></label>
      <h4>Assessment</h4>
      {(meta?.questions ?? []).map((q: any) => <div key={q.id} className="row small" style={{ gap: 8, marginBottom: 4 }}>
        <select value={f.answers[q.id] === undefined ? "" : f.answers[q.id] ? "yes" : "no"} onChange={(e) => setF({ ...f, answers: { ...f.answers, [q.id]: e.target.value === "yes" } })}><option value="">—</option><option value="yes">Yes</option><option value="no">No</option></select>
        <span>{q.text}</span></div>)}
      <div className="form-grid">
        <label className="field">Confirmed risk tier<select value={f.tier} onChange={(e) => setF({ ...f, tier: e.target.value })}><option value="">Not confirmed</option>{(meta?.tiers ?? []).map((t: string) => <option key={t}>{t}</option>)}</select></label>
      </div>
      <label className="field">Why this tier<textarea rows={2} value={f.tierRationale} onChange={(e) => setF({ ...f, tierRationale: e.target.value })} /></label>
      <label className="field">Impact assessment (people affected, harms, mitigations)<textarea rows={3} value={f.impacts} onChange={(e) => setF({ ...f, impacts: e.target.value })} /></label>
      <h4>Human oversight</h4>
      {f.oversight.map((o, i) => <div key={i} className="row small" style={{ gap: 6 }}><input value={o.measure} onChange={(e) => setF({ ...f, oversight: f.oversight.map((x, j) => j === i ? { ...x, measure: e.target.value } : x) })} placeholder="Measure" /><input value={o.owner} onChange={(e) => setF({ ...f, oversight: f.oversight.map((x, j) => j === i ? { ...x, owner: e.target.value } : x) })} placeholder="Owner" /></div>)}
      <button className="small" onClick={() => setF({ ...f, oversight: [...f.oversight, { measure: "", owner: "", frequency: "" }] })}>Add a measure</button>
    </Modal>
  );
}
