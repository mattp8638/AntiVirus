// Purview labels (M365-27): retention and sensitivity labels, drift from a template, and deployments that a second
// person must approve. DLP and retention policies are not in Microsoft Graph, so they are shown as unavailable.
import { useState } from "react";
import { api, fmtTime } from "../api";
import { ErrorNote, Pill, Table, useAction, useData } from "../components/ui";

const TONE: Record<string, string> = { matches: "good", missing: "bad", different: "warn", proposed: "blue", completed: "good",
  rejected: "neutral", partial: "warn", failed: "bad" };

export default function M365Purview({ connection }: { connection: any }) {
  const { run, busy } = useAction();
  const { data: baselines, reload: reloadBaselines } = useData<any[]>("m365/purview/baselines");
  const [baselineId, setBaselineId] = useState("");
  const { data, error, reload } = useData<any>(`m365/purview/connections/${connection.id}`, { baselineId: baselineId || undefined }, [baselineId]);
  const [json, setJson] = useState('[{"displayName": "Finance 7 years", "retentionDurationDays": 2555, "actionAfterRetentionPeriod": "delete"}]');
  const inv = data?.inventory?.data;
  return (
    <div style={{ marginTop: 12 }}>
      <div className="row"><p className="small muted" style={{ flex: 1 }}>{data?.inventory ? `Read ${fmtTime(data.inventory.takenAt)}.` : "Not read yet."} Retention labels can be read and created; sensitivity labels only read (Microsoft Graph beta). Creating labels needs approval by a second person.</p>
        <button className="primary" disabled={busy} onClick={() => run(() => api(`m365/purview/connections/${connection.id}/inventory`, { method: "POST" }), "Read").then(reload)}>Read labels</button></div>
      <ErrorNote error={error} />
      {inv && <>
        {Object.entries(inv.unavailable).map(([k, v]: any) => <p key={k} className="small"><Pill value="unavailable" tone="neutral" /> {k}: {v}</p>)}
        <h3>Retention labels</h3>
        <Table rows={inv.retentionLabels || []} empty="None." columns={[{ key: "displayName", label: "Label" }, { key: "retentionDurationDays", label: "Days" },
          { key: "behaviorDuringRetentionPeriod", label: "During" }, { key: "actionAfterRetentionPeriod", label: "After" }]} />
        <h3>Sensitivity labels</h3>
        <Table rows={inv.sensitivityLabels || []} empty="None or unavailable." columns={[{ key: "name", label: "Label" }, { key: "parent", label: "Parent" },
          { key: "isActive", label: "Active", render: (l: any) => (l.isActive ? "yes" : "no") }]} />
      </>}
      <div className="card">
        <h3>Template</h3>
        <div className="row" style={{ gap: 8 }}><select value={baselineId} onChange={(e) => setBaselineId(e.target.value)}><option value="">Choose a template…</option>
          {(baselines || []).map((b: any) => <option key={b.id} value={b.id}>{b.name}</option>)}</select>
          {baselineId && inv && <button disabled={busy} onClick={() => run(() => api(`m365/purview/connections/${connection.id}/changes`, { body: { baselineId } }), "Proposed: a second person must approve it").then(reload)}>Propose missing labels</button>}</div>
        <details className="small"><summary>New template</summary>
          <textarea style={{ width: "100%", minHeight: 80 }} value={json} onChange={(e) => setJson(e.target.value)} />
          <button disabled={busy} onClick={() => { try { const labels = JSON.parse(json); run(() => api("m365/purview/baselines", { body: { tenantId: connection.tenantId, name: `Template ${new Date().toLocaleDateString()}`, retentionLabels: labels } }), "Saved").then(reloadBaselines); } catch { /* invalid JSON: ignored */ } }}>Save template</button>
        </details>
        {data?.drift && (data.drift.status === "unknown" ? <p className="small">Drift unknown: {data.drift.reason}</p> :
          <Table rows={data.drift.items} columns={[{ key: "label", label: "Label" }, { key: "state", label: "", render: (i: any) => <Pill value={i.state} tone={TONE[i.state]} /> },
            { key: "differences", label: "Differences", render: (i: any) => <span className="small">{i.differences.map((d: any) => `${d.field}: template ${d.template}, tenant ${d.tenant}`).join("; ")}</span> }]} />)}
      </div>
      <h3>Changes</h3>
      <Table rows={data?.changes || []} empty="None." columns={[
        { key: "createdAt", label: "Proposed", render: (c: any) => `${fmtTime(c.createdAt)} by ${c.requestedBy}` },
        { key: "plan", label: "Plan", render: (c: any) => <span className="small">{c.plan.map((p: any) => `${p.action} ${p.label}`).join("; ")}</span> },
        { key: "status", label: "Status", render: (c: any) => <><Pill value={c.status} tone={TONE[c.status]} />{c.reviewedBy && <span className="small"> by {c.reviewedBy}</span>}</> },
        { key: "id", label: "", render: (c: any) => c.status === "proposed" ? <span className="row" style={{ gap: 4 }}>
          <button className="link" onClick={() => run(() => api(`m365/purview/changes/${c.id}/review`, { body: { approve: true } }), "Approved and applied").then(reload)}>Approve</button>
          <button className="link" onClick={() => run(() => api(`m365/purview/changes/${c.id}/review`, { body: { approve: false } }), "Rejected").then(reload)}>Reject</button></span> : null },
      ]} />
    </div>
  );
}
