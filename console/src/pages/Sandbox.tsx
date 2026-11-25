// Sandbox analysis (AV-15): submissions with approval and confidential-data controls; verdicts land on the incident.
import { useEffect, useState } from "react";
import { api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { PageHead, Pill, Table, useAction, useData } from "../components/ui";

const TONE: Record<string, string> = { malicious: "bad", suspicious: "warn", clean: "good", unknown: "neutral", refused: "neutral", rejected: "neutral",
  failed: "bad", completed: "good", awaiting_approval: "warn", approved: "blue", collecting: "blue", submitted: "blue" };

export default function Sandbox() {
  const { tenantId } = useApp();
  const { run, busy } = useAction();
  const { data: policy, reload: reloadPolicy } = useData<any>(tenantId ? `sandbox/policy/${tenantId}` : null, undefined, [tenantId]);
  const { data: subs, reload } = useData<any[]>("sandbox/submissions", { tenantId: tenantId || undefined }, [tenantId]);
  const [f, setF] = useState({ enabled: false, mode: "hash", autoApproveExecutables: false, neverSubmit: "" });
  const [prov, setProv] = useState({ name: "", baseUrl: "", apiKey: "" });
  useEffect(() => { if (policy) setF({ enabled: !!policy.enabled, mode: policy.mode || "hash", autoApproveExecutables: !!policy.autoApproveExecutables, neverSubmit: (policy.neverSubmit || []).join("\n") }); }, [policy]);
  return (
    <>
      <PageHead title="Sandbox analysis" subtitle="Send suspicious files to the sandbox you license (CAPE-compatible API). Documents need a second person's approval; files with personal data or on never-submit paths are refused." />
      {!tenantId ? <div className="card empty">Choose a customer.</div> : <>
        {policy && !policy.provider && <div className="card"><p className="small"><Pill value="no provider" tone="warn" /> No sandbox is configured, so nothing can be submitted.</p>
          <div className="form-grid">
            <label className="field">Name<input value={prov.name} onChange={(e) => setProv({ ...prov, name: e.target.value })} /></label>
            <label className="field">API address<input placeholder="https://cape.example.net" value={prov.baseUrl} onChange={(e) => setProv({ ...prov, baseUrl: e.target.value })} /></label>
            <label className="field">API key<input type="password" value={prov.apiKey} onChange={(e) => setProv({ ...prov, apiKey: e.target.value })} /></label>
          </div><button disabled={busy} onClick={() => run(() => api("sandbox/providers", { body: { tenantId, ...prov } }), "Saved").then(reloadPolicy)}>Add provider</button></div>}
        <div className="card"><div className="form-grid">
          <label className="field"><span><input type="checkbox" checked={f.enabled} onChange={(e) => setF({ ...f, enabled: e.target.checked })} /> Allow sandbox submissions for this customer</span></label>
          <label className="field">Mode<select value={f.mode} onChange={(e) => setF({ ...f, mode: e.target.value })}><option value="hash">Hash lookup only (files never leave)</option><option value="file">Upload the file when the hash is unknown</option></select></label>
          <label className="field"><span><input type="checkbox" checked={f.autoApproveExecutables} onChange={(e) => setF({ ...f, autoApproveExecutables: e.target.checked })} /> Approve executables and scripts automatically</span></label>
          <label className="field">Never submit paths containing (one per line)<textarea value={f.neverSubmit} onChange={(e) => setF({ ...f, neverSubmit: e.target.value })} /></label>
        </div><button className="primary" disabled={busy} onClick={() => run(() => api(`sandbox/policy/${tenantId}`, { method: "PUT", body: { ...f, neverSubmit: f.neverSubmit.split("\n").map((x) => x.trim()).filter(Boolean) } }), "Saved").then(reloadPolicy)}>Save</button></div>
        <Table rows={subs || []} empty="No submissions." columns={[
          { key: "filename", label: "File", render: (s: any) => <>{s.filename || s.sha256.slice(0, 16)}<div className="small muted">{s.sha256.slice(0, 16)}… · {s.mode}</div></> },
          { key: "status", label: "Status", render: (s: any) => <><Pill value={s.status.replace("_", " ")} tone={TONE[s.status]} /> <span className="small">{s.reason}</span></> },
          { key: "verdict", label: "Verdict", render: (s: any) => s.verdict ? <Pill value={`${s.verdict}${s.score != null ? ` ${s.score}` : ""}`} tone={TONE[s.verdict]} /> : "" },
          { key: "createdAt", label: "Requested", render: (s: any) => `${fmtTime(s.createdAt)} by ${s.requestedBy}` },
          { key: "id", label: "", render: (s: any) => s.status === "awaiting_approval" ? <span className="row" style={{ gap: 4 }}>
            <button className="link" onClick={() => run(() => api(`sandbox/submissions/${s.id}/review`, { body: { approve: true } }), "Approved").then(reload)}>Approve</button>
            <button className="link" onClick={() => run(() => api(`sandbox/submissions/${s.id}/review`, { body: { approve: false } }), "Rejected").then(reload)}>Reject</button></span> : null },
        ]} />
      </>}
    </>
  );
}
