// Google Workspace posture (VULN-12): read-only by default; safe changes only when the customer allowed the write scope.
import { useState } from "react";
import { api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { promptDialog } from "../components/dialogs";
import { PageHead, Pill, Table, useAction, useData } from "../components/ui";

const TONE: Record<string, string> = { pass: "good", warn: "warn", fail: "bad", unavailable: "neutral" };

export default function GoogleWorkspace() {
  const { tenantId } = useApp();
  const { run, busy } = useAction();
  const { data: scopes } = useData<any>("google-workspace/scopes");
  const { data: conns, reload } = useData<any[]>(tenantId ? "google-workspace/connections" : null, { tenantId: tenantId || undefined }, [tenantId]);
  const [f, setF] = useState({ domain: "", adminEmail: "", serviceAccountKey: "", allowChanges: false });
  const [result, setResult] = useState<any>(null);
  const conn = conns?.[0];
  const fix = async (action: string, email: string) => {
    const typed = await promptDialog(`Type ${email} to confirm`);
    if (typed) await run(() => api(`google-workspace/connections/${conn.id}/remediate`, { body: { action, email, confirmEmail: typed } }), "Done");
  };
  return (
    <>
      <PageHead title="Google Workspace" subtitle="2-Step Verification, administrators, stale accounts, third-party app access and email authentication, read through the Admin SDK with explicit scopes." />
      {!tenantId ? <div className="card empty">Choose a customer.</div> : !conn ? (
        <div className="card"><h3>Connect</h3>
          <p className="small muted">Create a service account, authorise its client ID for domain-wide delegation (Admin console › Security › API controls) with these scopes: {scopes?.read.join(", ")}.
            To let Fenrir make the safe changes, also add {scopes?.write.join(", ")}.</p>
          <div className="form-grid">
            <label className="field">Primary domain<input value={f.domain} onChange={(e) => setF({ ...f, domain: e.target.value })} /></label>
            <label className="field">Admin to act as<input value={f.adminEmail} onChange={(e) => setF({ ...f, adminEmail: e.target.value })} /></label>
            <label className="field">Service account key (JSON)<textarea value={f.serviceAccountKey} onChange={(e) => setF({ ...f, serviceAccountKey: e.target.value })} /></label>
            <label className="field"><span><input type="checkbox" checked={f.allowChanges} onChange={(e) => setF({ ...f, allowChanges: e.target.checked })} /> Allow safe changes (write scope granted)</span></label>
          </div>
          <button className="primary" disabled={busy} onClick={() => run(() => api("google-workspace/connections", { body: { tenantId, ...f } }), "Connected").then(reload)}>Connect</button></div>
      ) : <>
        <div className="row"><p className="small muted" style={{ flex: 1 }}>{conn.domain} as {conn.adminEmail} · {conn.allowChanges ? "changes allowed" : "read only"} · {conn.status}{conn.lastError && `: ${conn.lastError}`}</p>
          <button className="primary" disabled={busy} onClick={async () => setResult(await run(() => api<any>(`google-workspace/connections/${conn.id}/assess`, { method: "POST" })))}>Assess now</button></div>
        {result && <><p className="small">Assessed {fmtTime(result.createdAt)}</p>
          <Table rows={result.checks} columns={[
            { key: "status", label: "", render: (c: any) => <Pill value={c.status} tone={TONE[c.status]} /> },
            { key: "title", label: "Check", render: (c: any) => <>{c.title}<div className="small muted">{c.detail}</div></> },
            { key: "evidence", label: "Evidence", render: (c: any) => <span className="small">{c.evidence.map((e: string) => (
              <div key={e}>{e}{conn.allowChanges && c.check === "stale-accounts" && <button className="link" onClick={() => fix("suspend", e)}>suspend</button>}
                {conn.allowChanges && c.check === "2sv-users" && <button className="link" onClick={() => fix("signout", e)}>sign out</button>}</div>))}</span> },
            { key: "remedy", label: "Fix", render: (c: any) => <span className="small">{c.remedy}</span> },
          ]} /></>}
      </>}
    </>
  );
}
