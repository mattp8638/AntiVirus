import { useState } from "react";
import { api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { PageHead, Pill, Table, TenantSelect, useAction, useData } from "../components/ui";

export default function Deploy() {
  const { tenantId, tenantName, can } = useApp();
  const [target, setTarget] = useState(tenantId);
  const [label, setLabel] = useState("Rollout");
  const [groupId, setGroupId] = useState("");
  const [days, setDays] = useState("30");
  const [created, setCreated] = useState<any>(null);
  const { data: tokens, reload } = useData<any[]>("enrollment-tokens", { tenant_id: tenantId });
  const { data: groups } = useData<any[]>("groups", { tenant_id: target }, [target]);
  const { run, busy } = useAction();

  const create = async () => {
    const result = await run(() => api("enrollment-tokens", { body: { tenantId: target, label, groupId: groupId || null, expiresInDays: Number(days) || null } }));
    if (result) {
      setCreated(result);
      reload();
    }
  };

  return (
    <>
      <PageHead title="Deploy agents" subtitle="Create an enrollment token, then install with one command or your RMM/GPO/Intune/Jamf." />
      {can("configure") && (
        <div className="card">
          <h3>New enrollment token</h3>
          <div className="form-grid">
            <label className="field">Tenant<TenantSelect value={target} onChange={setTarget} allowAll={false} /></label>
            <label className="field">Label<input value={label} onChange={(e) => setLabel(e.target.value)} /></label>
            <label className="field">Place devices in group
              <select value={groupId} onChange={(e) => setGroupId(e.target.value)}>
                <option value="">None</option>{groups?.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
              </select>
            </label>
            <label className="field">Expires after (days)<input type="number" value={days} onChange={(e) => setDays(e.target.value)} /></label>
          </div>
          <div className="row" style={{ marginTop: 12 }}><button className="primary" disabled={busy || !target} onClick={create}>Create token</button></div>
          {created && (
            <div style={{ marginTop: 16 }}>
              <p>Copy this token now; it is not shown again.</p>
              <pre>{created.token}</pre>
              <h3 style={{ marginTop: 12 }}>Windows (Administrator PowerShell, in the folder with fenrir-agent-service.exe, fenrir-remote.exe and fenrir-amsi-provider.dll)</h3><pre>{created.install.windows}</pre>
              <h3 style={{ marginTop: 12 }}>Linux (systemd)</h3><pre>{created.install.linux}</pre>
              <h3 style={{ marginTop: 12 }}>macOS</h3><pre>{created.install.macos}</pre>
            </div>
          )}
        </div>
      )}
      <div className="card">
        <h3>Tokens</h3>
        <Table rows={tokens} empty="No tokens yet."
               columns={[{ key: "label", label: "Label" }, { key: "tenantId", label: "Tenant", render: (r) => tenantName(r.tenantId) },
                         { key: "tokenHint", label: "Ends with", render: (r) => <span className="mono">…{r.tokenHint}</span> },
                         { key: "uses", label: "Used", render: (r) => `${r.uses}${r.maxUses ? ` / ${r.maxUses}` : ""}` },
                         { key: "expiresAt", label: "Expires", render: (r) => fmtTime(r.expiresAt) },
                         { key: "revoked", label: "", render: (r) => r.revoked ? <Pill value="revoked" tone="muted" /> :
                             can("configure") && <button className="small danger" onClick={async () => { await run(() => api(`enrollment-tokens/${r.id}`, { method: "DELETE" }), "Token revoked"); reload(); }}>Revoke</button> }]} />
      </div>
    </>
  );
}
