import { useEffect, useState } from "react";
import { confirmDialog } from "../components/dialogs";
import { api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { ErrorNote, Modal, PageHead, Pill, Table, TenantSelect, useAction, useListData } from "../components/ui";

export default function Vault() {
  const { tenantId, can } = useApp();
  const { data, error, reload } = useListData<any>(can("vault") ? "vault/credentials" : null, { tenant_id: tenantId });
  const [editing, setEditing] = useState<any>(null);
  const [revealed, setRevealed] = useState<string | null>(null);
  const { run, busy } = useAction();
  useEffect(() => { setEditing(null); setRevealed(null); }, [tenantId]);
  useEffect(() => { if (revealed === null) return; const timer = setTimeout(() => setRevealed(null), 30000); return () => clearTimeout(timer); }, [revealed]);
  if (!can("vault")) return <PageHead title="Credential vault" subtitle="Your role does not have vault access." />;
  const close = () => { setEditing(null); setRevealed(null); };
  const save = async () => {
    const body = editing.id ? { name: editing.name, username: editing.username, url: editing.url, notes: editing.notes, ...(editing.secret ? { secret: editing.secret } : {}) }
      : { tenantId: editing.tenantId, name: editing.name, username: editing.username, url: editing.url, notes: editing.notes, secret: editing.secret };
    if (await run(() => api(editing.id ? "vault/credentials/" + editing.id : "vault/credentials", { method: editing.id ? "PATCH" : "POST", body }), "Credential saved")) { close(); reload(); }
  };
  return <>
    <PageHead title="Credential vault" subtitle="Customer credentials, encrypted at rest. Reveals require fresh authentication and are audited."
      actions={<button className="primary" onClick={() => { setRevealed(null); setEditing({ tenantId, name: "", username: "", url: "", notes: "", secret: "" }); }}>New credential</button>} />
    <ErrorNote error={error} />
    <div className="card"><Table rows={data} onRow={row => { setRevealed(null); setEditing({ ...row, secret: "" }); }} columns={[
      { key: "name", label: "Credential" }, { key: "username", label: "Username" }, { key: "url", label: "Address" },
      { key: "archived", label: "Status", render: row => <Pill value={row.archived ? "archived" : "active"} /> },
      { key: "updatedAt", label: "Updated", render: row => fmtTime(row.updatedAt) }
    ]} empty="No credentials for this customer." /></div>
    {editing && <Modal title={editing.id ? editing.name : "New credential"} onClose={close} footer={<>
      {editing.id && <button disabled={busy} onClick={async () => { if (await run(() => api("vault/credentials/" + editing.id, { method: "PATCH", body: { archived: !editing.archived } }), editing.archived ? "Restored" : "Archived")) { close(); reload(); } }}>{editing.archived ? "Restore" : "Archive"}</button>}
      {editing.id && editing.archived && <button className="danger" disabled={busy} onClick={async () => {
        if (await confirmDialog(`Delete "${editing.name}" permanently? The secret is destroyed and cannot be recovered. The audit log keeps that it existed.`, { confirmLabel: "Delete permanently" })
            && await run(() => api("vault/credentials/" + editing.id, { method: "DELETE" }), "Credential deleted")) { close(); reload(); }
      }}>Delete permanently</button>}
      <button className="primary" disabled={busy || !editing.name || (!editing.id && (!editing.tenantId || !editing.secret))} onClick={save}>Save</button>
    </>}>
      {!editing.id && <label className="field">Customer<TenantSelect value={editing.tenantId} onChange={id => setEditing({ ...editing, tenantId: id })} /></label>}
      {[["name","Name"],["username","Username"],["url","Address"],["notes","Notes (no secrets)"]].map(([key,label]) => <label className="field" key={key}>{label}<input value={editing[key]} onChange={e => setEditing({ ...editing, [key]: e.target.value })} /></label>)}
      <label className="field">{editing.id ? "Replace secret (leave blank to keep)" : "Secret"}<input type="password" autoComplete="new-password" value={editing.secret} onChange={e => setEditing({ ...editing, secret: e.target.value })} /></label>
      {editing.id && !editing.archived && <button disabled={busy} onClick={async () => { const result = await run(() => api<{secret: string}>("vault/credentials/" + editing.id + "/reveal", { method: "POST" })); if (result) setRevealed(result.secret); }}>Reveal for 30 seconds</button>}
      {revealed !== null && <div className="card"><pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{revealed}</pre><button onClick={() => setRevealed(null)}>Hide now</button></div>}
    </Modal>}
  </>;
}
