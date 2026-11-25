// Hypervisor and virtual infrastructure monitoring (RMM-14): Proxmox VE and VMware vCenter read through their own APIs,
// with hosts, virtual machines and storage, their relationships, and alerts that are suppressed when the host is down.
import { useState } from "react";
import { api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { PageHead, Pill, Table, useAction, useData } from "../components/ui";

const TONE: Record<string, string> = { ok: "good", alert: "bad", suppressed: "neutral", unknown: "warn", pending: "blue", unreachable: "bad", auth_failed: "bad", error: "bad" };

export default function Infrastructure() {
  const { tenantId } = useApp();
  const { run, busy } = useAction();
  const { data: sources, reload } = useData<any[]>("infrastructure/sources", { tenantId: tenantId || undefined }, [tenantId]);
  const { data: devices } = useData<any[]>(tenantId ? "devices" : null, { tenant_id: tenantId || undefined }, [tenantId]);
  const [open, setOpen] = useState<any>(null);
  const { data: assets, reload: reloadAssets } = useData<any[]>(open ? `infrastructure/sources/${open.id}/assets` : null, undefined, [open?.id]);
  const [f, setF] = useState<any>({ name: "", provider: "proxmox", baseUrl: "", route: "agent", probeDeviceId: "", tokenId: "", secret: "", username: "", password: "", tlsInsecure: false });
  const create = () => run(() => api("infrastructure/sources", { body: { tenantId, name: f.name, provider: f.provider, baseUrl: f.baseUrl, route: f.route,
    probeDeviceId: f.route === "agent" ? f.probeDeviceId : null, tlsInsecure: f.tlsInsecure,
    credentials: f.provider === "proxmox" ? { tokenId: f.tokenId, secret: f.secret } : { username: f.username, password: f.password } } }), "Added").then(reload);
  const byId: Record<string, any> = Object.fromEntries((assets || []).map((a: any) => [a.externalId, a]));
  return (
    <>
      <PageHead title="Infrastructure" subtitle="Hypervisors read through their own APIs: hosts, virtual machines and storage, with alerts that know which host each VM runs on." />
      {tenantId && <details className="card"><summary>Add a Proxmox VE or vCenter source</summary>
        <div className="form-grid">
          <label className="field">Name<input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></label>
          <label className="field">Type<select value={f.provider} onChange={(e) => setF({ ...f, provider: e.target.value })}><option value="proxmox">Proxmox VE</option><option value="vsphere">VMware vCenter</option></select></label>
          <label className="field">Address<input placeholder="https://pve.example.local:8006" value={f.baseUrl} onChange={(e) => setF({ ...f, baseUrl: e.target.value })} /></label>
          <label className="field">Reached<select value={f.route} onChange={(e) => setF({ ...f, route: e.target.value })}><option value="agent">Through a device on that network (Linux or macOS)</option><option value="direct">Directly (public address)</option></select></label>
          {f.route === "agent" && <label className="field">Probe device<select value={f.probeDeviceId} onChange={(e) => setF({ ...f, probeDeviceId: e.target.value })}><option value="">Choose…</option>
            {(devices || []).filter((d: any) => d.platform !== "windows").map((d: any) => <option key={d.id} value={d.id}>{d.hostname}</option>)}</select></label>}
          {f.provider === "proxmox" ? <>
            <label className="field">API token ID<input placeholder="fenrir@pve!monitor" value={f.tokenId} onChange={(e) => setF({ ...f, tokenId: e.target.value })} /></label>
            <label className="field">Token secret<input type="password" value={f.secret} onChange={(e) => setF({ ...f, secret: e.target.value })} /></label></> : <>
            <label className="field">User (read-only role)<input value={f.username} onChange={(e) => setF({ ...f, username: e.target.value })} /></label>
            <label className="field">Password<input type="password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} /></label></>}
          <label className="field"><span><input type="checkbox" checked={f.tlsInsecure} onChange={(e) => setF({ ...f, tlsInsecure: e.target.checked })} /> Accept a self-signed certificate</span></label>
        </div><button className="primary" disabled={busy} onClick={create}>Add</button></details>}
      <Table rows={sources || []} empty="No sources yet." onRow={(s: any) => setOpen(s)} columns={[
        { key: "name", label: "Source" }, { key: "provider", label: "Type" }, { key: "route", label: "Reached" },
        { key: "status", label: "Status", render: (s: any) => <><Pill value={s.status} tone={TONE[s.status]} /> <span className="small">{s.lastError}</span></> },
        { key: "lastPolledAt", label: "Read", render: (s: any) => (s.lastPolledAt ? fmtTime(s.lastPolledAt) : "never") },
      ]} />
      {open && <div className="card">
        <div className="row"><h3 style={{ flex: 1, margin: 0 }}>{open.name}</h3>
          <button disabled={busy} onClick={() => run(() => api(`infrastructure/sources/${open.id}/poll`, { method: "POST" }), "Polled").then(() => { reload(); reloadAssets(); })}>Poll now</button>
          <button className="link" onClick={() => setOpen(null)}>Close</button></div>
        <Table rows={assets || []} empty="Nothing read yet." columns={[
          { key: "kind", label: "Kind" }, { key: "name", label: "Name" },
          { key: "parentExternalId", label: "Host", render: (a: any) => byId[a.parentExternalId]?.name || a.parentExternalId },
          { key: "state", label: "State" },
          { key: "health", label: "Health", render: (a: any) => <><Pill value={a.health} tone={TONE[a.health]} /> <span className="small">{a.reason}</span></> },
          { key: "expectedState", label: "Expected", render: (a: any) => a.kind !== "vm" ? "" : <select value={a.expectedState} onChange={(e) =>
            run(() => api(`infrastructure/assets/${a.id}/expected`, { method: "PUT", body: { expectedState: e.target.value } })).then(reloadAssets)}>
            <option value="">not watched</option><option value="running">running</option><option value="stopped">stopped</option></select> },
        ]} />
      </div>}
    </>
  );
}
