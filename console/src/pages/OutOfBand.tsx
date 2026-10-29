import { useState } from "react";
import { ago, api } from "../api";
import { useApp } from "../app-context";
import { displayValue } from "../components/DisplayValue";
import { ErrorNote, Modal, PageHead, Pill, Table, TenantSelect, useAction, useListData } from "../components/ui";
import { confirmDialog } from "../components/dialogs";

interface Endpoint {
  id: string; tenantId: string; deviceId: string | null; deviceName: string; name: string; host: string; port: number; tls: boolean;
  tlsInsecure: boolean; username: string; hasPassword: boolean; route: "agent" | "direct"; probeDeviceId: string | null; probeName: string;
  status: string; amtVersion: string; powerState: string; lastError: string; lastCheckedAt: string | null;
}

const STATUS_TONE: Record<string, string> = { online: "good", unreachable: "bad", auth_failed: "bad", pending: "warn", unknown: "muted" };
const ACTIONS: [string, string][] = [["on", "Power on"], ["graceful-reset", "Restart (graceful)"], ["reset", "Reset"], ["cycle", "Power cycle"],
                                     ["graceful-off", "Shut down (graceful)"], ["off", "Power off"]];

export default function OutOfBand() {
  const { tenantId, tenantName, can } = useApp();
  const { data, error, reload } = useListData<Endpoint>("oob/amt", { tenant_id: tenantId });
  const { run, busy } = useAction();
  const [editing, setEditing] = useState<Partial<Endpoint> | null>(null);

  const check = async (row: Endpoint) => {
    const r = await run(() => api<any>(`oob/amt/${row.id}/check`, { method: "POST" }));
    if (r) reload();
  };
  const power = async (row: Endpoint, action: string, label: string) => {
    if (action !== "on" && !await confirmDialog(`${label} ${row.name || row.host}? This acts on the hardware, whatever Windows is doing.`)) return;
    const r = await run(() => api<any>(`oob/amt/${row.id}/power`, { body: { action } }),
                        row.route === "agent" ? `${label} sent through ${row.probeName}` : `${label} sent`);
    if (r) reload();
  };
  const remove = async (row: Endpoint) => {
    if (await confirmDialog(`Remove ${row.name || row.host}? Its stored AMT password is deleted.`) && await run(() => api(`oob/amt/${row.id}`, { method: "DELETE" }), "Removed")) reload();
  };

  return (
    <>
      <PageHead title="Out-of-band management"
                subtitle="Intel AMT / vPro power control that works when Windows has crashed, hangs at boot or is switched off. Fenrir reaches the management engine directly (site VPN) or through an agent on the same network; the AMT password stays encrypted in Fenrir and is released to that agent for one request at a time. For hardware KVM, open a tunnel to the AMT address (port 5900 or 16994/16995) from Network topology."
                actions={can("configure") && <button className="primary" onClick={() => setEditing({ tenantId: tenantId || "", port: 16992, route: "agent", username: "admin" })}>Add AMT device</button>} />
      <ErrorNote error={error} />
      <div className="card">
        <Table rows={data ?? undefined} empty="No Intel AMT devices. Network topology flags machines answering on the AMT ports (16992/16993)."
               columns={[
                 { key: "name", label: "Machine", render: (r) => <><b>{displayValue(r.name || r.deviceName || r.host)}</b>
                   <div className="small muted">{tenantName(r.tenantId)} · {r.host}:{r.port}{r.tls ? " (TLS)" : ""} · {r.route === "agent" ? `via ${r.probeName || "agent"}` : "direct"}</div></> },
                 { key: "status", label: "AMT", render: (r) => <><Pill value={r.status.replace("_", " ")} tone={STATUS_TONE[r.status]} />
                   <div className="small muted">{displayValue(r.amtVersion)}{r.lastCheckedAt ? ` · ${ago(r.lastCheckedAt)}` : ""}</div>
                   {r.lastError && <div className="small error">{displayValue(r.lastError)}</div>}</> },
                 { key: "powerState", label: "Power", render: (r) => <Pill value={r.powerState || "unknown"} tone={r.powerState === "on" ? "good" : r.powerState ? "warn" : "muted"} /> },
                 { key: "actions", label: "", className: "right", render: (r) => <span style={{ display: "inline-flex", gap: 6, flexWrap: "wrap", justifyContent: "flex-end" }}>
                   <button className="ghost" disabled={busy} onClick={() => check(r)}>Check</button>
                   {can("respond") && <select aria-label="Power action" value="" disabled={busy} onChange={(e) => { const a = ACTIONS.find(([k]) => k === e.target.value); if (a) power(r, a[0], a[1]); }}>
                     <option value="">Power…</option>{ACTIONS.map(([k, label]) => <option key={k} value={k}>{label}</option>)}</select>}
                   {can("configure") && <><button className="ghost" onClick={() => setEditing(r)}>Edit</button>
                     <button className="danger" disabled={busy} onClick={() => remove(r)}>Remove</button></>}</span> },
               ]} />
      </div>
      {editing && <EndpointEditor value={editing} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); reload(); }} />}
    </>
  );
}

function EndpointEditor({ value, onClose, onSaved }: { value: Partial<Endpoint>; onClose: () => void; onSaved: () => void }) {
  const { run, busy } = useAction();
  const [form, setForm] = useState<any>({ ...value, password: "" });
  const { data: devices } = useListData<any>(form.tenantId ? "devices" : null, { tenant_id: form.tenantId });
  const set = (key: string) => (e: { target: { value: string } }) => setForm({ ...form, [key]: e.target.value });
  const save = async () => {
    const body: any = { tenantId: form.tenantId, name: form.name, host: form.host, port: Number(form.port), username: form.username, route: form.route,
                        probeDeviceId: form.route === "agent" ? form.probeDeviceId || null : null, deviceId: form.deviceId || null, tlsInsecure: !!form.tlsInsecure };
    if (form.password) body.password = form.password;
    if (await run(() => (form.id ? api(`oob/amt/${form.id}`, { method: "PATCH", body }) : api("oob/amt", { body })), "AMT device saved")) onSaved();
  };
  return (
    <Modal title={form.id ? `Edit ${form.name || form.host}` : "Add Intel AMT device"} onClose={onClose}
           footer={<button className="primary" disabled={busy || !form.host || !form.tenantId || (!form.id && !form.password) || (form.route === "agent" && !form.probeDeviceId)} onClick={save}>Save</button>}>
      <div className="form-grid">
        {!form.id && <TenantSelect value={form.tenantId || ""} allowAll={false} label="Customer" onChange={(id) => setForm({ ...form, tenantId: id })} />}
        <label className="field">Name<input value={form.name || ""} onChange={set("name")} placeholder="Reception PC" /></label>
        <label className="field">AMT address<input value={form.host || ""} onChange={set("host")} placeholder="192.168.1.40" /></label>
        <label className="field">Port<select value={form.port} onChange={set("port")}><option value={16992}>16992 (HTTP)</option><option value={16993}>16993 (TLS)</option></select></label>
        <label className="field">AMT user<input value={form.username || ""} onChange={set("username")} /></label>
        <label className="field">{form.id ? "New AMT password (blank keeps it)" : "AMT password"}<input type="password" value={form.password} onChange={set("password")} autoComplete="new-password" /></label>
        <label className="field">Reach it<select value={form.route} onChange={set("route")}><option value="agent">Through an agent on the same network</option><option value="direct">Directly from the Fenrir server (site VPN)</option></select></label>
        {form.route === "agent" && <label className="field">Agent on the same network<select value={form.probeDeviceId || ""} onChange={set("probeDeviceId")}>
          <option value="">Choose…</option>{devices?.map((d) => <option key={d.id} value={d.id}>{displayValue(d.hostname)}</option>)}</select></label>}
        <label className="field">This is the AMT of (optional)<select value={form.deviceId || ""} onChange={set("deviceId")}>
          <option value="">Not a managed device</option>{devices?.map((d) => <option key={d.id} value={d.id}>{displayValue(d.hostname)}</option>)}</select></label>
      </div>
      {Number(form.port) === 16993 && <label className="small"><input type="checkbox" checked={!!form.tlsInsecure} onChange={(e) => setForm({ ...form, tlsInsecure: e.target.checked })} /> Accept AMT's self-signed certificate</label>}
    </Modal>
  );
}
