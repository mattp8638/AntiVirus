import { useState } from "react";
import { api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { Modal, PageHead, Sev, Table, TenantSelect, useAction, useData } from "../components/ui";

export default function AttackSurface() {
  const { tenantId, tenantName, can } = useApp();
  const { data, reload } = useData<any[]>("exposure/assets", { tenant_id: tenantId });
  const [adding, setAdding] = useState(false);
  const [open, setOpen] = useState<any>(null);
  const { run } = useAction();
  return (
    <>
      <PageHead title="External attack surface" subtitle="Scan the internet-facing IPs and hostnames you own for exposed RDP, SMB, databases, weak TLS and expiring certificates."
                actions={can("configure") && <button className="primary" onClick={() => setAdding(true)}>Add asset</button>} />
      <div className="card">
        <Table rows={data} onRow={(r) => r.lastResult?.findings && setOpen(r)} empty="No external assets yet."
               columns={[{ key: "target", label: "Asset", render: (r) => <><b className="mono">{r.target}</b><div className="small muted">{r.label}</div></> },
                         { key: "tenantId", label: "Tenant", render: (r) => tenantName(r.tenantId) },
                         { key: "open", label: "Open ports", render: (r) => r.lastResult?.openPorts?.map((p: any) => p.port).join(", ") || "—" },
                         { key: "worst", label: "Worst finding", render: (r) => r.lastResult?.findings?.[0] ? <Sev level={r.lastResult.findings[0].risk} /> : "—" },
                         { key: "lastScanAt", label: "Last scan", render: (r) => fmtTime(r.lastScanAt) },
                         { key: "scan", label: "", render: (r) => can("respond") && <button className="small" onClick={async (e) => { e.stopPropagation(); await run(() => api(`exposure/assets/${r.id}/scan`, { body: {} }), "Scan started; refresh in a minute"); setTimeout(reload, 15000); }}>Scan</button> }]} />
      </div>
      {open && (
        <Modal title={`Findings · ${open.target}`} onClose={() => setOpen(null)}>
          <p className="muted">{open.lastResult.address} · {open.lastResult.scannedPorts} ports checked · {fmtTime(open.lastResult.scannedAt)}</p>
          <Table rows={open.lastResult.findings.map((f: any, i: number) => ({ ...f, id: i }))} empty="No risky exposure found."
                 columns={[{ key: "risk", label: "Risk", render: (f) => <Sev level={f.risk} /> }, { key: "port", label: "Port" }, { key: "service", label: "Service" },
                           { key: "advice", label: "What to do" }, { key: "banner", label: "Banner", render: (f) => <span className="mono small">{f.banner}</span> }]} />
        </Modal>
      )}
      {adding && <AddAsset onClose={() => { setAdding(false); reload(); }} />}
    </>
  );
}

function AddAsset({ onClose }: { onClose: () => void }) {
  const { tenantId } = useApp();
  const [tenant, setTenant] = useState(tenantId);
  const [target, setTarget] = useState("");
  const [label, setLabel] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const { run, busy } = useAction();
  const submit = async () => { if (await run(() => api("exposure/assets", { body: { tenantId: tenant, target, label, ownershipConfirmed: confirmed } }), "Asset added")) onClose(); };
  return (
    <Modal title="Add external asset" onClose={onClose} footer={<><button onClick={onClose}>Cancel</button><button className="primary" disabled={busy || !confirmed || !target || !tenant} onClick={submit}>Add</button></>}>
      <div className="form-grid">
        <label className="field">Tenant<TenantSelect value={tenant} onChange={setTenant} allowAll={false} /></label>
        <label className="field">Hostname or IP<input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="vpn.customer.co.uk" /></label>
        <label className="field">Label<input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Office firewall" /></label>
      </div>
      <label className="row" style={{ marginTop: 12 }}><input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
        I confirm this customer owns this asset and has authorised us to scan it. Your name is recorded with the asset.</label>
    </Modal>
  );
}
