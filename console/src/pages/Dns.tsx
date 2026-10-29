import { displayValue } from "../components/DisplayValue";
import { useState } from "react";
import { api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { PageHead, Pill, Stat, Table, useAction, useData, useListData } from "../components/ui";

export default function Dns() {
  const { tenantId, can } = useApp();
  const [action, setAction] = useState("");
  const [hours, setHours] = useState(24);
  const { data } = useData<any>("dns/log", { tenant_id: tenantId, action, hours });
  const [domain, setDomain] = useState("");
  const [check, setCheck] = useState<any>(null);
  const { run, busy } = useAction();
  const blocked = data?.entries.filter((e: any) => e.action === "block").length ?? 0;
  return (
    <>
      <PageHead title="DNS protection" subtitle="Encrypted DNS filtering that follows every device on and off the network. Configure categories and lists in each policy's DNS section." />
      <div className="grid k3">
        <Stat label={`Blocked (${hours}h)`} value={blocked} accent="red" />
        <Stat label="Top blocked category" value={data?.topCategories[0]?.[0] ?? "—"} hint={data?.topCategories[0] ? `${data.topCategories[0][1]} lookups` : ""} />
        <div className="card">
          <div className="label small muted">Check a domain</div>
          <div className="row" style={{ marginTop: 6 }}>
            <input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="example.com" onKeyDown={(e) => e.key === "Enter" && domain && run(() => api("dns/check", { query: { domain, tenant_id: tenantId } })).then(setCheck)} />
            <button disabled={!domain || busy} onClick={async () => setCheck(await run(() => api("dns/check", { query: { domain, tenant_id: tenantId } })))}>Check</button>
          </div>
          {check && <p className="small"><Pill value={check.action} /> {displayValue(check.reason)}{check.category ? ` · ${check.category}` : ""}</p>}
        </div>
      </div>
      <div className="grid k2" style={{ marginTop: 16 }}>
        <div className="card"><h3>Top blocked domains</h3>
          <Table rows={data?.topDomains.map(([d, c]: [string, number]) => ({ id: d, domain: d, count: c }))} empty="Nothing blocked in this window."
                 columns={[{ key: "domain", label: "Domain", render: (r) => <span className="mono">{displayValue(r.domain)}</span> }, { key: "count", label: "Lookups", className: "right" }]} /></div>
        <div className="card"><h3>Blocked categories</h3>
          <Table rows={data?.topCategories.map(([c, n]: [string, number]) => ({ id: c, category: c, count: n }))} empty="—"
                 columns={[{ key: "category", label: "Category" }, { key: "count", label: "Lookups", className: "right" }]} /></div>
      </div>
      <BlocklistsCard canManage={can("platform")} />
      <div className="card">
        <div className="row" style={{ marginBottom: 10 }}>
          <h3 style={{ margin: 0 }}>Query log</h3><span style={{ flex: 1 }} />
          <select value={action} onChange={(e) => setAction(e.target.value)} aria-label="Action"><option value="">All logged</option><option value="block">Blocked</option><option value="observe">Observed</option><option value="allow">Allowed</option></select>
          <select value={hours} onChange={(e) => setHours(Number(e.target.value))} aria-label="Window">{[1, 24, 168].map((h) => <option key={h} value={h}>{h}h</option>)}</select>
        </div>
        <Table rows={data?.entries} empty="No logged queries. Logging defaults to blocked lookups only."
               columns={[{ key: "at", label: "Time", render: (r) => fmtTime(r.at) }, { key: "qname", label: "Domain", render: (r) => <span className="mono">{displayValue(r.qname)}</span> },
                         { key: "qtype", label: "Type" }, { key: "action", label: "Action", render: (r) => <Pill value={r.action} /> },
                         { key: "category", label: "Category" }, { key: "reason", label: "Reason" }]} />
      </div>
    </>
  );
}

function BlocklistsCard({ canManage }: { canManage: boolean }) {
  const { data, reload } = useListData<any>("dns/blocklists");
  const { run, busy } = useAction();
  const toggle = async (row: any) => {
    if (await run(() => api(`dns/blocklists/${row.id}`, { method: "PATCH", body: { enabled: !row.enabled } }), row.enabled ? "List disabled" : "List enabled")) reload();
  };
  const sync = async (row: any) => {
    const result = await run(() => api<any>(`dns/blocklists/${row.id}/sync`, { method: "POST" }));
    if (result) reload();
  };
  return (
    <div className="card">
      <h3>External blocklists</h3>
      <p className="small muted">Refreshed on a schedule by the server. Malware lists block wherever DNS protection is on; other lists block only where a policy blocks their category. Policy allow lists and allow indicators always win.</p>
      <Table rows={data ?? undefined} empty="No lists configured."
             columns={[{ key: "name", label: "List", render: (r) => <><b>{displayValue(r.name)}</b><div className="small muted">{displayValue(r.description)}</div></> },
                       { key: "category", label: "Category" },
                       { key: "enabled", label: "State", render: (r) => <Pill value={r.enabled ? "enabled" : "disabled"} /> },
                       { key: "domainCount", label: "Domains", className: "right", render: (r) => Number(r.domainCount || 0).toLocaleString() },
                       { key: "lastSuccessAt", label: "Last refresh", render: (r) => r.lastSuccessAt ? fmtTime(r.lastSuccessAt) : "never" },
                       { key: "lastError", label: "Problem", render: (r) => r.lastError ? <span className="small" style={{ color: "var(--red)" }}>{displayValue(r.lastError)}</span> : "" },
                       ...(canManage ? [{ key: "actions", label: "", render: (r: any) => <div className="row">
                         <button className="ghost" disabled={busy} onClick={() => toggle(r)}>{r.enabled ? "Disable" : "Enable"}</button>
                         <button className="ghost" disabled={busy || !r.enabled} onClick={() => sync(r)}>Refresh now</button></div> }] : [])]} />
    </div>
  );
}
