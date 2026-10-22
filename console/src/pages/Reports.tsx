import { useState } from "react";
import { getToken } from "../api";
import { useApp } from "../app-context";
import { PageHead, Stat, TenantSelect, useAction, useData } from "../components/ui";

export default function Reports() {
  const { tenantId, me } = useApp();
  const [tenant, setTenant] = useState(tenantId || me?.user.tenantId || "");
  const [days, setDays] = useState(30);
  const { data } = useData<any>("reports/executive", { tenant_id: tenant, days }, [tenant, days]);
  const { run } = useAction();

  const openHtml = async () => {
    // Fetch with the session token, then open the report as a printable page.
    await run(async () => {
      const response = await fetch(`/api/console/reports/executive.html?tenant_id=${tenant}&days=${days}`, { headers: { Authorization: `Bearer ${getToken()}` } });
      if (!response.ok) throw new Error(`Report failed (${response.status})`);
      const url = URL.createObjectURL(new Blob([await response.text()], { type: "text/html" }));
      window.open(url, "_blank", "noopener");
    });
  };

  return (
    <>
      <PageHead title="Reports" subtitle="Executive summaries for customers: protection delivered, risk outstanding, compliance and service levels."
                actions={<>
                  <TenantSelect value={tenant} onChange={setTenant} allowAll={false} />
                  <select value={days} onChange={(e) => setDays(Number(e.target.value))} aria-label="Period">{[7, 30, 90].map((d) => <option key={d} value={d}>Last {d} days</option>)}</select>
                  <button className="primary" onClick={openHtml}>Open printable report</button>
                </>} />
      {data && (
        <>
          <div className="grid k4">
            <Stat label="Protected devices" value={data.devices.total} hint={`${data.devices.highRisk} high risk`} />
            <Stat label="Threat events stopped" value={data.threatEvents} accent="green" />
            <Stat label="Malicious domains blocked" value={data.dnsBlocked} accent="green" />
            <Stat label="Incidents" value={data.incidents.total} hint={`${data.incidents.resolved} resolved`} />
          </div>
          <div className="grid k2" style={{ marginTop: 16 }}>
            <div className="card"><h3>Compliance</h3>
              {data.compliance.map((c: any) => <div key={c.name} className="row" style={{ padding: "4px 0" }}><span style={{ flex: 1 }}>{c.name}</span><b>{c.score}%</b></div>)}
            </div>
            <div className="card"><h3>Service</h3>
              <dl className="kv"><dt>Tickets</dt><dd>{data.service.tickets}</dd><dt>Resolved</dt><dd>{data.service.resolved}</dd>
                <dt>Within SLA</dt><dd>{data.service.slaMet === null ? "n/a" : `${data.service.slaMet}%`}</dd></dl>
              <h3 style={{ marginTop: 12 }}>Open vulnerabilities</h3>
              <pre>{JSON.stringify(data.openVulnerabilities, null, 2)}</pre>
            </div>
          </div>
          <p className="small muted">Want this in the customer's inbox monthly? Add a webhook under Settings, or schedule it with the API: <code>{`GET /api/console/reports/executive?tenant_id=${tenant}`}</code></p>
        </>
      )}
    </>
  );
}
