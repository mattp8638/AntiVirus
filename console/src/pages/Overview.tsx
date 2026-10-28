import { displayValue } from "../components/DisplayValue";
import { Fragment } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ago } from "../api";
import { useApp } from "../app-context";
import { Bars, ErrorNote, Meter, PageHead, Sev, Stat, Table, useData } from "../components/ui";

export default function Overview() {
  const { tenantId, tenantName } = useApp();
  const navigate = useNavigate();
  const { data, error } = useData<any>("dashboard", { tenant_id: tenantId, days: 14 });
  const sev = data?.alerts.bySeverity ?? {};
  const days: { label: string; value: number }[] = (data?.alerts.perDay ?? []).map((d: any) => ({ label: d.day, value: d.count }));
  return (
    <>
      <PageHead title="Security overview" subtitle={`${tenantId ? tenantName(tenantId) : "All tenants"} · last 14 days`} />
      <ErrorNote error={error} />
      {data && (
        <>
          <div className="grid k4">
            <Stat label="Protected devices" value={data.devices.total} hint={`${data.devices.online} online · ${data.devices.pendingApproval} awaiting approval`} />
            <Stat label="Open incidents" value={data.incidents.length} accent={data.incidents.length ? "red" : "green"}
                  hint={`${sev.critical ?? 0} critical · ${sev.high ?? 0} high alerts`} />
            <Stat label="Threats stopped" value={data.protection.threatEvents} accent="green" hint={`${data.protection.dnsBlocked} malicious DNS lookups blocked`} />
            <Stat label="Known-exploited vulns" value={data.vulnerabilities.knownExploited} accent={data.vulnerabilities.knownExploited ? "amber" : "green"}
                  hint={`${data.vulnerabilities.bySeverity.critical ?? 0} critical open`} />
          </div>
          <div className="grid side" style={{ marginTop: 16 }}>
            <div className="card">
              <h3>Alerts per day</h3>
              <Bars data={days} />
              <div className="row small muted" style={{ marginTop: 6 }}>
                {["critical", "high", "medium", "low"].map((s) => <span key={s}><Sev level={s} /> {displayValue(sev[s] ?? 0)}</span>)}
              </div>
            </div>
            <div className="card">
              <h3>Fleet</h3>
              <dl className="kv">
                <dt>Isolated now</dt><dd>{displayValue(data.devices.isolated)}</dd>
                <dt>At risk (score ≥ 40)</dt><dd>{displayValue(data.devices.atRisk)}</dd>
                {Object.entries(data.devices.byPlatform).map(([k, v]) => (<Fragment key={k}><dt>{k}</dt><dd>{String(v)}</dd></Fragment>))}
                <dt>Open tickets</dt><dd>{displayValue(data.psa.openTickets)} {data.psa.slaBreached ? <span className="badge tone-bad">{displayValue(data.psa.slaBreached)} past SLA</span> : null}</dd>
              </dl>
            </div>
          </div>
          <div className="grid k2" style={{ marginTop: 16 }}>
            <div className="card">
              <div className="row"><h3 style={{ margin: 0 }}>Open incidents</h3><span style={{ flex: 1 }} /><Link to="/incidents">All incidents →</Link></div>
              <Table rows={data.incidents} onRow={(r) => navigate(`/incidents/${r.id}`)} empty="No open incidents. Quiet is good."
                     columns={[{ key: "severity", label: "Sev", render: (r) => <Sev level={r.severity} /> },
                               { key: "title", label: "Incident" },
                               { key: "createdAt", label: "Opened", render: (r) => ago(r.createdAt) }]} />
            </div>
            <div className="card">
              <h3>Riskiest devices</h3>
              <Table rows={data.riskiestDevices} onRow={(r) => navigate(`/devices/${r.id}`)} empty="No devices with open risk."
                     columns={[{ key: "hostname", label: "Device" },
                               { key: "tenantId", label: "Tenant", render: (r) => tenantName(r.tenantId) },
                               { key: "riskScore", label: "Risk", render: (r) => <div style={{ minWidth: 120 }}><Meter value={r.riskScore} /> <span className="small">{displayValue(r.riskScore)}</span></div> }]} />
            </div>
          </div>
          <div className="grid k2" style={{ marginTop: 16 }}>
            <div className="card">
              <h3>Top detections</h3>
              <Table rows={data.alerts.topRules} columns={[{ key: "title", label: "Rule" }, { key: "count", label: "Alerts", className: "right" }]} />
            </div>
            <div className="card">
              <h3>MITRE ATT&CK techniques seen</h3>
              <div className="heat">
                {data.mitre.length ? data.mitre.map((m: any) => (
                  <div key={m.technique} style={{ background: `rgba(244,63,94,${Math.min(0.6, 0.1 + m.count / 20)})` }}>
                    <a href={`https://attack.mitre.org/techniques/${m.technique.replace(".", "/")}/`} target="_blank" rel="noreferrer">{displayValue(m.technique)}</a>
                    <span className="muted"> ×{displayValue(m.count)}</span>
                  </div>
                )) : <span className="muted">None in this period.</span>}
              </div>
            </div>
          </div>
        </>
      )}
    </>
  );
}
