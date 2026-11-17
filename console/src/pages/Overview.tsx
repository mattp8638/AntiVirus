import { displayValue } from "../components/DisplayValue";
import { Fragment } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ago, fmtTime } from "../api";
import { useApp } from "../app-context";
import { Bars, ErrorNote, Meter, PageHead, Pill, Sev, Stat, Table, useData } from "../components/ui";
import { PRIORITY_TONE } from "./psa/ServiceBoard";

// The signed-in technician's queue: their tickets and alerts, what is past SLA, what failed, what waits for a decision.
function MyWork() {
  const { tenantId } = useApp();
  const navigate = useNavigate();
  const { data } = useData<any>("my-work", { tenant_id: tenantId });
  if (!data) return null;
  const { tickets, alerts, jobs, decisions } = data;
  const waiting = decisions.approvals + decisions.adminRequests;
  return (
    <>
      <h2 style={{ margin: "0 0 10px" }}>My work <Link to="/inbox?view=mine" className="small" style={{ fontWeight: 400 }}>Open my inbox</Link></h2>
      <div className="grid k4">
        <Stat label="My open tickets" value={tickets.mineCount} to="/service-board?assignee=me" hint={`${tickets.unassignedCount} unassigned in view`} />
        <Stat label="Past SLA" value={tickets.breachedCount} accent={tickets.breachedCount ? "red" : "green"} to="/service-board" hint="open tickets, everyone's" />
        <Stat label="My alerts" value={alerts.mineCount} to="/alerts?owner=me"
              accent={alerts.urgentUnowned ? "amber" : undefined} hint={`${alerts.urgentUnowned} critical/high with no owner`} />
        <Stat label="Waiting for a decision" value={waiting} accent={waiting ? "amber" : undefined}
              to={decisions.adminRequests ? "/admin-requests" : "/settings?tab=Approvals"}
              hint={`${decisions.adminRequests} admin requests · ${decisions.approvals} approvals`} />
      </div>
      <div className="grid k2" style={{ marginTop: 16 }}>
        <div className="card">
          <h3>My tickets <span className="small muted">by SLA</span></h3>
          <Table rows={tickets.mine} onRow={(t) => navigate(`/tickets/${t.id}`)} empty="Nothing assigned to you."
                 columns={[{ key: "number", label: "#", render: (t) => `#${t.number}` },
                           { key: "priority", label: "Pri", render: (t) => <Pill value={t.priority} tone={PRIORITY_TONE[t.priority]} /> },
                           { key: "subject", label: "Ticket", render: (t) => <>{displayValue(t.subject)}<div className="small muted">{displayValue(t.customer)}</div></> },
                           { key: "slaDueAt", label: "SLA", render: (t) => t.breached ? <Pill value="breached" tone="bad" /> : t.slaDueAt ? <span className="small">{fmtTime(t.slaDueAt)}</span> : "" }]} />
        </div>
        <div className="card">
          <h3>My alerts</h3>
          <Table rows={alerts.mine} onRow={() => navigate("/alerts?owner=me")} empty="No alerts assigned to you."
                 columns={[{ key: "severity", label: "Sev", render: (a) => <Sev level={a.severity} /> },
                           { key: "title", label: "Alert", render: (a) => <>{displayValue(a.title)}<div className="small muted">{displayValue(a.hostname)}</div></> },
                           { key: "createdAt", label: "When", render: (a) => ago(a.createdAt) }]} />
          {jobs.failedCount > 0 && <>
            <h3 style={{ marginTop: 16 }}>Failed jobs <span className="small muted">last 24 hours</span></h3>
            <Table rows={jobs.failed} onRow={() => navigate("/automation")}
                   columns={[{ key: "name", label: "Job" }, { key: "status", label: "Result", render: (j) => <Pill value={j.status} tone="bad" /> },
                             { key: "finishedAt", label: "Finished", render: (j) => ago(j.finishedAt) }]} />
          </>}
        </div>
      </div>
    </>
  );
}

// Penetration testing at a glance (docs/PENTEST.md): shown when the module is on and there is something to see or do.
function PentestCard() {
  const { tenantId, tenantName, can } = useApp();
  const navigate = useNavigate();
  const { data: modules } = useData<any>("modules");
  const on = !!modules?.enabled?.includes("pentest");
  const { data } = useData<any>(on ? "pentest/summary" : null, { tenant_id: tenantId });
  if (!on || !data || (!data.open && !can("pentest"))) return null;
  const waiting = data.awaitingAuthorisation + data.approvalsWaiting + data.findingsToReview;
  const n = (count: number, word: string) => `${count} ${word}${count === 1 ? "" : "s"}`;
  return (
    <>
      <h2 style={{ margin: "24px 0 10px" }}>Penetration testing <Link to="/pentest" className="small" style={{ fontWeight: 400 }}>Open engagements</Link></h2>
      <div className="grid k4">
        <Stat label="Open engagements" value={data.open} to="/pentest" hint={`${data.testingNow} authorised for testing right now`} />
        <Stat label="Checks running" value={data.checksRunning} accent={data.checksRunning ? "amber" : undefined} to="/pentest" hint="queued, running or waiting for an agent" />
        <Stat label="Waiting for a decision" value={waiting} accent={waiting ? "amber" : "green"} to={data.approvalsWaiting ? "/settings?tab=Approvals" : "/pentest"}
              hint={`${n(data.awaitingAuthorisation, "authorisation")} · ${n(data.approvalsWaiting, "check approval")} · ${n(data.findingsToReview, "finding")} to review`} />
        <Stat label="Not testing now" value={data.open - data.testingNow} accent={data.open - data.testingNow ? "amber" : "green"} to="/pentest"
              hint="awaiting authorisation, outside the window or hours, or stopped" />
      </div>
      {data.engagements.length > 0 && <div className="card" style={{ marginTop: 16 }}>
        <Table rows={data.engagements} onRow={(e) => navigate(`/pentest/${e.id}`)}
               columns={[{ key: "name", label: "Engagement", render: (e) => <><b>{displayValue(e.name)}</b><div className="small muted">{tenantName(e.tenantId)}</div></> },
                         { key: "state", label: "Testing", render: (e) => e.testingAllowed ? <Pill value="authorised" tone="good" />
                           : e.awaitingAuthorisation ? <Pill value="awaiting approval" tone="warn" /> : <span className="small muted">{displayValue(e.problem)}</span> },
                         { key: "running", label: "Checks running", className: "right" },
                         { key: "draftFindings", label: "Findings to review", className: "right" }]} />
      </div>}
    </>
  );
}

export default function Overview() {
  const { tenantId, tenantName } = useApp();
  const navigate = useNavigate();
  const { data, error } = useData<any>("dashboard", { tenant_id: tenantId, days: 14 });
  const sev = data?.alerts.bySeverity ?? {};
  const days: { label: string; value: number }[] = (data?.alerts.perDay ?? []).map((d: any) => ({ label: d.day, value: d.count }));
  return (
    <>
      <PageHead title="Dashboard" subtitle={`${tenantId ? tenantName(tenantId) : "All tenants"}`} />
      <MyWork />
      <PentestCard />
      <h2 style={{ margin: "24px 0 10px" }}>Security <span className="small muted">last 14 days</span></h2>
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
