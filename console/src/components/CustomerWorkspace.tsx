import { displayValue } from "./DisplayValue";
import { Link, useNavigate } from "react-router-dom";
import { ago } from "../api";
import { useApp } from "../app-context";
import { Pill, Sev, useData } from "./ui";

// One customer's open work across modules. "Open in ..." switches the console to this customer first, so the module
// opens already filtered: nothing is looked up or typed twice.
export function CustomerWorkspace({ tenantId }: { tenantId: string }) {
  const { data, error } = useData<any>(`workspace/${tenantId}`);
  const { setTenantId } = useApp();
  const navigate = useNavigate();
  const open = (path: string) => { setTenantId(tenantId); navigate(path); };
  if (error) return <p className="small muted">{error}</p>;
  if (!data) return <p className="small muted">Loading…</p>;
  const v = data.vulnerabilities;
  return (
    <div className="grid k2" style={{ gap: 14 }}>
      <div>
        <div className="row small" style={{ justifyContent: "space-between" }}>
          <b>Open tickets: {data.tickets.open}{data.tickets.overdue ? <span style={{ color: "#f87171" }}> ({data.tickets.overdue} past SLA)</span> : null}</b>
          <button className="small" onClick={() => open("/service-board")}>Open in Service board</button>
        </div>
        {data.tickets.items.map((t: any) => (
          <div key={t.id} className="small" style={{ padding: "3px 0" }}>
            <Link to={`/tickets/${t.id}`}>#{t.number} {displayValue(t.subject)}</Link>
            <span className="muted"> · {displayValue(t.priority)} · {displayValue(t.status)}{t.assignee ? ` · ${t.assignee}` : " · unassigned"}{t.device ? ` · ${t.device}` : ""}</span>
          </div>
        ))}
        {data.tickets.open === 0 && <p className="small muted">No open tickets.</p>}

        <div className="row small" style={{ justifyContent: "space-between", marginTop: 12 }}>
          <b>Devices: {data.devices.online}/{data.devices.total} online{data.devices.attentionCount ? `, ${data.devices.attentionCount} need attention` : ""}</b>
          <button className="small" onClick={() => open("/devices")}>Open in Devices</button>
        </div>
        {data.devices.attention.map((d: any) => (
          <div key={d.deviceId} className="small" style={{ padding: "3px 0" }}>
            <Link to={`/devices/${d.deviceId}`}>{displayValue(d.hostname)}</Link> <span className="muted">· {d.reasons.join(", ")}</span>
          </div>
        ))}
      </div>
      <div>
        <div className="row small" style={{ justifyContent: "space-between" }}>
          <b>Open alerts: {data.alerts.open}{data.incidents.length ? `, incidents: ${data.incidents.length}` : ""}</b>
          <button className="small" onClick={() => open("/alerts")}>Open in Alerts</button>
        </div>
        {data.incidents.map((i: any) => (
          <div key={i.id} className="small" style={{ padding: "3px 0" }}><Sev level={i.severity} /> <Link to={`/incidents/${i.id}`}>{displayValue(i.title)}</Link> <span className="muted">· {displayValue(i.status)}</span></div>
        ))}
        {data.alerts.items.map((a: any) => (
          <div key={a.id} className="small" style={{ padding: "3px 0" }}><Sev level={a.severity} /> {displayValue(a.title)} <span className="muted">· {displayValue(a.device || "")} · {ago(a.at)}</span></div>
        ))}

        <div className="row small" style={{ justifyContent: "space-between", marginTop: 12 }}>
          <b>Vulnerabilities: {v.open} open{v.byPriority.P1 ? `, ${v.byPriority.P1} urgent (P1)` : ""}</b>
          <button className="small" onClick={() => open("/vulnerabilities")}>Open in Vulnerabilities</button>
        </div>
        {v.urgent.map((u: any) => (
          <div key={u.vulnId} className="small" style={{ padding: "3px 0" }}>
            <b className="mono">{displayValue(u.vulnId)}</b> {displayValue(u.package)} <span className="muted">· {u.devices} device(s){u.knownExploited ? " · known exploited" : ""}</span>
            {u.ticketId && <> · <Link to={`/tickets/${u.ticketId}`}>ticket</Link></>}
          </div>
        ))}

        <div className="small" style={{ marginTop: 12 }}>
          {data.microsoft365 && <div>Microsoft 365: <Pill value={data.microsoft365.status} /> <span className="muted">{displayValue(data.microsoft365.detail)}</span></div>}
          {data.backup && <div>Backups: <Pill value={data.backup.status} /> <span className="muted">{displayValue(data.backup.detail)}</span></div>}
          <div>Onboarding: {data.onboarding.done}/{data.onboarding.total}{data.onboarding.failed ? `, ${data.onboarding.failed} failing` : ""} · <Link to="/onboarding">checklist</Link></div>
        </div>
      </div>
      <div style={{ gridColumn: "1 / -1" }}>
        <b className="small">Recent actions</b>
        {data.recent.length === 0 && <p className="small muted">Nothing recorded yet.</p>}
        {data.recent.slice(0, 10).map((r: any, i: number) => (
          <div key={i} className="small muted" style={{ padding: "2px 0" }}>{ago(r.at)} · {displayValue(r.actor)} · {displayValue(r.action)} {displayValue(r.target)}</div>
        ))}
      </div>
    </div>
  );
}
