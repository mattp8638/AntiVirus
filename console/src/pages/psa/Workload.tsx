import { displayValue } from "../../components/DisplayValue";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ago, fmtTime } from "../../api";
import { useApp } from "../../app-context";
import { ErrorNote, Meter, PageHead, Pill, Stat, Table, Tabs, useData, useListData } from "../../components/ui";
import { CHANGE_TONE } from "./ServiceRecord";

export default function Workload() {
  const { tenantName } = useApp();
  const navigate = useNavigate();
  const [tab, setTab] = useState("Workload");
  const [days, setDays] = useState(7);
  const { data: load, error } = useData<any>("psa/workload", { days }, [days]);
  const { data: problems } = useListData<any>(tab === "Problems" ? "psa/problems" : null);
  const { data: changes } = useListData<any>(tab === "Changes" ? "psa/changes" : null);
  const members = load?.members ?? null;
  const overdue = members?.reduce((n: number, m: any) => n + m.overdue, 0) ?? 0;

  return (
    <>
      <PageHead title="Workload & changes" subtitle="Who is carrying what, which tickets are at SLA risk, open problems and the change calendar." />
      <ErrorNote error={error} />
      <Tabs tabs={["Workload", "Problems", "Changes"]} active={tab} onChange={setTab} />
      {tab === "Workload" && <>
        <div className="grid k4">
          <Stat label="Open tickets assigned" value={members ? members.reduce((n: number, m: any) => n + m.openTickets, 0) : "—"} />
          <Stat label="Past SLA" value={members ? overdue : "—"} accent={overdue ? "red" : "green"} />
          <Stat label="Unassigned open tickets" value={load?.unassignedOpen ?? "—"} accent={load?.unassignedOpen ? "red" : undefined} />
          <Stat label="Capacity per person" value={load ? `${load.capacityHours.toFixed(1)} h` : "—"} hint={`next ${days} days`} />
        </div>
        <div className="row" style={{ margin: "8px 0", gap: 6 }}>
          <span className="small muted">Booking horizon</span>
          {[7, 14].map((d) => <button key={d} className={`small ${d === days ? "primary" : ""}`} onClick={() => setDays(d)}>{d} days</button>)}
        </div>
        <div className="card">
          <Table rows={members?.map((m: any) => ({ ...m, id: m.member }))} onRow={(m) => navigate(`/service-board?assignee=${encodeURIComponent(m.member)}`)}
                 empty="No technicians or assigned tickets yet."
                 columns={[{ key: "name", label: "Technician", render: (m) => <><b>{displayValue(m.name)}</b>{m.name !== m.member && <div className="small muted">{displayValue(m.member)}</div>}</> },
                           { key: "openTickets", label: "Open", className: "right" },
                           { key: "p1p2", label: "P1/P2", className: "right", render: (m) => m.p1p2 ? <b>{displayValue(m.p1p2)}</b> : 0 },
                           { key: "overdue", label: "Past SLA", className: "right", render: (m) => m.overdue ? <span style={{ color: "#fca5a5", fontWeight: 700 }}>{displayValue(m.overdue)}</span> : 0 },
                           { key: "dueToday", label: "Due in 24h", className: "right" },
                           { key: "bookedPercent", label: `Booked (${days}d)`, render: (m) => <div style={{ minWidth: 120 }}><Meter value={Math.min(m.bookedPercent, 100)} />
                             <span className="small muted">{displayValue(m.scheduledHours)} h · {displayValue(m.bookedPercent)}%</span></div> },
                           { key: "utilisationPercent", label: "This week", render: (m) => <span className="small">{displayValue(m.loggedHoursThisWeek)} h logged · {displayValue(m.utilisationPercent)}% billable</span> }]} />
        </div>
      </>}
      {tab === "Problems" && <div className="card">
        <Table rows={problems} onRow={(p) => navigate(`/tickets/${p.id}`)} empty="No open problems. Mark a ticket's record type as Problem to investigate a recurring issue."
               columns={[{ key: "subject", label: "Problem", render: (p) => <><b>#{displayValue(p.number)} {displayValue(p.subject)}</b>{p.knownError && <> <Pill value="known error" tone="warn" /></>}
                           {p.workaround && <div className="small muted">Workaround: {displayValue(p.workaround)}</div>}</> },
                         { key: "accountTenantId", label: "Company", render: (p) => tenantName(p.accountTenantId) },
                         { key: "openIncidents", label: "Linked incidents", className: "right", render: (p) => `${p.openIncidents} open / ${p.linkedIncidents}` },
                         { key: "status", label: "Status", render: (p) => <Pill value={p.status} /> },
                         { key: "createdAt", label: "Opened", render: (p) => ago(p.createdAt) }]} />
      </div>}
      {tab === "Changes" && <div className="card">
        <Table rows={changes} onRow={(c) => navigate(`/tickets/${c.id}`)} empty="No changes in progress. Mark a ticket's record type as Change to plan one."
               columns={[{ key: "plannedStart", label: "Window", render: (c) => c.plannedStart ? <>{fmtTime(c.plannedStart)}<div className="small muted">to {fmtTime(c.plannedEnd)}</div></> : <span className="muted">not scheduled</span> },
                         { key: "subject", label: "Change", render: (c) => <><b>#{displayValue(c.number)} {displayValue(c.subject)}</b><div className="small muted">{tenantName(c.accountTenantId)}{c.assignee ? ` · ${c.assignee}` : ""}</div></> },
                         { key: "changeRisk", label: "Risk", render: (c) => c.changeRisk ? <Pill value={c.changeRisk} tone={c.changeRisk === "High" ? "bad" : c.changeRisk === "Medium" ? "warn" : "muted"} /> : "—" },
                         { key: "changeState", label: "State", render: (c) => <><Pill value={c.changeState} tone={CHANGE_TONE[c.changeState]} />
                           {c.changeState === "Submitted" && <div className="small muted">{displayValue(c.approvals)} of {displayValue(c.approvalsNeeded)} approvals</div>}</> }]} />
      </div>}
    </>
  );
}
