import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api, fmtTime } from "../../api";
import { useApp } from "../../app-context";
import { PageHead, Pill, Stat, Table, Tabs, useAction, useData } from "../../components/ui";

const DAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

function mondayOf(date: Date) {
  const d = new Date(date);
  d.setHours(0, 0, 0, 0);
  d.setDate(d.getDate() - ((d.getDay() + 6) % 7));
  return d;
}
const iso = (d: Date) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;

export default function Time() {
  const { can } = useApp();
  const [tab, setTab] = useState("My time");
  const [week, setWeek] = useState(() => mondayOf(new Date()));
  const weekEnd = useMemo(() => new Date(week.getTime() + 7 * 86400000), [week]);
  const { data: mine, reload } = useData<any[]>("psa/time", { member: "me", start: week.toISOString(), end: weekEnd.toISOString() });
  const { data: sheets, reload: reloadSheets } = useData<any[]>("psa/timesheets", { weekStart: iso(week) });
  const { run, busy } = useAction();
  const days = DAY_NAMES.map((name, i) => {
    const day = new Date(week.getTime() + i * 86400000);
    const hours = (mine || []).filter((e) => new Date(e.startedAt).toDateString() === day.toDateString()).reduce((n, e) => n + e.hours, 0);
    return { name, day, hours };
  });
  const total = days.reduce((n, d) => n + d.hours, 0);
  const billable = (mine || []).filter((e) => e.billable === "Billable").reduce((n, e) => n + e.hours, 0);
  const open = (mine || []).filter((e) => ["Open", "Rejected"].includes(e.status)).length;
  return (
    <>
      <PageHead title="Time & timesheets" subtitle="Time entries roll into weekly timesheets, manager approval, and agreement billing."
                actions={<>
                  <button onClick={() => setWeek(new Date(week.getTime() - 7 * 86400000))}>‹ Previous</button>
                  <span className="small">Week of {week.toLocaleDateString()}</span>
                  <button onClick={() => setWeek(new Date(week.getTime() + 7 * 86400000))}>Next ›</button>
                </>} />
      <Tabs tabs={can("manage_tenants") ? ["My time", "Team approval"] : ["My time"]} active={tab} onChange={setTab} />
      {tab === "My time" ? <>
        <div className="grid k4">
          <Stat label="Hours this week" value={total.toFixed(2)} />
          <Stat label="Billable" value={billable.toFixed(2)} accent="green" hint={total ? `${Math.round((100 * billable) / total)}% of your time` : undefined} />
          <Stat label="Utilisation" value={`${Math.round((100 * billable) / 37.5)}%`} hint="of a 37.5 hour week" />
          <Stat label="Not submitted" value={open} accent={open ? "amber" : undefined} />
        </div>
        <div className="card" style={{ marginTop: 16 }}>
          <div className="grid" style={{ gridTemplateColumns: "repeat(7, 1fr)", gap: 8 }}>
            {days.map((d) => (
              <div key={d.name} className="card" style={{ padding: 10, textAlign: "center" }}>
                <div className="small muted">{d.name} {d.day.getDate()}</div><div style={{ fontSize: 22, fontWeight: 700 }}>{d.hours.toFixed(1)}</div>
              </div>
            ))}
          </div>
          <div className="row" style={{ marginTop: 12 }}>
            <span style={{ flex: 1 }} />
            <button className="primary" disabled={busy || !open} onClick={async () => { await run(() => api("psa/timesheets/submit", { body: { weekStart: iso(week) } }), "Timesheet submitted"); reload(); reloadSheets(); }}>Submit timesheet</button>
          </div>
        </div>
        <div className="card">
          <Table rows={mine} empty="No time this week. Add time from a ticket."
                 columns={[{ key: "startedAt", label: "When", render: (e) => fmtTime(e.startedAt) },
                           { key: "ticketNumber", label: "Charge to", render: (e) => e.ticketId ? <Link to={`/tickets/${e.ticketId}`}>#{e.ticketNumber}</Link> : e.chargeTo },
                           { key: "account", label: "Company" }, { key: "workType", label: "Work type" },
                           { key: "hours", label: "Hours", render: (e) => e.hours.toFixed(2) },
                           { key: "billable", label: "Billing", render: (e) => <>{e.billable}{e.covered && <> <Pill value="agreement" tone="good" /></>}</> },
                           { key: "status", label: "Status", render: (e) => <Pill value={e.status} tone={e.status === "Approved" || e.status === "Billed" ? "good" : e.status === "Rejected" ? "bad" : e.status === "Submitted" ? "blue" : "muted"} /> },
                           { key: "notes", label: "Notes", render: (e) => <span className="small">{e.notes}</span> }]} />
        </div>
      </> : (
        <div className="card">
          <Table rows={sheets?.map((s) => ({ ...s, id: s.member }))} empty="No time recorded this week."
                 columns={[{ key: "member", label: "Member", render: (s) => <b>{s.member}</b> },
                           ...DAY_NAMES.map((name, i) => ({ key: name, label: name, render: (s: any) => s.days[i] ? s.days[i].toFixed(1) : "·" })),
                           { key: "total", label: "Total", render: (s) => <b>{s.total.toFixed(2)}</b> },
                           { key: "utilisation", label: "Billable %", render: (s) => `${s.utilisation}%` },
                           { key: "statuses", label: "Status", render: (s) => Object.entries(s.statuses).map(([k, v]) => <span key={k} className="chip">{k} {String(v)}</span>) },
                           { key: "approve", label: "", render: (s) => s.statuses.Submitted ? <span className="row">
                               <button className="small primary" onClick={async () => { await run(() => api("psa/timesheets/approve", { body: { weekStart: iso(week), member: s.member } }), "Approved"); reloadSheets(); }}>Approve</button>
                               <button className="small" onClick={async () => { await run(() => api("psa/timesheets/approve", { body: { weekStart: iso(week), member: s.member, approve: false } }), "Sent back"); reloadSheets(); }}>Reject</button>
                             </span> : null }]} />
          <p className="small muted" style={{ marginTop: 8 }}>Approving locks the entries for billing.</p>
        </div>
      )}
    </>
  );
}
