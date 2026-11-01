import { displayValue } from "../../components/DisplayValue";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api, fmtTime } from "../../api";
import { useApp } from "../../app-context";
import { Modal, PageHead, Pill, Stat, Table, Tabs, useAction, useListData } from "../../components/ui";
import { confirmDialog } from "../../components/dialogs";

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
  const { data: mine, reload } = useListData<any>("psa/time", { member: "me", start: week.toISOString(), end: weekEnd.toISOString() });
  const { data: sheets, reload: reloadSheets } = useListData<any>("psa/timesheets", { weekStart: iso(week) });
  const { run, busy } = useAction();
  const [editing, setEditing] = useState<any>(null);
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
                <div className="small muted">{d.name} {d.day.getDate()}</div><div style={{ fontSize: 22, fontWeight: 700 }}>{displayValue(d.hours.toFixed(1))}</div>
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
                           { key: "ticketNumber", label: "Charge to", render: (e) => e.ticketId ? <Link to={`/tickets/${e.ticketId}`}>#{displayValue(e.ticketNumber)}</Link> : e.chargeTo },
                           { key: "account", label: "Company" }, { key: "workType", label: "Work type" },
                           { key: "hours", label: "Hours", render: (e) => e.hours.toFixed(2) },
                           { key: "billable", label: "Billing", render: (e) => <>{displayValue(e.billable)}{e.covered && <> <Pill value="agreement" tone="good" /></>}</> },
                           { key: "status", label: "Status", render: (e) => <Pill value={e.status} tone={e.status === "Approved" || e.status === "Billed" ? "good" : e.status === "Rejected" ? "bad" : e.status === "Submitted" ? "blue" : "muted"} /> },
                           { key: "notes", label: "Notes", render: (e) => <span className="small">{displayValue(e.notes)}</span> },
                           { key: "manage", label: "", render: (e) => ["Open", "Rejected"].includes(e.status) && <span style={{ whiteSpace: "nowrap" }}>
                               <button className="small" onClick={() => setEditing({ id: e.id, hours: String(e.hours), notes: e.notes || "", billable: e.billable, workType: e.workType })}>Edit</button>{" "}
                               <button className="small danger" onClick={async () => {
                                 if (await confirmDialog(`Remove ${e.hours.toFixed(2)} hours from ${fmtTime(e.startedAt)}?`, { confirmLabel: "Remove" }) && await run(() => api(`psa/time/${e.id}`, { method: "DELETE" }), "Time removed")) reload();
                               }}>Remove</button></span> }]} />
        </div>
        {editing && <Modal title="Edit time" onClose={() => setEditing(null)} footer={<button className="primary" disabled={busy || !(Number(editing.hours) > 0)} onClick={async () => {
          if (await run(() => api(`psa/time/${editing.id}`, { method: "PATCH", body: { hours: Number(editing.hours), notes: editing.notes, billable: editing.billable, workType: editing.workType } }), "Time saved")) { setEditing(null); reload(); }
        }}>Save</button>}>
          <div className="form-grid">
            <label className="field">Hours<input type="number" min="0.05" step="0.05" value={editing.hours} onChange={(ev) => setEditing({ ...editing, hours: ev.target.value })} /></label>
            <label className="field">Billing<select value={editing.billable} onChange={(ev) => setEditing({ ...editing, billable: ev.target.value })}>
              {["Billable", "Do Not Bill", "No Charge"].map((b) => <option key={b}>{b}</option>)}</select></label>
            <label className="field">Work type<input value={editing.workType} onChange={(ev) => setEditing({ ...editing, workType: ev.target.value })} /></label>
          </div>
          <label className="field">Notes<textarea value={editing.notes} onChange={(ev) => setEditing({ ...editing, notes: ev.target.value })} /></label>
        </Modal>}
      </> : (
        <div className="card">
          <Table rows={sheets?.map((s) => ({ ...s, id: s.member }))} empty="No time recorded this week."
                 columns={[{ key: "member", label: "Member", render: (s) => <b>{displayValue(s.member)}</b> },
                           ...DAY_NAMES.map((name, i) => ({ key: name, label: name, render: (s: any) => s.days[i] ? s.days[i].toFixed(1) : "·" })),
                           { key: "total", label: "Total", render: (s) => <b>{displayValue(s.total.toFixed(2))}</b> },
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
