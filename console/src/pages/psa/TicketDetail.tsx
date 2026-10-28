import { displayValue } from "../../components/DisplayValue";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ago, api, fmtTime } from "../../api";
import { useApp } from "../../app-context";
import { ConnectButtons } from "../../components/rmm";
import { ErrorNote, Modal, Pill, Table, Tabs, useAction, useData, useListData } from "../../components/ui";
import ServiceRecord from "./ServiceRecord";
import { PRIORITY_TONE } from "./ServiceBoard";

const NOTE_TONE: Record<string, string> = { discussion: "blue", internal: "warn", resolution: "good", system: "muted" };

export default function TicketDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { data: t, error, reload } = useData<any>(`tickets/${id}`);
  const { data: meta } = useData<any>("psa/meta");
  const [tab, setTab] = useState("Notes");
  const [note, setNote] = useState("");
  const [kind, setKind] = useState("discussion");
  const [emailContact, setEmailContact] = useState(true);
  const [timeOpen, setTimeOpen] = useState(false);
  const [scheduleOpen, setScheduleOpen] = useState(false);
  const [mergeOpen, setMergeOpen] = useState(false);
  const [task, setTask] = useState("");
  const { run, busy } = useAction();
  if (error) return <ErrorNote error={error} />;
  if (!t) return <div className="empty">Loading…</div>;
  const board = t.boardDetail;
  const types = board?.types || [];
  const subtypes = types.find((x: any) => x.name === t.type)?.subtypes || [];
  const items = subtypes.find((x: any) => x.name === t.subtype)?.items || [];
  const update = async (body: any, message?: string) => { if (await run(() => api(`tickets/${t.id}`, { method: "PATCH", body }), message)) reload(); };
  const addNote = async () => {
    await update({ comment: note, kind, emailContact: kind !== "internal" && emailContact }, kind === "internal" ? "Internal note added" : emailContact && t.contactEmail ? "Note added and emailed" : "Note added");
    setNote("");
  };
  const taskOp = async (body: any) => { await run(() => api(`tickets/${t.id}/tasks`, { body })); reload(); };
  return (
    <>
      <div className="page-head">
        <div>
          <div className="small muted"><Link to="/service-board">Service board</Link> › {displayValue(t.board)}</div>
          <h1>#{displayValue(t.number)} {displayValue(t.subject)}</h1>
          <p>{displayValue(t.account)}{t.contact ? ` · ${t.contact.name}` : t.contactEmail ? ` · ${t.contactEmail}` : ""} · opened {fmtTime(t.createdAt)} via {displayValue(t.source)}</p>
        </div>
        <div className="actions">
          {t.device && <ConnectButtons device={t.device} ticketId={t.id} />}
          <button onClick={() => setTimeOpen(true)}>Add time</button>
          <button onClick={() => setScheduleOpen(true)}>Schedule</button>
          <button onClick={() => setMergeOpen(true)}>Merge…</button>
        </div>
      </div>

      <div className="grid side">
        <div>
          <div className="card">
            <div className="form-grid">
              <label className="field">Status<select value={t.status} onChange={(e) => update({ status: e.target.value }, `Status: ${e.target.value}`)}>
                {(board?.statuses || [{ name: t.status }]).map((s: any) => <option key={s.name}>{displayValue(s.name)}</option>)}</select></label>
              <label className="field">Board<select value={t.boardId || ""} onChange={(e) => update({ boardId: e.target.value }, "Moved to another board")}>
                {meta?.boards.map((b: any) => <option key={b.id} value={b.id}>{displayValue(b.name)}</option>)}</select></label>
              <label className="field">Resource<select value={t.assignee || ""} onChange={(e) => update({ assignee: e.target.value }, "Assigned")}>
                <option value="">Unassigned</option>{meta?.members.map((m: any) => <option key={m.email} value={m.email}>{displayValue(m.name)}</option>)}
                {t.assignee && !meta?.members.some((m: any) => m.email === t.assignee) && <option value={t.assignee}>{displayValue(t.assignee)}</option>}</select></label>
              <label className="field">Impact<select value={t.impact || "Medium"} onChange={(e) => update({ impact: e.target.value }, "Priority recalculated")}>{["High", "Medium", "Low"].map((x) => <option key={x}>{x}</option>)}</select></label>
              <label className="field">Urgency<select value={t.urgency || "Medium"} onChange={(e) => update({ urgency: e.target.value }, "Priority recalculated")}>{["High", "Medium", "Low"].map((x) => <option key={x}>{x}</option>)}</select></label>
              <label className="field">Priority<select value={t.priority} onChange={(e) => update({ priority: e.target.value }, "Priority changed; SLA recalculated")}>{["P1", "P2", "P3", "P4"].map((x) => <option key={x}>{x}</option>)}</select></label>
              <label className="field">Type<select value={t.type || ""} onChange={(e) => update({ type: e.target.value, subtype: "", item: "" })}><option value="">—</option>{types.map((x: any) => <option key={x.name}>{displayValue(x.name)}</option>)}</select></label>
              <label className="field">Subtype<select value={t.subtype || ""} onChange={(e) => update({ subtype: e.target.value, item: "" })}><option value="">—</option>{subtypes.map((x: any) => <option key={x.name}>{displayValue(x.name)}</option>)}</select></label>
              <label className="field">Item<select value={t.item || ""} onChange={(e) => update({ item: e.target.value })}><option value="">—</option>{items.map((x: string) => <option key={x}>{x}</option>)}</select></label>
            </div>
            {t.description && <pre style={{ whiteSpace: "pre-wrap", marginTop: 12, fontFamily: "var(--font)", fontSize: 14 }}>{displayValue(t.description)}</pre>}
          </div>

          <div className="card">
            <Tabs tabs={["Notes", `Time (${t.timeEntries.length})`, `Tasks (${(t.tasks || []).filter((x: any) => !x.done).length})`, "Configurations", "Schedule", "Remote sessions", "RMM jobs"]}
                  active={tab.startsWith("Time") ? `Time (${t.timeEntries.length})` : tab.startsWith("Tasks") ? `Tasks (${(t.tasks || []).filter((x: any) => !x.done).length})` : tab}
                  onChange={(x) => setTab(x.split(" (")[0])} />
            {tab === "Notes" && <>
              <div className="timeline">
                {[...(t.comments || [])].reverse().map((c: any, i: number) => (
                  <div key={i} className="item" style={{ opacity: c.kind === "system" ? 0.7 : 1 }}>
                    <div className="small muted"><Pill value={c.kind || (c.internal ? "internal" : "discussion")} tone={NOTE_TONE[c.kind || (c.internal ? "internal" : "discussion")]} /> {displayValue(c.by)} · {fmtTime(c.at)}</div>
                    <div style={{ whiteSpace: "pre-wrap" }}>{displayValue(c.text)}</div>
                  </div>
                ))}
                {!t.comments?.length && <p className="muted">No notes yet.</p>}
              </div>
              <div style={{ marginTop: 12 }}>
                <div className="row" style={{ marginBottom: 6 }}>
                  {["discussion", "internal", "resolution"].map((k) => <button key={k} className={kind === k ? "small primary" : "small"} onClick={() => setKind(k)}>{k[0].toUpperCase() + k.slice(1)}</button>)}
                  <span style={{ flex: 1 }} />
                  {kind !== "internal" && t.contactEmail && <label className="small"><input type="checkbox" checked={emailContact} onChange={(e) => setEmailContact(e.target.checked)} /> Email {displayValue(t.contactEmail)}</label>}
                </div>
                <textarea rows={4} value={note} onChange={(e) => setNote(e.target.value)} placeholder={kind === "internal" ? "Only your team sees internal notes" : "The customer sees this note"} style={{ width: "100%", fontFamily: "var(--font)" }} />
                <div className="row" style={{ marginTop: 6 }}>
                  <span style={{ flex: 1 }} />
                  {kind === "resolution" && <button disabled={!note || busy} onClick={async () => { await update({ comment: note, kind, emailContact, status: "Resolved" }, "Resolved"); setNote(""); }}>Save and resolve</button>}
                  <button className="primary" disabled={!note || busy} onClick={addNote}>Save note</button>
                </div>
              </div>
            </>}
            {tab === "Time" && <>
              <Table rows={t.timeEntries} empty="No time logged."
                     columns={[{ key: "member", label: "Member" }, { key: "startedAt", label: "Date", render: (e) => fmtTime(e.startedAt) },
                               { key: "workType", label: "Work type" }, { key: "hours", label: "Actual", render: (e) => e.hours.toFixed(2) },
                               { key: "hoursBilled", label: "Billed", render: (e) => e.hoursBilled.toFixed(2) },
                               { key: "billable", label: "Billing", render: (e) => <>{displayValue(e.billable)}{e.covered && <> <Pill value="agreement" tone="good" /></>}</> },
                               { key: "status", label: "Status", render: (e) => <Pill value={e.status} /> }, { key: "notes", label: "Notes", render: (e) => <span className="small">{displayValue(e.notes)}</span> }]} />
              <button style={{ marginTop: 8 }} onClick={() => setTimeOpen(true)}>Add time</button>
            </>}
            {tab === "Tasks" && <>
              {(t.tasks || []).map((x: any, i: number) => (
                <div key={i} className="row" style={{ padding: "4px 0" }}>
                  <input type="checkbox" checked={x.done} onChange={() => taskOp({ toggle: i })} />
                  <span style={{ textDecoration: x.done ? "line-through" : undefined, flex: 1 }}>{displayValue(x.text)}</span>
                  <span className="small muted">{displayValue(x.done ? `done by ${x.doneBy}` : x.by)}</span>
                  <button className="small ghost" onClick={() => taskOp({ remove: i })}>✕</button>
                </div>
              ))}
              <form className="row" style={{ marginTop: 8 }} onSubmit={async (e) => { e.preventDefault(); if (task) { await taskOp({ add: task }); setTask(""); } }}>
                <input value={task} onChange={(e) => setTask(e.target.value)} placeholder="Add a checklist task" style={{ flex: 1 }} /><button>Add</button>
              </form>
            </>}
            {tab === "Configurations" && <ConfigsTab ticket={t} onChange={reload} />}
            {tab === "Schedule" && <Table rows={t.schedule} empty="Not scheduled."
                                          columns={[{ key: "member", label: "Member" }, { key: "startAt", label: "Start", render: (e) => fmtTime(e.startAt) },
                                                    { key: "endAt", label: "End", render: (e) => fmtTime(e.endAt) }, { key: "kind", label: "Type" }, { key: "status", label: "Status" }]} />}
            {tab === "Remote sessions" && <Table rows={t.remoteSessions} empty="No remote sessions from this ticket."
                                                 columns={[{ key: "technician", label: "Technician" }, { key: "mode", label: "Mode" }, { key: "status", label: "Status", render: (s) => <Pill value={s.status} /> },
                                                           { key: "createdAt", label: "Started", render: (s) => fmtTime(s.createdAt) }]} />}
            {tab === "RMM jobs" && <Table rows={Array.isArray(t.rmmJobs) ? t.rmmJobs : []}
                        empty="No RMM remediation jobs are linked to this ticket."
                        columns={[{ key: "name", label: "Action", render: (j) => <Link to={`/automation?job=${encodeURIComponent(j.id)}`}>{displayValue(j.name)}</Link> },
                                  { key: "kind", label: "Kind" },
                                  { key: "status", label: "Outcome", render: (j) => <Pill value={j.status} /> },
                                  { key: "summary", label: "Results",
                                    render: (j) => <span>{displayValue(j.summary?.completed || 0)} completed, {displayValue(j.summary?.failed || 0)} failed, {displayValue(j.summary?.dispatched || 0)} in progress</span> },
                                  { key: "createdAt", label: "Started", render: (j) => fmtTime(j.createdAt) }]} />}
          </div>
        </div>

        <div>
          <ServiceRecord ticket={t} onChange={reload} />
          <div className="card">
            <h3>SLA</h3>
            <dl className="kv">
              <dt>Priority</dt><dd><Pill value={t.priority} tone={PRIORITY_TONE[t.priority]} /></dd>
              <dt>Respond by</dt><dd>{t.respondedAt ? <>responded {ago(t.respondedAt)}</> : <span style={{ color: t.respondBreached ? "#fecaca" : undefined }}>{fmtTime(t.respondDueAt)}</span>}</dd>
              <dt>Resolve by</dt><dd style={{ color: t.slaBreached ? "#fecaca" : undefined }}>{t.closed ? `resolved ${ago(t.resolvedAt)}` : fmtTime(t.slaDueAt)}</dd>
              <dt>Hours logged</dt><dd>{displayValue(t.hours.toFixed(2))}{t.budgetHours ? ` of ${t.budgetHours} budget` : ""}</dd>
            </dl>
          </div>
          <div className="card">
            <h3>Company</h3>
            <dl className="kv">
              <dt>Company</dt><dd><Link to={`/companies/${t.accountTenantId}`}>{displayValue(t.account)}</Link></dd>
              <dt>Contact</dt><dd>{t.contact ? <>{displayValue(t.contact.name)}<div className="small muted">{displayValue(t.contact.email)} {displayValue(t.contact.phone)}</div></> : t.contactEmail || "—"}</dd>
              <dt>Agreement</dt><dd>{t.agreement ? <>{displayValue(t.agreement.name)}<div className="small muted">{displayValue(t.agreement.agreementType)}</div></> : <span className="muted">none (time is billable)</span>}</dd>
            </dl>
          </div>
          {t.device && <div className="card">
            <h3>Device</h3>
            <p><Link to={`/devices/${t.device.id}`}>{displayValue(t.device.hostname)}</Link><br /><span className="small muted">{displayValue(t.device.osVersion)}</span></p>
            <ConnectButtons device={t.device} ticketId={t.id} />
          </div>}
          {t.incidentId && <div className="card"><h3>Security incident</h3><Link to={`/incidents/${t.incidentId}`}>Open the linked incident</Link></div>}
          {t.children?.length > 0 && <div className="card"><h3>Merged tickets</h3>{t.children.map((c: any) => <div key={c.id}><Link to={`/tickets/${c.id}`}>#{displayValue(c.number)}</Link> {displayValue(c.subject)}</div>)}</div>}
          {t.parentId && <div className="card"><h3>Merged into</h3><Link to={`/tickets/${t.parentId}`}>parent ticket</Link></div>}
        </div>
      </div>
      {timeOpen && <TimeEntryModal ticket={t} meta={meta} onClose={() => { setTimeOpen(false); reload(); }} />}
      {scheduleOpen && <ScheduleModal ticket={t} meta={meta} onClose={() => { setScheduleOpen(false); reload(); }} />}
      {mergeOpen && <MergeModal ticket={t} onClose={(target) => { setMergeOpen(false); if (target) navigate(`/tickets/${target}`); }} />}
    </>
  );
}

function ConfigsTab({ ticket, onChange }: { ticket: any; onChange: () => void }) {
  const { data } = useListData<any>("psa/configurations", { accountTenantId: ticket.accountTenantId });
  const { run } = useAction();
  const attached = new Set(ticket.configurationIds || []);
  const toggle = async (id: string) => {
    const next = attached.has(id) ? [...attached].filter((x) => x !== id) : [...attached, id];
    await run(() => api(`tickets/${ticket.id}`, { method: "PATCH", body: { configurationIds: next } }));
    onChange();
  };
  return <Table rows={data} empty="This company has no configurations. Sync them from RMM on the Configurations page."
                columns={[{ key: "on", label: "", render: (c) => <input type="checkbox" checked={attached.has(c.id)} onChange={() => toggle(c.id)} /> },
                          { key: "name", label: "Configuration" }, { key: "type", label: "Type" }, { key: "serialNumber", label: "Serial" }, { key: "os", label: "OS" }]} />;
}

export function TimeEntryModal({ ticket, meta, onClose }: { ticket: any; meta: any; onClose: () => void }) {
  const now = new Date();
  const local = (d: Date) => new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
  const [form, setForm] = useState({ startedAt: local(new Date(now.getTime() - 30 * 60000)), endedAt: local(now), workType: ticket.boardDetail?.defaultWorkType || "Remote Support",
                                     billable: "Billable", notes: "", internalNotes: "" });
  const { run, busy } = useAction();
  const hours = Math.max(0, (new Date(form.endedAt).getTime() - new Date(form.startedAt).getTime()) / 3600000);
  return (
    <Modal title={`Time on #${ticket.number}`} onClose={onClose}
           footer={<><button onClick={onClose}>Cancel</button><button className="primary" disabled={busy || hours <= 0} onClick={async () => {
             if (await run(() => api("psa/time", { body: { ...form, ticketId: ticket.id, startedAt: new Date(form.startedAt).toISOString(), endedAt: new Date(form.endedAt).toISOString() } }), "Time saved")) onClose();
           }}>Save time</button></>}>
      <div className="form-grid">
        <label className="field">Start<input type="datetime-local" value={form.startedAt} onChange={(e) => setForm({ ...form, startedAt: e.target.value })} /></label>
        <label className="field">End<input type="datetime-local" value={form.endedAt} onChange={(e) => setForm({ ...form, endedAt: e.target.value })} /></label>
        <label className="field">Hours<div style={{ paddingTop: 6 }}><b>{hours.toFixed(2)}</b> <span className="small muted">billed in 15-minute steps</span></div></label>
        <label className="field">Work type<select value={form.workType} onChange={(e) => setForm({ ...form, workType: e.target.value })}>{meta?.workTypes.map((w: string) => <option key={w}>{w}</option>)}</select></label>
        <label className="field">Billing<select value={form.billable} onChange={(e) => setForm({ ...form, billable: e.target.value })}><option>Billable</option><option>Do Not Bill</option><option>No Charge</option></select></label>
      </div>
      <label className="field" style={{ marginTop: 10 }}>Notes (added to the ticket as a discussion note)<textarea rows={3} value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} /></label>
      <label className="field" style={{ marginTop: 10 }}>Internal notes<textarea rows={2} value={form.internalNotes} onChange={(e) => setForm({ ...form, internalNotes: e.target.value })} /></label>
    </Modal>
  );
}

function ScheduleModal({ ticket, meta, onClose }: { ticket: any; meta: any; onClose: () => void }) {
  const { me } = useApp();
  const start = new Date();
  start.setMinutes(0, 0, 0);
  start.setHours(start.getHours() + 1);
  const local = (d: Date) => new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
  const [form, setForm] = useState({ member: ticket.assignee || me?.user.email || "", startAt: local(start), endAt: local(new Date(start.getTime() + 3600000)), kind: "Service", location: "" });
  const { run, busy } = useAction();
  return (
    <Modal title={`Schedule #${ticket.number}`} onClose={onClose}
           footer={<><button onClick={onClose}>Cancel</button><button className="primary" disabled={busy} onClick={async () => {
             const r = await run(() => api<any>("psa/schedule", { body: { ...form, ticketId: ticket.id, startAt: new Date(form.startAt).toISOString(), endAt: new Date(form.endAt).toISOString() } }), "Scheduled");
             if (r) { if (r.conflict) window.alert(`${form.member} already has something booked at that time.`); onClose(); }
           }}>Schedule</button></>}>
      <div className="form-grid">
        <label className="field">Member<select value={form.member} onChange={(e) => setForm({ ...form, member: e.target.value })}>{meta?.members.map((m: any) => <option key={m.email} value={m.email}>{displayValue(m.name)}</option>)}</select></label>
        <label className="field">Type<select value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value })}>{["Service", "Onsite", "Meeting", "Project"].map((k) => <option key={k}>{k}</option>)}</select></label>
        <label className="field">Start<input type="datetime-local" value={form.startAt} onChange={(e) => setForm({ ...form, startAt: e.target.value })} /></label>
        <label className="field">End<input type="datetime-local" value={form.endAt} onChange={(e) => setForm({ ...form, endAt: e.target.value })} /></label>
        <label className="field">Location<input value={form.location} onChange={(e) => setForm({ ...form, location: e.target.value })} /></label>
      </div>
    </Modal>
  );
}

function MergeModal({ ticket, onClose }: { ticket: any; onClose: (target?: string) => void }) {
  const [q, setQ] = useState("");
  const { data } = useListData<any>("tickets", { q, status: "active" });
  const { run } = useAction();
  return (
    <Modal title={`Merge #${ticket.number} into…`} onClose={() => onClose()}>
      <p className="muted small">Notes and time move to the other ticket. This one closes and links to it.</p>
      <input placeholder="Search tickets" value={q} onChange={(e) => setQ(e.target.value)} style={{ width: "100%", marginBottom: 8 }} />
      <Table rows={data?.filter((x) => x.id !== ticket.id)} onRow={async (target) => {
        if (window.confirm(`Merge #${ticket.number} into #${target.number}?`) && await run(() => api(`tickets/${ticket.id}/merge`, { body: { intoTicketId: target.id } }), "Merged")) onClose(target.id);
      }} columns={[{ key: "number", label: "#", render: (x) => `#${x.number}` }, { key: "subject", label: "Summary" }, { key: "account", label: "Company" }]} />
    </Modal>
  );
}
