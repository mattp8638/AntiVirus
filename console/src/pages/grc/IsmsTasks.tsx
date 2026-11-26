import { useState } from "react";
import { api, fmtTime } from "../../api";
import { useApp } from "../../app-context";
import { displayValue } from "../../components/DisplayValue";
import { ErrorNote, Modal, Pill, Table, useAction, useData } from "../../components/ui";
import { safeArray } from "../../data-shapes";

/** ISMS tasks and calendar (ISO 27001 8.1). */

const KIND_LABEL: Record<string, string> = { implement: "Put in place", operate: "Check", manual: "Task" };
const URGENCY: Record<string, [string, string]> = { overdue: ["overdue", "bad"], due_soon: ["due soon", "warn"], later: ["", "muted"] };
const ddmmyyyy = (iso: string) => `${iso.slice(8, 10)}/${iso.slice(5, 7)}/${iso.slice(0, 4)}`;

function useIsms() {
  const { tenantId } = useApp();
  const { data: me } = useData<any>(tenantId ? "isms/me" : null, { tenant_id: tenantId }, [tenantId]);
  return { tenantId, me, perms: safeArray<string>(me?.permissions) };
}

export function IsmsTasksTab() {
  const { tenantId, me, perms } = useIsms();
  const allowed = perms.includes("tasks.complete");
  const [status, setStatus] = useState("open");
  const [view, setView] = useState<"list" | "calendar">("list");
  const { data, error, reload } = useData<any>(tenantId && allowed ? "isms/tasks" : null, { tenant_id: tenantId, status }, [tenantId, allowed, status]);
  const [open, setOpen] = useState<any>(null);
  const [adding, setAdding] = useState(false);
  if (!tenantId) return <p className="muted">Choose a customer in the tenant picker to see its ISMS tasks.</p>;
  if (!allowed) return me ? <p className="muted">Your ISMS role in this customer ({displayValue(me.role ?? "none")}) has no tasks.</p> : null;
  const rows = safeArray<any>(data?.tasks);
  const manage = perms.includes("programme.manage");
  return <div className="card">
    <ErrorNote error={error} />
    <div className="row" style={{ gap: 8, flexWrap: "wrap", alignItems: "end", marginBottom: 8 }}>
      <label className="field">Show<select value={status} onChange={(e) => setStatus(e.target.value)}><option value="open">Open</option><option value="done">Done</option><option value="all">All</option></select></label>
      <label className="field">View<select value={view} onChange={(e) => setView(e.target.value as any)}><option value="list">List</option><option value="calendar">Calendar</option></select></label>
      <span style={{ flex: 1 }} />
      {manage && <button className="primary" onClick={() => setAdding(true)}>Add task</button>}
    </div>
    <p className="small muted">{data?.ownOnly ? "Your tasks." : "Every task in this customer's ISMS."} Controls not yet in place get a task to put them in place; controls in place with a regular test get a recurring check. Reminders go out when a task is due within 7 days and when it is overdue; after 14 days overdue it is escalated to the ISMS managers.</p>
    {view === "list" ? <Table rows={rows} empty="No tasks." onRow={setOpen} columns={[
      { key: "title", label: "Task", render: (t) => <><b>{displayValue(t.title)}</b><div className="small muted">{KIND_LABEL[t.kind]}{t.recurrence ? `, ${t.recurrence}` : ""}</div></> },
      { key: "dueOn", label: "Due", render: (t) => <>{ddmmyyyy(t.dueOn)}{t.urgency && URGENCY[t.urgency][0] && <> <Pill value={URGENCY[t.urgency][0]} tone={URGENCY[t.urgency][1]} /></>}</> },
      { key: "assigneeName", label: "Assigned to", render: (t) => displayValue(t.assigneeName ?? "Nobody") },
      { key: "status", label: "Status", render: (t) => t.status === "done" ? <span className="small">Done {fmtTime(t.completedAt)}</span> : t.status }]} />
      : <Calendar tasks={rows} onOpen={setOpen} />}
    {open && <TaskDetail task={open} tenantId={tenantId} canComplete={open.status === "open" && open.kind !== "implement" && (manage || open.assigneeId === me?.userId)} onClose={() => { setOpen(null); reload(); }} />}
    {adding && <AddTask tenantId={tenantId} onClose={() => { setAdding(false); reload(); }} />}
  </div>;
}

function Calendar({ tasks, onOpen }: { tasks: any[]; onOpen: (t: any) => void }) {
  const first = tasks.length ? tasks.map((t) => t.dueOn).sort()[0] : new Date().toISOString().slice(0, 10);
  const [month, setMonth] = useState(first.slice(0, 7));
  const [y, m] = month.split("-").map(Number);
  const start = new Date(Date.UTC(y, m - 1, 1));
  const days = new Date(Date.UTC(y, m, 0)).getUTCDate();
  const lead = (start.getUTCDay() + 6) % 7;  // weeks start on Monday
  const cells = [...Array(lead).fill(null), ...Array.from({ length: days }, (_, i) => i + 1)];
  const step = (n: number) => { const d = new Date(Date.UTC(y, m - 1 + n, 1)); setMonth(d.toISOString().slice(0, 7)); };
  const label = start.toLocaleDateString("en-GB", { month: "long", year: "numeric", timeZone: "UTC" });
  return <div>
    <div className="row" style={{ gap: 8, marginBottom: 6 }}><button onClick={() => step(-1)} aria-label="Previous month">Previous</button><b aria-live="polite">{label}</b><button onClick={() => step(1)} aria-label="Next month">Next</button></div>
    <table className="small" aria-label={`Tasks due in ${label}`} style={{ width: "100%", tableLayout: "fixed" }}>
      <thead><tr>{["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"].map((d) => <th key={d} scope="col">{d}</th>)}</tr></thead>
      <tbody>{Array.from({ length: Math.ceil(cells.length / 7) }, (_, w) => <tr key={w}>{cells.slice(w * 7, w * 7 + 7).map((d, i) => {
        const iso = d ? `${month}-${String(d).padStart(2, "0")}` : "";
        const due = d ? tasks.filter((t) => t.dueOn === iso) : [];
        return <td key={i} style={{ verticalAlign: "top", height: 64 }}>{d && <><div className="muted">{d}</div>
          {due.slice(0, 3).map((t) => <button key={t.id} className="small" style={{ display: "block", width: "100%", textAlign: "left" }} onClick={() => onOpen(t)}>{t.controlRef ?? KIND_LABEL[t.kind]}{t.urgency === "overdue" ? " (overdue)" : ""}</button>)}
          {due.length > 3 && <span className="muted">and {due.length - 3} more</span>}</>}</td>;
      })}</tr>)}</tbody>
    </table>
  </div>;
}

function TaskDetail({ task, tenantId, canComplete, onClose }: { task: any; tenantId: string; canComplete: boolean; onClose: () => void }) {
  const { data: ev } = useData<any>(canComplete && task.controlId ? "isms/evidence" : null, { tenant_id: tenantId, control_id: task.controlId }, [task.id]);
  const [note, setNote] = useState("");
  const [evidenceId, setEvidenceId] = useState("");
  const { run, busy } = useAction();
  const done = async () => { if (await run(() => api(`isms/tasks/${task.id}/complete`, { body: { note, evidenceId: evidenceId || null } }), "Task completed")) onClose(); };
  return <Modal title={task.title} wide onClose={onClose} footer={canComplete && <button className="primary" disabled={busy || (!note.trim() && !evidenceId)} onClick={done}>Mark as done</button>}>
    <p className="small">{KIND_LABEL[task.kind]}{task.recurrence ? ` (${task.recurrence})` : ""}, due {ddmmyyyy(task.dueOn)}, assigned to {displayValue(task.assigneeName ?? "nobody")}.</p>
    {task.description && <p style={{ whiteSpace: "pre-wrap" }}>{displayValue(task.description)}</p>}
    {task.kind === "implement" && task.status === "open" && <p className="small muted">This task closes itself when the control is marked as in place on the ISMS controls tab.</p>}
    {task.status === "done" && <p className="small">Done {fmtTime(task.completedAt)} by {displayValue(task.completedByName)}: {displayValue(task.completionNote ?? "")}{task.evidenceTitle ? ` (evidence: ${task.evidenceTitle})` : ""}</p>}
    {canComplete && <>
      <label className="field">What was checked<textarea rows={3} value={note} onChange={(e) => setNote(e.target.value)} /></label>
      {safeArray<any>(ev?.evidence).length > 0 && <label className="field">Evidence (optional)<select value={evidenceId} onChange={(e) => setEvidenceId(e.target.value)}>
        <option value="">None</option>{safeArray<any>(ev?.evidence).map((e) => <option key={e.id} value={e.id}>{e.title}</option>)}</select></label>}
    </>}
  </Modal>;
}

function AddTask({ tenantId, onClose }: { tenantId: string; onClose: () => void }) {
  const { data: people } = useData<any>("isms/members", { tenant_id: tenantId }, [tenantId]);
  const [form, setForm] = useState({ title: "", dueOn: "", assigneeId: "", description: "" });
  const { run, busy } = useAction();
  const save = async () => { if (await run(() => api("isms/tasks", { body: { tenantId, ...form, assigneeId: form.assigneeId || null } }), "Task added")) onClose(); };
  return <Modal title="Add a task" onClose={onClose} footer={<button className="primary" disabled={busy || !form.title.trim() || !form.dueOn} onClick={save}>Add</button>}>
    <label className="field">Title<input value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} /></label>
    <label className="field">Due on<input type="date" value={form.dueOn} onChange={(e) => setForm({ ...form, dueOn: e.target.value })} /></label>
    <label className="field">Assigned to<select value={form.assigneeId} onChange={(e) => setForm({ ...form, assigneeId: e.target.value })}>
      <option value="">Nobody yet</option>{safeArray<any>(people?.members).map((m) => <option key={m.id} value={m.id}>{m.name ? `${m.name} (${m.email})` : m.email}</option>)}</select></label>
    <label className="field">Details<textarea rows={3} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></label>
  </Modal>;
}
