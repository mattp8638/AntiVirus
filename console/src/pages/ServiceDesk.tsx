import { useState } from "react";
import { Link } from "react-router-dom";
import { ago, api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { Modal, PageHead, Pill, Stat, Table, TenantSelect, useAction, useData } from "../components/ui";

export default function ServiceDesk() {
  const { tenantId } = useApp();
  const [status, setStatus] = useState("active");
  const [queue, setQueue] = useState("");
  const { data, reload } = useData<any[]>("tickets", { tenant_id: tenantId, status, queue });
  const [open, setOpen] = useState<any>(null);
  const [creating, setCreating] = useState(false);
  const breached = data?.filter((t) => t.slaBreached).length ?? 0;
  return (
    <>
      <PageHead title="Service desk" subtitle="PSA ticketing with contract SLAs. Security incidents open tickets automatically per policy."
                actions={<button className="primary" onClick={() => setCreating(true)}>New ticket</button>} />
      <div className="grid k3">
        <Stat label="In view" value={data?.length ?? "—"} />
        <Stat label="Past SLA" value={breached} accent={breached ? "red" : "green"} />
        <Stat label="P1 open" value={data?.filter((t) => t.priority === "P1" && !["Resolved", "Closed"].includes(t.status)).length ?? 0} accent="amber" />
      </div>
      <div className="row" style={{ margin: "16px 0 12px" }}>
        <select value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status"><option value="active">Active</option><option value="">All</option>{["Open", "In Progress", "Waiting", "Resolved", "Closed"].map((s) => <option key={s}>{s}</option>)}</select>
        <select value={queue} onChange={(e) => setQueue(e.target.value)} aria-label="Queue"><option value="">All queues</option><option>Service Desk</option><option>Security Operations</option><option>Projects</option></select>
      </div>
      <div className="card">
        <Table rows={data} onRow={setOpen} empty="No tickets."
               columns={[{ key: "number", label: "#", render: (t) => `#${t.number}` },
                         { key: "priority", label: "P", render: (t) => <Pill value={t.priority} tone={t.priority === "P1" ? "bad" : t.priority === "P2" ? "warn" : "muted"} /> },
                         { key: "subject", label: "Subject", render: (t) => <><b>{t.subject}</b><div className="small muted">{t.queue} · {t.source}</div></> },
                         { key: "account", label: "Account" },
                         { key: "assignee", label: "Assignee", render: (t) => t.assignee || "—" },
                         { key: "status", label: "Status", render: (t) => <Pill value={t.status} /> },
                         { key: "slaDueAt", label: "SLA", render: (t) => t.slaBreached ? <Pill value="breached" tone="bad" /> : <span className="small">{fmtTime(t.slaDueAt)}</span> },
                         { key: "updatedAt", label: "Updated", render: (t) => ago(t.updatedAt) }]} />
      </div>
      {open && <TicketModal ticket={open} onClose={() => { setOpen(null); reload(); }} />}
      {creating && <NewTicket onClose={() => { setCreating(false); reload(); }} />}
    </>
  );
}

function TicketModal({ ticket, onClose }: { ticket: any; onClose: () => void }) {
  const { me } = useApp();
  const [comment, setComment] = useState("");
  const [internal, setInternal] = useState(false);
  const [minutes, setMinutes] = useState(0);
  const [t, setT] = useState(ticket);
  const { run, busy } = useAction();
  const update = async (body: any, message?: string) => {
    const updated = await run(() => api(`tickets/${t.id}`, { method: "PATCH", body }), message);
    if (updated) setT({ ...t, ...updated });
  };
  return (
    <Modal title={`#${t.number} ${t.subject}`} onClose={onClose}>
      <div className="form-grid">
        <label className="field">Status<select value={t.status} onChange={(e) => update({ status: e.target.value }, "Status updated")}>{["Open", "In Progress", "Waiting", "Resolved", "Closed"].map((s) => <option key={s}>{s}</option>)}</select></label>
        <label className="field">Priority<select value={t.priority} onChange={(e) => update({ priority: e.target.value }, "Priority updated; SLA recalculated")}>{["P1", "P2", "P3", "P4"].map((s) => <option key={s}>{s}</option>)}</select></label>
        <label className="field">Assignee<div className="row"><input value={t.assignee} onChange={(e) => setT({ ...t, assignee: e.target.value })} onBlur={() => update({ assignee: t.assignee })} />
          <button className="small" onClick={() => update({ assignee: me?.user.email }, "Assigned")}>Me</button></div></label>
        <label className="field">Log time (minutes)<div className="row"><input type="number" value={minutes} onChange={(e) => setMinutes(Number(e.target.value))} style={{ width: 90 }} />
          <button className="small" disabled={!minutes} onClick={() => { update({ addMinutes: minutes }, "Time logged"); setMinutes(0); }}>Add</button></div></label>
      </div>
      <p className="small muted">{t.timeMinutes} min logged · SLA due {fmtTime(t.slaDueAt)} · {t.billable ? "billable" : "not billable"}
        {t.incidentId && <> · <Link to={`/incidents/${t.incidentId}`}>linked incident</Link></>}</p>
      {t.description && <pre style={{ whiteSpace: "pre-wrap" }}>{t.description}</pre>}
      <h3 style={{ marginTop: 12 }}>Conversation</h3>
      <div className="timeline">
        {(t.comments || []).map((c: any, i: number) => (
          <div key={i} className="item"><div className="small muted">{fmtTime(c.at)} · {c.by}{c.internal ? " · internal" : ""}</div><div>{c.text}</div></div>
        ))}
      </div>
      <textarea style={{ minHeight: 80 }} value={comment} onChange={(e) => setComment(e.target.value)} placeholder="Reply or add a note" />
      <div className="row" style={{ marginTop: 8 }}>
        <label className="small"><input type="checkbox" checked={internal} onChange={(e) => setInternal(e.target.checked)} /> Internal note</label>
        <span style={{ flex: 1 }} />
        <button className="primary" disabled={!comment || busy} onClick={async () => { await update({ comment, internal }, "Comment added"); setComment(""); }}>Add comment</button>
      </div>
    </Modal>
  );
}

function NewTicket({ onClose }: { onClose: () => void }) {
  const { tenantId, me } = useApp();
  const [account, setAccount] = useState(tenantId || me?.user.tenantId || "");
  const [subject, setSubject] = useState("");
  const [description, setDescription] = useState("");
  const [priority, setPriority] = useState("P3");
  const [queue, setQueue] = useState("Service Desk");
  const { run, busy } = useAction();
  const submit = async () => { if (await run(() => api("tickets", { body: { accountTenantId: account, subject, description, priority, queue } }), "Ticket created")) onClose(); };
  return (
    <Modal title="New ticket" onClose={onClose} footer={<><button onClick={onClose}>Cancel</button><button className="primary" disabled={busy || !subject} onClick={submit}>Create</button></>}>
      <div className="form-grid">
        <label className="field">Account<TenantSelect value={account} onChange={setAccount} allowAll={false} /></label>
        <label className="field">Priority<select value={priority} onChange={(e) => setPriority(e.target.value)}>{["P1", "P2", "P3", "P4"].map((p) => <option key={p}>{p}</option>)}</select></label>
        <label className="field">Queue<select value={queue} onChange={(e) => setQueue(e.target.value)}><option>Service Desk</option><option>Security Operations</option><option>Projects</option></select></label>
      </div>
      <label className="field" style={{ marginTop: 12 }}>Subject<input value={subject} onChange={(e) => setSubject(e.target.value)} /></label>
      <label className="field" style={{ marginTop: 12 }}>Description<textarea value={description} onChange={(e) => setDescription(e.target.value)} style={{ fontFamily: "var(--font)" }} /></label>
    </Modal>
  );
}
