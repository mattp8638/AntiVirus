import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ago, api, fmtTime } from "../../api";
import { useApp } from "../../app-context";
import { Modal, PageHead, Pill, Stat, Table, TenantSelect, useAction, useData } from "../../components/ui";

export const PRIORITY_TONE: Record<string, string> = { P1: "bad", P2: "warn", P3: "blue", P4: "muted" };

function slaCell(t: any) {
  if (t.closed) return <span className="muted small">—</span>;
  if (t.slaBreached) return <Pill value="breached" tone="bad" />;
  if (t.respondBreached) return <Pill value="no response" tone="warn" />;
  const due = t.slaDueAt ? new Date(t.slaDueAt).getTime() - Date.now() : 0;
  const hours = due / 3600000;
  return <span className="small" style={{ color: hours < 2 ? "#fde68a" : undefined }}>{hours < 48 ? `${hours.toFixed(1)}h left` : fmtTime(t.slaDueAt)}</span>;
}

export default function ServiceBoard() {
  const { tenantId } = useApp();
  const navigate = useNavigate();
  const { data: meta } = useData<any>("psa/meta");
  const [boardId, setBoardId] = useState(() => { try { return localStorage.getItem("fenrir.board") || ""; } catch { return ""; } });
  const [view, setView] = useState<"list" | "board">("list");
  const [status, setStatus] = useState("active");
  const [assignee, setAssignee] = useState("");
  const [q, setQ] = useState("");
  const [creating, setCreating] = useState(false);
  const { data, reload } = useData<any[]>("tickets", { tenant_id: tenantId, board_id: boardId, status, assignee, q });
  const board = meta?.boards.find((b: any) => b.id === boardId);
  useEffect(() => { try { localStorage.setItem("fenrir.board", boardId); } catch { /* ignore */ } }, [boardId]);
  useEffect(() => { const t = window.setInterval(reload, 20000); return () => window.clearInterval(t); }, [reload]);
  const breached = data?.filter((t) => t.slaBreached).length ?? 0;
  const unassigned = data?.filter((t) => !t.assignee && !t.closed).length ?? 0;
  return (
    <>
      <PageHead title="Service board" subtitle="Tickets by board with SLAs, priorities from impact × urgency, and time tracked against agreements."
                actions={<button className="primary" onClick={() => setCreating(true)}>New ticket</button>} />
      <div className="grid k4">
        <Stat label="Open in view" value={data?.filter((t) => !t.closed).length ?? "—"} />
        <Stat label="Past SLA" value={breached} accent={breached ? "red" : "green"} />
        <Stat label="Unassigned" value={unassigned} accent={unassigned ? "amber" : undefined} />
        <Stat label="P1" value={data?.filter((t) => t.priority === "P1" && !t.closed).length ?? 0} accent="red" />
      </div>
      <div className="row" style={{ margin: "16px 0 12px" }}>
        <select value={boardId} onChange={(e) => setBoardId(e.target.value)} aria-label="Board">
          <option value="">All boards</option>{meta?.boards.map((b: any) => <option key={b.id} value={b.id}>{b.name}</option>)}</select>
        <select value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status">
          <option value="active">Open tickets</option><option value="closed">Closed</option><option value="">Everything</option>
          {(board?.statuses || []).map((s: any) => <option key={s.name} value={s.name}>{s.name}</option>)}</select>
        <select value={assignee} onChange={(e) => setAssignee(e.target.value)} aria-label="Assignee">
          <option value="">Anyone</option><option value="me">My tickets</option><option value="unassigned">Unassigned</option>
          {meta?.members.map((m: any) => <option key={m.email} value={m.email}>{m.name}</option>)}</select>
        <input placeholder="Search # or text" value={q} onChange={(e) => setQ(e.target.value)} />
        <span style={{ flex: 1 }} />
        <button className={view === "list" ? "primary small" : "small"} onClick={() => setView("list")}>List</button>
        <button className={view === "board" ? "primary small" : "small"} onClick={() => setView("board")} disabled={!board}>Board</button>
      </div>
      {view === "list" || !board ? (
        <div className="card">
          <Table rows={data} onRow={(t) => navigate(`/tickets/${t.id}`)} empty="No tickets."
                 columns={[{ key: "number", label: "#", render: (t) => <b>#{t.number}</b> },
                           { key: "priority", label: "Pri", render: (t) => <Pill value={t.priority} tone={PRIORITY_TONE[t.priority]} /> },
                           { key: "subject", label: "Summary", render: (t) => <><b>{t.subject}</b><div className="small muted">{t.board}{t.type ? ` · ${t.type}${t.subtype ? ` / ${t.subtype}` : ""}` : ""} · {t.source}</div></> },
                           { key: "account", label: "Company" },
                           { key: "assignee", label: "Resource", render: (t) => t.assignee || <span className="muted">unassigned</span> },
                           { key: "status", label: "Status", render: (t) => <Pill value={t.status} tone={t.closed ? "muted" : t.status === "New" ? "warn" : "blue"} /> },
                           { key: "sla", label: "SLA", render: slaCell },
                           { key: "hours", label: "Hours", render: (t) => t.hours ? t.hours.toFixed(2) : "—" },
                           { key: "updatedAt", label: "Updated", render: (t) => ago(t.updatedAt) }]} />
        </div>
      ) : <Kanban board={board} tickets={data || []} onMoved={reload} />}
      {creating && <NewTicket meta={meta} defaultBoard={boardId} onClose={(id) => { setCreating(false); if (id) navigate(`/tickets/${id}`); else reload(); }} />}
    </>
  );
}

function Kanban({ board, tickets, onMoved }: { board: any; tickets: any[]; onMoved: () => void }) {
  const { run } = useAction();
  const navigate = useNavigate();
  const columns = board.statuses.filter((s: any) => !s.closed);
  const move = async (id: string, status: string) => {
    await run(() => api(`tickets/${id}`, { method: "PATCH", body: { status } }), `Moved to ${status}`);
    onMoved();
  };
  return (
    <div className="kanban" style={{ gridTemplateColumns: `repeat(${columns.length}, minmax(210px, 1fr))` }}>
      {columns.map((col: any) => (
        <div key={col.name} className="col" onDragOver={(e) => e.preventDefault()} onDrop={(e) => move(e.dataTransfer.getData("text/plain"), col.name)}>
          <div className="row"><b>{col.name}</b><span className="muted small">{tickets.filter((t) => t.status === col.name).length}</span></div>
          {tickets.filter((t) => t.status === col.name).map((t) => (
            <div key={t.id} className="lead" draggable onDragStart={(e) => e.dataTransfer.setData("text/plain", t.id)} onClick={() => navigate(`/tickets/${t.id}`)} style={{ cursor: "pointer" }}>
              <div className="row"><Pill value={t.priority} tone={PRIORITY_TONE[t.priority]} /><span className="small muted">#{t.number}</span><span style={{ flex: 1 }} />{slaCell(t)}</div>
              <div style={{ marginTop: 4 }}><b>{t.subject}</b></div>
              <div className="small muted">{t.account} · {t.assignee || "unassigned"}</div>
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}

export function NewTicket({ meta, defaultBoard, onClose, preset }: { meta: any; defaultBoard?: string; onClose: (id?: string) => void; preset?: any }) {
  const { tenantId, me } = useApp();
  const [form, setForm] = useState<any>({ accountTenantId: tenantId || me?.user.tenantId || "", boardId: defaultBoard || "", subject: "", description: "",
                                          impact: "Medium", urgency: "Medium", type: "", subtype: "", item: "", contactId: "", ...preset });
  const { data: contacts } = useData<any[]>("crm/contacts");
  const board = meta?.boards.find((b: any) => b.id === form.boardId) || meta?.boards.find((b: any) => b.name === "Service Desk");
  const types = board?.types || [];
  const subtypes = types.find((t: any) => t.name === form.type)?.subtypes || [];
  const items = subtypes.find((s: any) => s.name === form.subtype)?.items || [];
  const priority = useMemo(() => meta?.priorityMatrix.find((p: any) => p.impact === form.impact && p.urgency === form.urgency)?.priority || "P3", [meta, form.impact, form.urgency]);
  const { run, busy } = useAction();
  const submit = async () => {
    const created = await run(() => api<any>("tickets", { body: { ...form, boardId: form.boardId || board?.id, source: "phone" } }), "Ticket created");
    if (created) onClose(created.id);
  };
  return (
    <Modal title="New service ticket" onClose={() => onClose()}
           footer={<><button onClick={() => onClose()}>Cancel</button><button className="primary" disabled={busy || !form.subject} onClick={submit}>Create ticket</button></>}>
      <div className="form-grid">
        <label className="field">Company<TenantSelect value={form.accountTenantId} onChange={(id) => setForm({ ...form, accountTenantId: id, contactId: "" })} allowAll={false} /></label>
        <label className="field">Contact<select value={form.contactId} onChange={(e) => setForm({ ...form, contactId: e.target.value })}>
          <option value="">—</option>{contacts?.filter((c) => c.accountTenantId === form.accountTenantId).map((c) => <option key={c.id} value={c.id}>{c.name} ({c.email})</option>)}</select></label>
        <label className="field">Board<select value={form.boardId || board?.id || ""} onChange={(e) => setForm({ ...form, boardId: e.target.value, type: "", subtype: "", item: "" })}>
          {meta?.boards.map((b: any) => <option key={b.id} value={b.id}>{b.name}</option>)}</select></label>
        <label className="field">Type<select value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value, subtype: "", item: "" })}><option value="">—</option>{types.map((t: any) => <option key={t.name}>{t.name}</option>)}</select></label>
        <label className="field">Subtype<select value={form.subtype} onChange={(e) => setForm({ ...form, subtype: e.target.value, item: "" })}><option value="">—</option>{subtypes.map((s: any) => <option key={s.name}>{s.name}</option>)}</select></label>
        <label className="field">Item<select value={form.item} onChange={(e) => setForm({ ...form, item: e.target.value })}><option value="">—</option>{items.map((i: string) => <option key={i}>{i}</option>)}</select></label>
        <label className="field">Impact<select value={form.impact} onChange={(e) => setForm({ ...form, impact: e.target.value })}>{["High", "Medium", "Low"].map((x) => <option key={x}>{x}</option>)}</select></label>
        <label className="field">Urgency<select value={form.urgency} onChange={(e) => setForm({ ...form, urgency: e.target.value })}>{["High", "Medium", "Low"].map((x) => <option key={x}>{x}</option>)}</select></label>
        <label className="field">Priority<div style={{ paddingTop: 6 }}><Pill value={priority} tone={PRIORITY_TONE[priority]} /> <span className="small muted">from impact × urgency</span></div></label>
      </div>
      <label className="field" style={{ marginTop: 12 }}>Summary<input value={form.subject} onChange={(e) => setForm({ ...form, subject: e.target.value })} autoFocus /></label>
      <label className="field" style={{ marginTop: 12 }}>Initial description<textarea rows={5} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} style={{ fontFamily: "var(--font)" }} /></label>
    </Modal>
  );
}
