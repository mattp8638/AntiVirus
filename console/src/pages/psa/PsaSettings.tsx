import { displayValue } from "../../components/DisplayValue";
import { useState } from "react";
import { useParams } from "react-router-dom";
import { api } from "../../api";
import { useApp } from "../../app-context";
import { Modal, PageHead, Pill, Table, Tabs, useAction, useData, useListData } from "../../components/ui";
import { confirmDialog, promptDialog } from "../../components/dialogs";

export default function PsaSettings() {
  const [tab, setTab] = useState("Boards");
  return (
    <>
      <PageHead title="Service settings" subtitle="Boards, statuses and types; workflow rules; email-to-ticket; AI triage." />
      <Tabs tabs={["Boards", "Workflow rules", "Email to ticket", "AI triage"]} active={tab} onChange={setTab} />
      {tab === "Boards" && <Boards />}
      {tab === "Workflow rules" && <Workflows />}
      {tab === "Email to ticket" && <InboundEmail />}
      {tab === "AI triage" && <AiTriage />}
    </>
  );
}

function Boards() {
  const { can } = useApp();
  const { data, reload } = useListData<any>("psa/boards");
  const [editing, setEditing] = useState<any>(null);
  const { run } = useAction();
  return (
    <>
      {can("configure") && <button className="primary" style={{ marginBottom: 12 }} onClick={async () => { const name = await promptDialog("Board name"); if (name && await run(() => api("psa/boards", { body: { name } }), "Board created")) reload(); }}>New board</button>}
      <div className="card">
        <Table rows={data} onRow={setEditing} empty="No boards."
               columns={[{ key: "name", label: "Board", render: (b) => <b>{displayValue(b.name)}</b> },
                         { key: "statuses", label: "Statuses", render: (b) => <span className="small">{displayValue(b.statuses.map((s: any) => s.name).join(" → "))}</span> },
                         { key: "types", label: "Types", render: (b) => b.types.length },
                         { key: "members", label: "Members", render: (b) => b.members.length || "everyone" },
                         { key: "autoAssign", label: "Assignment", render: (b) => b.autoAssign === "round_robin" ? "round robin" : "manual" },
                         { key: "mailbox", label: "Mailbox", render: (b) => b.mailbox || "—" }]} />
      </div>
      {editing && <BoardEditor board={editing} onClose={() => { setEditing(null); reload(); }} />}
    </>
  );
}

function BoardEditor({ board, onClose }: { board: any; onClose: () => void }) {
  const { data: members } = useListData<any>("psa/members");
  const [form, setForm] = useState<any>({ ...board, statuses: board.statuses.map((s: any) => ({ ...s })), typesText: board.types.map((t: any) =>
    `${t.name}: ${t.subtypes.map((s: any) => s.items.length ? `${s.name} (${s.items.join(", ")})` : s.name).join("; ")}`).join("\n") });
  const { run, busy } = useAction();
  const save = async () => {
    const types = form.typesText.split("\n").filter((l: string) => l.trim()).map((line: string) => {
      const [name, rest = ""] = line.split(":");
      const subtypes = rest.split(";").map((s: string) => s.trim()).filter(Boolean).map((s: string) => {
        const m = s.match(/^([^(]+)\(([^)]*)\)$/);
        return m ? { name: m[1].trim(), items: m[2].split(",").map((i) => i.trim()).filter(Boolean) } : { name: s, items: [] };
      });
      return { name: name.trim(), subtypes };
    });
    const body = { name: form.name, statuses: form.statuses, types, members: form.members, defaultPriority: form.defaultPriority, defaultWorkType: form.defaultWorkType,
                   mailbox: form.mailbox, autoAssign: form.autoAssign };
    if (await run(() => api(`psa/boards/${form.id}`, { method: "PATCH", body }), "Board saved")) onClose();
  };
  const setStatus = (i: number, patch: any) => setForm({ ...form, statuses: form.statuses.map((s: any, j: number) => (i === j ? { ...s, ...patch } : s)) });
  return (
    <Modal title={`Board: ${form.name}`} onClose={onClose} footer={<>
      <button className="danger" disabled={busy} onClick={async () => {
        if (await confirmDialog(`Delete the board "${form.name}"? Fenrir refuses while tickets are on it, or if it is the only board.`, { confirmLabel: "Delete board" })
            && await run(() => api(`psa/boards/${form.id}`, { method: "DELETE" }), "Board deleted")) onClose();
      }}>Delete board</button>
      <button className="primary" disabled={busy} onClick={save}>Save board</button></>}>
      <div className="form-grid">
        <label className="field">Name<input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label>
        <label className="field">Default priority<select value={form.defaultPriority} onChange={(e) => setForm({ ...form, defaultPriority: e.target.value })}>{["P1", "P2", "P3", "P4"].map((p) => <option key={p}>{p}</option>)}</select></label>
        <label className="field">Default work type<input value={form.defaultWorkType} onChange={(e) => setForm({ ...form, defaultWorkType: e.target.value })} /></label>
        <label className="field">Inbound mailbox<input value={form.mailbox} onChange={(e) => setForm({ ...form, mailbox: e.target.value })} placeholder="projects@yourmsp.co.uk" /></label>
        <label className="field">Assignment<select value={form.autoAssign} onChange={(e) => setForm({ ...form, autoAssign: e.target.value })}><option value="none">Manual</option><option value="round_robin">Round robin across members</option></select></label>
      </div>
      <h3 style={{ marginTop: 14 }}>Members</h3>
      <div className="row">{members?.map((m) => <label key={m.email} className="small"><input type="checkbox" checked={form.members.includes(m.email)}
        onChange={() => setForm({ ...form, members: form.members.includes(m.email) ? form.members.filter((x: string) => x !== m.email) : [...form.members, m.email] })} /> {displayValue(m.name)}</label>)}</div>
      <h3 style={{ marginTop: 14 }}>Statuses</h3>
      {form.statuses.map((s: any, i: number) => (
        <div key={i} className="row" style={{ marginBottom: 4 }}>
          <input value={s.name} onChange={(e) => setStatus(i, { name: e.target.value })} style={{ width: 200 }} />
          <label className="small"><input type="radio" checked={!!s.default} onChange={() => setForm({ ...form, statuses: form.statuses.map((x: any, j: number) => ({ ...x, default: i === j })) })} /> default</label>
          <label className="small"><input type="checkbox" checked={!!s.closed} onChange={(e) => setStatus(i, { closed: e.target.checked })} /> closed</label>
          <label className="small"><input type="checkbox" checked={!!s.customerResponded} onChange={(e) => setStatus(i, { customerResponded: e.target.checked })} /> on customer reply</label>
          <button className="small ghost" onClick={() => setForm({ ...form, statuses: form.statuses.filter((_: any, j: number) => j !== i) })}>✕</button>
        </div>
      ))}
      <button className="small" onClick={() => setForm({ ...form, statuses: [...form.statuses, { name: "New status", closed: false }] })}>Add status</button>
      <h3 style={{ marginTop: 14 }}>Types, subtypes and items</h3>
      <p className="small muted">One type per line: <span className="mono">Type: Subtype (Item, Item); Subtype</span></p>
      <textarea rows={7} value={form.typesText} onChange={(e) => setForm({ ...form, typesText: e.target.value })} style={{ width: "100%", fontFamily: "var(--mono)", fontSize: 12 }} />
    </Modal>
  );
}

const FIELDS = ["status", "priority", "board", "account", "type", "subtype", "source", "subject", "assignee_empty"];

function Workflows() {
  const { can } = useApp();
  const { data, reload } = useListData<any>("psa/workflows");
  const { data: boards } = useListData<any>("psa/boards");
  const [editing, setEditing] = useState<any>(null);
  return (
    <>
      {can("configure") && <button className="primary" style={{ marginBottom: 12 }} onClick={() => setEditing({ name: "", trigger: "ticket.created", conditions: [], actions: [], enabled: true, idleHours: 0 })}>New rule</button>}
      <div className="card">
        <Table rows={data} onRow={setEditing} empty="No workflow rules. Example: close tickets that wait on the customer for 3 days."
               columns={[{ key: "name", label: "Rule", render: (w) => <b>{displayValue(w.name)}</b> },
                         { key: "trigger", label: "When", render: (w) => w.trigger === "ticket.idle" ? `in the same status for ${w.idleHours}h` : w.trigger.replace(".", " ") },
                         { key: "boardId", label: "Board", render: (w) => boards?.find((b) => b.id === w.boardId)?.name || "all boards" },
                         { key: "conditions", label: "If", render: (w) => <span className="small">{displayValue(w.conditions.map((c: any) => `${c.field} ${c.op} ${c.value}`).join(" and ") || "always")}</span> },
                         { key: "actions", label: "Then", render: (w) => <span className="small">{displayValue(w.actions.map((a: any) => a.type === "set" ? `set ${a.field}=${a.value}` : a.type).join(", "))}</span> },
                         { key: "runs", label: "Runs" }, { key: "enabled", label: "", render: (w) => <Pill value={w.enabled ? "on" : "off"} tone={w.enabled ? "good" : "muted"} /> }]} />
      </div>
      {editing && <WorkflowEditor rule={editing} boards={boards || []} onClose={() => { setEditing(null); reload(); }} />}
    </>
  );
}

function WorkflowEditor({ rule, boards, onClose }: { rule: any; boards: any[]; onClose: () => void }) {
  const [form, setForm] = useState<any>({ ...rule, conditions: [...rule.conditions], actions: [...rule.actions] });
  const { run, busy } = useAction();
  const save = async () => {
    const body = { name: form.name, trigger: form.trigger, boardId: form.boardId || null, conditions: form.conditions, actions: form.actions, enabled: form.enabled, idleHours: Number(form.idleHours) };
    if (await run(() => (form.id ? api(`psa/workflows/${form.id}`, { method: "PATCH", body }) : api("psa/workflows", { body })), "Rule saved")) onClose();
  };
  const setCond = (i: number, patch: any) => setForm({ ...form, conditions: form.conditions.map((c: any, j: number) => (i === j ? { ...c, ...patch } : c)) });
  const setAct = (i: number, patch: any) => setForm({ ...form, actions: form.actions.map((a: any, j: number) => (i === j ? { ...a, ...patch } : a)) });
  return (
    <Modal title={form.id ? form.name : "New workflow rule"} onClose={onClose}
           footer={<>{form.id && <button className="danger" onClick={async () => { if (await run(() => api(`psa/workflows/${form.id}`, { method: "DELETE" }), "Deleted")) onClose(); }}>Delete</button>}
                   <button className="primary" disabled={busy || !form.name} onClick={save}>Save</button></>}>
      <div className="form-grid">
        <label className="field">Name<input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label>
        <label className="field">When<select value={form.trigger} onChange={(e) => setForm({ ...form, trigger: e.target.value })}>
          <option value="ticket.created">A ticket is created</option><option value="ticket.updated">A ticket is updated</option>
          <option value="ticket.idle">A ticket sits in one status</option><option value="sla.warning">75% of the SLA has passed</option><option value="sla.breached">The SLA is breached</option></select></label>
        {form.trigger === "ticket.idle" && <label className="field">For (hours)<input type="number" value={form.idleHours} onChange={(e) => setForm({ ...form, idleHours: e.target.value })} /></label>}
        <label className="field">Board<select value={form.boardId || ""} onChange={(e) => setForm({ ...form, boardId: e.target.value })}><option value="">All boards</option>{boards.map((b) => <option key={b.id} value={b.id}>{displayValue(b.name)}</option>)}</select></label>
        <label className="field">Enabled<select value={form.enabled ? "yes" : "no"} onChange={(e) => setForm({ ...form, enabled: e.target.value === "yes" })}><option value="yes">Yes</option><option value="no">No</option></select></label>
      </div>
      <h3 style={{ marginTop: 14 }}>If</h3>
      {form.conditions.map((c: any, i: number) => (
        <div key={i} className="row" style={{ marginBottom: 4 }}>
          <select value={c.field} onChange={(e) => setCond(i, { field: e.target.value })}>{FIELDS.map((f) => <option key={f}>{f}</option>)}</select>
          <select value={c.op} onChange={(e) => setCond(i, { op: e.target.value })}>{["equals", "not_equals", "contains", "in"].map((o) => <option key={o}>{o}</option>)}</select>
          <input value={c.value} onChange={(e) => setCond(i, { value: e.target.value })} style={{ flex: 1 }} />
          <button className="small ghost" onClick={() => setForm({ ...form, conditions: form.conditions.filter((_: any, j: number) => j !== i) })}>✕</button>
        </div>
      ))}
      <button className="small" onClick={() => setForm({ ...form, conditions: [...form.conditions, { field: "status", op: "equals", value: "" }] })}>Add condition</button>
      <h3 style={{ marginTop: 14 }}>Then</h3>
      {form.actions.map((a: any, i: number) => (
        <div key={i} className="row" style={{ marginBottom: 4 }}>
          <select value={a.type} onChange={(e) => setAct(i, { type: e.target.value })}>
            <option value="set">Set a field</option><option value="assign">Assign</option><option value="note">Add a note</option><option value="email_contact">Email the contact</option><option value="notify">Notify a member</option></select>
          {a.type === "set" && <><select value={a.field || "status"} onChange={(e) => setAct(i, { field: e.target.value })}>{["status", "priority", "assignee", "team", "type", "subtype", "item"].map((f) => <option key={f}>{f}</option>)}</select>
            <input value={a.value || ""} onChange={(e) => setAct(i, { value: e.target.value })} placeholder="value" /></>}
          {a.type === "assign" && <input value={a.member || ""} onChange={(e) => setAct(i, { member: e.target.value })} placeholder="email or round_robin" style={{ flex: 1 }} />}
          {a.type === "note" && <><input value={a.text || ""} onChange={(e) => setAct(i, { text: e.target.value })} style={{ flex: 1 }} />
            <select value={a.kind || "internal"} onChange={(e) => setAct(i, { kind: e.target.value })}><option>internal</option><option>discussion</option><option>resolution</option></select></>}
          {a.type === "email_contact" && <><input value={a.subject || ""} onChange={(e) => setAct(i, { subject: e.target.value })} placeholder="Subject ({number}, {subject})" />
            <input value={a.body || ""} onChange={(e) => setAct(i, { body: e.target.value })} placeholder="Message" style={{ flex: 1 }} /></>}
          {a.type === "notify" && <input value={a.to || ""} onChange={(e) => setAct(i, { to: e.target.value })} placeholder="who (blank = assignee)" style={{ flex: 1 }} />}
          <button className="small ghost" onClick={() => setForm({ ...form, actions: form.actions.filter((_: any, j: number) => j !== i) })}>✕</button>
        </div>
      ))}
      <button className="small" onClick={() => setForm({ ...form, actions: [...form.actions, { type: "set", field: "status", value: "" }] })}>Add action</button>
    </Modal>
  );
}

function InboundEmail() {
  const { can } = useApp();
  const [result, setResult] = useState<any>(null);
  const { run, busy } = useAction();
  return (
    <div className="card">
      <h2>Email to ticket</h2>
      <p>New emails become tickets; replies that keep <span className="mono">[Ticket #1234]</span> in the subject are added to the existing ticket and re-open it if it was closed.
        Senders are matched to companies by contact email, then by each company's email domains.</p>
      <h3>Option 1: IMAP mailbox</h3>
      <p className="small">Set <span className="mono">FENRIR_IMAP_HOST</span>, <span className="mono">FENRIR_IMAP_USER</span> and <span className="mono">FENRIR_IMAP_PASSWORD</span> on the server. Fenrir checks the inbox every two minutes.
        Outbound notifications use <span className="mono">FENRIR_SMTP_HOST</span>, <span className="mono">FENRIR_SMTP_USER</span>, <span className="mono">FENRIR_SMTP_PASSWORD</span> and <span className="mono">FENRIR_SMTP_FROM</span>.</p>
      <h3>Option 2: Webhook</h3>
      <p className="small">Point your mail provider's inbound webhook (Mailgun, SendGrid, Postmark, Microsoft 365 via Power Automate) at the URL below. It accepts raw RFC 822 messages or JSON with from, to, subject, text and messageId.</p>
      {can("configure") && <button disabled={busy} onClick={async () => setResult(await run(() => api<any>("psa/inbound-token", { method: "POST" }), "New inbound URL created"))}>Create a new inbound URL</button>}
      {result && <pre style={{ marginTop: 10 }}>{window.location.origin}{displayValue(result.url)}</pre>}
      <p className="small muted" style={{ marginTop: 8 }}>Creating a new URL disables the previous one.</p>
    </div>
  );
}

export function ProjectDetail() {
  const { id } = useParams();
  const { data, reload } = useData<any>(`psa/projects/${id}`);
  const { run } = useAction();
  const [phase, setPhase] = useState("");
  if (!data) return <div className="empty">Loading…</div>;
  const p = data.project;
  const savePhases = async (phases: any[]) => { await run(() => api(`crm/projects/${p.id}`, { method: "PATCH", body: { phases } }), "Saved"); reload(); };
  return (
    <>
      <PageHead title={p.name} subtitle={<>{displayValue(p.status)} · {displayValue(p.billingMethod || "Time & Materials")} · {displayValue(data.actualHours)} of {displayValue(p.estimatedHours || 0)} estimated hours · due {displayValue(p.dueDate || "—")}</>} />
      <div className="grid k3">
        {data.phases.map((ph: any, i: number) => (
          <div key={i} className="card">
            <div className="row"><b>{displayValue(ph.name)}</b><Pill value={ph.status || "Open"} /><span style={{ flex: 1 }} />
              <select value={ph.status || "Open"} onChange={(e) => savePhases(p.phases.map((x: any, j: number) => (j === i ? { ...x, status: e.target.value } : x)))}>{["Open", "In Progress", "Done"].map((s) => <option key={s}>{s}</option>)}</select></div>
            <div className="small muted">{ph.budgetHours ? `${ph.budgetHours}h budget` : ""}</div>
            {ph.tickets.map((t: any) => <div key={t.id} className="small" style={{ marginTop: 4 }}><a href={`/tickets/${t.id}`}>#{displayValue(t.number)}</a> {displayValue(t.subject)} <Pill value={t.status} /></div>)}
            {!ph.tickets.length && <p className="small muted">No tickets in this phase. Create a ticket on the Projects board and set its phase.</p>}
          </div>
        ))}
      </div>
      <form className="row" style={{ marginTop: 12 }} onSubmit={async (e) => { e.preventDefault(); if (phase) { await savePhases([...(p.phases || []), { name: phase, status: "Open", budgetHours: 0 }]); setPhase(""); } }}>
        <input value={phase} onChange={(e) => setPhase(e.target.value)} placeholder="New phase name" /><button>Add phase</button>
      </form>
      {data.unphased.length > 0 && <div className="card" style={{ marginTop: 12 }}><h3>Tickets without a phase</h3>{data.unphased.map((t: any) => <div key={t.id}><a href={`/tickets/${t.id}`}>#{displayValue(t.number)}</a> {displayValue(t.subject)}</div>)}</div>}
    </>
  );
}

function AiTriage() {
  const { can } = useApp();
  const { data, error, reload } = useData<any>("psa/ai-triage");
  const { run, busy } = useAction();
  if (error) return <div className="error">{error}</div>;
  if (!data) return <div className="empty">Loading…</div>;
  const save = async (body: any) => { if (await run(() => api("psa/ai-triage", { method: "PUT", body: { mode: data.mode, engine: data.engine, ...body } }), "Triage settings saved")) reload(); };
  return (
    <div className="card">
      <p className="small muted">New tickets from email, the portal and phone are categorised and prioritised, matched to knowledge-base articles and remediation packages, and given a suggested reply as an internal note. With the Claude engine, passwords and secrets, card and National Insurance numbers and long tokens are redacted before the ticket text leaves Fenrir.</p>
      <div className="form-grid">
        <label className="field">Mode<select value={data.mode} disabled={busy || !can("configure")} onChange={(e) => save({ mode: e.target.value })}>
          <option value="off">Off</option><option value="suggest">Suggest (internal note only)</option><option value="apply">Apply (also sets type, impact and urgency; only ever raises priority)</option></select></label>
        <label className="field">Engine<select value={data.engine} disabled={busy || !can("configure")} onChange={(e) => save({ engine: e.target.value })}>
          <option value="local">Local rules (nothing leaves Fenrir)</option><option value="claude">Claude (sends redacted ticket text to Anthropic)</option></select></label>
      </div>
      {data.engine === "claude" && !data.claudeConfigured && <p className="error small">Set ANTHROPIC_API_KEY on the server to use Claude; until then local rules are used.</p>}
      {data.engine === "claude" && data.claudeConfigured && <p className="small muted">Model {displayValue(data.model)}. If the API is unavailable, local rules are used for that ticket.</p>}
    </div>
  );
}
