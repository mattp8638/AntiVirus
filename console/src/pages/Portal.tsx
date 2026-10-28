import { displayValue } from "../components/DisplayValue";
// Client portal: what a customer's staff see when they sign in.
import { useState } from "react";
import { api, fmtTime, money } from "../api";
import { useApp } from "../app-context";
import { Modal, Pill, Table, Tabs, useAction, useData, useListData } from "../components/ui";

export default function Portal() {
  const { logout } = useApp();
  const { data: me } = useData<any>("/api/portal/me");
  const [tab, setTab] = useState("My requests");
  const [open, setOpen] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const { data: tickets, reload } = useListData<any>("/api/portal/tickets");
  const { data: kb } = useListData<any>("/api/portal/kb");
  const { data: invoices } = useListData<any>("/api/portal/invoices");
  const { data: devices } = useListData<any>("/api/portal/devices");
  return (
    <div style={{ maxWidth: 1100, margin: "0 auto", padding: 24 }}>
      <div className="row" style={{ marginBottom: 20 }}>
        <div className="brand-mark">F</div>
        <div><b style={{ fontSize: 18 }}>{displayValue(me?.provider || "Support")} portal</b><div className="small muted">{displayValue(me?.company)} · {displayValue(me?.user.email)}</div></div>
        <span style={{ flex: 1 }} />
        {me?.supportPhone && <span className="small">Call us: <b>{displayValue(me.supportPhone)}</b></span>}
        <button className="primary" onClick={() => setCreating(true)}>Get help</button>
        <button className="small" onClick={logout}>Sign out</button>
      </div>
      <Tabs tabs={["My requests", "Knowledge base", "Invoices", "Devices"]} active={tab} onChange={setTab} />
      <div className="card">
        {tab === "My requests" && <Table rows={tickets} onRow={(t) => setOpen(t.id)} empty="You have no requests. Use Get help to raise one."
                                         columns={[{ key: "number", label: "#", render: (t) => `#${t.number}` }, { key: "subject", label: "Request", render: (t) => <b>{displayValue(t.subject)}</b> },
                                                   { key: "status", label: "Status", render: (t) => <Pill value={t.status} tone={t.closed ? "muted" : "blue"} /> },
                                                   { key: "assignee", label: "Engineer", render: (t) => t.assignee || "—" }, { key: "updatedAt", label: "Updated", render: (t) => fmtTime(t.updatedAt) }]} />}
        {tab === "Knowledge base" && (kb?.length ? kb.map((a) => (
          <details key={a.id} style={{ padding: "8px 0", borderBottom: "1px solid var(--line)" }}><summary><b>{displayValue(a.title)}</b> <span className="small muted">{displayValue(a.category)}</span></summary>
            <div style={{ whiteSpace: "pre-wrap", marginTop: 8 }}>{displayValue(a.body)}</div></details>)) : <div className="empty">No articles yet.</div>)}
        {tab === "Invoices" && <Table rows={invoices} empty="No invoices."
                                      columns={[{ key: "number", label: "Invoice" }, { key: "period", label: "Period" }, { key: "total", label: "Total", render: (i) => money(i.total, i.currency) },
                                                { key: "dueDate", label: "Due" }, { key: "status", label: "Status", render: (i) => <Pill value={i.status} /> }]} />}
        {tab === "Devices" && <Table rows={devices} empty="No managed devices."
                                     columns={[{ key: "hostname", label: "Device", render: (d) => <><span className={`dot ${d.online ? "on" : "off"}`} /> {displayValue(d.hostname)}</> },
                                               { key: "osVersion", label: "System" }, { key: "loggedOnUser", label: "User" },
                                               { key: "healthState", label: "Protection", render: (d) => <Pill value={d.healthState} tone={d.healthState === "healthy" ? "good" : "warn"} /> }]} />}
      </div>
      {creating && <NewRequest onClose={() => { setCreating(false); reload(); }} />}
      {open && <RequestDetail id={open} onClose={() => { setOpen(null); reload(); }} />}
    </div>
  );
}

function NewRequest({ onClose }: { onClose: () => void }) {
  const [form, setForm] = useState({ subject: "", description: "", urgency: "Medium", impact: "Low" });
  const { run, busy } = useAction();
  return (
    <Modal title="How can we help?" onClose={onClose}
           footer={<><button onClick={onClose}>Cancel</button><button className="primary" disabled={busy || !form.subject} onClick={async () => {
             if (await run(() => api("/api/portal/tickets", { body: form }), "Request sent. We'll be in touch.")) onClose();
           }}>Send request</button></>}>
      <label className="field">Short summary<input value={form.subject} onChange={(e) => setForm({ ...form, subject: e.target.value })} autoFocus /></label>
      <label className="field" style={{ marginTop: 10 }}>What's happening?<textarea rows={5} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} style={{ fontFamily: "var(--font)" }} /></label>
      <div className="form-grid" style={{ marginTop: 10 }}>
        <label className="field">How urgent is it?<select value={form.urgency} onChange={(e) => setForm({ ...form, urgency: e.target.value })}><option value="High">I can't work</option><option value="Medium">It's slowing me down</option><option value="Low">It can wait</option></select></label>
        <label className="field">Who is affected?<select value={form.impact} onChange={(e) => setForm({ ...form, impact: e.target.value })}><option value="High">The whole company</option><option value="Medium">My team</option><option value="Low">Just me</option></select></label>
      </div>
    </Modal>
  );
}

function RequestDetail({ id, onClose }: { id: string; onClose: () => void }) {
  const { data, reload } = useData<any>(`/api/portal/tickets/${id}`);
  const [text, setText] = useState("");
  const { run, busy } = useAction();
  if (!data) return null;
  const reply = async (close = false) => { if (await run(() => api(`/api/portal/tickets/${id}/reply`, { body: { text: text || "Please close this request.", close } }), close ? "Closed" : "Reply sent")) { setText(""); reload(); } };
  return (
    <Modal title={`#${data.number} ${data.subject}`} onClose={onClose}>
      <p className="small muted"><Pill value={data.status} tone={data.closed ? "muted" : "blue"} /> Opened {fmtTime(data.createdAt)}{data.assignee ? ` · ${data.assignee}` : ""}</p>
      {data.description && <pre style={{ whiteSpace: "pre-wrap", fontFamily: "var(--font)" }}>{displayValue(data.description)}</pre>}
      <div className="timeline" style={{ marginTop: 10 }}>
        {data.notes.map((n: any, i: number) => <div key={i} className="item"><div className="small muted">{displayValue(n.by)} · {fmtTime(n.at)}</div><div style={{ whiteSpace: "pre-wrap" }}>{displayValue(n.text)}</div></div>)}
      </div>
      <textarea rows={3} value={text} onChange={(e) => setText(e.target.value)} placeholder="Write a reply" style={{ width: "100%", marginTop: 10, fontFamily: "var(--font)" }} />
      <div className="row" style={{ marginTop: 6 }}>
        <span style={{ flex: 1 }} />
        {!data.closed && <button disabled={busy} onClick={() => reply(true)}>It's fixed — close it</button>}
        <button className="primary" disabled={busy || !text} onClick={() => reply()}>Send reply</button>
      </div>
    </Modal>
  );
}
