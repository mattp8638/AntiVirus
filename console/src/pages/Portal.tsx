import { displayValue } from "../components/DisplayValue";
// Client portal: what a customer's staff see when they sign in.
import { useState } from "react";
import { api, fmtTime, money } from "../api";
import { useApp } from "../app-context";
import { Modal, Pill, Table, Tabs, useAction, useData, useListData } from "../components/ui";
import { FileBrowser, type BrowseImage } from "./BackupFiles";
import { Markdown } from "../components/Markdown";

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
  // Self-service restore: only for devices the IT provider granted to this user.
  const { data: backups } = useListData<BrowseImage>("/api/portal/backups");
  const [browsing, setBrowsing] = useState<BrowseImage | null>(null);
  const { data: policies, reload: reloadPolicies } = useListData<any>("/api/portal/policies");
  const [reading, setReading] = useState<string | null>(null);
  // ISMS documents the customer's ISMS manager has asked this person to acknowledge.
  const { data: ismsAcks, reload: reloadAcks } = useData<any>("/api/portal/isms/acknowledgements");
  const ismsPending: any[] = Array.isArray(ismsAcks?.pending) ? ismsAcks.pending : [];
  const [ismsReading, setIsmsReading] = useState<string | null>(null);
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
      <Tabs tabs={["My requests", "Knowledge base", "Invoices", "Devices", ...(policies?.length ? [`Policies${policies.some((p: any) => p.status !== "current") ? " (to read)" : ""}`] : []), ...(ismsPending.length ? [`Documents to read (${ismsPending.length})`] : []), ...(backups?.length ? ["My backups"] : [])]} active={tab} onChange={setTab} />
      <div className="card">
        {tab.startsWith("Policies") && <Table rows={policies} onRow={(p: any) => setReading(p.policyId)} empty="No policies to read." columns={[
          { key: "title", label: "Policy", render: (p: any) => <b>{displayValue(p.title)}</b> },
          { key: "version", label: "Version", render: (p: any) => `v${p.version}` },
          { key: "status", label: "", render: (p: any) => <Pill value={p.status === "current" ? `accepted ${fmtTime(p.acknowledgedAt)}` : "please read"} tone={p.status === "current" ? "good" : "warn"} /> }]} />}
        {tab.startsWith("Documents to read") && <Table rows={ismsPending} onRow={(p: any) => setIsmsReading(p.id)} empty="Nothing to read." columns={[
          { key: "documentTitle", label: "Document", render: (p: any) => <b>{p.documentNumber} {displayValue(p.documentTitle)}</b> },
          { key: "version", label: "Version", render: (p: any) => `v${p.version}` },
          { key: "dueOn", label: "Please read by", render: (p: any) => `${p.dueOn.slice(8, 10)}/${p.dueOn.slice(5, 7)}/${p.dueOn.slice(0, 4)}` }]} />}
        {tab === "My backups" && <>
          <p className="small muted" style={{ marginTop: 0 }}>Backups of your devices. Open one to find files and download them as they were then.</p>
          <Table rows={backups} onRow={(b) => setBrowsing(b)} empty="No backups yet." columns={[
            { key: "hostname", label: "Device", render: (b) => <b>{displayValue(b.vmName || b.hostname)}</b> },
            { key: "created", label: "Backed up", render: (b) => new Date(b.created * 1000).toLocaleString() },
            { key: "source", label: "", render: (b) => <button className="small" onClick={(e) => { e.stopPropagation(); setBrowsing(b); }}>Find files</button> }]} />
        </>}
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
      {browsing && <FileBrowser image={browsing} portal onClose={() => setBrowsing(null)} />}
      {reading && <ReadPolicy id={reading} onClose={() => { setReading(null); reloadPolicies(); }} />}
      {ismsReading && <ReadIsmsDocument id={ismsReading} onClose={() => { setIsmsReading(null); reloadAcks(); }} />}
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

function ReadPolicy({ id, onClose }: { id: string; onClose: () => void }) {
  const { data } = useData<any>(`/api/portal/policies/${id}`);
  const { run, busy } = useAction();
  const [ok, setOk] = useState(false);
  if (!data) return null;
  return (
    <Modal title={`${data.title} (version ${data.version})`} onClose={onClose}
      footer={data.status === "current" ? <button onClick={onClose}>Close</button> : <>
        <label className="row small" style={{ gap: 6 }}><input type="checkbox" checked={ok} onChange={(e) => setOk(e.target.checked)} /> I have read this policy and accept it</label>
        <button className="primary" disabled={!ok || busy} onClick={() => run(() => api(`/api/portal/policies/${id}/acknowledge`, { body: { version: data.version, sha256: data.sha256, confirm: true } }), "Thank you: your acceptance is recorded").then((r) => r && onClose())}>Accept</button>
      </>}>
      <Markdown text={data.body} />
    </Modal>
  );
}

function ReadIsmsDocument({ id, onClose }: { id: string; onClose: () => void }) {
  const { data } = useData<any>(`/api/portal/isms/acknowledgements/${id}`);
  const { run, busy } = useAction();
  const [ok, setOk] = useState(false);
  if (!data) return null;
  return (
    <Modal title={`${data.documentNumber} ${data.documentTitle} (version ${data.version})`} wide onClose={onClose}
      footer={data.acknowledgedAt ? <button onClick={onClose}>Close</button> : <>
        <label className="row small" style={{ gap: 6 }}><input type="checkbox" checked={ok} onChange={(e) => setOk(e.target.checked)} /> I have read and understood this document</label>
        <button className="primary" disabled={!ok || busy} onClick={() => run(() => api(`/api/portal/isms/acknowledgements/${id}/acknowledge`, { body: { sha256: data.sha256, confirm: true } }), "Thank you: your acknowledgement is recorded").then((r) => r && onClose())}>Acknowledge</button>
      </>}>
      {(Array.isArray(data.blocks) ? data.blocks : []).map((b: any) => <section key={b.ref} aria-label={b.ref}><Markdown text={b.markdown} /></section>)}
    </Modal>
  );
}
