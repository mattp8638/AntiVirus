import { displayValue } from "../components/DisplayValue";
import { useState } from "react";
import { api, ago } from "../api";
import { confirmDialog } from "../components/dialogs";
import { ErrorNote, Pill, Table, Tabs, useAction, useData } from "../components/ui";

// Exchange Online for one Microsoft 365 connection: mailboxes (shared, permissions, forwarding, aliases, address
// book), suspicious inbox rules, distribution lists, quarantine and message trace. Every change is previewed first
// and asks you to confirm who you are.
export default function M365Exchange({ connection }: { connection: any }) {
  const base = `m365/connections/${connection.id}/exchange`;
  const [tab, setTab] = useState("Mailboxes");
  return (
    <>
      <Tabs tabs={["Mailboxes", "Distribution lists", "Quarantine", "Message trace"]} active={tab} onChange={setTab} />
      {tab === "Mailboxes" && <Mailboxes base={base} />}
      {tab === "Distribution lists" && <Lists base={base} />}
      {tab === "Quarantine" && <Quarantine base={base} />}
      {tab === "Message trace" && <Trace base={base} />}
    </>
  );
}

function useChange(base: string, onDone: () => void) {
  const { run, busy } = useAction();
  const change = async (operation: string, parameters: any) => {
    const preview = await run(() => api<any>(base + "/actions", { body: { operation, parameters } }));
    if (!preview || !(await confirmDialog(`${preview.description}?`))) return;
    if (await run(() => api(base + "/actions", { body: { operation, parameters, confirmed: true } }), "Done in Exchange")) onDone();
  };
  return { change, busy };
}

function Mailboxes({ base }: { base: string }) {
  const { data, error, reload } = useData<any[]>(base + "/mailboxes", {}, [], true);
  const [filter, setFilter] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const rows = (data || []).filter((m) => !filter || `${m.displayName} ${m.address}`.toLowerCase().includes(filter.toLowerCase()));
  return (
    <div className="card">
      <ErrorNote error={error} />
      <input placeholder="Find a mailbox" value={filter} onChange={(e) => setFilter(e.target.value)} style={{ marginBottom: 8 }} />
      <Table rows={rows.map((m) => ({ ...m, id: m.address }))} onRow={(m) => setOpen(m.address)} empty={data ? "No mailboxes." : "Loading…"}
             columns={[{ key: "displayName", label: "Mailbox", render: (m) => <><b>{displayValue(m.displayName)}</b><div className="small muted">{displayValue(m.address)}</div></> },
                       { key: "type", label: "Type", render: (m) => <Pill value={m.type} tone={m.type === "shared" ? "blue" : undefined} /> },
                       { key: "forwardingTo", label: "Forwarding", render: (m) => m.forwardingTo ? <span title={m.forwardingKeepsCopy ? "keeps a copy" : "no copy kept"}>→ {displayValue(m.forwardingTo)}</span> : <span className="muted">—</span> },
                       { key: "aliases", label: "Aliases", render: (m) => <span className="small">{(m.aliases || []).join(", ") || "—"}</span> },
                       { key: "hiddenFromAddressBook", label: "Address book", render: (m) => m.hiddenFromAddressBook ? <Pill value="hidden" /> : <span className="muted">shown</span> }]} />
      {open && <MailboxDetail base={base} address={open} onChanged={reload} onClose={() => setOpen(null)} />}
    </div>
  );
}

function MailboxDetail({ base, address, onChanged, onClose }: { base: string; address: string; onChanged: () => void; onClose: () => void }) {
  const { data, error, reload } = useData<any>(`${base}/mailboxes/${encodeURIComponent(address)}`);
  const refresh = () => { reload(); onChanged(); };
  const { change, busy } = useChange(base, refresh);
  const [who, setWho] = useState("");
  const [forward, setForward] = useState("");
  const [alias, setAlias] = useState("");
  const m = data?.mailbox;
  return (
    <div className="card" style={{ marginTop: 14, borderColor: "var(--line-2)" }}>
      <div className="row" style={{ justifyContent: "space-between" }}><h3 style={{ margin: 0 }}>{displayValue(m?.displayName || address)}</h3><button className="small" onClick={onClose}>Close</button></div>
      <ErrorNote error={error} />
      {m && <>
        <div className="small muted" style={{ marginBottom: 8 }}>{displayValue(m.address)} · {displayValue(m.type)} mailbox</div>
        <div className="row" style={{ gap: 6, flexWrap: "wrap", marginBottom: 10 }}>
          {m.type === "user" && <button disabled={busy} onClick={() => change("mailbox.convert", { mailbox: address, to: "shared" })}>Convert to shared</button>}
          {m.type === "shared" && <button disabled={busy} onClick={() => change("mailbox.convert", { mailbox: address, to: "user" })}>Convert to user mailbox</button>}
          <button disabled={busy} onClick={() => change("mailbox.hide", { mailbox: address, hide: !m.hiddenFromAddressBook })}>{m.hiddenFromAddressBook ? "Show in address book" : "Hide from address book"}</button>
          {m.forwardingTo && <button disabled={busy} onClick={() => change("mailbox.forwarding", { mailbox: address, to: "" })}>Stop forwarding</button>}
        </div>
        <div className="grid k2" style={{ gap: 14 }}>
          <div>
            <b className="small">Full access</b>
            {(data.fullAccess || []).map((u: string) => <div key={u} className="small row" style={{ justifyContent: "space-between" }}>{u}
              <button className="small" disabled={busy} onClick={() => change("mailbox.full_access", { mailbox: address, user: u, add: false })}>Remove</button></div>)}
            {!data.fullAccess?.length && <div className="small muted">Nobody else</div>}
            <b className="small" style={{ display: "block", marginTop: 8 }}>Send As</b>
            {(data.sendAs || []).map((u: string) => <div key={u} className="small row" style={{ justifyContent: "space-between" }}>{u}
              <button className="small" disabled={busy} onClick={() => change("mailbox.send_as", { mailbox: address, user: u, add: false })}>Remove</button></div>)}
            {!data.sendAs?.length && <div className="small muted">Nobody else</div>}
            <div className="row" style={{ gap: 6, marginTop: 8 }}>
              <input placeholder="person@domain" value={who} onChange={(e) => setWho(e.target.value)} />
              <button disabled={busy || !who} onClick={() => change("mailbox.full_access", { mailbox: address, user: who, add: true })}>Give full access</button>
              <button disabled={busy || !who} onClick={() => change("mailbox.send_as", { mailbox: address, user: who, add: true })}>Give Send As</button>
            </div>
          </div>
          <div>
            <b className="small">Forwarding</b>
            <div className="small muted">{m.forwardingTo ? `Forwards to ${m.forwardingTo}${m.forwardingKeepsCopy ? " and keeps a copy" : ""}` : "Not forwarded"}</div>
            <div className="row" style={{ gap: 6, marginTop: 4 }}>
              <input placeholder="forward to person@domain" value={forward} onChange={(e) => setForward(e.target.value)} />
              <button disabled={busy || !forward} onClick={() => change("mailbox.forwarding", { mailbox: address, to: forward, keepCopy: true })}>Forward (keep a copy)</button>
            </div>
            <b className="small" style={{ display: "block", marginTop: 8 }}>Aliases</b>
            {(m.aliases || []).map((a: string) => <div key={a} className="small row" style={{ justifyContent: "space-between" }}>{a}
              <button className="small" disabled={busy} onClick={() => change("mailbox.alias", { mailbox: address, alias: a, add: false })}>Remove</button></div>)}
            <div className="row" style={{ gap: 6, marginTop: 4 }}>
              <input placeholder="alias@domain" value={alias} onChange={(e) => setAlias(e.target.value)} />
              <button disabled={busy || !alias} onClick={() => change("mailbox.alias", { mailbox: address, alias, add: true })}>Add alias</button>
            </div>
          </div>
        </div>
        <b className="small" style={{ display: "block", marginTop: 12 }}>Inbox rules</b>
        {!data.rules?.length && <div className="small muted">No inbox rules.</div>}
        {(data.rules || []).map((r: any) => (
          <div key={r.id} className="small" style={{ padding: "4px 0", borderBottom: "1px solid var(--line)" }}>
            {r.suspicious.length > 0 && <><Pill value="suspicious" tone="bad" /> </>}<b>{displayValue(r.name)}</b> {r.enabled ? "" : <span className="muted">(off)</span>}
            {r.suspicious.length > 0 && <span style={{ color: "#fca5a5" }}> · {r.suspicious.join("; ")}</span>}
            {r.enabled && <button className="small" style={{ marginLeft: 8 }} disabled={busy} onClick={() => change("inbox_rule.disable", { mailbox: address, ruleId: r.id })}>Turn off</button>}
          </div>
        ))}
      </>}
    </div>
  );
}

function Lists({ base }: { base: string }) {
  const { data, error } = useData<any[]>(base + "/groups", {}, [], true);
  const [open, setOpen] = useState<string | null>(null);
  const members = useData<any[]>(open ? `${base}/groups/${encodeURIComponent(open)}/members` : null, {}, [open], true);
  const { change, busy } = useChange(base, () => members.reload());
  const [who, setWho] = useState("");
  return (
    <div className="card">
      <ErrorNote error={error} />
      <Table rows={(data || []).map((g) => ({ ...g, id: g.address }))} onRow={(g) => setOpen(g.address)} empty={data ? "No distribution lists." : "Loading…"}
             columns={[{ key: "displayName", label: "List", render: (g) => <><b>{displayValue(g.displayName)}</b><div className="small muted">{displayValue(g.address)}</div></> },
                       { key: "external", label: "Outside senders", render: (g) => g.external ? <Pill value="accepted" tone="warn" /> : <span className="muted">blocked</span> }]} />
      {open && <div style={{ marginTop: 12 }}>
        <b className="small">Members of {open}</b>
        {(members.data || []).map((m: any) => <div key={m.address} className="small row" style={{ justifyContent: "space-between" }}>{displayValue(m.displayName)} <span className="muted">{displayValue(m.address)}</span>
          <button className="small" disabled={busy} onClick={() => change("dl.member", { group: open, mailbox: m.address, add: false })}>Remove</button></div>)}
        <div className="row" style={{ gap: 6, marginTop: 6 }}>
          <input placeholder="person@domain" value={who} onChange={(e) => setWho(e.target.value)} />
          <button disabled={busy || !who} onClick={() => change("dl.member", { group: open, mailbox: who, add: true })}>Add member</button>
        </div>
      </div>}
    </div>
  );
}

function Quarantine({ base }: { base: string }) {
  const { data, error, reload } = useData<any[]>(base + "/quarantine", {}, [], true);
  const { change, busy } = useChange(base, reload);
  return (
    <div className="card">
      <ErrorNote error={error} />
      <Table rows={data} empty="Nothing in quarantine."
             columns={[{ key: "subject", label: "Message", render: (q) => <><b>{displayValue(q.subject)}</b><div className="small muted">from {displayValue(q.sender)} to {(q.recipients || []).join(", ")}</div></> },
                       { key: "type", label: "Why", render: (q) => <Pill value={q.type} tone={String(q.type).includes("Phish") || String(q.type).includes("Malware") ? "bad" : "warn"} /> },
                       { key: "received", label: "Received", render: (q) => ago(q.received) },
                       { key: "released", label: "", render: (q) => q.released ? <Pill value="released" tone="good" />
                         : <button className="small" disabled={busy} onClick={() => change("quarantine.release", { messageId: q.id })}>Release</button> }]} />
    </div>
  );
}

function Trace({ base }: { base: string }) {
  const [sender, setSender] = useState("");
  const [recipient, setRecipient] = useState("");
  const [days, setDays] = useState(2);
  const [rows, setRows] = useState<any[] | null>(null);
  const { run, busy } = useAction();
  const search = async () => {
    const out = await run(() => api<any[]>(base + "/trace", { query: { sender, recipient, days } }));
    if (out) setRows(out);
  };
  return (
    <div className="card">
      <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
        <input placeholder="Sender address" value={sender} onChange={(e) => setSender(e.target.value)} />
        <input placeholder="Recipient address" value={recipient} onChange={(e) => setRecipient(e.target.value)} />
        <select value={days} onChange={(e) => setDays(Number(e.target.value))}>{[1, 2, 5, 10].map((d) => <option key={d} value={d}>Last {d} day{d > 1 ? "s" : ""}</option>)}</select>
        <button className="primary" disabled={busy || (!sender && !recipient)} onClick={search}>Trace</button>
      </div>
      {rows && <div style={{ marginTop: 10 }}><Table rows={rows.map((r, i) => ({ ...r, id: `${r.messageId}-${i}` }))} empty="No messages match."
        columns={[{ key: "received", label: "Received", render: (r) => ago(r.received) },
                  { key: "sender", label: "From" }, { key: "recipient", label: "To" },
                  { key: "subject", label: "Subject" }, { key: "status", label: "Status", render: (r) => <Pill value={r.status} tone={r.status === "Delivered" ? "good" : r.status === "Failed" ? "bad" : "warn"} /> }]} /></div>}
    </div>
  );
}
