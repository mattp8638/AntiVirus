import { useState } from "react";
import { ago, api } from "../api";
import { useApp } from "../app-context";
import { ErrorNote, Modal, PageHead, Pill, Stat, Table, Tabs, useAction, useData, useListData } from "../components/ui";

interface Overview {
  days: number; scanned: number; fenrirFlagged: number; microsoftFlagged: number; both: number; fenrirOnly: number;
  microsoftOnly: number; suspicious: number; microsoftSpam: number; agreementPercent: number | null; labelled: number;
  labelledFenrirRight: number; labelledMicrosoftRight: number; topFlaggedSenders: { domain: string; count: number }[];
}
interface Connection {
  connectionId: string; tenantId: string; name: string; authMode: string; mode: string; retentionDays: number;
  lastRunAt: string | null; lastScanned: number; lastError: string; mailboxes: number; permission: boolean | null; supported: boolean;
}
interface Scan {
  id: string; tenantId: string; mailbox: string; receivedAt: string; folder: string; sender: string; senderName: string; subject: string;
  verdict: string; score: number; microsoftVerdict: string; agreement: string; label: string; topReason: string; attachments: number;
}
interface ScanDetail extends Scan {
  reasons: { code: string; points: number; detail: string }[];
  microsoft: Record<string, string | number | null>; attachmentDetails: { name: string; size?: number; sha256?: string }[];
  linkDomains: string[]; internetMessageId: string; labelledBy: string; labelledAt: string | null;
}

const TONE: Record<string, string> = { clean: "good", suspicious: "warn", phish: "bad", malware: "bad", spam: "warn", bulk: "muted", unknown: "muted" };
const AGREEMENT: Record<string, string> = { both: "Both flagged", fenrir_only: "Only Fenrir", microsoft_only: "Only Microsoft", neither: "Neither" };
const LABELS = ["phish", "malware", "spam", "safe"];

export default function EmailSecurity() {
  const [tab, setTab] = useState("Overview");
  return (
    <>
      <PageHead title="Email security"
                subtitle="Fenrir reads each customer's new Microsoft 365 mail and gives its own verdict next to Microsoft's. Shadow mode: nothing in any mailbox is moved or changed. Label messages to teach it; the comparison shows where each one is right." />
      <Tabs tabs={["Overview", "Messages", "Customers"]} active={tab} onChange={setTab} />
      {tab === "Overview" && <OverviewTab />}
      {tab === "Messages" && <MessagesTab />}
      {tab === "Customers" && <CustomersTab />}
    </>
  );
}

function OverviewTab() {
  const { tenantId } = useApp();
  const [days, setDays] = useState(7);
  const { data, error } = useData<Overview>("email-security/overview", { tenant_id: tenantId, days }, [days]);
  const d = data;
  return (
    <>
      <ErrorNote error={error} />
      <div className="card" style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <span className="small muted">Period</span>
        {[1, 7, 30, 90].map((n) => <button key={n} className={n === days ? "primary" : ""} onClick={() => setDays(n)}>{n === 1 ? "24 hours" : `${n} days`}</button>)}
      </div>
      <div className="grid k4">
        <Stat label="Messages scanned" value={d?.scanned ?? "—"} />
        <Stat label="Flagged by Fenrir" value={d?.fenrirFlagged ?? "—"} hint={d ? `${d.suspicious} more suspicious` : undefined} accent={d?.fenrirFlagged ? "red" : undefined} />
        <Stat label="Flagged by Microsoft" value={d?.microsoftFlagged ?? "—"} hint={d ? `${d.microsoftSpam} spam or bulk` : undefined} />
        <Stat label="Agreement on flagged mail" value={d?.agreementPercent == null ? "—" : `${d.agreementPercent}%`} />
      </div>
      <div className="grid k3">
        <Stat label="Both flagged" value={d?.both ?? "—"} />
        <Stat label="Only Fenrir flagged" value={d?.fenrirOnly ?? "—"} hint="Possible misses by Microsoft, or Fenrir false positives: label them" accent={d?.fenrirOnly ? "amber" : undefined} />
        <Stat label="Only Microsoft flagged" value={d?.microsoftOnly ?? "—"} hint="What Fenrir still misses" accent={d?.microsoftOnly ? "amber" : undefined} />
      </div>
      <div className="grid k2">
        <div className="card">
          <h3>Who is right (your labels)</h3>
          {d && d.labelled > 0 ? (
            <p>Of {d.labelled} labelled messages, Fenrir was right on <b>{d.labelledFenrirRight}</b> ({Math.round(100 * d.labelledFenrirRight / d.labelled)}%)
              and Microsoft on <b>{d.labelledMicrosoftRight}</b> ({Math.round(100 * d.labelledMicrosoftRight / d.labelled)}%).</p>
          ) : <p className="muted">No labels yet. Open a message on the Messages tab and say what it really was; start with the ones only one side flagged.</p>}
        </div>
        <div className="card">
          <h3>Senders Fenrir flagged most</h3>
          <Table rows={d?.topFlaggedSenders.map((s) => ({ ...s, id: s.domain }))} empty="Nothing flagged in this period."
                 columns={[{ key: "domain", label: "Domain" }, { key: "count", label: "Messages", className: "right" }]} />
        </div>
      </div>
    </>
  );
}

function MessagesTab() {
  const { tenantId, tenantName } = useApp();
  const [verdict, setVerdict] = useState("flagged");
  const [agreement, setAgreement] = useState("");
  const [q, setQ] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const { data, error, reload } = useListData<Scan>("email-security/messages", { tenant_id: tenantId, verdict, agreement, q }, [verdict, agreement, q]);
  return (
    <>
      <ErrorNote error={error} />
      <div className="card" style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        <select value={verdict} onChange={(e) => setVerdict(e.target.value)} aria-label="Fenrir's verdict">
          <option value="flagged">Fenrir flagged (phish or malware)</option>
          <option value="suspicious">Suspicious</option>
          <option value="clean">Clean</option>
          <option value="">Every verdict</option>
        </select>
        <select value={agreement} onChange={(e) => setAgreement(e.target.value)} aria-label="Agreement with Microsoft">
          <option value="">Any agreement</option>
          {Object.entries(AGREEMENT).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
        <input placeholder="Search sender, subject or mailbox" value={q} onChange={(e) => setQ(e.target.value)} style={{ flex: 1, minWidth: 200 }} />
      </div>
      <div className="card">
        <Table rows={data ?? undefined} onRow={(s) => setOpen(s.id)} empty="No messages match. Turn scanning on for a customer on the Customers tab."
               columns={[
                 { key: "verdict", label: "Fenrir", render: (s) => <><Pill value={s.verdict} tone={TONE[s.verdict]} /><div className="small muted">score {s.score}</div></> },
                 { key: "microsoftVerdict", label: "Microsoft", render: (s) => <Pill value={s.microsoftVerdict} tone={TONE[s.microsoftVerdict]} /> },
                 { key: "subject", label: "Message", render: (s) => <><b>{s.subject || "(no subject)"}</b><div className="small muted">{s.senderName ? `${s.senderName} <${s.sender}>` : s.sender}</div>
                   {s.topReason && <div className="small">{s.topReason}</div>}</> },
                 { key: "mailbox", label: "Mailbox", render: (s) => <>{s.mailbox}<div className="small muted">{tenantName(s.tenantId)}{s.folder === "junkemail" ? " · Junk" : ""}</div></> },
                 { key: "receivedAt", label: "Received", render: (s) => ago(s.receivedAt) },
                 { key: "label", label: "Label", render: (s) => s.label ? <Pill value={s.label} tone={s.label === "safe" ? "good" : "bad"} /> : <span className="muted small">none</span> },
               ]} />
      </div>
      {open && <MessageDetail id={open} onClose={() => setOpen(null)} onChanged={reload} />}
    </>
  );
}

function MessageDetail({ id, onClose, onChanged }: { id: string; onClose: () => void; onChanged: () => void }) {
  const { data, error, reload } = useData<ScanDetail>(`email-security/messages/${id}`, {}, [id]);
  const { run, busy } = useAction();
  const setLabel = async (label: string) => {
    await run(() => api(`email-security/messages/${id}/label`, { method: "PUT", body: { label } }), label ? `Labelled ${label}.` : "Label removed.");
    reload();
    onChanged();
  };
  const m = data?.microsoft ?? {};
  return (
    <Modal title={data?.subject || "Message"} onClose={onClose} wide
           footer={<span style={{ display: "inline-flex", gap: 6, flexWrap: "wrap" }}>
             <span className="small muted" style={{ alignSelf: "center" }}>What was it really?</span>
             {LABELS.map((l) => <button key={l} disabled={busy} className={data?.label === l ? "primary" : ""} onClick={() => setLabel(l)}>{l}</button>)}
             {data?.label && <button disabled={busy} onClick={() => setLabel("")}>Clear</button>}
           </span>}>
      <ErrorNote error={error} />
      {data && (
        <>
          <p className="small muted">From {data.senderName ? `${data.senderName} <${data.sender}>` : data.sender} to {data.mailbox}, {ago(data.receivedAt)}
            {data.folder === "junkemail" ? " (in Junk Email)" : ""}. {AGREEMENT[data.agreement]}.</p>
          <div className="grid k2">
            <div>
              <h3>Fenrir: <Pill value={data.verdict} tone={TONE[data.verdict]} /> <span className="small muted">score {data.score}</span></h3>
              {data.reasons.length ? (
                <ul>{data.reasons.map((r, i) => <li key={i}><b>+{r.points}</b> {r.detail}</li>)}</ul>
              ) : <p className="muted">Nothing suspicious found.</p>}
            </div>
            <div>
              <h3>Microsoft: <Pill value={data.microsoftVerdict} tone={TONE[data.microsoftVerdict]} /></h3>
              <table className="small"><tbody>
                <tr><td>Spam confidence (SCL)</td><td>{m.scl ?? "—"}</td></tr>
                <tr><td>Bulk (BCL)</td><td>{m.bcl ?? "—"}</td></tr>
                <tr><td>Category</td><td>{m.cat || "—"}</td></tr>
                <tr><td>SPF / DKIM / DMARC</td><td>{[m.spf, m.dkim, m.dmarc].map((v) => v || "—").join(" / ")}</td></tr>
                <tr><td>Composite authentication</td><td>{m.compauth || "—"}</td></tr>
                <tr><td>Sending country</td><td>{m.country || "—"}</td></tr>
              </tbody></table>
            </div>
          </div>
          {data.attachmentDetails.length > 0 && <>
            <h3>Attachments</h3>
            <ul>{data.attachmentDetails.map((a, i) => <li key={i}>{a.name}{a.sha256 && <span className="small muted mono"> {a.sha256}</span>}</li>)}</ul>
          </>}
          {data.linkDomains.length > 0 && <p className="small"><b>Links go to:</b> {data.linkDomains.join(", ")}</p>}
          {data.label && <p className="small muted">Labelled {data.label} by {data.labelledBy}{data.labelledAt ? `, ${ago(data.labelledAt)}` : ""}.</p>}
          <p className="small muted mono">{data.internetMessageId}</p>
        </>
      )}
    </Modal>
  );
}

function CustomersTab() {
  const { tenantId, can } = useApp();
  const { data, error, reload } = useListData<Connection>("email-security/connections", { tenant_id: tenantId });
  const { run, busy } = useAction();
  const set = async (c: Connection, mode: string) => {
    await run(() => api(`email-security/connections/${c.connectionId}`, { method: "PUT", body: { mode } }),
              mode === "shadow" ? `Scanning ${c.name}'s mail every five minutes.` : `Stopped scanning ${c.name}.`);
    reload();
  };
  const scan = async (c: Connection) => {
    const result = await run(() => api<{ stored: number; error: string }>(`email-security/connections/${c.connectionId}/scan`, { method: "POST" }));
    if (result) await run(async () => { if (result.error) throw new Error(result.error); }, `Scanned ${result.stored} new messages.`);
    reload();
  };
  return (
    <>
      <ErrorNote error={error} />
      <div className="card small muted">
        Scanning needs the Microsoft Graph permission <b>Mail.Read</b> on the customer's app connection (admin sign-in or the Fenrir app).
        Existing connections: open the customer in Microsoft 365 and choose <b>Update permissions</b>. Partner (GDAP) connections cannot read mail.
      </div>
      <div className="card">
        <Table rows={data?.map((c) => ({ ...c, id: c.connectionId }))} empty="No Microsoft 365 connections yet. Connect a customer under Microsoft 365 first."
               columns={[
                 { key: "name", label: "Customer", render: (c) => <><b>{c.name}</b><div className="small muted">{c.mailboxes} licensed mailboxes · {c.authMode}</div></> },
                 { key: "mode", label: "Email security", render: (c) => <Pill value={c.mode === "shadow" ? "shadow mode" : "off"} tone={c.mode === "shadow" ? "good" : "muted"} /> },
                 { key: "permission", label: "Mail.Read", render: (c) => !c.supported ? <span className="small">Not possible with GDAP</span>
                   : c.permission === true ? <Pill value="granted" tone="good" /> : c.permission === false ? <Pill value="missing" tone="bad" /> : <span className="small muted">not checked</span> },
                 { key: "lastRunAt", label: "Last scan", render: (c) => <>{c.lastRunAt ? `${ago(c.lastRunAt)} · ${c.lastScanned} new` : "never"}
                   {c.lastError && <div className="small" style={{ color: "#fca5a5" }}>{c.lastError}</div>}</> },
                 { key: "actions", label: "", className: "right", render: (c) => can("configure") && c.supported ? (
                   <span style={{ display: "inline-flex", gap: 6 }}>
                     {c.mode === "shadow" && <button disabled={busy} onClick={() => scan(c)}>Scan now</button>}
                     <button disabled={busy} className={c.mode === "shadow" ? "" : "primary"} onClick={() => set(c, c.mode === "shadow" ? "off" : "shadow")}>
                       {c.mode === "shadow" ? "Turn off" : "Turn on (shadow)"}</button>
                   </span>) : null },
               ]} />
      </div>
    </>
  );
}
