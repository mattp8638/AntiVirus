import { useState } from "react";
import { ago, api } from "../api";
import { useApp } from "../app-context";
import { ErrorNote, Modal, PageHead, Pill, Stat, Table, Tabs, useAction, useData, useListData } from "../components/ui";

interface Overview {
  days: number; scanned: number; fenrirFlagged: number; microsoftFlagged: number; both: number; fenrirOnly: number;
  microsoftOnly: number; suspicious: number; microsoftSpam: number; agreementPercent: number | null; labelled: number;
  labelledFenrirRight: number; labelledMicrosoftRight: number; topFlaggedSenders: { domain: string; count: number }[];
  quarantined: number; junked: number; tagged: number; released: number; releaseRequests: number; actionFailures: number;
}
interface Notify { digest: boolean; alertEmail: string; openTicket: boolean }
interface Connection {
  connectionId: string; tenantId: string; name: string; authMode: string; mode: string; retentionDays: number;
  lastRunAt: string | null; lastScanned: number; lastError: string; mailboxes: number; permission: boolean | null;
  protectPermission: boolean | null; supported: boolean; actions: Record<string, string>; notify: Notify;
  protectSince: string | null; pausedReason: string;
}
interface Scan {
  id: string; tenantId: string; mailbox: string; receivedAt: string; folder: string; sender: string; senderName: string; subject: string;
  verdict: string; score: number; microsoftVerdict: string; agreement: string; label: string; topReason: string; attachments: number;
  source: string; action: string; actionStatus: string; modelScore: number | null;
}
interface ScanDetail extends Scan {
  reasons: { code: string; points: number; detail: string }[];
  microsoft: Record<string, string | number | null>; attachmentDetails: { name: string; size?: number; sha256?: string }[];
  linkDomains: string[]; internetMessageId: string; labelledBy: string; labelledAt: string | null; actionError: string;
  actedAt: string | null; releasedBy: string; releasedAt: string | null; releaseRequestedAt: string | null; recipients: string[];
}
interface ListEntry { id: string; tenantId: string; kind: string; match: string; value: string; note: string; createdBy: string; createdAt: string }
interface GatewayDomain {
  id: string; tenantId: string; domain: string; destination: string; destinationPort: number; requireTls: boolean;
  rejectUnknownRecipients: boolean; tagSubject: boolean; actions: Record<string, string>; notify: Notify; retentionDays: number;
  enabled: boolean; m365Connector: { status?: string; error?: string; at?: string; lockdown?: boolean }; lastMessageAt: string | null; mx: string | null;
}
interface Gateway { domains: GatewayDomain[]; status: { lastRunAt: string | null; ok: boolean | null; error: string; hostname: string | null; publicIps: string[] } }
interface ModelView {
  id: string; version: number; createdAt: string; samples: number; positives: number; labelled: number; threshold: number; active: boolean;
  reason: string; metrics: { precision?: number | null; recall?: number | null; tested?: number; tp?: number; fp?: number; fn?: number };
  strongestSignals: { input: string; weight: number }[];
}
interface ModelState {
  active: ModelView | null; latest: ModelView | null; history: ModelView[]; labels: Record<string, number>;
  requirements: { samples: number; positives: number; precision: number; recall: number; threshold: number };
}

const TONE: Record<string, string> = { clean: "good", suspicious: "warn", phish: "bad", malware: "bad", spam: "warn", bulk: "muted", unknown: "muted" };
const AGREEMENT: Record<string, string> = { both: "Both flagged", fenrir_only: "Only Fenrir", microsoft_only: "Only Microsoft", neither: "Neither" };
const LABELS = ["phish", "malware", "spam", "safe"];
const MAILBOX_ACTIONS = ["quarantine", "junk", "tag", "none"];
const GATEWAY_ACTIONS = ["quarantine", "tag", "deliver"];
const ACTION_TEXT: Record<string, string> = { quarantine: "Quarantined", junk: "Moved to Junk", tag: "Tagged", deliver: "Delivered" };

export default function EmailSecurity() {
  const [tab, setTab] = useState("Overview");
  return (
    <>
      <PageHead title="Email security"
                subtitle="Fenrir checks each customer's mail for phishing and malware: in their Microsoft 365 mailboxes (shadow mode compares, protect mode acts) and, for domains routed through it, at Fenrir's own mail gateway before Microsoft 365. Every verdict says why." />
      <Tabs tabs={["Overview", "Messages", "Customers", "Gateway", "Lists", "Model"]} active={tab} onChange={setTab} />
      {tab === "Overview" && <OverviewTab />}
      {tab === "Messages" && <MessagesTab />}
      {tab === "Customers" && <CustomersTab />}
      {tab === "Gateway" && <GatewayTab />}
      {tab === "Lists" && <ListsTab />}
      {tab === "Model" && <ModelTab />}
    </>
  );
}

function OverviewTab() {
  const { tenantId } = useApp();
  const [days, setDays] = useState(7);
  const { data: d, error } = useData<Overview>("email-security/overview", { tenant_id: tenantId, days }, [days]);
  return (
    <>
      <ErrorNote error={error} />
      <div className="card" style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <span className="small muted">Period</span>
        {[1, 7, 30, 90].map((n) => <button key={n} className={n === days ? "primary" : ""} onClick={() => setDays(n)}>{n === 1 ? "24 hours" : `${n} days`}</button>)}
      </div>
      <div className="grid k4">
        <Stat label="Messages checked" value={d?.scanned ?? "—"} />
        <Stat label="Flagged by Fenrir" value={d?.fenrirFlagged ?? "—"} hint={d ? `${d.suspicious} more suspicious` : undefined} accent={d?.fenrirFlagged ? "red" : undefined} />
        <Stat label="Quarantined" value={d?.quarantined ?? "—"} hint={d ? `${d.junked} to Junk · ${d.tagged} tagged` : undefined} />
        <Stat label="Release requests waiting" value={d?.releaseRequests ?? "—"} hint={d ? `${d.released} released` : undefined} accent={d?.releaseRequests ? "amber" : undefined} />
      </div>
      <div className="grid k4">
        <Stat label="Flagged by Microsoft" value={d?.microsoftFlagged ?? "—"} hint={d ? `${d.microsoftSpam} spam or bulk` : undefined} />
        <Stat label="Both flagged" value={d?.both ?? "—"} hint={d?.agreementPercent == null ? undefined : `${d.agreementPercent}% agreement on flagged mail`} />
        <Stat label="Only Fenrir flagged" value={d?.fenrirOnly ?? "—"} hint="Microsoft's misses, or Fenrir's false positives: label them" accent={d?.fenrirOnly ? "amber" : undefined} />
        <Stat label="Only Microsoft flagged" value={d?.microsoftOnly ?? "—"} hint="What Fenrir still misses" accent={d?.microsoftOnly ? "amber" : undefined} />
      </div>
      {d && d.actionFailures > 0 && <div className="card" style={{ borderColor: "rgba(239,68,68,.5)" }}>
        {d.actionFailures} action{d.actionFailures === 1 ? "" : "s"} could not be carried out (usually a missing Mail.ReadWrite permission). Filter the Messages tab by "Action failed".</div>}
      <div className="grid k2">
        <div className="card">
          <h3>Who is right (your labels)</h3>
          {d && d.labelled > 0 ? (
            <p>Of {d.labelled} labelled messages, Fenrir was right on <b>{d.labelledFenrirRight}</b> ({Math.round(100 * d.labelledFenrirRight / d.labelled)}%)
              and Microsoft on <b>{d.labelledMicrosoftRight}</b> ({Math.round(100 * d.labelledMicrosoftRight / d.labelled)}%).</p>
          ) : <p className="muted">No labels yet. Open a message and say what it really was, starting with the ones only one side flagged. Labels also train the model.</p>}
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
        <Table rows={data ?? undefined} onRow={(s) => setOpen(s.id)} empty="No messages match. Turn checking on for a customer on the Customers or Gateway tab."
               columns={[
                 { key: "verdict", label: "Fenrir", render: (s) => <><Pill value={s.verdict} tone={TONE[s.verdict]} /><div className="small muted">score {s.score}</div></> },
                 { key: "microsoftVerdict", label: "Microsoft", render: (s) => s.source === "gateway" ? <span className="small muted">gateway</span> : <Pill value={s.microsoftVerdict} tone={TONE[s.microsoftVerdict]} /> },
                 { key: "subject", label: "Message", render: (s) => <><b>{s.subject || "(no subject)"}</b><div className="small muted">{s.senderName ? `${s.senderName} <${s.sender}>` : s.sender}</div>
                   {s.topReason && <div className="small">{s.topReason}</div>}</> },
                 { key: "mailbox", label: "Mailbox", render: (s) => <>{s.mailbox}<div className="small muted">{tenantName(s.tenantId)}{s.folder === "junkemail" ? " · Junk" : ""}</div></> },
                 { key: "action", label: "Done", render: (s) => <ActionPill action={s.action} status={s.actionStatus} /> },
                 { key: "receivedAt", label: "Received", render: (s) => ago(s.receivedAt) },
                 { key: "label", label: "Label", render: (s) => s.label ? <Pill value={s.label} tone={s.label === "safe" ? "good" : "bad"} /> : <span className="muted small">none</span> },
               ]} />
      </div>
      {open && <MessageDetail id={open} onClose={() => setOpen(null)} onChanged={reload} />}
    </>
  );
}

function ActionPill({ action, status }: { action: string; status: string }) {
  if (!action || status === "skipped") return <span className="muted small">nothing</span>;
  if (status === "failed") return <Pill value="action failed" tone="bad" />;
  if (status === "released") return <Pill value="released" tone="good" />;
  if (status === "release_requested") return <Pill value="release requested" tone="warn" />;
  return <Pill value={ACTION_TEXT[action] ?? action} tone={action === "quarantine" ? "bad" : action === "deliver" ? "muted" : "warn"} />;
}

function MessageDetail({ id, onClose, onChanged }: { id: string; onClose: () => void; onChanged: () => void }) {
  const { can } = useApp();
  const { data, error, reload } = useData<ScanDetail>(`email-security/messages/${id}`, {}, [id]);
  const { run, busy } = useAction();
  const [allowSender, setAllowSender] = useState(false);
  const after = () => { reload(); onChanged(); };
  const setLabel = async (label: string) => {
    await run(() => api(`email-security/messages/${id}/label`, { method: "PUT", body: { label } }), label ? `Labelled ${label}.` : "Label removed.");
    after();
  };
  const release = async () => {
    await run(() => api(`email-security/messages/${id}/release`, { method: "POST", body: { allowSender } }), "Released to the Inbox.");
    after();
  };
  const block = async (match: "sender" | "domain") => {
    if (!data) return;
    const value = match === "sender" ? data.sender : data.sender.split("@").pop() ?? "";
    await run(() => api("email-security/lists", { method: "POST", body: { tenantId: data.tenantId, kind: "block", match, value, note: `From message: ${data.subject}`.slice(0, 300) } }),
              `Blocked ${value} for this customer.`);
  };
  const m = data?.microsoft ?? {};
  const releasable = data && ["quarantine", "junk"].includes(data.action) && ["done", "release_requested"].includes(data.actionStatus);
  return (
    <Modal title={data?.subject || "Message"} onClose={onClose} wide
           footer={<span style={{ display: "inline-flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
             <span className="small muted">What was it really?</span>
             {LABELS.map((l) => <button key={l} disabled={busy} className={data?.label === l ? "primary" : ""} onClick={() => setLabel(l)}>{l}</button>)}
             {data?.label && <button disabled={busy} onClick={() => setLabel("")}>Clear</button>}
           </span>}>
      <ErrorNote error={error} />
      {data && (
        <>
          <p className="small muted">From {data.senderName ? `${data.senderName} <${data.sender}>` : data.sender} to {(data.recipients?.length ? data.recipients : [data.mailbox]).join(", ")},
            {" "}{ago(data.receivedAt)}{data.folder === "junkemail" ? " (in Junk Email)" : ""}{data.source === "gateway" ? " (through the gateway)" : ""}.
            {data.source !== "gateway" && ` ${AGREEMENT[data.agreement]}.`}</p>
          {data.action && <div className="card" style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <ActionPill action={data.action} status={data.actionStatus} />
            <span className="small">{data.actionStatus === "released" ? `Released by ${data.releasedBy}${data.releasedAt ? `, ${ago(data.releasedAt)}` : ""}.`
              : data.actionStatus === "release_requested" ? `The user asked for it back${data.releaseRequestedAt ? ` ${ago(data.releaseRequestedAt)}` : ""}.`
              : data.actionError ? data.actionError : data.actedAt ? `${ago(data.actedAt)}.` : ""}</span>
            {releasable && can("respond") && <>
              <label className="small" style={{ display: "inline-flex", gap: 4, alignItems: "center" }}>
                <input type="checkbox" checked={allowSender} onChange={(e) => setAllowSender(e.target.checked)} /> and allow this sender</label>
              <button className="primary" disabled={busy} onClick={release}>Release to Inbox</button>
            </>}
          </div>}
          <div className="grid k2">
            <div>
              <h3>Fenrir: <Pill value={data.verdict} tone={TONE[data.verdict]} /> <span className="small muted">score {data.score}{data.modelScore != null ? ` · model ${Math.round(data.modelScore * 100)}%` : ""}</span></h3>
              {data.reasons.length ? <ul>{data.reasons.map((r, i) => <li key={i}><b>+{r.points}</b> {r.detail}</li>)}</ul> : <p className="muted">Nothing suspicious found.</p>}
            </div>
            <div>
              {data.source === "gateway" ? <h3>Sender checks (gateway)</h3> : <h3>Microsoft: <Pill value={data.microsoftVerdict} tone={TONE[data.microsoftVerdict]} /></h3>}
              <table className="small"><tbody>
                {data.source !== "gateway" && <>
                  <tr><td>Spam confidence (SCL)</td><td>{m.scl ?? "—"}</td></tr>
                  <tr><td>Bulk (BCL)</td><td>{m.bcl ?? "—"}</td></tr>
                  <tr><td>Category</td><td>{m.cat || "—"}</td></tr>
                </>}
                <tr><td>SPF / DKIM / DMARC</td><td>{[m.spf, m.dkim, m.dmarc].map((v) => v || "—").join(" / ")}</td></tr>
                {data.source !== "gateway" ? <><tr><td>Composite authentication</td><td>{m.compauth || "—"}</td></tr>
                  <tr><td>Sending country</td><td>{m.country || "—"}</td></tr></>
                  : <><tr><td>Sender's DMARC policy</td><td>{m.dmarcPolicy || "none"}</td></tr><tr><td>Sending IP</td><td>{m.peer || "—"}</td></tr></>}
              </tbody></table>
            </div>
          </div>
          {data.attachmentDetails.length > 0 && <>
            <h3>Attachments</h3>
            <ul>{data.attachmentDetails.map((a, i) => <li key={i}>{a.name}{a.sha256 && <span className="small muted mono"> {a.sha256}</span>}</li>)}</ul>
          </>}
          {data.linkDomains.length > 0 && <p className="small"><b>Links go to:</b> {data.linkDomains.join(", ")}</p>}
          {can("configure") && data.sender && <p style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            <button disabled={busy} onClick={() => block("sender")}>Block sender</button>
            <button disabled={busy} onClick={() => block("domain")}>Block {data.sender.split("@").pop()}</button>
          </p>}
          {data.label && <p className="small muted">Labelled {data.label} by {data.labelledBy}{data.labelledAt ? `, ${ago(data.labelledAt)}` : ""}.</p>}
          <p className="small muted mono">{data.internetMessageId}</p>
        </>
      )}
    </Modal>
  );
}

function ActionPicker({ value, options, onChange, disabled }: { value: Record<string, string>; options: string[]; onChange: (v: Record<string, string>) => void; disabled?: boolean }) {
  return (
    <span style={{ display: "inline-flex", gap: 8, flexWrap: "wrap" }}>
      {["malware", "phish", "suspicious"].map((verdict) => (
        <label key={verdict} className="small">{verdict}{" "}
          <select value={value[verdict]} disabled={disabled} onChange={(e) => onChange({ ...value, [verdict]: e.target.value })}>
            {options.map((o) => <option key={o} value={o}>{o}</option>)}
          </select>
        </label>
      ))}
    </span>
  );
}

function NotifyEditor({ value, onSave, disabled }: { value: Notify; onSave: (v: Notify) => void; disabled?: boolean }) {
  const [draft, setDraft] = useState<Notify>(value);
  const changed = JSON.stringify(draft) !== JSON.stringify(value);
  return (
    <span style={{ display: "inline-flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
      <label className="small"><input type="checkbox" checked={draft.digest} disabled={disabled} onChange={(e) => setDraft({ ...draft, digest: e.target.checked })} /> Daily digest to users</label>
      <label className="small"><input type="checkbox" checked={draft.openTicket} disabled={disabled} onChange={(e) => setDraft({ ...draft, openTicket: e.target.checked })} /> Open a ticket</label>
      <input className="small" placeholder="Alert email (optional)" value={draft.alertEmail} disabled={disabled} onChange={(e) => setDraft({ ...draft, alertEmail: e.target.value })} style={{ width: 200 }} />
      {changed && <button disabled={disabled} onClick={() => onSave(draft)}>Save</button>}
    </span>
  );
}

function CustomersTab() {
  const { tenantId, can } = useApp();
  const { data, error, reload } = useListData<Connection>("email-security/connections", { tenant_id: tenantId });
  const { run, busy } = useAction();
  const save = async (c: Connection, body: Record<string, unknown>, message: string) => {
    await run(() => api(`email-security/connections/${c.connectionId}`, { method: "PUT", body: { mode: c.mode, ...body } }), message);
    reload();
  };
  const scan = async (c: Connection) => {
    const result = await run(() => api<{ stored: number; error: string }>(`email-security/connections/${c.connectionId}/scan`, { method: "POST" }));
    if (result) await run(async () => { if (result.error) throw new Error(result.error); }, `Checked ${result.stored} new messages.`);
    reload();
  };
  const editable = can("configure");
  return (
    <>
      <ErrorNote error={error} />
      <div className="card small muted">
        <b>Shadow</b> scans and compares; nothing in the mailbox changes (needs <b>Mail.Read</b>). <b>Protect</b> also quarantines, moves to Junk or tags
        new mail as chosen below (needs <b>Mail.ReadWrite</b>); only mail received after protect mode starts is touched, and it pauses itself if one scan
        would move more than 40 messages. Update an existing connection's permissions from its page under Microsoft 365. Partner (GDAP) connections cannot read mail.
      </div>
      {(data ?? []).length === 0 && <div className="card muted">No Microsoft 365 connections yet. Connect a customer under Microsoft 365 first.</div>}
      {(data ?? []).map((c) => (
        <div className="card" key={c.connectionId}>
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <b style={{ flex: 1 }}>{c.name}</b>
            <span className="small muted">{c.mailboxes} licensed mailboxes</span>
            <Pill value={c.mode === "protect" ? (c.pausedReason ? "protect: paused" : "protect") : c.mode === "shadow" ? "shadow" : "off"}
                  tone={c.mode === "protect" ? (c.pausedReason ? "warn" : "good") : c.mode === "shadow" ? "blue" : "muted"} />
            {editable && c.supported && <>
              <select value={c.mode} disabled={busy} aria-label="Mode" onChange={(e) => save(c, { mode: e.target.value },
                e.target.value === "protect" ? "Protect mode on: new mail is acted on from now." : e.target.value === "shadow" ? "Shadow mode: scanning, acting on nothing." : "Email checking off.")}>
                <option value="off">Off</option><option value="shadow">Shadow (compare only)</option><option value="protect">Protect (act)</option>
              </select>
              {c.mode !== "off" && <button disabled={busy} onClick={() => scan(c)}>Scan now</button>}
            </>}
          </div>
          {!c.supported && <p className="small">Partner (GDAP) connections cannot read mail. Connect this customer with an admin sign-in to check their mail.</p>}
          {c.pausedReason && <p className="small" style={{ color: "#fbbf24" }}>{c.pausedReason} {editable && <button disabled={busy} onClick={() => save(c, { mode: "protect" }, "Protect mode resumed.")}>Resume</button>}</p>}
          {c.lastError && <p className="small" style={{ color: "#fca5a5" }}>{c.lastError}</p>}
          <p className="small muted">
            Mail.Read: {c.permission === true ? "granted" : c.permission === false ? "missing" : "not checked"} ·
            Mail.ReadWrite: {c.protectPermission === true ? "granted" : c.protectPermission === false ? "missing" : "not checked"} ·
            Last scan: {c.lastRunAt ? `${ago(c.lastRunAt)}, ${c.lastScanned} new` : "never"}
            {c.protectSince && c.mode === "protect" ? ` · Acting on mail since ${ago(c.protectSince)}` : ""}
          </p>
          {c.supported && c.mode !== "off" && <div style={{ display: "grid", gap: 6 }}>
            <div><span className="small muted">Actions: </span><ActionPicker value={c.actions} options={MAILBOX_ACTIONS} disabled={!editable || busy}
              onChange={(actions) => save(c, { actions }, "Actions saved.")} /></div>
            <div><span className="small muted">Notifications: </span><NotifyEditor value={c.notify} disabled={!editable || busy}
              onSave={(notify) => save(c, { notify }, "Notifications saved.")} /></div>
          </div>}
        </div>
      ))}
    </>
  );
}

function GatewayTab() {
  const { tenantId, me, can } = useApp();
  const tenants = me?.tenants ?? [];
  const { data, error, reload } = useData<Gateway>("email-security/gateway", { tenant_id: tenantId });
  const { run, busy } = useAction();
  const [adding, setAdding] = useState<{ tenantId: string; domain: string } | null>(null);
  const update = async (d: GatewayDomain, body: Record<string, unknown>, message = "Saved.") => {
    await run(() => api(`email-security/gateway/domains/${d.id}`, { method: "PUT", body }), message);
    reload();
  };
  const add = async () => {
    if (!adding) return;
    const ok = await run(() => api("email-security/gateway/domains", { method: "POST", body: adding }), `${adding.domain} added. Mail arrives once its MX record points at the gateway.`);
    if (ok) { setAdding(null); reload(); }
  };
  const remove = async (d: GatewayDomain) => {
    if (!window.confirm(`Stop accepting mail for ${d.domain}? Point its MX record back at Microsoft 365 first, or its mail will be refused.`)) return;
    await run(() => api(`email-security/gateway/domains/${d.id}`, { method: "DELETE" }), `${d.domain} removed.`);
    reload();
  };
  const connect = async (d: GatewayDomain, lockdown: boolean) => {
    await run(() => api(`email-security/gateway/domains/${d.id}/connect-m365`, { method: "POST", body: { lockdown } }),
              lockdown ? "Connector created and locked down: Microsoft 365 now only accepts internet mail from the gateway." : "Microsoft 365 connector created.");
    reload();
  };
  const s = data?.status;
  const running = s?.lastRunAt && Date.now() - new Date(s.lastRunAt).getTime() < 120000;
  return (
    <>
      <ErrorNote error={error} />
      <div className="card">
        <p style={{ margin: 0 }}>
          Gateway: {running ? <Pill value="running" tone="good" /> : <Pill value={s?.lastRunAt ? "not running" : "never started"} tone="bad" />}
          {s?.hostname && <> · MX host <b className="mono">{s.hostname}</b></>}
          {s?.publicIps?.length ? <> · IPs {s.publicIps.join(", ")}</> : null}
          {s?.lastRunAt && <span className="small muted"> · last pass {ago(s.lastRunAt)}</span>}
        </p>
        {s?.error && <p className="small" style={{ color: "#fca5a5" }}>{s.error}</p>}
        {!running && <p className="small muted">Start it with <span className="mono">docker compose -f docker-compose.yml -f docker-compose.mailgateway.yml up -d</span> after setting FENRIR_GATEWAY_HOSTNAME and FENRIR_GATEWAY_PUBLIC_IPS (docs/EMAIL_SECURITY.md).</p>}
      </div>
      {can("configure") && <div className="card" style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        {adding ? <>
          <select value={adding.tenantId} onChange={(e) => setAdding({ ...adding, tenantId: e.target.value })} aria-label="Customer">
            <option value="">Customer…</option>{tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
          </select>
          <input placeholder="contoso.co.uk" value={adding.domain} onChange={(e) => setAdding({ ...adding, domain: e.target.value })} />
          <button className="primary" disabled={busy || !adding.tenantId || !adding.domain} onClick={add}>Add domain</button>
          <button onClick={() => setAdding(null)}>Cancel</button>
          <span className="small muted">The domain must be verified in that customer's Microsoft 365.</span>
        </> : <button className="primary" onClick={() => setAdding({ tenantId: tenantId ?? "", domain: "" })}>Add a domain</button>}
      </div>}
      {(data?.domains ?? []).length === 0 && <div className="card muted">No domains are routed through the gateway yet.</div>}
      {(data?.domains ?? []).map((d) => (
        <div className="card" key={d.id}>
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <b className="mono" style={{ flex: 1 }}>{d.domain}</b>
            <Pill value={d.enabled ? "accepting" : "paused"} tone={d.enabled ? "good" : "muted"} />
            <span className="small muted">{d.lastMessageAt ? `last message ${ago(d.lastMessageAt)}` : "no mail yet"}</span>
            {can("configure") && <>
              <button disabled={busy} onClick={() => update(d, { enabled: !d.enabled }, d.enabled ? "Paused." : "Accepting mail.")}>{d.enabled ? "Pause" : "Resume"}</button>
              <button className="danger" disabled={busy} onClick={() => remove(d)}>Remove</button>
            </>}
          </div>
          <p className="small">Clean mail goes to <span className="mono">{d.destination}:{d.destinationPort}</span>{d.requireTls ? " over TLS" : ""}.
            {" "}MX record: <span className="mono">{d.domain} MX 10 {d.mx ?? "(set FENRIR_GATEWAY_HOSTNAME)"}</span></p>
          <div style={{ display: "grid", gap: 6 }}>
            <div><span className="small muted">Actions: </span><ActionPicker value={d.actions} options={GATEWAY_ACTIONS} disabled={!can("configure") || busy}
              onChange={(actions) => update(d, { actions })} /></div>
            <div><span className="small muted">Notifications: </span><NotifyEditor value={d.notify} disabled={!can("configure") || busy} onSave={(notify) => update(d, { notify })} /></div>
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
              <label className="small"><input type="checkbox" checked={d.requireTls} disabled={!can("configure") || busy} onChange={(e) => update(d, { requireTls: e.target.checked })} /> Require TLS to Microsoft 365</label>
              <label className="small"><input type="checkbox" checked={d.rejectUnknownRecipients} disabled={!can("configure") || busy} onChange={(e) => update(d, { rejectUnknownRecipients: e.target.checked })} /> Refuse unknown recipients</label>
              <label className="small"><input type="checkbox" checked={d.tagSubject} disabled={!can("configure") || busy} onChange={(e) => update(d, { tagSubject: e.target.checked })} /> Add "[Suspicious]" to subjects</label>
            </div>
            <div className="small">
              Microsoft 365 connector: {d.m365Connector.status === "done" ? <>created{d.m365Connector.lockdown ? ", locked down" : ""}{d.m365Connector.at ? ` ${ago(d.m365Connector.at)}` : ""}</>
                : d.m365Connector.status === "failed" ? <span style={{ color: "#fca5a5" }}>failed: {d.m365Connector.error}</span> : "not set up"}
              {can("m365_admin") && <> <button disabled={busy} onClick={() => connect(d, false)}>Create connector</button>
                <button disabled={busy} onClick={() => { if (window.confirm("Lock down: Microsoft 365 will refuse internet mail for this tenant that did not come through the gateway. Only do this once the MX record points at the gateway and mail is flowing.")) connect(d, true); }}>Create and lock down</button></>}
            </div>
          </div>
        </div>
      ))}
    </>
  );
}

function ListsTab() {
  const { tenantId, me, tenantName, can } = useApp();
  const tenants = me?.tenants ?? [];
  const { data, error, reload } = useListData<ListEntry>("email-security/lists", { tenant_id: tenantId });
  const { run, busy } = useAction();
  const [draft, setDraft] = useState({ tenantId: tenantId ?? "", kind: "block", match: "domain", value: "", note: "" });
  const add = async () => {
    const ok = await run(() => api("email-security/lists", { method: "POST", body: draft }), `${draft.kind === "allow" ? "Allowed" : "Blocked"} ${draft.value}.`);
    if (ok) { setDraft({ ...draft, value: "", note: "" }); reload(); }
  };
  const remove = async (e: ListEntry) => {
    await run(() => api(`email-security/lists/${e.id}`, { method: "DELETE" }), `Removed ${e.value}.`);
    reload();
  };
  return (
    <>
      <ErrorNote error={error} />
      <div className="card small muted">Allow skips Fenrir's checks for a sender (unless it fails DMARC, so a forged sender is never trusted). Block treats its mail as malicious.
        An entry on your own MSP tenant applies to every customer.</div>
      {can("configure") && <div className="card" style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        <select value={draft.tenantId} onChange={(e) => setDraft({ ...draft, tenantId: e.target.value })} aria-label="Customer">
          <option value="">Customer…</option>{tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
        </select>
        <select value={draft.kind} onChange={(e) => setDraft({ ...draft, kind: e.target.value })} aria-label="Allow or block"><option value="block">Block</option><option value="allow">Allow</option></select>
        <select value={draft.match} onChange={(e) => setDraft({ ...draft, match: e.target.value })} aria-label="Sender or domain"><option value="domain">domain</option><option value="sender">sender address</option></select>
        <input placeholder={draft.match === "domain" ? "supplier.co.uk" : "accounts@supplier.co.uk"} value={draft.value} onChange={(e) => setDraft({ ...draft, value: e.target.value })} />
        <input placeholder="Note (optional)" value={draft.note} onChange={(e) => setDraft({ ...draft, note: e.target.value })} />
        <button className="primary" disabled={busy || !draft.tenantId || !draft.value} onClick={add}>Add</button>
      </div>}
      <div className="card">
        <Table rows={data ?? undefined} empty="No allow or block entries."
               columns={[
                 { key: "kind", label: "", render: (e) => <Pill value={e.kind} tone={e.kind === "allow" ? "good" : "bad"} /> },
                 { key: "value", label: "Sender or domain", render: (e) => <><span className="mono">{e.value}</span><div className="small muted">{e.match}</div></> },
                 { key: "tenantId", label: "Customer", render: (e) => tenantName(e.tenantId) },
                 { key: "note", label: "Note", render: (e) => <>{e.note}<div className="small muted">{e.createdBy}, {ago(e.createdAt)}</div></> },
                 { key: "actions", label: "", className: "right", render: (e) => can("configure") ? <button disabled={busy} onClick={() => remove(e)}>Remove</button> : null },
               ]} />
      </div>
    </>
  );
}

function ModelTab() {
  const { can } = useApp();
  const { data, error, reload } = useData<ModelState>("email-security/model");
  const { run, busy } = useAction();
  const train = async () => {
    const result = await run(() => api<ModelView>("email-security/model/train", { method: "POST" }));
    if (result) await run(async () => undefined, result.active ? `Version ${result.version} trained and in use.` : `Version ${result.version} trained, not in use: ${result.reason}`);
    reload();
  };
  const r = data?.requirements;
  const active = data?.active;
  const latest = data?.latest;
  return (
    <>
      <ErrorNote error={error} />
      <div className="card small muted">
        The model learns from your labels (counted three times) and Microsoft's verdicts, using only the checks Fenrir records for each message, never the content.
        It is used only once it has {r?.samples ?? 200}+ examples ({r?.positives ?? 30}+ phishing) and, on messages held back from training, is right at least
        {" "}{Math.round((r?.precision ?? 0.9) * 100)}% of the times it flags one and catches at least {Math.round((r?.recall ?? 0.3) * 100)}% of the phishing.
        Even then it can only add to a message's score, never lower it. It retrains daily.
      </div>
      <div className="grid k3">
        <Stat label="Model in use" value={active ? `v${active.version}` : "none"} hint={active ? `trained ${ago(active.createdAt)}` : "the rules work alone"} accent={active ? "green" : undefined} />
        <Stat label="Precision (held back)" value={active?.metrics.precision != null ? `${Math.round(active.metrics.precision * 100)}%` : "—"} />
        <Stat label="Recall (held back)" value={active?.metrics.recall != null ? `${Math.round(active.metrics.recall * 100)}%` : "—"} />
      </div>
      <div className="card">
        <h3>Latest training</h3>
        {latest ? <>
          <p>Version {latest.version}, {ago(latest.createdAt)}: {latest.samples} examples, {latest.positives} phishing or malware, {latest.labelled} labelled by your team.</p>
          <p className="small">{latest.reason}</p>
          {latest.strongestSignals.length > 0 && <p className="small muted">Strongest signals: {latest.strongestSignals.map((s) => s.input.replace(/^code:/, "")).join(", ")}</p>}
        </> : <p className="muted">Not trained yet.</p>}
        <p className="small muted">Labels so far: {data && Object.keys(data.labels).length ? Object.entries(data.labels).map(([k, v]) => `${v} ${k}`).join(", ") : "none"}</p>
        {can("manage_tenants") && <button disabled={busy} onClick={train}>Train now</button>}
      </div>
      {(data?.history.length ?? 0) > 1 && <div className="card">
        <h3>History</h3>
        <Table rows={data?.history} columns={[
          { key: "version", label: "Version", render: (m) => <>v{m.version} {m.active && <Pill value="in use" tone="good" />}</> },
          { key: "createdAt", label: "Trained", render: (m) => ago(m.createdAt) },
          { key: "samples", label: "Examples", render: (m) => `${m.samples} (${m.positives} bad)` },
          { key: "metrics", label: "Precision / recall", render: (m) => m.metrics.precision != null ? `${Math.round((m.metrics.precision ?? 0) * 100)}% / ${Math.round((m.metrics.recall ?? 0) * 100)}%` : "—" },
        ]} />
      </div>}
    </>
  );
}
