import { useEffect, useState, type ReactNode } from "react";
import { ago, api, downloadFile } from "../api";
import { useApp } from "../app-context";
import { ErrorNote, Modal, PageHead, Pill, Stat, Table, Tabs, useAction, useData, useListData } from "../components/ui";
import EmailPolicies, { DecisionView, type Decision } from "./EmailPolicies";

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
  details: Evidence & { decision?: Decision }; canDownload: boolean;
}
interface Evidence {
  headers?: [string, string][];
  path?: { from: string; by: string; with: string; ip: string; at: string | null; delaySeconds: number | null; raw: string }[];
  origin?: { ip: string; public: boolean; ptr: string; asn: string; network: string; owner: string; country: string; listed: boolean };
  addresses?: { envelopeFrom: string; headerFrom: string; headerFromName: string; sender: string; replyTo: string[]; returnPath: string;
    to: string[]; cc: string[]; recipients: string[]; messageId: string; date: string; mailer: string; helo: string; notes: string[] };
  auth?: { spf: string; spfDomain: string; spfDetail: string; dkim: string; dkimDomain: string; dkimSelector: string; dkimAlgorithm: string;
    dmarc: string; dmarcPolicy: string; dmarcRecord: string; compauth: string; compauthReason: string; arc: boolean; results: string };
  links?: { url: string; host: string; text: string; flags: string[] }[];
  attachments?: { name: string; contentType?: string; size?: number; sha256?: string }[];
  size?: number | null; tls?: boolean | null;
  delivery?: { host: string; port: number; tls?: boolean; response?: string; at?: string; attempts?: number; lastError?: string };
}
interface ListEntry { id: string; tenantId: string; kind: string; match: string; value: string; note: string; createdBy: string; createdAt: string;
  expiresAt: string | null; expired: boolean; hits: number; lastHitAt: string | null }
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
const ACTION_TEXT: Record<string, string> = { quarantine: "Quarantined", junk: "Moved to Junk", tag: "Tagged", deliver: "Delivered", reject: "Rejected", delete: "Deleted" };

/** Re-read a tab's data every 30 seconds while it is open, so new mail and verdicts appear without a refresh. */
function useAutoRefresh(reload: () => unknown, seconds = 30) {
  useEffect(() => {
    const timer = window.setInterval(() => { if (!document.hidden) reload(); }, seconds * 1000);
    return () => window.clearInterval(timer);
  }, [reload, seconds]);
}

const NAV: { section: string; items: string[] }[] = [
  { section: "Investigate", items: ["Overview", "Explorer", "Quarantine", "Campaigns"] },
  { section: "Policies & rules", items: ["Threat policies", "Mail flow rules", "Allow / block lists"] },
  { section: "Settings", items: ["Mailbox scanning", "Gateway", "Model"] },
];

export default function EmailSecurity() {
  const [page, setPage] = useState(() => { try { return localStorage.getItem("fenrir.email.page") || "Overview"; } catch { return "Overview"; } });
  const go = (p: string) => { setPage(p); try { localStorage.setItem("fenrir.email.page", p); } catch { /* not kept */ } };
  return (
    <>
      <PageHead title="Email security"
                subtitle="Fenrir checks each customer's mail in their Microsoft 365 mailboxes and at its own gateway, decides what to do from your versioned policies and mail flow rules, and keeps the evidence for every decision." />
      <div className="email-layout" style={{ display: "grid", gridTemplateColumns: "minmax(170px, 210px) minmax(0, 1fr)", gap: 16, alignItems: "start" }}>
        <nav className="card" aria-label="Email security" style={{ padding: 8, position: "sticky", top: 8 }}>
          {NAV.map((g) => (
            <div key={g.section} style={{ marginBottom: 10 }}>
              <div className="small muted" style={{ textTransform: "uppercase", letterSpacing: ".05em", padding: "4px 8px" }}>{g.section}</div>
              {g.items.map((item) => (
                <button key={item} className={item === page ? "primary" : "ghost"} aria-current={item === page ? "page" : undefined}
                        onClick={() => go(item)} style={{ display: "block", width: "100%", textAlign: "left", marginBottom: 2 }}>{item}</button>
              ))}
            </div>
          ))}
        </nav>
        <div style={{ minWidth: 0 }}>
          {page === "Overview" && <OverviewTab />}
          {page === "Explorer" && <Explorer key="explorer" />}
          {page === "Quarantine" && <Explorer key="quarantine" quarantine />}
          {page === "Campaigns" && <CampaignsTab />}
          {page === "Threat policies" && <EmailPolicies key="policies" />}
          {page === "Mail flow rules" && <EmailPolicies key="rules" initialTab="Mail flow rules" />}
          {page === "Allow / block lists" && <ListsTab />}
          {page === "Mailbox scanning" && <CustomersTab />}
          {page === "Gateway" && <GatewayTab />}
          {page === "Model" && <ModelTab />}
        </div>
      </div>
      <style>{"@media (max-width: 760px) { .email-layout { grid-template-columns: minmax(0, 1fr) !important; } .email-layout > nav { position: static !important; } }"}</style>
    </>
  );
}

function OverviewTab() {
  const { tenantId } = useApp();
  const [days, setDays] = useState(7);
  const { data: d, error, reload } = useData<Overview>("email-security/overview", { tenant_id: tenantId, days }, [days]);
  useAutoRefresh(reload);
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

const EMPTY_FILTERS = { q: "", verdict: "", classification: "", action: "", actionStatus: "", source: "", label: "", agreement: "",
  sender: "", senderDomain: "", recipient: "", subject: "", messageId: "", ip: "", country: "", attachment: "", hash: "", link: "",
  decidedBy: "", microsoftVerdict: "", minScore: "", since: "", until: "" };
type Filters = typeof EMPTY_FILTERS;
const FILTER_PARAM: Record<string, string> = { senderDomain: "sender_domain", messageId: "message_id", decidedBy: "decided_by",
  actionStatus: "action_status", microsoftVerdict: "microsoft_verdict", minScore: "min_score" };

function query(filters: Filters, tenantId: string | null | undefined, quarantine: boolean): Record<string, string> {
  const out: Record<string, string> = {};
  if (tenantId) out.tenant_id = tenantId;
  for (const [k, v] of Object.entries(filters)) {
    if (!v) continue;
    out[FILTER_PARAM[k] ?? k] = k === "since" || k === "until" ? new Date(v).toISOString() : v;
  }
  if (quarantine) { out.action = "quarantine"; if (!filters.actionStatus) out.action_status = "done"; }
  return out;
}

/** Explorer: search every checked message, select several and act on them, or export what was found. Quarantine is the
 * same view fixed to quarantined mail. */
function Explorer({ quarantine = false }: { quarantine?: boolean }) {
  const { tenantId, tenantName, can } = useApp();
  const [filters, setFilters] = useState<Filters>({ ...EMPTY_FILTERS, verdict: quarantine ? "" : "flagged" });
  const [applied, setApplied] = useState<Filters>(filters);
  const [advanced, setAdvanced] = useState(false);
  const [open, setOpen] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const params = query(applied, tenantId, quarantine);
  const { data, error, reload } = useListData<Scan>("email-security/messages", { ...params, limit: 300 }, [JSON.stringify(params)]);
  useAutoRefresh(reload);
  const { run, busy } = useAction();
  const set = (k: keyof Filters) => (e: { target: { value: string } }) => setFilters({ ...filters, [k]: e.target.value });
  const apply = () => { setApplied(filters); setSelected(new Set()); };
  const toggle = (id: string) => setSelected((s) => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  const rows = data ?? [];
  const allOn = rows.length > 0 && rows.every((r) => selected.has(r.id));
  const bulk = async (op: string, value = "", confirmText = "") => {
    if (confirmText && !window.confirm(confirmText)) return;
    const result = await run(() => api<{ done: number; failed: { id: string; error: string }[] }>("email-security/messages/bulk", { method: "POST", body: { ids: [...selected], op, value } }));
    if (result) await run(async () => { if (result.failed.length && !result.done) throw new Error(result.failed[0].error); },
      `${result.done} done${result.failed.length ? `, ${result.failed.length} failed (${result.failed[0].error})` : ""}.`);
    setSelected(new Set());
    reload();
  };
  const exportCsv = () => run(() => downloadFile(`email-security/messages.csv?${new URLSearchParams(params).toString()}`, "fenrir-email.csv"), "Exported.");
  const input = (k: keyof Filters, placeholder: string, width = 180) =>
    <input placeholder={placeholder} value={filters[k]} onChange={set(k)} onKeyDown={(e) => e.key === "Enter" && apply()} style={{ width }} aria-label={placeholder} />;
  return (
    <>
      <ErrorNote error={error} />
      {quarantine && <div className="card small muted">Mail Fenrir is holding: in each mailbox's hidden Fenrir quarantine folder, or at the gateway. Release puts it in the Inbox (or delivers it);
        delete removes it for good. Users' release requests show as "release requested".</div>}
      <div className="card" style={{ display: "grid", gap: 8 }}>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <input placeholder="Search sender, subject, mailbox or Message-ID" value={filters.q} onChange={set("q")} onKeyDown={(e) => e.key === "Enter" && apply()} style={{ flex: 1, minWidth: 220 }} />
          {!quarantine && <select value={filters.verdict} onChange={set("verdict")} aria-label="Fenrir's verdict">
            <option value="flagged">Fenrir flagged (phish or malware)</option><option value="phish">Phishing</option><option value="malware">Malware</option>
            <option value="suspicious">Suspicious</option><option value="clean">Clean</option><option value="">Every verdict</option>
          </select>}
          <select value={filters.actionStatus} onChange={set("actionStatus")} aria-label="Status">
            <option value="">{quarantine ? "Held now" : "Any status"}</option><option value="release_requested">Release requested</option>
            <option value="released">Released</option><option value="failed">Action failed</option>{!quarantine && <option value="deleted">Deleted</option>}
          </select>
          <label className="small">From <input type="datetime-local" value={filters.since} onChange={set("since")} /></label>
          <label className="small">to <input type="datetime-local" value={filters.until} onChange={set("until")} /></label>
          <button onClick={() => setAdvanced(!advanced)}>{advanced ? "Fewer filters" : "More filters"}</button>
          <button className="primary" onClick={apply}>Search</button>
          <button onClick={() => { const f = { ...EMPTY_FILTERS, verdict: quarantine ? "" : "flagged" }; setFilters(f); setApplied(f); }}>Reset</button>
        </div>
        {advanced && <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          {input("sender", "Sender address")}{input("senderDomain", "Sender domain")}{input("recipient", "Recipient mailbox")}{input("subject", "Subject")}
          {input("messageId", "Message-ID")}{input("ip", "Originating IP", 140)}{input("country", "Country (GB)", 110)}
          {input("attachment", "Attachment name")}{input("hash", "Attachment SHA-256", 220)}{input("link", "Link or domain")}
          {input("decidedBy", "Decided by (rule or policy)")}{input("minScore", "Min score", 90)}
          <select value={filters.classification} onChange={set("classification")} aria-label="Classification">
            <option value="">Any classification</option>{["malware", "highphish", "phish", "impersonation", "spoof", "suspicious", "spam", "bulk", "clean"].map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
          {!quarantine && <select value={filters.action} onChange={set("action")} aria-label="Action">
            <option value="">Any action</option><option value="quarantine">Quarantined</option><option value="junk">Moved to Junk</option>
            <option value="tag">Tagged</option><option value="deliver">Delivered</option><option value="reject">Rejected</option><option value="delete">Deleted</option>
          </select>}
          <select value={filters.source} onChange={set("source")} aria-label="Source"><option value="">Mailbox and gateway</option><option value="graph">Mailbox</option><option value="gateway">Gateway</option></select>
          <select value={filters.microsoftVerdict} onChange={set("microsoftVerdict")} aria-label="Microsoft's verdict">
            <option value="">Any Microsoft verdict</option>{["clean", "spam", "bulk", "phish", "malware"].map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
          <select value={filters.agreement} onChange={set("agreement")} aria-label="Agreement"><option value="">Any agreement</option>{Object.entries(AGREEMENT).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select>
          <select value={filters.label} onChange={set("label")} aria-label="Label"><option value="">Labelled or not</option><option value="any">Labelled</option>{LABELS.map((l) => <option key={l} value={l}>Labelled {l}</option>)}</select>
        </div>}
      </div>
      <div className="card" style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        <span className="small"><b>{rows.length}</b> message{rows.length === 1 ? "" : "s"}{rows.length >= 300 ? " (newest 300; narrow the search)" : ""}{selected.size ? ` · ${selected.size} selected` : ""}</span>
        <span style={{ flex: 1 }} />
        {selected.size > 0 && <>
          <button disabled={busy} onClick={() => bulk("release", "", `Release ${selected.size} message(s) to the users' inboxes?`)}>Release</button>
          {LABELS.map((l) => <button key={l} disabled={busy} onClick={() => bulk("label", l)}>Label {l}</button>)}
          {can("configure") && <>
            <button disabled={busy} onClick={() => bulk("blockSender")}>Block senders</button>
            <button disabled={busy} onClick={() => bulk("blockDomain")}>Block domains</button>
            <button disabled={busy} onClick={() => bulk("allowSender")}>Allow senders</button>
            <button className="danger" disabled={busy} onClick={() => bulk("delete", "", `Delete ${selected.size} message(s) for good, from the mailboxes or the gateway? This cannot be undone.`)}>Delete</button>
          </>}
        </>}
        <button disabled={busy} onClick={exportCsv}>Export CSV</button>
      </div>
      <div className="card">
        <Table rows={data ?? undefined} onRow={(s) => setOpen(s.id)} empty={quarantine ? "Nothing in quarantine." : "No messages match."}
               columns={[
                 { key: "select", label: <input type="checkbox" aria-label="Select all" checked={allOn} onChange={() => setSelected(allOn ? new Set() : new Set(rows.map((r) => r.id)))} /> as unknown as string,
                   render: (s) => <input type="checkbox" aria-label="Select" checked={selected.has(s.id)} onClick={(e) => e.stopPropagation()} onChange={() => toggle(s.id)} /> },
                 { key: "verdict", label: "Fenrir", render: (s) => <><Pill value={s.verdict} tone={TONE[s.verdict]} /><div className="small muted">score {s.score}</div></> },
                 { key: "microsoftVerdict", label: "Microsoft", render: (s) => s.source === "gateway" ? <span className="small muted">gateway</span> : <Pill value={s.microsoftVerdict} tone={TONE[s.microsoftVerdict]} /> },
                 { key: "subject", label: "Message", render: (s) => <><b>{s.subject || "(no subject)"}</b><div className="small muted">{s.senderName ? `${s.senderName} <${s.sender}>` : s.sender}</div>
                   {s.topReason && <div className="small">{s.topReason}</div>}</> },
                 { key: "mailbox", label: "Recipient", render: (s) => <>{s.mailbox}<div className="small muted">{tenantName(s.tenantId)}{s.folder === "junkemail" ? " · Junk" : ""}</div></> },
                 { key: "action", label: "Done", render: (s) => <ActionPill action={s.action} status={s.actionStatus} /> },
                 { key: "receivedAt", label: "Received", render: (s) => ago(s.receivedAt) },
                 { key: "label", label: "Label", render: (s) => s.label ? <Pill value={s.label} tone={s.label === "safe" ? "good" : "bad"} /> : <span className="muted small">none</span> },
               ]} />
      </div>
      {open && <MessageDetail id={open} onClose={() => setOpen(null)} onChanged={reload} />}
    </>
  );
}

interface Campaign { senderDomain: string; subjectKey: string; subject: string; messages: number; recipients: number; tenants: number;
  verdicts: Record<string, number>; actions: Record<string, number>; first: string; last: string; senders: string[]; maxScore: number }
interface PurgePreview { matched: number; mailboxes: string[]; messages: Scan[] }

/** Campaigns: the same attack sent to many people, grouped, with a purge from every mailbox it reached. */
function CampaignsTab() {
  const { tenantId, can } = useApp();
  const [days, setDays] = useState(7);
  const [all, setAll] = useState(false);
  const { data, error, reload } = useListData<Campaign>("email-security/campaigns", { tenant_id: tenantId, days, all_mail: all }, [days, all]);
  const [purging, setPurging] = useState<Campaign | null>(null);
  return (
    <>
      <ErrorNote error={error} />
      <div className="card" style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <span className="small muted">Messages grouped by sender domain and subject (numbers ignored, so "Invoice 1234" and "Invoice 9876" group together).</span>
        <span style={{ flex: 1 }} />
        {[1, 7, 30].map((n) => <button key={n} className={n === days ? "primary" : ""} onClick={() => setDays(n)}>{n === 1 ? "24 hours" : `${n} days`}</button>)}
        <label className="small"><input type="checkbox" checked={all} onChange={(e) => setAll(e.target.checked)} /> Include clean mail</label>
      </div>
      <div className="card">
        <Table rows={(data ?? []).map((c) => ({ ...c, id: `${c.senderDomain}|${c.subjectKey}` }))} empty="No campaigns in this period."
               columns={[
                 { key: "subject", label: "Campaign", render: (c) => <><b>{c.subject || "(no subject)"}</b><div className="small muted mono">{c.senderDomain}</div>
                   <div className="small muted">{c.senders.slice(0, 3).join(", ")}{c.senders.length > 3 ? ` +${c.senders.length - 3}` : ""}</div></> },
                 { key: "messages", label: "Messages", render: (c) => <><b>{c.messages}</b><div className="small muted">{c.recipients} recipient{c.recipients === 1 ? "" : "s"}{c.tenants > 1 ? ` · ${c.tenants} customers` : ""}</div></> },
                 { key: "verdicts", label: "Verdicts", render: (c) => Object.entries(c.verdicts).map(([k, v]) => <span key={k} style={{ marginRight: 4 }}><Pill value={`${v} ${k}`} tone={TONE[k]} /></span>) },
                 { key: "actions", label: "Done", render: (c) => Object.entries(c.actions).map(([k, v]) => `${v} ${ACTION_TEXT[k]?.toLowerCase() ?? k}`).join(", ") || <span className="muted small">nothing</span> },
                 { key: "last", label: "When", render: (c) => <>{ago(c.last)}<div className="small muted">first {ago(c.first)}</div></> },
                 { key: "purge", label: "", className: "right", render: (c) => can("configure") ? <button onClick={() => setPurging(c)}>Remove from mailboxes…</button> : null },
               ]} />
      </div>
      {purging && <PurgeModal campaign={purging} days={days} onClose={() => setPurging(null)} onDone={reload} />}
    </>
  );
}

function PurgeModal({ campaign, days, onClose, onDone }: { campaign: Campaign; days: number; onClose: () => void; onDone: () => void }) {
  const { tenantId } = useApp();
  const [action, setAction] = useState<"quarantine" | "delete">("quarantine");
  const [preview, setPreview] = useState<PurgePreview | null>(null);
  const { run, busy } = useAction();
  const body = { tenantId: tenantId || null, senderDomain: campaign.senderDomain, subjectKey: campaign.subjectKey, days, action };
  useEffect(() => {
    let live = true;
    api<PurgePreview>("email-security/campaigns/purge", { method: "POST", body: { ...body, preview: true } }).then((p) => { if (live) setPreview(p); }).catch(() => setPreview(null));
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [action]);
  const go = async () => {
    const r = await run(() => api<{ done: number; failed: number }>("email-security/campaigns/purge", { method: "POST", body: { ...body, preview: false } }));
    if (r) { await run(async () => undefined, `${r.done} removed${r.failed ? `, ${r.failed} failed` : ""}.`); onDone(); onClose(); }
  };
  return (
    <Modal title="Remove a campaign from mailboxes" onClose={onClose} wide
           footer={<><button onClick={onClose}>Cancel</button><button className={action === "delete" ? "danger" : "primary"} disabled={busy || !preview?.matched} onClick={go}>
             {action === "delete" ? `Delete ${preview?.matched ?? 0} for good` : `Quarantine ${preview?.matched ?? 0}`}</button></>}>
      <p className="small">Messages from <b className="mono">{campaign.senderDomain}</b> with subjects like "<b>{campaign.subject}</b>" in the last {days} day{days === 1 ? "" : "s"}, in
        Microsoft 365 mailboxes (gateway mail is already held or delivered by Fenrir). Needs Mail.ReadWrite.</p>
      <p><label className="small"><input type="radio" checked={action === "quarantine"} onChange={() => setAction("quarantine")} /> Move to Fenrir's quarantine (can be released)</label>{" "}
        <label className="small"><input type="radio" checked={action === "delete"} onChange={() => setAction("delete")} /> Delete for good</label></p>
      {preview ? <>
        <p><b>{preview.matched}</b> message{preview.matched === 1 ? "" : "s"} in <b>{preview.mailboxes.length}</b> mailbox{preview.mailboxes.length === 1 ? "" : "es"}.</p>
        {preview.mailboxes.length > 0 && <p className="small muted">{preview.mailboxes.slice(0, 30).join(", ")}{preview.mailboxes.length > 30 ? ` and ${preview.mailboxes.length - 30} more` : ""}</p>}
      </> : <p className="muted small">Counting…</p>}
    </Modal>
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
  const [tab, setTab] = useState("Summary");
  const after = () => { reload(); onChanged(); };
  const setLabel = async (label: string) => {
    await run(() => api(`email-security/messages/${id}/label`, { method: "PUT", body: { label } }), label ? `Labelled ${label}.` : "Label removed.");
    after();
  };
  const release = async () => {
    await run(() => api(`email-security/messages/${id}/release`, { method: "POST", body: { allowSender } }),
              retry ? "Delivered to Microsoft 365." : "Released to the Inbox.");
    after();
  };
  const block = async (match: "sender" | "domain") => {
    if (!data) return;
    const value = match === "sender" ? data.sender : data.sender.split("@").pop() ?? "";
    await run(() => api("email-security/lists", { method: "POST", body: { tenantId: data.tenantId, kind: "block", match, value, note: `From message: ${data.subject}`.slice(0, 300) } }),
              `Blocked ${value} for this customer.`);
  };
  const m = data?.microsoft ?? {};
  const retry = data?.source === "gateway" && data.actionStatus === "failed";
  const releasable = data && (retry || (["quarantine", "junk"].includes(data.action) && ["done", "release_requested"].includes(data.actionStatus)));
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
              <button className="primary" disabled={busy} onClick={release}>{retry ? "Retry delivery" : "Release to Inbox"}</button>
            </>}
          </div>}
          <Tabs tabs={["Summary", "Decision", "Body", "Origin & path", "Headers", "Authentication", "Links & attachments", ...(data.source === "gateway" ? ["Delivery"] : [])]}
                active={tab} onChange={setTab} />
          {tab === "Summary" && <SummaryView data={data} m={m} />}
          {tab === "Decision" && <DecisionTab data={data} />}
          {tab === "Body" && <BodyView id={id} />}
          {tab === "Origin & path" && <OriginView e={data.details} />}
          {tab === "Headers" && <HeadersView e={data.details} />}
          {tab === "Authentication" && <AuthView e={data.details} m={m} gateway={data.source === "gateway"} />}
          {tab === "Links & attachments" && <LinksView e={data.details} fallback={data} />}
          {tab === "Delivery" && <DeliveryView e={data.details} />}
          {can("configure") && data.sender && <p style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            <button disabled={busy} onClick={() => block("sender")}>Block sender</button>
            <button disabled={busy} onClick={() => block("domain")}>Block {data.sender.split("@").pop()}</button>
          </p>}
          {data.label && <p className="small muted">Labelled {data.label} by {data.labelledBy}{data.labelledAt ? `, ${ago(data.labelledAt)}` : ""}.</p>}
          <p className="small muted mono">{data.internetMessageId}</p>
          {data.canDownload && can("respond") && <p className="small">
            <button disabled={busy} onClick={() => run(() => downloadFile(`email-security/messages/${id}/original`, `fenrir-${id}.eml`), "Downloaded. It may contain malware: open it only somewhere safe.")}>
              Download original (.eml)</button> <span className="muted">Recorded in the audit log.</span></p>}
        </>
      )}
    </Modal>
  );
}

function DecisionTab({ data }: { data: ScanDetail }) {
  const { toast } = useApp();
  const decision = data.details?.decision;
  return (
    <>
      {decision ? <DecisionView decision={decision} />
        : <p className="muted small">This message was checked before Fenrir recorded policy decisions. Test it against the current policy under Threat policies → Test.</p>}
      <p className="small muted">Message ID for policy tests: <span className="mono">{data.id}</span>{" "}
        <button className="ghost" onClick={() => { navigator.clipboard?.writeText(data.id); toast("Copied."); }}>Copy</button></p>
      <h3>Fenrir's checks</h3>
      {data.reasons.length ? <Table rows={data.reasons.map((r, i) => ({ ...r, id: String(i) }))} columns={[
        { key: "points", label: "Points", render: (r) => <b>+{r.points}</b> },
        { key: "code", label: "Check", render: (r) => <span className="mono small">{r.code}</span> },
        { key: "detail", label: "What it found" },
      ]} /> : <p className="muted small">No check found anything suspicious.</p>}
    </>
  );
}

interface BodyContent { html: string; text: string; source: string; phrases: string[]; flaggedHosts: string[] }
const SOURCE_TEXT: Record<string, string> = { kept: "Fenrir's encrypted copy", quarantine: "the gateway quarantine", mailbox: "the mailbox, just now" };

/** The message body, made safe: no scripts, styles, images or live links. Shown in a sandboxed frame that can run nothing. */
function BodyView({ id }: { id: string }) {
  const { data, error } = useData<BodyContent>(`email-security/messages/${id}/content`, {}, [id]);
  const [plain, setPlain] = useState(false);
  if (error) return <ErrorNote error={error} />;
  if (!data) return <p className="muted small">Loading the body…</p>;
  const doc = `<!doctype html><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<style>body{font:14px/1.5 system-ui,sans-serif;color:#111;background:#fff;margin:12px;word-break:break-word}mark{background:#fde68a;padding:0 2px}
.fenrir-link{color:#1d4ed8;text-decoration:underline}.fenrir-dest{color:#475569;font-family:monospace;font-size:12px}.fenrir-flag{color:#b91c1c;font-weight:bold}.fenrir-img{color:#6b7280;font-size:12px}
table{border-collapse:collapse}td,th{padding:2px 4px}</style><body>${data.html}</body>`;
  return (
    <>
      <p className="small muted">From {SOURCE_TEXT[data.source] ?? data.source}. Links are shown as text and images are not loaded, so opening this cannot alert the sender or run anything.
        Viewing is recorded in the audit log.</p>
      {(data.phrases.length > 0 || data.flaggedHosts.length > 0) && <div className="card small" style={{ borderColor: "rgba(245,158,11,.5)" }}>
        {data.phrases.length > 0 && <div><b>Wording often used in phishing</b> (highlighted): {data.phrases.map((p, i) => <span key={i} className="badge" style={{ marginRight: 4 }}>{p}</span>)}</div>}
        {data.flaggedHosts.length > 0 && <div><b>Suspicious link hosts</b> (in red): <span className="mono">{data.flaggedHosts.join(", ")}</span></div>}
      </div>}
      <p><button onClick={() => setPlain(!plain)}>{plain ? "Show formatted" : "Show plain text"}</button></p>
      {plain ? <pre className="mono small" style={{ whiteSpace: "pre-wrap", maxHeight: 480, overflow: "auto" }}>{data.text || "(empty)"}</pre>
        : <iframe title="Message body" sandbox="" srcDoc={doc} style={{ width: "100%", height: 480, border: "1px solid rgba(148,163,184,.3)", borderRadius: 6, background: "#fff" }} />}
    </>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return <tr><td className="muted" style={{ whiteSpace: "nowrap", paddingRight: 12, verticalAlign: "top" }}>{label}</td><td style={{ wordBreak: "break-word" }}>{children || "—"}</td></tr>;
}

function NoEvidence() {
  return <p className="muted small">Not recorded for this message (it was scanned before Fenrir kept this detail).</p>;
}

function SummaryView({ data, m }: { data: ScanDetail; m: Record<string, string | number | null> }) {
  const o = data.details?.origin;
  const a = data.details?.addresses;
  return (
    <>
      <div className="grid k2">
        <div>
          <h3>Fenrir: <Pill value={data.verdict} tone={TONE[data.verdict]} /> <span className="small muted">score {data.score}{data.modelScore != null ? ` · model ${Math.round(data.modelScore * 100)}%` : ""}</span></h3>
          {data.reasons.length ? <ul>{data.reasons.map((r, i) => <li key={i}><b>+{r.points}</b> {r.detail}</li>)}</ul> : <p className="muted">Nothing suspicious found.</p>}
        </div>
        <div>
          {data.source === "gateway" ? <h3>Gateway checks</h3> : <h3>Microsoft: <Pill value={data.microsoftVerdict} tone={TONE[data.microsoftVerdict]} /></h3>}
          <table className="small"><tbody>
            <Row label="Originating IP">{o?.ip ? <>{o.ip}{o.listed && <> <Pill value="on a threat list" tone="bad" /></>}</> : (m.peer as string)}</Row>
            <Row label="Network">{o?.owner ? `${o.owner}${o.asn ? ` (AS${o.asn})` : ""}` : ""}</Row>
            <Row label="Country">{o?.country || (m.country as string) || ""}</Row>
            <Row label="Reverse DNS">{o?.ptr}</Row>
            <Row label="SPF / DKIM / DMARC">{[m.spf, m.dkim, m.dmarc].map((v) => v || "—").join(" / ")}</Row>
            {data.source !== "gateway" && <Row label="Spam / bulk / category">{`${m.scl ?? "—"} / ${m.bcl ?? "—"} / ${m.cat || "—"}`}</Row>}
            <Row label="Envelope sender">{a?.envelopeFrom}</Row>
          </tbody></table>
        </div>
      </div>
      {a?.notes?.length ? <div className="card small" style={{ borderColor: "rgba(245,158,11,.5)" }}>{a.notes.map((n, i) => <div key={i}>⚠ {n}</div>)}</div> : null}
    </>
  );
}

function OriginView({ e }: { e: Evidence }) {
  if (!e?.origin && !e?.path) return <NoEvidence />;
  const o = e.origin;
  const a = e.addresses;
  return (
    <>
      <div className="grid k2">
        <div>
          <h3>Where it came from</h3>
          <table className="small"><tbody>
            <Row label="Originating IP">{o?.ip ? <>{o.ip} {o.public === false && <span className="muted">(private address)</span>} {o.listed && <Pill value="on a threat list" tone="bad" />}</> : ""}</Row>
            <Row label="Reverse DNS">{o?.ptr}</Row>
            <Row label="Network">{o?.owner ? `${o.owner}${o.asn ? ` · AS${o.asn}` : ""}` : ""}</Row>
            <Row label="IP range">{o?.network}</Row>
            <Row label="Country">{o?.country}</Row>
            <Row label="Server greeting (HELO)">{a?.helo}</Row>
            <Row label="Encrypted (TLS)">{e.tls == null ? "" : e.tls ? "yes" : "no"}</Row>
            <Row label="Size">{e.size ? (e.size < 1024 ? `${e.size} bytes` : `${Math.round(e.size / 1024)} KB`) : ""}</Row>
          </tbody></table>
        </div>
        <div>
          <h3>Addresses</h3>
          <table className="small"><tbody>
            <Row label="From">{a?.headerFromName ? `${a.headerFromName} <${a.headerFrom}>` : a?.headerFrom}</Row>
            <Row label="Envelope sender">{a?.envelopeFrom}</Row>
            <Row label="Return-Path">{a?.returnPath}</Row>
            <Row label="Sender">{a?.sender}</Row>
            <Row label="Reply-To">{a?.replyTo?.join(", ")}</Row>
            <Row label="To">{a?.to?.join(", ")}</Row>
            <Row label="Cc">{a?.cc?.join(", ")}</Row>
            <Row label="Delivered to">{a?.recipients?.join(", ")}</Row>
            <Row label="Date">{a?.date}</Row>
            <Row label="Mail client">{a?.mailer}</Row>
          </tbody></table>
          {a?.notes?.map((n, i) => <p key={i} className="small" style={{ color: "#fbbf24" }}>⚠ {n}</p>)}
        </div>
      </div>
      <h3>Path (oldest hop first)</h3>
      <Table rows={(e.path ?? []).map((h, i) => ({ ...h, id: String(i) }))} empty="No Received headers."
             columns={[
               { key: "id", label: "#", render: (h) => Number(h.id) + 1 },
               { key: "from", label: "From", render: (h) => <><span className="mono">{h.from || "—"}</span>{h.ip && <div className="small muted mono">{h.ip}</div>}</> },
               { key: "by", label: "By", render: (h) => <span className="mono">{h.by || "—"}</span> },
               { key: "with", label: "Protocol", render: (h) => h.with || "—" },
               { key: "at", label: "Time (UTC)", render: (h) => h.at ? h.at.replace("T", " ").slice(0, 19) : "—" },
               { key: "delaySeconds", label: "Delay", render: (h) => h.delaySeconds == null ? "" : `${h.delaySeconds}s` },
             ]} />
    </>
  );
}

function HeadersView({ e }: { e: Evidence }) {
  const { toast } = useApp();
  const [filter, setFilter] = useState("");
  if (!e?.headers?.length) return <NoEvidence />;
  const text = e.headers.map(([k, v]) => `${k}: ${v}`).join("\n");
  const shown = e.headers.filter(([k, v]) => !filter || k.toLowerCase().includes(filter.toLowerCase()) || v.toLowerCase().includes(filter.toLowerCase()));
  return (
    <>
      <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
        <input placeholder="Filter headers" value={filter} onChange={(ev) => setFilter(ev.target.value)} style={{ flex: 1 }} />
        <button onClick={() => { navigator.clipboard?.writeText(text); toast("Headers copied."); }}>Copy all</button>
      </div>
      <div className="mono small" style={{ maxHeight: 420, overflow: "auto", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
        {shown.map(([k, v], i) => <div key={i} style={{ marginBottom: 4 }}><b>{k}:</b> {v}</div>)}
      </div>
    </>
  );
}

function AuthView({ e, m, gateway }: { e: Evidence; m: Record<string, string | number | null>; gateway: boolean }) {
  const a = e?.auth;
  if (!a) return <NoEvidence />;
  const tone = (v: string) => v === "pass" ? "good" : v === "fail" || v === "softfail" ? "bad" : "muted";
  return (
    <table className="small"><tbody>
      <Row label="SPF"><Pill value={a.spf || "none"} tone={tone(a.spf)} /> {a.spfDomain && <>for <span className="mono">{a.spfDomain}</span></>} {a.spfDetail && <div className="muted">{a.spfDetail}</div>}</Row>
      <Row label="DKIM"><Pill value={a.dkim || "none"} tone={tone(a.dkim)} /> {a.dkimDomain && <>signed by <span className="mono">{a.dkimDomain}</span></>}
        {a.dkimSelector && <span className="muted"> (selector {a.dkimSelector}{a.dkimAlgorithm ? `, ${a.dkimAlgorithm}` : ""})</span>}</Row>
      <Row label="DMARC"><Pill value={a.dmarc || "none"} tone={tone(a.dmarc)} /> {a.dmarcPolicy && <>policy <b>{a.dmarcPolicy}</b></>}
        {a.dmarcRecord && <div className="muted mono">{a.dmarcRecord}</div>}</Row>
      {!gateway && <Row label="Composite authentication"><Pill value={a.compauth || (m.compauth as string) || "none"} tone={tone(a.compauth)} />{a.compauthReason && <span className="muted"> reason {a.compauthReason}</span>}</Row>}
      <Row label="ARC">{a.arc ? "present (forwarded through another service)" : "none"}</Row>
      <Row label="Authentication-Results"><span className="mono">{a.results}</span></Row>
    </tbody></table>
  );
}

function LinksView({ e, fallback }: { e: Evidence; fallback: ScanDetail }) {
  const links = e?.links;
  const files = e?.attachments?.length ? e.attachments : fallback.attachmentDetails;
  return (
    <>
      <h3>Links {links ? `(${links.length})` : ""}</h3>
      {links ? <Table rows={links.map((l, i) => ({ ...l, id: String(i) }))} empty="No links."
                      columns={[
                        { key: "url", label: "Link", render: (l) => <><span className="mono small" style={{ wordBreak: "break-all" }}>{l.url}</span>{l.text && <div className="small muted">shown as: {l.text}</div>}</> },
                        { key: "flags", label: "", render: (l) => l.flags.map((f) => <Pill key={f} value={f} tone="bad" />) },
                      ]} />
        : fallback.linkDomains.length ? <p className="small">Links go to: {fallback.linkDomains.join(", ")}</p> : <p className="muted small">No links.</p>}
      <h3>Attachments ({files.length})</h3>
      {files.length ? <Table rows={files.map((f, i) => ({ ...f, id: String(i) }))} columns={[
        { key: "name", label: "Name", render: (f) => <b>{f.name}</b> },
        { key: "contentType", label: "Type", render: (f) => (f as { contentType?: string }).contentType || "—" },
        { key: "size", label: "Size", render: (f) => f.size ? `${Math.max(1, Math.round(f.size / 1024))} KB` : "—" },
        { key: "sha256", label: "SHA-256", render: (f) => <span className="mono small" style={{ wordBreak: "break-all" }}>{f.sha256 || "—"}</span> },
      ]} /> : <p className="muted small">No attachments.</p>}
    </>
  );
}

function DeliveryView({ e }: { e: Evidence }) {
  const d = e?.delivery;
  if (!d) return <p className="muted small">Not handed on: quarantined messages stay with Fenrir until released.</p>;
  return (
    <table className="small"><tbody>
      <Row label="Handed to">{`${d.host}:${d.port}`}</Row>
      <Row label="When">{d.at ? `${ago(d.at)} (${d.at.replace("T", " ").slice(0, 19)} UTC)` : ""}</Row>
      <Row label="Encrypted (TLS)">{d.tls == null ? "" : d.tls ? "yes" : "no"}</Row>
      <Row label="Attempts">{d.attempts}</Row>
      <Row label="Reply from Microsoft 365"><span className="mono">{d.response}</span></Row>
      {d.lastError && <Row label="Last problem"><span style={{ color: "#fca5a5" }}>{d.lastError}</span></Row>}
    </tbody></table>
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
  useAutoRefresh(reload, 60);
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
        <b>Shadow</b> scans, compares and records what the policy would have done; nothing in the mailbox changes (needs <b>Mail.Read</b>). <b>Protect</b> also
        carries out the policy's decision (needs <b>Mail.ReadWrite</b>); only mail received after protect mode starts is touched, and it pauses itself if one scan
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
            <div className="small muted">What happens to each kind of mail is set under <b>Threat policies</b> and <b>Mail flow rules</b> (versioned, per customer or MSP-wide).</div>
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
  useAutoRefresh(reload);
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
            <div className="small muted">Verdict actions come from the customer's <b>Threat policies</b>; blocked IPs there are refused before the message is accepted.</div>
            <div><span className="small muted">Notifications: </span><NotifyEditor value={d.notify} disabled={!can("configure") || busy} onSave={(notify) => update(d, { notify })} /></div>
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
              <label className="small"><input type="checkbox" checked={d.requireTls} disabled={!can("configure") || busy} onChange={(e) => update(d, { requireTls: e.target.checked })} /> Require TLS to Microsoft 365</label>
              <label className="small"><input type="checkbox" checked={d.rejectUnknownRecipients} disabled={!can("configure") || busy} onChange={(e) => update(d, { rejectUnknownRecipients: e.target.checked })} /> Refuse unknown recipients</label>
              <label className="small"><input type="checkbox" checked={d.tagSubject} disabled={!can("configure") || busy} onChange={(e) => update(d, { tagSubject: e.target.checked })} /> Allow subject tags (the policy's prefix)</label>
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

const MATCH_TEXT: Record<string, string> = { sender: "Sender address", domain: "Sender domain", ip: "IP address or range", url: "URL or link domain", hash: "File SHA-256", subject: "Subject contains" };
const MATCH_HINT: Record<string, string> = { sender: "accounts@supplier.co.uk", domain: "supplier.co.uk", ip: "81.2.69.0/24", url: "bad-site.example", hash: "64 hex characters", subject: "Your parcel is waiting" };

function ListsTab() {
  const { tenantId, me, tenantName, can } = useApp();
  const tenants = me?.tenants ?? [];
  const { data, error, reload } = useListData<ListEntry>("email-security/lists", { tenant_id: tenantId });
  const { run, busy } = useAction();
  const [draft, setDraft] = useState({ tenantId: tenantId ?? "", kind: "block", match: "domain", value: "", note: "", expires: "" });
  const [kind, setKind] = useState("");
  const [search, setSearch] = useState("");
  const add = async () => {
    const { expires, ...rest } = draft;
    const ok = await run(() => api("email-security/lists", { method: "POST", body: { ...rest, expiresAt: expires ? new Date(expires).toISOString() : null } }),
                         `${draft.kind === "allow" ? "Allowed" : "Blocked"} ${draft.value}.`);
    if (ok) { setDraft({ ...draft, value: "", note: "", expires: "" }); reload(); }
  };
  const remove = async (e: ListEntry) => {
    await run(() => api(`email-security/lists/${e.id}`, { method: "DELETE" }), `Removed ${e.value}.`);
    reload();
  };
  const rows = (data ?? []).filter((e) => (!kind || e.kind === kind) && (!search || `${e.value} ${e.note}`.toLowerCase().includes(search.toLowerCase())));
  return (
    <>
      <ErrorNote error={error} />
      <div className="card small muted">Lists are checked after mail flow rules and before the policies. <b>Allow</b> skips spam and phishing checks (never malware checks, and never for
        a sender that fails DMARC, so a forged address is not trusted). <b>Block</b> quarantines (or, for an IP at the gateway, refuses the connection). An entry on your MSP
        tenant applies to every customer. Give temporary entries an expiry date.</div>
      {can("configure") && <div className="card" style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        <select value={draft.tenantId} onChange={(e) => setDraft({ ...draft, tenantId: e.target.value })} aria-label="Customer">
          <option value="">Customer…</option>{tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
        </select>
        <select value={draft.kind} onChange={(e) => setDraft({ ...draft, kind: e.target.value })} aria-label="Allow or block"><option value="block">Block</option><option value="allow">Allow</option></select>
        <select value={draft.match} onChange={(e) => setDraft({ ...draft, match: e.target.value })} aria-label="What to match">
          {Object.entries(MATCH_TEXT).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select>
        <input placeholder={MATCH_HINT[draft.match]} value={draft.value} onChange={(e) => setDraft({ ...draft, value: e.target.value })} style={{ minWidth: 200 }} />
        <input placeholder="Note (why)" value={draft.note} onChange={(e) => setDraft({ ...draft, note: e.target.value })} />
        <label className="small">Expires <input type="date" value={draft.expires} onChange={(e) => setDraft({ ...draft, expires: e.target.value })} /></label>
        <button className="primary" disabled={busy || !draft.tenantId || !draft.value} onClick={add}>Add</button>
      </div>}
      <div className="card" style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
        <select value={kind} onChange={(e) => setKind(e.target.value)} aria-label="Show"><option value="">Allow and block</option><option value="allow">Allow only</option><option value="block">Block only</option></select>
        <input placeholder="Search entries" value={search} onChange={(e) => setSearch(e.target.value)} style={{ flex: 1 }} />
      </div>
      <div className="card">
        <Table rows={data ? rows : undefined} empty="No allow or block entries."
               columns={[
                 { key: "kind", label: "", render: (e) => <><Pill value={e.kind} tone={e.kind === "allow" ? "good" : "bad"} />{e.expired && <div><Pill value="expired" tone="muted" /></div>}</> },
                 { key: "value", label: "Matches", render: (e) => <><span className="mono" style={{ wordBreak: "break-all" }}>{e.value}</span><div className="small muted">{MATCH_TEXT[e.match] ?? e.match}</div></> },
                 { key: "tenantId", label: "Customer", render: (e) => tenantName(e.tenantId) },
                 { key: "hits", label: "Hits", render: (e) => <>{e.hits}<div className="small muted">{e.lastHitAt ? `last ${ago(e.lastHitAt)}` : "never"}</div></> },
                 { key: "expiresAt", label: "Expires", render: (e) => e.expiresAt ? <span className={e.expired ? "muted" : ""}>{e.expiresAt.slice(0, 10)}</span> : <span className="muted small">never</span> },
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
