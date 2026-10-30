// The triage inbox: every item someone has to act on, from every module, in one list. The same monitor failing on 40
// devices is one item. Each has an owner, an SLA and snooze; from any item it is one click to raise a ticket, remote
// in, run a fix or bill the time.
import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ago, api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { displayValue } from "../components/DisplayValue";
import { JobDetail, useConnect } from "../components/rmm";
import { ErrorNote, Modal, PageHead, Pill, Sev, Table, useAction, useData, useListData } from "../components/ui";
import { promptDialog } from "../components/dialogs";
import { needsReview } from "../components/ScriptReview";
import { RunScript } from "./rmm/Scripts";

interface Item {
  key: string; kind: string; title: string; summary: string; severity: string; tenantId: string; customer: string;
  count: number; deviceIds: string[]; deviceCount: number; hostnames: string[]; owner: string | null; snoozedUntil: string | null;
  slaDueAt: string | null; breached: boolean; firstSeenAt: string; lastSeenAt: string | null; link: string; ticketId: string | null;
  dismissed: boolean; canDismiss: boolean;
}
interface Inbox { items: Item[]; counts: { open: number; mine: number; unassigned: number; breached: number; snoozed: number; byKind: Record<string, number> } }
interface Member { email: string; name: string }

export const KIND_LABELS: Record<string, string> = {
  alert: "Alerts", incident: "Incidents", ticket: "Tickets", patch: "Failed updates", job: "Failed jobs", elevation: "Admin requests",
  approval: "Approvals", m365: "Microsoft 365", grc: "Compliance", evidence: "Evidence",
};
const SNOOZE = [{ label: "1 hour", minutes: 60 }, { label: "4 hours", minutes: 240 }, { label: "1 day", minutes: 1440 }, { label: "1 week", minutes: 10080 }];
const VIEWS = [{ key: "all", label: "Everything open" }, { key: "mine", label: "Mine" }, { key: "unassigned", label: "Nobody's" }];

export function dueText(item: Pick<Item, "slaDueAt" | "breached">): string {
  if (!item.slaDueAt) return "";
  const minutes = Math.round((new Date(item.slaDueAt).getTime() - Date.now()) / 60000);
  const span = Math.abs(minutes) < 60 ? `${Math.abs(minutes)} min` : Math.abs(minutes) < 2880 ? `${Math.round(Math.abs(minutes) / 60)} h` : `${Math.round(Math.abs(minutes) / 1440)} d`;
  return item.breached ? `${span} over` : `due in ${span}`;
}

export default function InboxPage() {
  const { tenantId, can } = useApp();
  const [params] = useSearchParams();
  const [view, setView] = useState(() => params.get("view") ?? "all");
  const [kind, setKind] = useState("");
  const [severity, setSeverity] = useState("");
  const [snoozed, setSnoozed] = useState("hide");
  const [q, setQ] = useState("");
  const { data, error, reload } = useData<Inbox>("triage/items", { view, kind, severity, snoozed, q, tenant_id: tenantId });
  const { data: members } = useListData<Member>("psa/members");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [open, setOpen] = useState<string | null>(null);
  const { run, busy } = useAction();
  const items = data?.items;
  const toggle = (key: string) => setSelected((current) => {
    const next = new Set(current);
    if (next.has(key)) next.delete(key); else next.add(key);
    return next;
  });
  const act = async (path: string, body: Record<string, unknown>, message: string, keys = [...selected]) => {
    if (await run(() => api(`triage/${path}`, { body: { keys, ...body } }), message)) { setSelected(new Set()); reload(); }
  };
  const counts = data?.counts;
  return (
    <>
      <PageHead title="Inbox" subtitle="Everything that needs someone, from every module, in one list. Repeats collapse into one item: the same monitor failing on 40 devices is one line. Take an item, snooze it, or act on it in one click." />
      <div className="row" style={{ marginBottom: 12, flexWrap: "wrap", gap: 8 }}>
        <div className="tabs" role="tablist">
          {VIEWS.map((v) => <button key={v.key} role="tab" aria-selected={view === v.key} className={view === v.key ? "active" : ""} onClick={() => setView(v.key)}>
            {v.label}{counts ? ` (${v.key === "all" ? counts.open : v.key === "mine" ? counts.mine : counts.unassigned})` : ""}</button>)}
        </div>
        {counts && counts.breached > 0 && <Pill value={`${counts.breached} past SLA`} tone="bad" />}
        <select value={kind} onChange={(e) => setKind(e.target.value)} aria-label="Kind">
          <option value="">Every kind</option>
          {Object.entries(KIND_LABELS).map(([k, label]) => <option key={k} value={k}>{label}{counts?.byKind[k] ? ` (${counts.byKind[k]})` : ""}</option>)}
        </select>
        <select value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Severity">
          <option value="">Any severity</option>{["critical", "high", "medium", "low"].map((s) => <option key={s} value={s}>{s} and above</option>)}
        </select>
        <select value={snoozed} onChange={(e) => setSnoozed(e.target.value)} aria-label="Snoozed">
          <option value="hide">Hide snoozed and done</option><option value="only">Snoozed and done only{counts ? ` (${counts.snoozed})` : ""}</option><option value="all">Include snoozed and done</option>
        </select>
        <input placeholder="Search" value={q} onChange={(e) => setQ(e.target.value)} style={{ minWidth: 180 }} />
        <span className="spacer" />
        {can("configure") && can("manage_tenants") && <SlaSettingsButton />}
      </div>
      <ErrorNote error={error} />
      {selected.size > 0 && can("respond") && (
        <div className="card row" style={{ marginBottom: 12, flexWrap: "wrap", gap: 8 }}>
          <b>{selected.size} selected</b>
          <button className="primary" disabled={busy} onClick={() => act("assign", { owner: "me" }, "Yours now")}>Take</button>
          <select value="" disabled={busy} aria-label="Assign selected" onChange={(e) => e.target.value && act("assign", { owner: e.target.value === "-" ? "" : e.target.value }, "Reassigned")}>
            <option value="">Assign to…</option><option value="-">Nobody</option>
            {(members ?? []).map((m) => <option key={m.email} value={m.email}>{m.name}</option>)}
          </select>
          <select value="" disabled={busy} aria-label="Snooze selected" onChange={(e) => e.target.value && act("snooze", { minutes: Number(e.target.value) }, "Snoozed")}>
            <option value="">Snooze for…</option>{SNOOZE.map((o) => <option key={o.minutes} value={o.minutes}>{o.label}</option>)}
          </select>
          {snoozed !== "hide" && <button disabled={busy} onClick={() => act("snooze", { minutes: 0 }, "Back in the inbox")}>Unsnooze</button>}
          <button disabled={busy} title="Alerts are resolved; anything else stays hidden until it changes" onClick={() => act("dismiss", {}, "Done")}>Done</button>
          <button disabled={busy} onClick={() => act("ticket", {}, "Tickets raised")}>Raise tickets</button>
          <span className="spacer" />
          <button className="ghost" onClick={() => setSelected(new Set())}>Clear</button>
        </div>
      )}
      <div className="card">
        <Table rows={items?.map((i) => ({ ...i, id: i.key }))} onRow={(i) => setOpen(i.key)}
               empty={view === "mine" ? "Nothing is yours right now." : "Nothing needs anyone right now."}
               columns={[
                 ...(can("respond") ? [{ key: "sel", label: "", render: (i: Item) => <input type="checkbox" checked={selected.has(i.key)} aria-label={`Select ${i.title}`}
                                                                                            onClick={(e) => e.stopPropagation()} onChange={() => toggle(i.key)} /> }] : []),
                 { key: "severity", label: "Sev", render: (i) => <Sev level={i.severity === "info" ? "low" : i.severity} /> },
                 { key: "title", label: "Item", render: (i) => <>
                   <b>{displayValue(i.title)}</b> <span className="small muted">{KIND_LABELS[i.kind] ?? i.kind}</span>
                   {i.deviceCount > 1 && <> <Pill value={`${i.deviceCount} devices`} tone="blue" /></>}
                   <div className="small muted">{i.hostnames.join(", ")}{i.deviceCount > i.hostnames.length ? ` and ${i.deviceCount - i.hostnames.length} more` : ""}{i.hostnames.length && i.summary ? " · " : ""}{displayValue(i.summary)}</div></> },
                 { key: "customer", label: "Customer" },
                 { key: "owner", label: "Owner", render: (i) => i.owner ? <span className="small">{i.owner}</span> : <span className="small muted">nobody</span> },
                 { key: "sla", label: "SLA", render: (i) => <>{i.slaDueAt && <Pill value={dueText(i)} tone={i.breached ? "bad" : "muted"} />}
                   {i.snoozedUntil && <div className="small muted">snoozed until {fmtTime(i.snoozedUntil)}</div>}
                   {i.dismissed && <div className="small muted">done</div>}</> },
                 { key: "firstSeenAt", label: "Since", render: (i) => ago(i.firstSeenAt) },
               ]} />
      </div>
      {open && <ItemDrawer itemKey={open} members={members ?? []} onClose={() => { setOpen(null); reload(); }} />}
    </>
  );
}

function ItemDrawer({ itemKey, members, onClose }: { itemKey: string; members: Member[]; onClose: () => void }) {
  const { can } = useApp();
  const { data, error, reload } = useData<Item & { devices: any[] }>("triage/item", { key: itemKey });
  const { run, busy } = useAction();
  const { connect, busy: connecting } = useConnect();
  const [fixing, setFixing] = useState(false);
  const [jobId, setJobId] = useState<string | null>(null);
  const act = async (path: string, body: Record<string, unknown>, message: string, close = false) => {
    const result = await run(() => api<any>(`triage/${path}`, { body: { keys: [itemKey], key: itemKey, ...body } }), message);
    if (result) { if (close) onClose(); else reload(); }
    return result;
  };
  const logTime = async () => {
    const minutes = await promptDialog("Minutes spent (billed on the item's ticket; one is raised if it has none)", "15", { title: "Log time", required: true, inputMode: "numeric" });
    if (!minutes) return;
    const notes = await promptDialog("What did you do? (shown on the ticket)", "", { title: "Log time", multiline: true });
    if (notes === null) return;
    await act("time", { minutes: Number(minutes), notes }, "Time logged");
  };
  if (error) return <Modal title="Inbox item" onClose={onClose}><ErrorNote error={error} /></Modal>;
  if (!data) return null;
  const devices = data.devices ?? [];
  const remoteable = devices.filter((d) => d.approved && !d.retired && ["windows", "linux", "macos"].includes(d.platform));
  return (
    <Modal wide title={data.title} onClose={onClose}
           footer={can("respond") && <>
             <button className="primary" disabled={busy} onClick={() => act("assign", { owner: "me" }, "Yours now")}>Take</button>
             <select value="" disabled={busy} aria-label="Snooze" onChange={(e) => e.target.value && act("snooze", { minutes: Number(e.target.value) }, "Snoozed", true)}>
               <option value="">Snooze…</option>{SNOOZE.map((o) => <option key={o.minutes} value={o.minutes}>{o.label}</option>)}
             </select>
             {data.canDismiss && <button disabled={busy} onClick={() => act("dismiss", {}, data.kind === "alert" ? "Alerts resolved" : "Done", true)}>Done</button>}
           </>}>
      <div className="row" style={{ gap: 8, flexWrap: "wrap", marginBottom: 8 }}>
        <Sev level={data.severity === "info" ? "low" : data.severity} /> <Pill value={KIND_LABELS[data.kind] ?? data.kind} tone="blue" />
        <span className="small">{data.customer}</span>
        {data.slaDueAt && <Pill value={dueText(data)} tone={data.breached ? "bad" : "muted"} />}
        <span className="small muted">since {fmtTime(data.firstSeenAt)}{data.lastSeenAt ? ` · latest ${ago(data.lastSeenAt)}` : ""}</span>
      </div>
      {data.summary && <p style={{ whiteSpace: "pre-wrap" }}>{displayValue(data.summary)}</p>}
      <div className="row" style={{ gap: 8, flexWrap: "wrap", margin: "10px 0" }}>
        <label className="small">Owner <select value={data.owner && !data.owner.includes(",") ? data.owner : ""} disabled={!can("respond") || busy}
          onChange={(e) => act("assign", { owner: e.target.value }, "Owner changed")}>
          <option value="">Nobody</option>{members.map((m) => <option key={m.email} value={m.email}>{m.name}</option>)}
          {data.owner?.includes(",") && <option value="" disabled>{data.owner}</option>}
        </select></label>
        <span className="spacer" />
        {data.ticketId ? <Link className="btn" to={`/tickets/${data.ticketId}`}>Open ticket</Link>
          : (can("respond") || can("crm")) && <button disabled={busy} onClick={() => act("ticket", {}, "Ticket raised")}>Raise ticket</button>}
        {(can("respond") || can("crm")) && <button disabled={busy} onClick={logTime}>Log time</button>}
        {can("scripts") && devices.length > 0 && <button disabled={busy} onClick={() => setFixing(true)}>Run a fix…</button>}
        {data.link && <Link className="btn" to={data.link}>Open in {KIND_LABELS[data.kind] ?? "its page"}</Link>}
      </div>
      {devices.length > 0 && <>
        <h3>Devices ({data.deviceCount})</h3>
        <Table rows={devices} columns={[
          { key: "hostname", label: "Device", render: (d) => <Link to={`/devices/${d.id}`}>{displayValue(d.hostname)}</Link> },
          { key: "platform", label: "Platform" },
          { key: "lastSeenAt", label: "Last seen", render: (d) => (d.lastSeenAt ? ago(d.lastSeenAt) : "never") },
          { key: "remote", label: "", className: "right", render: (d) => can("remote") && remoteable.includes(d) &&
            <button className="small primary" disabled={connecting} onClick={() => connect(d.id, "desktop", data.ticketId ?? undefined)}>⧉ Connect</button> },
        ]} />
        {data.deviceCount > devices.length && <p className="small muted">Showing the first {devices.length}.</p>}
      </>}
      {fixing && <FixPicker deviceIds={devices.map((d) => d.id)} platforms={[...new Set(devices.map((d) => d.platform))]}
                            onClose={() => setFixing(false)} onStarted={(id) => { setFixing(false); setJobId(id); }} />}
      {jobId && <JobDetail jobId={jobId} onClose={() => setJobId(null)} />}
    </Modal>
  );
}

function FixPicker({ deviceIds, platforms, onClose, onStarted }: { deviceIds: string[]; platforms: string[]; onClose: () => void; onStarted: (jobId: string) => void }) {
  const { data } = useListData<any>("rmm/scripts");
  const [script, setScript] = useState<any>(null);
  const [q, setQ] = useState("");
  if (script) return <RunScript script={script} presetDeviceIds={deviceIds} onClose={onClose} onStarted={onStarted} />;
  const usable = (data || []).filter((s) => s.platforms.some((p: string) => platforms.includes(p)) && !needsReview(s.review)
    && (!q || `${s.name} ${s.description}`.toLowerCase().includes(q.toLowerCase())));
  return (
    <Modal title={`Run a fix on ${deviceIds.length} device${deviceIds.length === 1 ? "" : "s"}`} onClose={onClose}>
      <input placeholder="Search scripts" value={q} onChange={(e) => setQ(e.target.value)} style={{ width: "100%", marginBottom: 8 }} autoFocus />
      <Table rows={usable} onRow={setScript} empty="No scripts for these devices' platforms."
             columns={[{ key: "name", label: "Script", render: (s) => <><b>{displayValue(s.name)}</b><div className="small muted">{displayValue(s.description)}</div></> },
                       { key: "category", label: "Category" }]} />
    </Modal>
  );
}

function SlaSettingsButton() {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button className="ghost" onClick={() => setOpen(true)}>SLA targets</button>
      {open && <SlaSettings onClose={() => setOpen(false)} />}
    </>
  );
}

function SlaSettings({ onClose }: { onClose: () => void }) {
  const { data } = useData<{ slaHours: Record<string, number>; defaults: Record<string, number> }>("triage/settings");
  const [hours, setHours] = useState<Record<string, string> | null>(null);
  const { run, busy } = useAction();
  if (!data) return null;
  const values = hours ?? Object.fromEntries(Object.entries(data.slaHours).map(([k, v]) => [k, String(v)]));
  const save = async () => {
    const body = { slaHours: Object.fromEntries(Object.entries(values).map(([k, v]) => [k, Number(v)])) };
    if (await run(() => api("triage/settings", { method: "PUT", body }), "SLA targets saved")) onClose();
  };
  return (
    <Modal title="Inbox SLA targets" onClose={onClose} footer={<button className="primary" disabled={busy} onClick={save}>Save</button>}>
      <p className="small muted">How long an item of each severity may wait, from when it first appeared, before it shows as past SLA.
        Tickets keep their service board's SLA and approvals their expiry.</p>
      <div className="form-grid">
        {Object.keys(data.defaults).map((severity) => (
          <label key={severity} className="field">{severity} (hours)
            <input type="number" min={0.25} step={0.25} value={values[severity]} onChange={(e) => setHours({ ...values, [severity]: e.target.value })} /></label>
        ))}
      </div>
    </Modal>
  );
}
