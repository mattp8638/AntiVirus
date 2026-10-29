import { displayValue } from "../components/DisplayValue";
import { Fragment, useState } from "react";
import { Link } from "react-router-dom";
import { ago, api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { Modal, PageHead, Pill, Sev, Table, useAction, useData, useListData } from "../components/ui";
import { EvidenceList } from "../components/Evidence";

interface Member { email: string; name: string; role: string }

const SNOOZE = [{ label: "1 hour", minutes: 60 }, { label: "4 hours", minutes: 240 }, { label: "1 day", minutes: 1440 }, { label: "1 week", minutes: 10080 }];

export default function Alerts() {
  const { tenantId, tenantName, can } = useApp();
  const [status, setStatus] = useState("new");
  const [severity, setSeverity] = useState("");
  const [owner, setOwner] = useState("");
  const [snoozed, setSnoozed] = useState("hide");
  const { data, reload } = useListData<any>("alerts", { tenant_id: tenantId, status, severity, assignee: owner, snoozed });
  const { data: members } = useListData<Member>("psa/members");
  const [open, setOpen] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const { run, busy } = useAction();
  const toggle = (id: string) => setSelected((current) => {
    const next = new Set(current);
    if (next.has(id)) next.delete(id); else next.add(id);
    return next;
  });
  const bulk = async (body: Record<string, unknown>, message: string) => {
    if (await run(() => api("alerts/bulk", { body: { ids: [...selected], ...body } }), message)) { setSelected(new Set()); reload(); }
  };
  return (
    <>
      <PageHead title="Alerts" subtitle="Every rule hit at medium or above. Related alerts on a device roll up into one incident. Take an alert to own it, or snooze it to take it out of the queue for a while." />
      <div className="row" style={{ marginBottom: 12, flexWrap: "wrap" }}>
        <select value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status">
          <option value="">Any status</option><option value="new">New</option><option value="triaged">Triaged</option>
          <option value="resolved">Resolved</option><option value="false_positive">False positive</option>
        </select>
        <select value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Severity">
          <option value="">Any severity</option>{["critical", "high", "medium", "low"].map((s) => <option key={s}>{s}</option>)}
        </select>
        <select value={owner} onChange={(e) => setOwner(e.target.value)} aria-label="Owner">
          <option value="">Anyone's</option><option value="me">Mine</option><option value="unassigned">Unassigned</option>
          {(members ?? []).map((m) => <option key={m.email} value={m.email}>{m.name}</option>)}
        </select>
        <select value={snoozed} onChange={(e) => setSnoozed(e.target.value)} aria-label="Snoozed">
          <option value="hide">Hide snoozed</option><option value="only">Snoozed only</option><option value="all">Include snoozed</option>
        </select>
      </div>
      {selected.size > 0 && can("respond") && (
        <div className="card row" style={{ marginBottom: 12, flexWrap: "wrap", gap: 8 }}>
          <b>{selected.size} selected</b>
          <button className="primary" disabled={busy} onClick={() => bulk({ assignee: "me", acknowledge: true }, "Assigned to you")}>Take</button>
          <select value="" disabled={busy} aria-label="Assign selected" onChange={(e) => e.target.value && bulk({ assignee: e.target.value === "-" ? "" : e.target.value }, "Alerts reassigned")}>
            <option value="">Assign to…</option><option value="-">Nobody</option>
            {(members ?? []).map((m) => <option key={m.email} value={m.email}>{m.name}</option>)}
          </select>
          <select value="" disabled={busy} aria-label="Snooze selected" onChange={(e) => e.target.value && bulk({ snoozeMinutes: Number(e.target.value) }, "Alerts snoozed")}>
            <option value="">Snooze for…</option>{SNOOZE.map((o) => <option key={o.minutes} value={o.minutes}>{o.label}</option>)}
          </select>
          <button disabled={busy} onClick={() => bulk({ status: "resolved" }, "Alerts resolved")}>Resolve</button>
          <button disabled={busy} onClick={() => bulk({ status: "false_positive" }, "Marked false positive")}>False positive</button>
          <span className="spacer" />
          <button className="ghost" onClick={() => setSelected(new Set())}>Clear</button>
        </div>
      )}
      <div className="card">
        <Table rows={data} onRow={(r) => setOpen(r.id)} empty="No alerts match."
               columns={[
                         ...(can("respond") ? [{ key: "sel", label: "", render: (r: any) => <input type="checkbox" checked={selected.has(r.id)} aria-label={`Select ${r.title}`}
                                                                                                 onClick={(e) => e.stopPropagation()} onChange={() => toggle(r.id)} /> }] : []),
                         { key: "severity", label: "Sev", render: (r) => <Sev level={r.severity} /> },
                         { key: "title", label: "Alert", render: (r) => <><b>{displayValue(r.title)}</b><div className="small muted mono">{displayValue(r.details?.process || r.details?.file || "")}</div></> },
                         { key: "hostname", label: "Device" },
                         { key: "tenantId", label: "Tenant", render: (r) => tenantName(r.tenantId) },
                         { key: "assignee", label: "Owner", render: (r) => <>{r.assignee ? <span className="small">{displayValue(r.assignee)}</span> : <span className="small muted">unassigned</span>}
                           {r.snoozed && <div className="small muted">snoozed until {fmtTime(r.snoozedUntil)}</div>}</> },
                         { key: "mitre", label: "MITRE", render: (r) => r.mitre.filter((m: string) => m.startsWith("T")).join(", ") },
                         { key: "events", label: "Events", render: (r) => r.eventIds.length },
                         { key: "status", label: "Status", render: (r) => <Pill value={r.status} /> },
                         { key: "createdAt", label: "When", render: (r) => ago(r.createdAt) }]} />
      </div>
      {open && <AlertDrawer id={open} members={members ?? []} onClose={() => { setOpen(null); reload(); }} />}
    </>
  );
}

function AlertDrawer({ id, members, onClose }: { id: string; members: Member[]; onClose: () => void }) {
  const { can, me } = useApp();
  const { data, reload } = useData<any>(`alerts/${id}`);
  const { run } = useAction();
  const triage = async (body: Record<string, unknown>, message: string) => {
    await run(() => api(`alerts/${id}`, { method: "PATCH", body }), message);
    reload();
  };
  const setStatus = async (status: string, suppress = false) => {
    await run(() => api(`alerts/${id}`, { method: "PATCH", body: { status, suppress } }), suppress ? "Marked false positive and tuned the rule for this tenant" : "Alert updated");
    reload();
  };
  const trust = async () => {
    await run(() => api(`alerts/${id}`, { method: "PATCH", body: { status: "false_positive", trust: true } }),
      "File trusted: its other alerts are closed, and agents stop flagging it at their next policy check-in");
    reload();
  };
  if (!data) return null;
  const a = data.alert;
  const fileSha = a.details?.sha256 || (a.details?.evidence || []).map((e: any) => e.file?.sha256).find(Boolean);
  return (
    <Modal title={a.title} onClose={onClose}
           footer={can("respond") && <>
             <button onClick={() => setStatus("triaged")}>Triage</button>
             <button onClick={() => setStatus("resolved")}>Resolve</button>
             <button onClick={() => setStatus("false_positive")}>False positive</button>
             {a.details?.process && <button className="primary" onClick={() => setStatus("false_positive", true)}>False positive + suppress this process</button>}
             {fileSha && <button className="primary" title={`Adds ${fileSha} to the tenant's allow list`} onClick={trust}>Not malware: trust this file</button>}
           </>}>
      <div className="row"><Sev level={a.severity} /><Pill value={a.status} />{a.incidentId && <Link to={`/incidents/${a.incidentId}`}>Open incident →</Link>}</div>
      <div className="row" style={{ marginTop: 10, flexWrap: "wrap", gap: 8 }}>
        <span className="small">Owner: <b>{a.assignee || "nobody"}</b>{a.acknowledgedAt && <span className="muted"> · taken {ago(a.acknowledgedAt)} by {displayValue(a.acknowledgedBy)}</span>}</span>
        {can("respond") && <>
          {a.assignee !== me?.user.email && <button className="small" onClick={() => triage({ assignee: "me", acknowledge: true }, "It's yours")}>Take it</button>}
          <select className="small" value="" aria-label="Assign" onChange={(e) => e.target.value && triage({ assignee: e.target.value === "-" ? "" : e.target.value }, "Owner changed")}>
            <option value="">Assign to…</option><option value="-">Nobody</option>
            {members.map((m) => <option key={m.email} value={m.email}>{m.name}</option>)}
          </select>
          {a.snoozedUntil && new Date(a.snoozedUntil) > new Date()
            ? <button className="small" onClick={() => triage({ unsnooze: true }, "Back in the queue")}>Snoozed until {fmtTime(a.snoozedUntil)}: wake now</button>
            : <select className="small" value="" aria-label="Snooze" onChange={(e) => e.target.value && triage({ snoozeMinutes: Number(e.target.value) }, "Snoozed")}>
                <option value="">Snooze for…</option>{SNOOZE.map((o) => <option key={o.minutes} value={o.minutes}>{o.label}</option>)}
              </select>}
        </>}
      </div>
      <dl className="kv" style={{ marginTop: 12 }}>
        <dt>Rule</dt><dd>{displayValue(data.rule?.title)} <span className="muted small mono">{displayValue(a.ruleId)}</span></dd>
        <dt>MITRE ATT&CK</dt><dd>{a.mitre.map((m: string) => <span key={m} className="chip">{m}</span>)}</dd>
        <dt>First seen</dt><dd>{fmtTime(a.createdAt)}</dd>
        {Object.entries(a.details || {}).filter(([k, v]) => !["description", "evidence", "falsePositives"].includes(k) && (typeof v !== "object" || v === null)).map(([k, v]) =>
          <Fragment key={k}><dt>{k}</dt><dd className="mono small" style={{ wordBreak: "break-all" }}>{String(v)}</dd></Fragment>)}
      </dl>
      {a.details?.description && <p className="muted">{displayValue(a.details.description)}</p>}
      <h3 style={{ marginTop: 16 }}>Evidence</h3>
      <EvidenceList details={a.details} />
      <details style={{ marginTop: 14 }}><summary className="small">Raw events ({displayValue(data.events.length)})</summary>
        <pre>{JSON.stringify(data.events.slice(0, 5).map((e: any) => ({ at: e.occurredAt, type: e.eventType, ...e.fields })), null, 2)}</pre>
      </details>
      {data.processContext.length > 0 && (
        <>
          <h3 style={{ marginTop: 16 }}>Process context (±5 minutes)</h3>
          <Table rows={data.processContext} columns={[
            { key: "occurredAt", label: "Time", render: (e) => new Date(e.occurredAt).toLocaleTimeString() },
            { key: "eventType", label: "Event" },
            { key: "pid", label: "PID", render: (e) => e.fields.ProcessId ?? "" },
            { key: "detail", label: "Detail", render: (e) => <span className="mono small">{displayValue(e.fields.CommandLine || e.fields.TargetFilename || e.fields.DestinationIp || e.summary)}</span> },
          ]} />
        </>
      )}
    </Modal>
  );
}
