import { displayValue } from "../components/DisplayValue";
import { IncidentEvidence } from "./SocWorkflows";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ago, api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { ErrorNote, PageHead, Pill, Sev, Table, useAction, useData } from "../components/ui";
import { CommandModal } from "./DeviceDetail";
import { EvidenceList, Indicators } from "../components/Evidence";

export default function IncidentDetail() {
  const { id } = useParams();
  const { me, can, tenantName } = useApp();
  const { data, error, reload } = useData<any>(`incidents/${id}`);
  const [note, setNote] = useState("");
  const [action, setAction] = useState<string | null>(null);
  const [openAlert, setOpenAlert] = useState<string | null>(null);
  const { run, busy } = useAction();

  if (error) return <ErrorNote error={error} />;
  if (!data) return <div className="empty">Loading…</div>;
  const inc = data.incident;

  const update = async (body: any, message: string) => {
    await run(() => api(`incidents/${inc.id}`, { method: "PATCH", body }), message);
    reload();
  };
  const toggleItem = (index: number) => {
    const checklist = inc.checklist.map((item: any, i: number) => (i === index ? { ...item, done: !item.done } : item));
    update({ checklist }, "Checklist updated");
  };
  const done = inc.checklist.filter((i: any) => i.done).length;

  return (
    <>
      <PageHead title={inc.title}
                subtitle={<><Sev level={inc.severity} /> <Pill value={inc.status} /> · {tenantName(inc.tenantId)} · opened {fmtTime(inc.createdAt)}</>}
                actions={can("respond") && <>
                  {!inc.assignee && <button onClick={() => update({ assignee: me?.user.email }, "Assigned to you")}>Assign to me</button>}
                  {data.device && <button className="danger" onClick={() => setAction("device.isolate")}>Contain device</button>}
                  {data.device && <button onClick={() => setAction("")}>Response action…</button>}
                  <button onClick={async () => { const t = window.prompt("What was restored? (systems back in service, data restored, accounts re-enabled)"); if (t) { await api(`incidents/${inc.id}/restoration`, { body: { text: t } }); reload(); } }}>Record restoration</button>
                  <button onClick={async () => { const r = await api(`incidents/${inc.id}/report`); const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([JSON.stringify(r, null, 2)], { type: "application/json" })); a.download = `incident-${inc.id}.json`; a.click(); }}>Full record</button>
                  <select value={inc.status} onChange={(e) => update({ status: e.target.value }, "Status updated")} aria-label="Status">
                    {["open", "investigating", "contained", "resolved", "closed"].map((s) => <option key={s}>{s}</option>)}
                  </select>
                </>} />
      {inc.playbook === "backup_failure" && <BackupRecovery incidentId={inc.id} onDone={reload} />}
      <IncidentEvidence incidentId={inc.id} />
      <div className="grid side">
        <div>
          <div className="card">
            <h3>Alerts ({displayValue(data.alerts.length)})</h3>
            <p className="small muted" style={{ marginTop: 0 }}>Click an alert to see its evidence: the file, hash, process, user and where it came from.</p>
            <Table rows={data.alerts} onRow={(a) => setOpenAlert(openAlert === a.id ? null : a.id)} columns={[{ key: "severity", label: "Sev", render: (a) => <Sev level={a.severity} /> },
              { key: "title", label: "Alert", render: (a) => <><b>{displayValue(a.title)}</b>{a.details?.threat && <div className="small muted">{displayValue(a.details.threat)}</div>}</> },
              { key: "process", label: "File / process", render: (a) => <span className="mono small" style={{ wordBreak: "break-all" }}>{displayValue(a.details?.file || a.details?.process || "")}</span> },
              { key: "mitre", label: "MITRE", render: (a) => a.mitre.join(", ") },
              { key: "createdAt", label: "When", render: (a) => ago(a.createdAt) }]} />
            {openAlert && (() => { const a = data.alerts.find((x: any) => x.id === openAlert); return a && (
              <div className="card evidence-card">
                <div className="row"><Sev level={a.severity} /><b style={{ flex: 1 }}>{displayValue(a.title)}</b><button className="ghost small" onClick={() => setOpenAlert(null)}>Close</button></div>
                {a.details?.description && <p className="small muted">{displayValue(a.details.description)}</p>}
                <EvidenceList details={a.details} />
              </div>); })()}
          </div>
          <div className="card">
            <h3>Response actions</h3>
            <Table rows={data.commands} empty="No actions taken yet." columns={[{ key: "type", label: "Action" },
              { key: "status", label: "Status", render: (c) => <Pill value={c.status} /> }, { key: "issuedBy", label: "By" },
              { key: "targetPath", label: "Target", render: (c) => <span className="mono small">{displayValue(c.targetPath)}</span> },
              { key: "createdAt", label: "When", render: (c) => ago(c.createdAt) }]} />
          </div>
          <div className="card">
            <h3>Timeline</h3>
            <div className="timeline">
              {[...inc.timeline].reverse().map((item: any, i: number) => (
                <div key={i} className={`item ${item.kind}`}>
                  <div className="small muted">{fmtTime(item.at)} · {displayValue(item.kind)}{item.by ? ` · ${item.by}` : ""}</div>
                  <div>{displayValue(item.text)}</div>
                </div>
              ))}
            </div>
            {can("respond") && (
              <div className="row" style={{ marginTop: 8 }}>
                <input style={{ flex: 1 }} placeholder="Add an investigation note" value={note} onChange={(e) => setNote(e.target.value)} />
                <button disabled={!note || busy} onClick={async () => { await update({ note }, "Note added"); setNote(""); }}>Add note</button>
              </div>
            )}
          </div>
        </div>
        <div>
          <div className="card">
            <h3>Context</h3>
            <dl className="kv">
              <dt>Device</dt><dd>{data.device ? <Link to={`/devices/${data.device.id}`}>{displayValue(data.device.hostname)}</Link> : "—"}</dd>
              <dt>Owner</dt><dd>{displayValue(inc.assignee || "Unassigned")}</dd>
              <dt>MITRE</dt><dd>{inc.mitre.map((m: string) => <span key={m} className="chip">{m}</span>)}</dd>
              <dt>Ticket</dt><dd>{data.ticket ? <Link to="/service-desk">#{displayValue(data.ticket.number)} · {displayValue(data.ticket.status)}</Link>
                : can("respond") && <button className="small" onClick={() => run(() => api(`incidents/${inc.id}/ticket`, { body: {} }), "Ticket opened").then(reload)}>Open ticket</button>}</dd>
            </dl>
          </div>
          <div className="card">
            <h3>Indicators</h3>
            <Indicators indicators={data.indicators || {}} />
          </div>
          <div className="card">
            <h3>Playbook: {displayValue(data.playbook?.name ?? "none")} ({displayValue(done)}/{displayValue(inc.checklist.length)})</h3>
            {inc.checklist.map((item: any, i: number) => (
              <label key={i} className="row" style={{ alignItems: "flex-start", flexWrap: "nowrap", padding: "6px 0", borderBottom: "1px solid #172138" }}>
                <input type="checkbox" checked={item.done} disabled={!can("respond")} onChange={() => toggleItem(i)} />
                <span><span className={`badge ${item.stage === "closure_gate" ? "tone-warn" : "tone-blue"}`}>{displayValue(item.stage.replace(/_/g, " "))}</span> {displayValue(item.task)}</span>
              </label>
            ))}
            {data.playbook?.key_questions && (
              <><h3 style={{ marginTop: 12 }}>Key questions</h3>
                <ul className="small">{data.playbook.key_questions.map((q: string) => <li key={q}>{q.replace(/^q_/, "").replace(/_/g, " ")}?</li>)}</ul></>
            )}
          </div>
        </div>
      </div>
      {action !== null && data.device && <CommandModal device={data.device} initial={action} incidentId={inc.id} onClose={() => { setAction(null); reload(); }} />}
    </>
  );
}

/** FLOW-07: recover the machine's newest good backup (or an older one) in an isolated VM on a boot host; the result,
 * with the measured RTO and RPO, is added to the incident's evidence. */
function BackupRecovery({ incidentId, onDone }: { incidentId: string; onDone: () => void }) {
  const { can } = useApp();
  const { run, busy } = useAction();
  const { data, reload } = useData<any>(`backup/incidents/${incidentId}/recovery`);
  const [imageId, setImageId] = useState("");
  const when = (t: number) => new Date(t * 1000).toLocaleString();
  const dur = (s?: number | null) => (s == null ? "—" : s < 120 ? `${s}s` : s < 7200 ? `${Math.round(s / 60)} min` : `${(s / 3600).toFixed(1)} h`);
  if (!data) return null;
  const results = (data.runs as any[]).filter((r) => r.kind === "recovery_result");
  const pending = (data.runs as any[]).filter((r) => r.kind === "recovery_requested" && !results.some((x) => x.jobId === r.jobId));
  const chosen = data.candidates.find((c: any) => c.imageId === imageId) ?? data.candidates[0];
  return (
    <div className="card">
      <h3>Recover in isolation</h3>
      <p className="small muted" style={{ marginTop: 0 }}>Boots a backup of this machine as a VM on a boot host, with no network route to the production machine, and checks it starts. The result, with the measured recovery time (RTO) and recovery point (RPO), is added to the evidence. Needs your password again.</p>
      {data.candidates.length === 0 ? <p className="small">No bootable backup of this machine yet.</p> : (
        <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
          <select value={chosen?.imageId ?? ""} onChange={(e) => setImageId(e.target.value)} aria-label="Backup to recover">
            {data.candidates.map((c: any) => <option key={c.imageId} value={c.imageId}>{when(c.createdUnix)} · {c.hostname}{c.bootHost ? "" : " (no boot host)"}</option>)}
          </select>
          {chosen?.bootHost && <span className="small muted">on {chosen.bootHost.name}{chosen.bootHost.online ? "" : " (offline: starts when it checks in)"}</span>}
          {can("respond") && <button className="primary" disabled={busy || !chosen?.bootHost || pending.length > 0}
            onClick={() => run(() => api(`backup/incidents/${incidentId}/recover`, { body: { imageId: chosen.imageId } }), "Isolated recovery started").then(() => { reload(); onDone(); })}>Recover in isolation</button>}
        </div>
      )}
      {pending.length > 0 && <p className="small"><Pill value="running" tone="blue" /> {pending[0].text}</p>}
      {results.length > 0 && <Table rows={results} columns={[
        { key: "outcome", label: "Result", render: (r) => <Pill value={r.outcome} tone={r.outcome === "verified" ? "good" : "bad"} /> },
        { key: "rtoSeconds", label: "RTO", render: (r) => dur(r.rtoSeconds) },
        { key: "rpoSeconds", label: "RPO", render: (r) => dur(r.rpoSeconds) },
        { key: "at", label: "When", render: (r) => fmtTime(r.at) }]} />}
    </div>
  );
}
