import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ago, api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { ErrorNote, PageHead, Pill, Sev, Table, useAction, useData } from "../components/ui";
import { CommandModal } from "./DeviceDetail";

export default function IncidentDetail() {
  const { id } = useParams();
  const { me, can, tenantName } = useApp();
  const { data, error, reload } = useData<any>(`incidents/${id}`);
  const [note, setNote] = useState("");
  const [action, setAction] = useState<string | null>(null);
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
                  <select value={inc.status} onChange={(e) => update({ status: e.target.value }, "Status updated")} aria-label="Status">
                    {["open", "investigating", "contained", "resolved", "closed"].map((s) => <option key={s}>{s}</option>)}
                  </select>
                </>} />
      <div className="grid side">
        <div>
          <div className="card">
            <h3>Alerts ({data.alerts.length})</h3>
            <Table rows={data.alerts} columns={[{ key: "severity", label: "Sev", render: (a) => <Sev level={a.severity} /> },
              { key: "title", label: "Alert" }, { key: "mitre", label: "MITRE", render: (a) => a.mitre.join(", ") },
              { key: "process", label: "Process", render: (a) => <span className="mono small">{a.details?.process ?? ""}</span> },
              { key: "createdAt", label: "When", render: (a) => ago(a.createdAt) }]} />
          </div>
          <div className="card">
            <h3>Response actions</h3>
            <Table rows={data.commands} empty="No actions taken yet." columns={[{ key: "type", label: "Action" },
              { key: "status", label: "Status", render: (c) => <Pill value={c.status} /> }, { key: "issuedBy", label: "By" },
              { key: "targetPath", label: "Target", render: (c) => <span className="mono small">{c.targetPath}</span> },
              { key: "createdAt", label: "When", render: (c) => ago(c.createdAt) }]} />
          </div>
          <div className="card">
            <h3>Timeline</h3>
            <div className="timeline">
              {[...inc.timeline].reverse().map((item: any, i: number) => (
                <div key={i} className={`item ${item.kind}`}>
                  <div className="small muted">{fmtTime(item.at)} · {item.kind}{item.by ? ` · ${item.by}` : ""}</div>
                  <div>{item.text}</div>
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
              <dt>Device</dt><dd>{data.device ? <Link to={`/devices/${data.device.id}`}>{data.device.hostname}</Link> : "—"}</dd>
              <dt>Owner</dt><dd>{inc.assignee || "Unassigned"}</dd>
              <dt>MITRE</dt><dd>{inc.mitre.map((m: string) => <span key={m} className="chip">{m}</span>)}</dd>
              <dt>Ticket</dt><dd>{data.ticket ? <Link to="/service-desk">#{data.ticket.number} · {data.ticket.status}</Link>
                : can("respond") && <button className="small" onClick={() => run(() => api(`incidents/${inc.id}/ticket`, { body: {} }), "Ticket opened").then(reload)}>Open ticket</button>}</dd>
            </dl>
          </div>
          <div className="card">
            <h3>Playbook: {data.playbook?.name ?? "none"} ({done}/{inc.checklist.length})</h3>
            {inc.checklist.map((item: any, i: number) => (
              <label key={i} className="row" style={{ alignItems: "flex-start", flexWrap: "nowrap", padding: "6px 0", borderBottom: "1px solid #172138" }}>
                <input type="checkbox" checked={item.done} disabled={!can("respond")} onChange={() => toggleItem(i)} />
                <span><span className={`badge ${item.stage === "closure_gate" ? "tone-warn" : "tone-blue"}`}>{item.stage.replace(/_/g, " ")}</span> {item.task}</span>
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
