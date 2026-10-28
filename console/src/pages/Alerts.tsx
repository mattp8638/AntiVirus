import { displayValue } from "../components/DisplayValue";
import { Fragment, useState } from "react";
import { Link } from "react-router-dom";
import { ago, api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { Modal, PageHead, Pill, Sev, Table, useAction, useData, useListData } from "../components/ui";
import { EvidenceList } from "../components/Evidence";

export default function Alerts() {
  const { tenantId, tenantName } = useApp();
  const [status, setStatus] = useState("new");
  const [severity, setSeverity] = useState("");
  const { data, reload } = useListData<any>("alerts", { tenant_id: tenantId, status, severity });
  const [open, setOpen] = useState<string | null>(null);
  return (
    <>
      <PageHead title="Alerts" subtitle="Every rule hit at medium or above. Related alerts on a device roll up into one incident." />
      <div className="row" style={{ marginBottom: 12 }}>
        <select value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status">
          <option value="">Any status</option><option value="new">New</option><option value="triaged">Triaged</option>
          <option value="resolved">Resolved</option><option value="false_positive">False positive</option>
        </select>
        <select value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Severity">
          <option value="">Any severity</option>{["critical", "high", "medium", "low"].map((s) => <option key={s}>{s}</option>)}
        </select>
      </div>
      <div className="card">
        <Table rows={data} onRow={(r) => setOpen(r.id)} empty="No alerts match."
               columns={[{ key: "severity", label: "Sev", render: (r) => <Sev level={r.severity} /> },
                         { key: "title", label: "Alert", render: (r) => <><b>{displayValue(r.title)}</b><div className="small muted mono">{displayValue(r.details?.process || r.details?.file || "")}</div></> },
                         { key: "hostname", label: "Device" },
                         { key: "tenantId", label: "Tenant", render: (r) => tenantName(r.tenantId) },
                         { key: "mitre", label: "MITRE", render: (r) => r.mitre.filter((m: string) => m.startsWith("T")).join(", ") },
                         { key: "events", label: "Events", render: (r) => r.eventIds.length },
                         { key: "status", label: "Status", render: (r) => <Pill value={r.status} /> },
                         { key: "createdAt", label: "When", render: (r) => ago(r.createdAt) }]} />
      </div>
      {open && <AlertDrawer id={open} onClose={() => { setOpen(null); reload(); }} />}
    </>
  );
}

function AlertDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const { can } = useApp();
  const { data, reload } = useData<any>(`alerts/${id}`);
  const { run } = useAction();
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
