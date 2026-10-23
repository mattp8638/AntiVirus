import { useState } from "react";
import { api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { Bars, Modal, PageHead, Pill, Sev, Stat, Table, useAction, useData } from "../components/ui";

// "fixed" is not offered: only a rescan that no longer finds the vulnerability marks it fixed.
const MANUAL_STATUSES = ["open", "patching", "mitigated", "accepted"];

export default function Vulnerabilities() {
  const { tenantId, can } = useApp();
  const [status, setStatus] = useState("open");
  const [severity, setSeverity] = useState("");
  const { data, reload } = useData<any[]>("vulnerabilities", { tenant_id: tenantId, status, severity });
  const { data: trends } = useData<any[]>("vulnerabilities/trends", { tenant_id: tenantId, weeks: 12 });
  const [open, setOpen] = useState<any>(null);
  const [accepting, setAccepting] = useState<any>(null);
  const { run, busy } = useAction();
  const kev = data?.filter((v) => v.knownExploited).length ?? 0;
  const exposures = data?.reduce((n, v) => n + v.devices.length, 0) ?? 0;
  const overdue = data?.reduce((n, v) => n + (v.overdue || 0), 0) ?? 0;
  const setRowStatus = async (row: any, next: string) => {
    if (next === "accepted") { setAccepting(row); return; }
    if (await run(() => api(`vulnerabilities/${row.id}`, { method: "PATCH", body: { status: next } }), "Status updated")) { reload(); setOpen(null); }
  };
  return (
    <>
      <PageHead title="Vulnerabilities" subtitle="Software inventory matched against OSV.dev, ranked by risk: CVSS, CISA's Known Exploited Vulnerabilities catalogue and how critical each device is. Fixes are confirmed by rescanning."
                actions={can("respond") && <button className="primary" disabled={busy} onClick={() => run(() => api<any>("vulnerabilities/scan", { body: { tenantId: tenantId || undefined } }), "Scan queued for all devices in scope")}>Scan now</button>} />
      <div className="grid k4">
        <Stat label="Unique vulnerabilities" value={data?.length ?? "—"} />
        <Stat label="Known exploited (fix first)" value={kev} accent={kev ? "red" : "green"} />
        <Stat label="Device exposures" value={exposures} />
        <Stat label="Past remediation due date" value={overdue} accent={overdue ? "red" : "green"} />
      </div>
      {trends && trends.length > 1 && (
        <div className="card" style={{ marginTop: 14 }}>
          <div className="label muted small">Open critical + high vulnerabilities by week (fixed ones are counted from the rescan that verified them)</div>
          <Bars data={trends.map((t) => ({ label: t.weekEnding.slice(5), value: t.open.critical + t.open.high }))} height={110} />
        </div>
      )}
      <div className="row" style={{ margin: "16px 0 12px" }}>
        <select value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status"><option value="">Any status</option>{[...MANUAL_STATUSES, "fixed"].map((s) => <option key={s}>{s}</option>)}</select>
        <select value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Severity"><option value="">Any severity</option>{["critical", "high", "medium", "low"].map((s) => <option key={s}>{s}</option>)}</select>
      </div>
      <div className="card">
        <Table rows={data?.map((v) => ({ ...v, id: v.vulnId }))} onRow={setOpen} empty="No vulnerabilities in this view."
               columns={[{ key: "priority", label: "Priority", render: (v) => <Pill value={v.priority} tone={v.priority === "P1" ? "bad" : v.priority === "P2" ? "warn" : "muted"} /> },
                         { key: "riskScore", label: "Risk", render: (v) => <b>{v.riskScore}</b>, className: "right" },
                         { key: "vulnId", label: "Vulnerability", render: (v) => <><b>{v.vulnId}</b> {v.knownExploited && <Pill value="actively exploited" tone="bad" />} {v.overdue > 0 && <Pill value={`${v.overdue} overdue`} tone="bad" />}<div className="small muted">{v.summary.slice(0, 110)}</div></> },
                         { key: "severity", label: "Severity", render: (v) => <Sev level={v.severity} /> },
                         { key: "packages", label: "Package", render: (v) => v.packages.join(", ") },
                         { key: "fixedVersion", label: "Fix", render: (v) => v.fixedVersion || "—" },
                         { key: "devices", label: "Devices", render: (v) => v.devices.length, className: "right" }]} />
      </div>
      {open && (
        <Modal title={open.vulnId} onClose={() => setOpen(null)}
               footer={can("respond") && open.devices.some((d: any) => !d.ticketId && d.status !== "fixed") && (
                 <button className="primary" disabled={busy} onClick={async () => {
                   const ids = open.devices.filter((d: any) => !d.ticketId && d.status !== "fixed" && d.status !== "accepted").map((d: any) => d.id);
                   const result = await run(() => api<any>("vulnerabilities/ticket", { body: { ids } }), "Remediation ticket opened");
                   if (result) { reload(); setOpen(null); }
                 }}>Open remediation ticket</button>)}>
          <p>{open.summary}</p>
          <p><b>Recommendation:</b> {open.recommendation}</p>
          <p><a href={`https://osv.dev/vulnerability/${open.vulnId}`} target="_blank" rel="noreferrer">OSV record</a> · <a href={`https://nvd.nist.gov/vuln/detail/${open.vulnId}`} target="_blank" rel="noreferrer">NVD</a></p>
          <Table rows={open.devices} columns={[
            { key: "hostname", label: "Device", render: (d) => <>{d.hostname} <span className="small muted">({d.criticality})</span></> },
            { key: "installed", label: "Installed" },
            { key: "riskScore", label: "Risk", className: "right" },
            { key: "dueAt", label: "Due", render: (d) => d.dueAt ? <span style={{ color: d.overdue ? "#fca5a5" : undefined }}>{fmtTime(d.dueAt)}</span> : "—" },
            { key: "status", label: "Status", render: (d) => <>
                <Pill value={d.status} /> {d.ticketId && <Pill value="ticket" tone="blue" />}
                {d.verifiedAt && <div className="small muted">verified {fmtTime(d.verifiedAt)}</div>}
                {d.exception && <div className="small muted">accepted by {d.exception.approvedBy} until {fmtTime(d.exception.expiresAt)}: {d.exception.reason}</div>}
              </> },
            { key: "act", label: "", render: (d) => can("respond") && d.status !== "fixed" && <select value={d.status} aria-label="Set status" onChange={(e) => setRowStatus(d, e.target.value)}>
                {MANUAL_STATUSES.filter((s) => s !== "accepted" || can("configure")).map((s) => <option key={s}>{s}</option>)}</select> }]} />
        </Modal>
      )}
      {accepting && <AcceptRisk row={accepting} onClose={(saved) => { setAccepting(null); if (saved) { reload(); setOpen(null); } }} />}
    </>
  );
}

function AcceptRisk({ row, onClose }: { row: any; onClose: (saved: boolean) => void }) {
  const inDays = (days: number) => new Date(Date.now() + days * 86400000).toISOString().slice(0, 10);
  const [reason, setReason] = useState("");
  const [until, setUntil] = useState(inDays(90));
  const { run, busy } = useAction();
  return (
    <Modal title={`Accept risk on ${row.hostname}`} onClose={() => onClose(false)}
           footer={<button className="primary" disabled={busy || !reason.trim()} onClick={async () => {
             if (await run(() => api(`vulnerabilities/${row.id}`, { method: "PATCH", body: { status: "accepted", reason, expiresAt: `${until}T00:00:00Z` } }), "Risk accepted")) onClose(true);
           }}>Accept until review date</button>}>
      <p className="muted">Record why this vulnerability is not being fixed. You are recorded as the approver, and it reopens automatically on the review date (at most a year away).</p>
      <label className="field">Reason and compensating controls<textarea rows={3} value={reason} onChange={(e) => setReason(e.target.value)} /></label>
      <label className="field" style={{ marginTop: 10 }}>Review date<input type="date" value={until} min={inDays(1)} max={inDays(365)} onChange={(e) => setUntil(e.target.value)} /></label>
    </Modal>
  );
}
