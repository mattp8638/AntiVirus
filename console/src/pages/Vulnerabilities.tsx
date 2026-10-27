import { Link } from "react-router-dom";
import { useMemo, useState } from "react";
import { api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { Bars, Modal, PageHead, Pill, Sev, Stat, Table, useAction, useData } from "../components/ui";
import { EpssPill, FixBlock, IntelCard, RiskBadge, VulnEvidence } from "../components/Vuln";

// "fixed" is not offered: only a rescan that no longer finds the vulnerability marks it fixed.
const MANUAL_STATUSES = ["open", "patching", "mitigated", "accepted"];
const SOURCE_LABEL: Record<string, string> = { "windows-update": "Windows Update", "nvd-cpe": "Installed program", osv: "Package" };

export default function Vulnerabilities() {
  const { tenantId, can } = useApp();
  const [status, setStatus] = useState("open");
  const [severity, setSeverity] = useState("");
  const [focus, setFocus] = useState("");
  const [q, setQ] = useState("");
  const { data, reload } = useData<any[]>("vulnerabilities", { tenant_id: tenantId, status, severity });
  const { data: trends } = useData<any[]>("vulnerabilities/trends", { tenant_id: tenantId, weeks: 12 });
  const [open, setOpen] = useState<string | null>(null);
  const { run, busy } = useAction();
  const rows = useMemo(() => (data || []).filter((v) =>
    (!focus || (focus === "kev" ? v.knownExploited : focus === "epss" ? (v.epss ?? 0) >= 0.1 : v.sources.includes(focus))) &&
    (!q || `${v.vulnId} ${v.summary} ${v.packages.join(" ")} ${v.fix?.ref || ""}`.toLowerCase().includes(q.toLowerCase()))), [data, focus, q]);
  const kev = data?.filter((v) => v.knownExploited).length ?? 0;
  const likely = data?.filter((v) => (v.epss ?? 0) >= 0.1).length ?? 0;
  const exposures = data?.reduce((n, v) => n + v.devices.length, 0) ?? 0;
  const overdue = data?.reduce((n, v) => n + (v.overdue || 0), 0) ?? 0;
  return (
    <>
      <PageHead title="Vulnerabilities" subtitle="Missing Windows security updates, vulnerable installed programs (matched against NVD) and Linux packages (OSV.dev). Ranked by risk: CVSS, exploitation in the wild (CISA KEV), exploit probability (EPSS) and how critical each device is. Fixes are confirmed by the next scan."
                actions={can("respond") && <button className="primary" disabled={busy} onClick={() => run(() => api<any>("vulnerabilities/scan", { body: { tenantId: tenantId || undefined } }), "Scan queued for all devices in scope")}>Scan now</button>} />
      <div className="grid k4">
        <Stat label="Unique vulnerabilities" value={data?.length ?? "—"} hint={`${exposures} device exposures`} />
        <Stat label="Exploited in the wild" value={kev} accent={kev ? "red" : "green"} hint="CISA KEV: fix first" />
        <Stat label="Likely to be exploited" value={likely} accent={likely ? "amber" : "green"} hint="EPSS 10% or higher" />
        <Stat label="Past remediation due date" value={overdue} accent={overdue ? "red" : "green"} />
      </div>
      {trends && trends.length > 1 && (
        <div className="card" style={{ marginTop: 14 }}>
          <div className="label muted small">Open critical + high vulnerabilities by week (fixed ones count from the scan that verified them)</div>
          <Bars data={trends.map((t) => ({ label: t.weekEnding.slice(5), value: t.open.critical + t.open.high }))} height={110} />
        </div>
      )}
      <div className="row" style={{ margin: "16px 0 12px" }}>
        <input placeholder="Search CVE, program, KB" value={q} onChange={(e) => setQ(e.target.value)} style={{ minWidth: 220 }} />
        <select value={focus} onChange={(e) => setFocus(e.target.value)} aria-label="Show">
          <option value="">Everything</option><option value="kev">Exploited in the wild</option><option value="epss">Likely to be exploited</option>
          <option value="windows-update">Missing Windows updates</option><option value="nvd-cpe">Installed programs</option><option value="osv">Linux packages</option>
        </select>
        <select value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status"><option value="">Any status</option>{[...MANUAL_STATUSES, "fixed"].map((s) => <option key={s}>{s}</option>)}</select>
        <select value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Severity"><option value="">Any severity</option>{["critical", "high", "medium", "low"].map((s) => <option key={s}>{s}</option>)}</select>
        <span className="small muted">{rows.length} shown</span>
      </div>
      <div className="card">
        <Table rows={rows.map((v) => ({ ...v, id: v.vulnId }))} onRow={(v) => setOpen(v.vulnId)} empty="No vulnerabilities in this view."
               columns={[{ key: "riskScore", label: "Risk", render: (v) => <RiskBadge score={v.riskScore} /> },
                         { key: "vulnId", label: "Vulnerability", render: (v) => <><b className="mono">{v.vulnId}</b> {v.knownExploited && <Pill value="exploited in the wild" tone="bad" />} <EpssPill epss={v.epss} /> {v.overdue > 0 && <Pill value={`${v.overdue} overdue`} tone="bad" />}
                           <div className="small muted">{v.summary.slice(0, 140)}</div></> },
                         { key: "severity", label: "Severity", render: (v) => <><Sev level={v.severity} />{v.cvss !== null && v.cvss !== undefined && <div className="small muted">CVSS {v.cvss}</div>}</> },
                         { key: "packages", label: "Affects", render: (v) => <><span className="small">{v.packages.join(", ")}</span><div className="small muted">{v.sources.map((s: string) => SOURCE_LABEL[s] || s).join(", ")}</div></> },
                         { key: "fix", label: "Fix", render: (v) => <span className="small">{v.fix?.kind === "kb" ? <b>{v.fix.ref}</b> : v.fix?.ref || v.fixedVersion || "—"}</span> },
                         { key: "devices", label: "Devices", render: (v) => v.devices.length, className: "right" }]} />
      </div>
      {open && <CveModal cve={open} onClose={(changed) => { setOpen(null); if (changed) reload(); }} />}
    </>
  );
}

function CveModal({ cve, onClose }: { cve: string; onClose: (changed: boolean) => void }) {
  const { tenantId, can } = useApp();
  const { data, reload } = useData<any>(`vulnerabilities/cve/${cve}`, { tenant_id: tenantId });
  const { run, busy } = useAction();
  const [expanded, setExpanded] = useState<number | null>(null);
  const [accepting, setAccepting] = useState<any>(null);
  const affected: any[] = data?.affected || [];
  const openRows = affected.filter((d) => d.status !== "fixed");
  const setRowStatus = async (row: any, next: string) => {
    if (next === "accepted") { setAccepting(row); return; }
    if (await run(() => api(`vulnerabilities/${row.id}`, { method: "PATCH", body: { status: next } }), "Status updated")) reload();
  };
  const installAll = async () => {
    const groups = new Map<string, string[]>();
    openRows.filter((d) => d.fix?.patchKey).forEach((d) => groups.set(d.fix.patchKey, [...(groups.get(d.fix.patchKey) || []), d.deviceId]));
    for (const [patchKey, deviceIds] of groups) await run(() => api("rmm/patches/install", { body: { targets: { deviceIds }, patchKeys: [patchKey] } }));
    reload();
  };
  const installable = openRows.filter((d) => d.fix?.patchKey).length;
  return (
    <Modal title={cve} wide onClose={() => onClose(false)}
           footer={<>
             {can("configure") && installable > 0 && <button disabled={busy} onClick={installAll}>Install fix on {installable} device{installable === 1 ? "" : "s"}</button>}
             {can("respond") && openRows.some((d) => !d.ticketId && d.status !== "accepted") && <button className="primary" disabled={busy} onClick={async () => {
               const ids = openRows.filter((d) => !d.ticketId && d.status !== "accepted").map((d) => d.id);
               if (await run(() => api<any>("vulnerabilities/ticket", { body: { ids } }), "Remediation ticket opened")) reload();
             }}>Open remediation ticket</button>}
           </>}>
      {!data ? <div className="empty">Loading…</div> : <>
        <IntelCard intel={data.intel} cve={cve} />
        <h3 style={{ marginTop: 16 }}>Affected devices ({openRows.length} open{affected.length > openRows.length ? `, ${affected.length - openRows.length} fixed` : ""})</h3>
        <Table rows={affected} onRow={(d) => setExpanded(expanded === d.id ? null : d.id)} columns={[
          { key: "riskScore", label: "Risk", render: (d) => <RiskBadge score={d.riskScore} /> },
          { key: "hostname", label: "Device", render: (d) => <><Link to={`/devices/${d.deviceId}?tab=security&sub=Vulnerabilities`} onClick={(e) => e.stopPropagation()}>{d.hostname}</Link><div className="small muted">{d.package} {d.installedVersion}</div></> },
          { key: "fix", label: "Fix", render: (d) => <span className="small">{d.fix?.ref || d.fixedVersion || "—"}</span> },
          { key: "dueAt", label: "Due", render: (d) => d.dueAt ? fmtTime(d.dueAt).split(",")[0] : "—" },
          { key: "status", label: "Status", render: (d) => <>
              <Pill value={d.status} /> {d.ticketId && <Link to={`/tickets/${d.ticketId}`} onClick={(e) => e.stopPropagation()}><Pill value="ticket" tone="blue" /></Link>}
              {d.verifiedAt && <div className="small muted">verified {fmtTime(d.verifiedAt)}</div>}
            </> },
          { key: "act", label: "", render: (d) => can("respond") && d.status !== "fixed" && <select value={d.status} aria-label="Set status" onClick={(e) => e.stopPropagation()} onChange={(e) => setRowStatus(d, e.target.value)}>
              {MANUAL_STATUSES.filter((s) => s !== "accepted" || can("configure")).map((s) => <option key={s}>{s}</option>)}</select> }]} />
        {expanded !== null && (() => { const d = affected.find((x) => x.id === expanded); return d && (
          <div className="card evidence-card">
            <div className="row"><b style={{ flex: 1 }}>{d.hostname}</b><button className="ghost small" onClick={() => setExpanded(null)}>Close</button></div>
            <div className="grid k2" style={{ marginTop: 8 }}>
              <div><div className="evidence-title">Evidence</div><VulnEvidence evidence={d.evidence} installed={d.installedVersion} /></div>
              <div><div className="evidence-title">Fix</div><FixBlock fix={d.fix} deviceId={d.deviceId} status={d.status} onQueued={reload} />
                <div className="small muted" style={{ marginTop: 8 }}>{d.recommendation}</div>
                {d.reasons?.length > 0 && <div className="small" style={{ marginTop: 8 }}>Risk {d.riskScore}: {d.reasons.join(" · ")}</div>}</div>
            </div>
          </div>); })()}
      </>}
      {accepting && <AcceptRisk row={accepting} onClose={(saved) => { setAccepting(null); if (saved) reload(); }} />}
    </Modal>
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
