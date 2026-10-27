import { useMemo, useState } from "react";
import { api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { Pill, Sev, Table, useAction } from "../components/ui";
import { EpssPill, FixBlock, IntelCard, RiskBadge, RiskBreakdown, VulnEvidence } from "../components/Vuln";

const SOURCE_LABEL: Record<string, string> = { "windows-update": "Missing Windows update", "nvd-cpe": "Installed program", osv: "Package" };

// A device's vulnerabilities, worst first: what's affected (missing KB or program and where it's installed),
// the CVE facts, and the fix with Install when the device already offers it.
export function DeviceVulns({ device, vulnerabilities, risk, scans, onChanged }: { device: any; vulnerabilities: any[]; risk: any; scans?: any[]; onChanged: () => void }) {
  const { can } = useApp();
  const { run, busy } = useAction();
  const [show, setShow] = useState("open");
  const [expanded, setExpanded] = useState<number | null>(null);
  const rows = useMemo(() => (vulnerabilities || []).filter((v) => show === "all" || (show === "open" ? ["open", "patching"].includes(v.status) : v.status === show)), [vulnerabilities, show]);
  const byFix = useMemo(() => {
    const groups = new Map<string, { fix: any; count: number; top: number }>();
    rows.filter((v) => v.fix?.ref).forEach((v) => {
      const g = groups.get(v.fix.ref) || { fix: v.fix, count: 0, top: 0 };
      g.count += 1; g.top = Math.max(g.top, v.riskScore); groups.set(v.fix.ref, g);
    });
    return [...groups.values()].sort((a, b) => b.top - a.top || b.count - a.count);
  }, [rows]);
  return (
    <div className="grid side">
      <div className="stack">
        <div className="card">
          <div className="row" style={{ marginBottom: 10 }}>
            <select value={show} onChange={(e) => setShow(e.target.value)} aria-label="Show">
              <option value="open">Open</option><option value="mitigated">Mitigated</option><option value="accepted">Accepted</option><option value="fixed">Fixed</option><option value="all">All</option>
            </select>
            <span className="small muted" style={{ flex: 1 }}>{rows.length} shown · click one for evidence and the fix</span>
            {can("respond") && <button disabled={busy} onClick={() => run(() => api("vulnerabilities/scan", { body: { deviceId: device.id } }), "Vulnerability scan queued")}>Scan programs now</button>}
            {can("respond") && device.platform === "windows" && <button disabled={busy} onClick={() => run(() => api(`devices/${device.id}/commands`, { body: { type: "patch.scan", reason: "Patch scan from Vulnerabilities" } }), "Patch scan queued")}>Check Windows updates</button>}
          </div>
          {(scans || []).filter((s) => s.status !== "complete").map((s) => (
            <div key={s.id} className="small" style={{ marginBottom: 8, color: s.status === "failed" ? "#fca5a5" : "#fcd34d" }}>
              Last {SOURCE_LABEL[s.source] || s.source} scan was <b>{s.status}</b> ({s.packagesAssessed} of {s.packagesTotal} packages assessed, {fmtTime(s.startedAt)}).
              Findings outside what was assessed are kept as they were, not marked fixed.{s.errors?.length ? ` ${s.errors[0]}` : ""}
            </div>))}
          <Table rows={rows} onRow={(v) => setExpanded(expanded === v.id ? null : v.id)} empty={show === "open" ? "No open vulnerabilities on this device." : "Nothing here."}
                 columns={[{ key: "riskScore", label: "Risk", render: (v) => <RiskBadge score={v.riskScore} /> },
                           { key: "vulnId", label: "Vulnerability", render: (v) => <><b className="mono">{v.vulnId}</b> {v.knownExploited && <Pill value="exploited in the wild" tone="bad" />} <EpssPill epss={v.epss} />
                             <div className="small muted">{(v.intel?.description || v.summary || "").slice(0, 130)}</div></> },
                           { key: "severity", label: "Severity", render: (v) => <><Sev level={v.severity} />{v.cvss !== null && v.cvss !== undefined && <div className="small muted">CVSS {v.cvss}</div>}</> },
                           { key: "package", label: "Affected", render: (v) => <><span className="small">{v.package} <span className="muted">{v.source === "windows-update" ? "" : v.installedVersion}</span></span><div className="small muted">{SOURCE_LABEL[v.source] || v.source}</div></> },
                           { key: "fix", label: "Fix", render: (v) => <span className="small"><b>{v.fix?.ref || v.fixedVersion || "—"}</b></span> },
                           { key: "status", label: "Status", render: (v) => <Pill value={v.status} /> }]} />
          {expanded !== null && (() => { const v = rows.find((x) => x.id === expanded); return v && (
            <div className="card evidence-card">
              <div className="row"><RiskBadge score={v.riskScore} /><b className="mono" style={{ flex: 1 }}>{v.vulnId}</b><button className="ghost small" onClick={() => setExpanded(null)}>Close</button></div>
              {v.reasons?.length > 0 && <p className="small muted">Risk {v.riskScore}/10: {v.reasons.join(" · ")}{device.criticality && device.criticality !== "medium" ? ` · ${device.criticality}-criticality device` : ""}</p>}
              <div className="grid k2">
                <div><div className="evidence-title">Why this device is affected</div><VulnEvidence evidence={v.evidence} installed={v.installedVersion} /></div>
                <div><div className="evidence-title">Fix</div><FixBlock fix={v.fix} deviceId={device.id} status={v.status} onQueued={onChanged} />
                  <div className="small muted" style={{ marginTop: 8 }}>{v.recommendation}</div></div>
              </div>
              <div className="evidence-title" style={{ marginTop: 12 }}>About {v.vulnId}</div>
              <IntelCard intel={v.intel} cve={v.vulnId} />
            </div>); })()}
        </div>
      </div>
      <div className="stack">
        <div className="card"><h3>Risk score</h3><RiskBreakdown risk={risk} /></div>
        {byFix.length > 0 && <div className="card">
          <h3>Fixes that clear the most</h3>
          {byFix.slice(0, 8).map((g) => (
            <div key={g.fix.ref} style={{ marginBottom: 10 }}>
              <div className="row small"><RiskBadge score={g.top} /><b style={{ flex: 1 }}>{g.fix.kind === "kb" ? g.fix.ref : g.fix.title || g.fix.ref}</b><span className="muted">{g.count} CVE{g.count === 1 ? "" : "s"}</span></div>
              {g.fix.patchKey && <div style={{ paddingLeft: 42 }}><FixBlock fix={g.fix} deviceId={device.id} onQueued={onChanged} /></div>}
            </div>
          ))}
        </div>}
      </div>
    </div>
  );
}
