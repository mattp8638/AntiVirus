import { Fragment, ReactNode } from "react";
import { api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { Pill, Sev, useAction } from "./ui";

// Shared vulnerability views: the CVE's intelligence (NVD, EPSS, CISA KEV), the evidence that the device is
// affected (missing update / installed program and where it is), the fix (KB or version) with an install button,
// and the device risk-score breakdown.

export const pctText = (p?: number | null) => p === null || p === undefined ? "—" : p >= 0.1 ? `${Math.round(p * 100)}%` : `${(p * 100).toFixed(p >= 0.01 ? 1 : 2)}%`;

export function EpssPill({ epss }: { epss?: number | null }) {
  if (epss === null || epss === undefined) return null;
  return <span title="EPSS: probability this CVE is exploited in the next 30 days (FIRST.org)"><Pill value={`EPSS ${pctText(epss)}`} tone={epss >= 0.1 ? "bad" : epss >= 0.01 ? "warn" : "muted"} /></span>;
}

export function RiskBadge({ score }: { score: number }) {
  const tone = score >= 9 ? "bad" : score >= 7 ? "warn" : score >= 4 ? "blue" : "muted";
  return <span className={`badge tone-${tone}`} style={{ minWidth: 34, justifyContent: "center" }} title="Risk on this device (0-10)">{score.toFixed(1)}</span>;
}

/** NVD / EPSS / KEV facts for one CVE. */
export function IntelCard({ intel, cve }: { intel: any; cve: string }) {
  if (!intel) return <p className="muted small">No NVD record has been fetched for {cve} yet; the server fetches it in the background (usually within 15 minutes). <a href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noreferrer">Open on NVD</a></p>;
  return (
    <div className="intel">
      {intel.kev && <div className="kev-banner">
        <b>Known exploited in the wild</b> (CISA KEV, added {intel.kevAdded || "—"}{intel.kevDue ? `, federal due date ${intel.kevDue}` : ""}){intel.kevRansomware && <> · <b>used by ransomware</b></>}
        {intel.kevAction && <div className="small">{intel.kevAction}</div>}
      </div>}
      {intel.description && <p style={{ marginTop: 0 }}>{intel.description}</p>}
      <div className="intel-facts">
        <div><div className="evidence-title">CVSS</div><b style={{ fontSize: 20 }}>{intel.cvss ?? "—"}</b> {intel.severity && <Sev level={intel.severity} />}
          {intel.vector && <div className="mono small muted" style={{ wordBreak: "break-all" }}>{intel.vector}</div>}</div>
        <div><div className="evidence-title">Exploit probability (EPSS)</div><b style={{ fontSize: 20 }}>{pctText(intel.epss)}</b>
          {intel.epssPercentile !== null && intel.epssPercentile !== undefined && <div className="small muted">higher than {Math.round(intel.epssPercentile * 100)}% of CVEs</div>}</div>
        <div><div className="evidence-title">Weakness</div>{(intel.cwe || []).length ? intel.cwe.map((c: string) => <a key={c} className="chip" href={`https://cwe.mitre.org/data/definitions/${c.replace("CWE-", "")}.html`} target="_blank" rel="noreferrer">{c}</a>) : "—"}</div>
        <div><div className="evidence-title">Published</div>{intel.published ? fmtTime(intel.published).split(",")[0] : "—"}</div>
      </div>
      <div className="row small" style={{ marginTop: 8 }}>
        <a href={intel.nvdUrl} target="_blank" rel="noreferrer">NVD</a>
        {intel.advisory && <a href={intel.advisory} target="_blank" rel="noreferrer">Vendor advisory</a>}
        <a href={`https://www.cve.org/CVERecord?id=${intel.cve}`} target="_blank" rel="noreferrer">CVE.org</a>
      </div>
    </div>
  );
}

const kv = (rows: [string, ReactNode][]) => (
  <dl className="kv compact">{rows.filter(([, v]) => v !== undefined && v !== null && v !== "" && !(Array.isArray(v) && !v.length)).map(([k, v]) => <Fragment key={k}><dt>{k}</dt><dd>{v}</dd></Fragment>)}</dl>
);

/** Why we believe the device is affected. */
export function VulnEvidence({ evidence, installed }: { evidence: any; installed?: string }) {
  if (!evidence || !evidence.kind) return <p className="muted small">Detected on {installed || "this device"}. Rescan for full evidence.</p>;
  if (evidence.kind === "missing-update") return kv([
    ["Missing update", <><b>{evidence.update}</b> <span className="muted">{evidence.title}</span></>],
    ["Microsoft rating", evidence.msrcSeverity], ["Released", evidence.releasedAt && fmtTime(evidence.releasedAt).split(",")[0]],
    ["Missing since", evidence.missingSince && fmtTime(evidence.missingSince)], ["Operating system", evidence.os],
    ["Needs restart", evidence.rebootRequired ? "Yes" : undefined], ["Found by", `${evidence.detectedBy}, ${fmtTime(evidence.checkedAt)}`],
  ]);
  return kv([
    ["Program", <><b>{evidence.program}</b> <span className="muted">{evidence.version}</span></>],
    ["Publisher", evidence.publisher], ["Installed in", evidence.installLocation && <span className="mono small">{evidence.installLocation}</span>],
    ["Executables", (evidence.executables || []).length > 0 && <span className="mono small" style={{ whiteSpace: "pre-wrap" }}>{evidence.executables.join("\n")}</span>],
    ["Installed on", evidence.installDate], ["Package source", evidence.ecosystem],
    ["Affected versions", evidence.affectedRange], ["Matched as", evidence.matchedAs && <span className="mono small">{evidence.matchedAs}</span>],
    ["Advisory", evidence.advisory], ["Found by", `${evidence.detectedBy}${evidence.checkedAt ? `, ${fmtTime(evidence.checkedAt)}` : ""}`],
  ]);
}

/** How to fix it, with Install now when the device already offers the update (Windows Update KB or winget). */
export function FixBlock({ fix, deviceId, status, onQueued }: { fix: any; deviceId: string; status?: string; onQueued?: () => void }) {
  const { can } = useApp();
  const { run, busy } = useAction();
  if (!fix || !fix.kind) return <span className="muted small">No fix information yet.</span>;
  const install = async () => {
    if (await run(() => api("rmm/patches/install", { body: { targets: { deviceIds: [deviceId] }, patchKeys: [fix.patchKey] } }),
      `${fix.ref} queued for install; the vulnerability is verified fixed at the next scan`)) onQueued?.();
  };
  return (
    <div className="fix">
      <div><b>{fix.kind === "kb" ? `Install ${fix.ref}` : fix.title || `Update to ${fix.ref}`}</b>{fix.kind === "kb" && fix.title && <div className="small muted">{fix.title}</div>}</div>
      <div className="row small" style={{ marginTop: 4 }}>
        {fix.url && <a href={fix.url} target="_blank" rel="noreferrer">{fix.kind === "kb" ? "KB article" : "Advisory"}</a>}
        {fix.catalog && <a href={fix.catalog} target="_blank" rel="noreferrer">Microsoft Update Catalog</a>}
        {fix.winget && <span className="mono">winget upgrade --id {fix.winget}</span>}
        {fix.rebootRequired && <Pill value="restart needed" tone="warn" />}
        {fix.available && <span className="muted">device offers {fix.available}</span>}
        {fix.patchKey && can("configure") && status !== "fixed" && <button className="small primary" disabled={busy} onClick={install}>Install fix</button>}
      </div>
    </div>
  );
}

/** What makes up the device's 0-100 risk score. */
export function RiskBreakdown({ risk, onOpenVulns }: { risk: any; onOpenVulns?: () => void }) {
  if (!risk) return null;
  return (
    <div>
      <div className="row" style={{ alignItems: "baseline" }}>
        <b style={{ fontSize: 26 }}>{risk.score}</b><span className="muted">/ 100</span>
        <span className="small muted" style={{ flex: 1 }}>{risk.score >= 70 ? "High: act now" : risk.score >= 40 ? "Elevated" : risk.score > 0 ? "Low" : "Nothing open"}</span>
      </div>
      <div className="risk-bar"><span style={{ width: `${risk.score}%` }} /></div>
      {(risk.parts || []).map((part: any) => (
        <div key={part.kind} style={{ marginTop: 10 }}>
          <div className="row small"><b style={{ textTransform: "capitalize" }}>{part.kind}</b><span className="muted" style={{ flex: 1 }}>{part.detail}</span><b>+{part.points}</b></div>
          {(part.top || []).map((t: any) => (
            <div key={t.vulnId + t.package} className="row small" style={{ paddingLeft: 10, flexWrap: "nowrap" }}>
              <RiskBadge score={t.risk} /><span className="mono">{t.vulnId}</span><span className="muted ellipsis" style={{ flex: 1 }}>{t.package}{t.reasons?.length ? ` · ${t.reasons[0]}` : ""}</span>
              {t.fix && <span className="small">fix: {t.fix}</span>}
            </div>
          ))}
        </div>
      ))}
      {onOpenVulns && (risk.parts || []).some((p: any) => p.kind === "vulnerabilities") && <button className="small" style={{ marginTop: 10 }} onClick={onOpenVulns}>All vulnerabilities →</button>}
    </div>
  );
}
