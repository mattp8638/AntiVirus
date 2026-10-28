import { displayValue } from "./DisplayValue";
import { Fragment, ReactNode, useState } from "react";
import { fmtTime } from "../api";
import { Pill } from "./ui";

// Renders alert evidence (cloud/fenrir_cloud/evidence.py): what file, which threat, which process, where it came
// from, and any service, registry key, network destination or script involved.

const SECTION_TITLES: Record<string, string> = {
  file: "File", threat: "Detection", process: "Process", origin: "Where it came from", service: "Service",
  registry: "Registry", network: "Network", script: "Script", logon: "Sign-in",
};
const LABELS: Record<string, string> = {
  path: "Path", sha256: "SHA-256", sizeBytes: "Size", signer: "Signed by", signed: "Signed", reputation: "Reputation",
  contentType: "Type", entropy: "Entropy", quarantinedPath: "Quarantined to", quarantineRecordId: "Quarantine record",
  evidenceRecordId: "Evidence record", name: "Name", summary: "Summary", verdict: "Verdict", disposition: "Policy action",
  remediation: "Remediation", remediationError: "Why it failed", engine: "Engine", score: "Score", reasons: "Reasons",
  technique: "ATT&CK technique", tactic: "ATT&CK tactic", image: "Image", pid: "PID", commandLine: "Command line",
  user: "User", integrity: "Integrity", parentImage: "Parent", parentPid: "Parent PID", parentCommandLine: "Parent command line",
  label: "Origin", channel: "Channel", url: "URL", domain: "Domain", application: "Application", browser: "Browser",
  downloaded: "Downloaded", emailAttachment: "Email attachment", macroDocument: "Macro document", lure: "Lure name",
  fakeUpdate: "Fake update pattern", imagePath: "Binary", startType: "Start type", account: "Runs as", key: "Key",
  value: "Value", action: "Change", destination: "Destination", port: "Port", hostname: "Host", protocol: "Protocol",
  query: "DNS query", source: "Source", excerpt: "Content", type: "Type", sourceIp: "From", status: "Result",
};

const bytes = (n: number) => n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : n >= 1024 ? `${Math.round(n / 1024)} KB` : `${n} bytes`;

function value(section: string, key: string, v: any): ReactNode {
  if (v === true) return "Yes";
  if (v === false) return "No";
  if (Array.isArray(v)) return v.map((x) => <span key={String(x)} className="chip">{String(x)}</span>);
  if (key === "sha256") return <span className="mono small">{displayValue(v)} <a href={`https://www.virustotal.com/gui/file/${v}`} target="_blank" rel="noreferrer">VirusTotal</a> · <button className="ghost small" onClick={() => navigator.clipboard?.writeText(String(v))}>Copy</button></span>;
  if (key === "sizeBytes") return bytes(Number(v));
  if (key === "remediation") return <Pill value={String(v)} tone={/fail|none/i.test(String(v)) ? "bad" : "good"} />;
  if (key === "reputation") return <Pill value={String(v)} tone={/malic|bad/i.test(String(v)) ? "bad" : /suspic|unknown/i.test(String(v)) ? "warn" : "good"} />;
  if (key === "technique" && /^T\d/.test(String(v))) return <a href={`https://attack.mitre.org/techniques/${String(v).replace(".", "/")}/`} target="_blank" rel="noreferrer">{String(v)}</a>;
  if (key === "url" && /^https?:/i.test(String(v))) return <span className="mono small" style={{ wordBreak: "break-all" }}>{String(v)}</span>;
  if (["path", "image", "parentImage", "commandLine", "parentCommandLine", "key", "value", "imagePath", "quarantinedPath", "excerpt"].includes(key))
    return <span className="mono small" style={{ wordBreak: "break-all", whiteSpace: "pre-wrap" }}>{String(v)}</span>;
  return String(v);
}

export function EvidenceOccurrence({ ev }: { ev: any }) {
  const sections = Object.keys(SECTION_TITLES).filter((s) => ev[s]);
  return (
    <div className="evidence">
      <div className="small muted" style={{ marginBottom: 6 }}>
        {ev.event?.type && <span className="chip">{displayValue(ev.event.type)}</span>} {displayValue(ev.event?.at && fmtTime(ev.event.at))}
        {ev.count > 1 && <> · seen {displayValue(ev.count)} times{ev.lastAt ? `, last ${fmtTime(ev.lastAt)}` : ""}</>}
      </div>
      {ev.event?.summary && <div style={{ marginBottom: 8 }}>{displayValue(ev.event.summary)}</div>}
      <div className="evidence-grid">
        {sections.map((s) => (
          <div key={s} className="evidence-section">
            <div className="evidence-title">{SECTION_TITLES[s]}</div>
            <dl className="kv compact">
              {Object.entries(ev[s]).map(([k, v]) => <Fragment key={k}><dt>{LABELS[k] ?? k}</dt><dd>{value(s, k, v)}</dd></Fragment>)}
            </dl>
          </div>
        ))}
      </div>
      {!sections.length && <p className="muted small">This event carried no file, process or network details.</p>}
    </div>
  );
}

export function EvidenceList({ details }: { details: any }) {
  const list: any[] = details?.evidence || [];
  const [index, setIndex] = useState(list.length - 1);
  if (!list.length) return <p className="muted small">No evidence was recorded for this alert.</p>;
  const current = list[Math.min(Math.max(index, 0), list.length - 1)];
  return (
    <>
      {list.length > 1 && <div className="row small" style={{ marginBottom: 8 }}>
        <span className="muted">{list.length} different occurrences</span>
        {list.map((_, i) => <button key={i} className={`small ${i === index ? "primary" : ""}`} onClick={() => setIndex(i)}>{i + 1}</button>)}
      </div>}
      <EvidenceOccurrence ev={current} />
    </>
  );
}

const IOC_TITLES: Record<string, string> = {
  sha256: "File hashes (SHA-256)", files: "Files", processes: "Processes", commandLines: "Command lines", users: "Users",
  domains: "Domains", urls: "URLs", ips: "IP addresses", services: "Services", registry: "Registry keys",
};

export function Indicators({ indicators }: { indicators: Record<string, { value: string; count: number }[]> }) {
  const kinds = Object.keys(IOC_TITLES).filter((k) => indicators?.[k]?.length);
  if (!kinds.length) return <p className="muted small">No indicators yet.</p>;
  const copyAll = () => navigator.clipboard?.writeText(kinds.map((k) => `# ${IOC_TITLES[k]}\n${indicators[k].map((i) => i.value).join("\n")}`).join("\n\n"));
  return (
    <>
      <button className="small" style={{ float: "right" }} onClick={copyAll}>Copy all</button>
      {kinds.map((k) => (
        <div key={k} style={{ marginBottom: 10 }}>
          <div className="evidence-title">{IOC_TITLES[k]}</div>
          {indicators[k].map((i) => (
            <div key={i.value} className="mono small ioc">
              {k === "sha256" ? <a href={`https://www.virustotal.com/gui/file/${i.value}`} target="_blank" rel="noreferrer">{i.value}</a> : i.value}
              {i.count > 1 && <span className="muted"> ×{i.count}</span>}
            </div>
          ))}
        </div>
      ))}
    </>
  );
}
