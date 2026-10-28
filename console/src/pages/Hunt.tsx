import { displayValue } from "../components/DisplayValue";
import { useState } from "react";
import { api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { PageHead, Table, Tabs, useAction } from "../components/ui";

const EXAMPLES = [
  "ProcessName:powershell.exe AND CommandLine:*-enc*",
  "Category:network DestinationPort>1024 ProcessName:rundll32.exe",
  "TargetFilename:*.lockbit OR TargetFilename:*README_TO_DECRYPT*",
  "QueryName:*.top",
];

const SIGMA_TEMPLATE = `title: Hunt - LSASS access by unexpected process
id: hunt-lsass-access
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: lsass
  filter:
    Image|endswith: ['\\\\MsMpEng.exe', '\\\\taskmgr.exe']
  condition: selection and not filter
level: high
`;

export default function Hunt() {
  const { tenantId } = useApp();
  const [tab, setTab] = useState("Search");
  const [q, setQ] = useState(EXAMPLES[0]);
  const [hours, setHours] = useState(24);
  const [rule, setRule] = useState(SIGMA_TEMPLATE);
  const [days, setDays] = useState(30);
  const [result, setResult] = useState<any>(null);
  const { run, busy } = useAction();

  const search = async () => setResult(await run(() => api("events", { query: { q, hours, tenant_id: tenantId, limit: 500 } })));
  const hunt = async () => setResult(await run(() => api("hunt", { body: { rule, days, tenantId: tenantId || undefined } })));

  return (
    <>
      <PageHead title="Threat hunting" subtitle="Search raw telemetry across every device, or replay any Sigma rule over history before deploying it." />
      <Tabs tabs={["Search", "Sigma retro-hunt"]} active={tab} onChange={(t) => { setTab(t); setResult(null); }} />
      {tab === "Search" ? (
        <div className="card">
          <div className="row">
            <input style={{ flex: 1, fontFamily: "var(--mono)" }} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === "Enter" && search()} />
            <select value={hours} onChange={(e) => setHours(Number(e.target.value))} aria-label="Time range">
              {[1, 24, 168, 720, 2160].map((h) => <option key={h} value={h}>{h < 24 ? `${h}h` : `${h / 24}d`}</option>)}
            </select>
            <button className="primary" disabled={busy} onClick={search}>Search</button>
          </div>
          <p className="small muted">Syntax: <code>Field:value</code> (wildcards *), <code>Field!=value</code>, <code>Field&gt;N</code>, bare words, <code>AND</code> / <code>OR</code>. Try:{" "}
            {EXAMPLES.map((e) => <a key={e} href="#" onClick={(ev) => { ev.preventDefault(); setQ(e); }} className="chip">{e}</a>)}</p>
        </div>
      ) : (
        <div className="card">
          <textarea value={rule} onChange={(e) => setRule(e.target.value)} style={{ minHeight: 260 }} />
          <div className="row" style={{ marginTop: 8 }}>
            <label className="small muted">Look back <input type="number" value={days} onChange={(e) => setDays(Number(e.target.value))} style={{ width: 70 }} /> days</label>
            <button className="primary" disabled={busy} onClick={hunt}>Run retro-hunt</button>
          </div>
        </div>
      )}
      {result && (
        <div className="card">
          <h3>{"hits" in result ? `${result.hits} hits on ${Object.keys(result.devices).length} devices` : `${result.count} matches`} · {displayValue(result.scanned)} events scanned</h3>
          <Table rows={result.events} empty="No matches."
                 columns={[{ key: "occurredAt", label: "Time", render: (e) => fmtTime(e.occurredAt) },
                           { key: "eventType", label: "Event" },
                           { key: "host", label: "Device", render: (e) => e.fields.Hostname },
                           { key: "proc", label: "Process", render: (e) => e.fields.ProcessName },
                           { key: "detail", label: "Detail", render: (e) => <span className="mono small">{displayValue(e.fields.CommandLine || e.fields.TargetFilename || e.fields.DestinationIp || e.fields.QueryName || e.summary)}</span> }]} />
        </div>
      )}
    </>
  );
}
