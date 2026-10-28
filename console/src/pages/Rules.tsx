import { displayValue } from "../components/DisplayValue";
import { useState } from "react";
import { api } from "../api";
import { useApp } from "../app-context";
import { Modal, PageHead, Pill, Sev, Table, Tabs, useAction, useData, useListData } from "../components/ui";

const NEW_RULE = `title: My custom detection
id: custom-${Math.random().toString(36).slice(2, 8)}
description: What this catches and why it matters.
tags: [attack.execution, attack.t1059]
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\\\example.exe'
    CommandLine|contains: 'suspicious-flag'
  condition: selection
level: high
`;

export default function Rules() {
  const { can, tenantName } = useApp();
  const [tab, setTab] = useState("Rules");
  const [q, setQ] = useState("");
  const { data, reload } = useListData<any>("rules");
  const { data: mitre } = useData<any>("mitre");
  const [editing, setEditing] = useState<any>(null);
  const { run } = useAction();
  const rows = data?.filter((r) => `${r.title} ${r.mitre.join(" ")} ${r.id}`.toLowerCase().includes(q.toLowerCase()));
  return (
    <>
      <PageHead title="Detection rules" subtitle="Sigma-compatible rules with correlation. Import community rules or write your own."
                actions={can("configure") && <button className="primary" onClick={() => setEditing({ source: NEW_RULE, isNew: true })}>New rule</button>} />
      <Tabs tabs={["Rules", "MITRE coverage"]} active={tab} onChange={setTab} />
      {tab === "Rules" ? (
        <div className="card">
          <input placeholder="Filter by title, technique or id" value={q} onChange={(e) => setQ(e.target.value)} style={{ marginBottom: 10, minWidth: 300 }} />
          <Table rows={rows} onRow={(r) => setEditing(r)}
                 columns={[{ key: "level", label: "Level", render: (r) => <Sev level={r.level} /> },
                           { key: "title", label: "Rule", render: (r) => <><b>{displayValue(r.title)}</b><div className="small muted mono">{displayValue(r.id)}</div></> },
                           { key: "kind", label: "Type", render: (r) => <Pill value={r.kind} tone={r.kind === "correlation" ? "blue" : "muted"} /> },
                           { key: "scope", label: "Scope", render: (r) => r.tenantId ? tenantName(r.tenantId) : r.builtin ? "Built-in" : "Global" },
                           { key: "mitre", label: "MITRE", render: (r) => r.mitre.filter((m: string) => m.startsWith("T")).join(", ") },
                           { key: "hits", label: "Hits", className: "right" },
                           { key: "fp", label: "False positives", render: (r) => r.quality?.alerts ? <span title={r.quality.advice || ""}>
                               <Pill value={`${r.quality.falsePositive}/${r.quality.alerts}`} tone={(r.quality.fpRate ?? 0) >= 0.5 ? "bad" : (r.quality.fpRate ?? 0) >= 0.2 ? "warn" : "muted"} /></span> : <span className="muted">—</span> },
                           { key: "enabled", label: "On", render: (r) => <input type="checkbox" checked={r.enabled} disabled={!can("configure")}
                               onClick={(e) => e.stopPropagation()}
                               onChange={async () => { await run(() => api(`rules/${r.id}`, { method: "PATCH", body: { enabled: !r.enabled } }), "Rule updated"); reload(); }} /> }]} />
        </div>
      ) : (
        <div className="card">
          <p className="muted">{displayValue(mitre?.techniques.length ?? 0)} ATT&CK techniques covered by enabled rules.</p>
          <div className="heat">
            {mitre?.techniques.map((t: any) => (
              <div key={t.technique} title={t.rules.join("\n")} style={{ background: `rgba(34,197,94,${Math.min(0.55, 0.12 + t.rules.length * 0.1)})` }}>
                <b>{displayValue(t.technique)}</b> <span className="muted">{displayValue(t.rules.length)} rule(s) · {displayValue(t.hits)} hits</span>
              </div>
            ))}
          </div>
        </div>
      )}
      {editing && <RuleEditor rule={editing} onClose={() => { setEditing(null); reload(); }} />}
    </>
  );
}

function RuleEditor({ rule, onClose }: { rule: any; onClose: () => void }) {
  const { can, tenantId } = useApp();
  const [source, setSource] = useState<string>(rule.source);
  const [sample, setSample] = useState('{"eventType":"process.start","payload":{"processImagePath":"C:\\\\Temp\\\\example.exe","commandLine":"example.exe suspicious-flag"},"platform":"windows"}');
  const [result, setResult] = useState<any>(null);
  const [response, setResponse] = useState<string>((rule.response || []).join(", "));
  const { run, busy } = useAction();
  const editable = can("configure") && (rule.isNew || rule.tenantId || can("platform"));

  const test = async () => {
    let events: any[] = [];
    try {
      events = [JSON.parse(sample)];
    } catch {
      setResult({ valid: false, error: "Sample event is not valid JSON" });
      return;
    }
    setResult(await run(() => api("rules/test", { body: { rule: source, events } })));
  };
  const save = async () => {
    const responseList = response.split(",").map((s) => s.trim()).filter(Boolean);
    const ok = rule.isNew
      ? await run(() => api("rules", { body: { rule: source, tenantId: tenantId || null, response: responseList } }), "Rule created")
      : await run(() => api(`rules/${rule.id}`, { method: "PATCH", body: { rule: source, response: responseList } }), "Rule saved");
    if (ok) onClose();
  };
  return (
    <Modal title={rule.isNew ? "New rule" : rule.title} onClose={onClose}
           footer={<><button onClick={test} disabled={busy}>Test</button>{editable && <button className="primary" onClick={save} disabled={busy}>Save</button>}</>}>
      <textarea value={source} onChange={(e) => setSource(e.target.value)} style={{ minHeight: 280 }} readOnly={!editable} />
      <label className="field" style={{ marginTop: 10 }}>Auto-response when this fires (command types, comma separated)
        <input value={response} onChange={(e) => setResponse(e.target.value)} placeholder="e.g. process.tree.terminate, device.isolate" disabled={!editable} />
      </label>
      <label className="field" style={{ marginTop: 10 }}>Sample event (agent JSON)<textarea style={{ minHeight: 80 }} value={sample} onChange={(e) => setSample(e.target.value)} /></label>
      {result && (result.valid
        ? <p>Valid {displayValue(result.kind)} rule. {result.results?.map((r: any, i: number) => <span key={i}>{r.matched ? <Pill value="sample matched" tone="good" /> : <Pill value="sample did not match" tone="warn" />}</span>)}</p>
        : <p style={{ color: "#fecaca" }}>{displayValue(result.error)}</p>)}
    </Modal>
  );
}
