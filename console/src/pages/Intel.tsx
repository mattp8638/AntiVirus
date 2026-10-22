import { useState } from "react";
import { api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { Modal, PageHead, Pill, Table, Tabs, TenantSelect, useAction, useData } from "../components/ui";

export default function Intel() {
  const { tenantId, can, tenantName } = useApp();
  const [tab, setTab] = useState("Lookup");
  const [value, setValue] = useState("");
  const [result, setResult] = useState<any>(null);
  const [q, setQ] = useState("");
  const { data, reload } = useData<any>("intel/indicators", { tenant_id: tenantId, q, limit: 500 });
  const { data: yara, reload: reloadYara } = useData<any[]>("intel/yara");
  const [adding, setAdding] = useState(false);
  const [addingYara, setAddingYara] = useState(false);
  const { run, busy } = useAction();

  return (
    <>
      <PageHead title="Threat intelligence" subtitle="MalwareBazaar, URLhaus and YARAify via the Fenrir feed, plus your own indicators and YARA rules. Pushed to agents and DNS in minutes."
                actions={<>
                  {can("platform") && <button disabled={busy} onClick={async () => { const r = await run(() => api<any>("intel/sync", { body: {} })); if (r) { reload(); reloadYara(); } }}>Sync feed now</button>}
                  {can("configure") && <button className="primary" onClick={() => setAdding(true)}>Add indicators</button>}
                </>} />
      <Tabs tabs={["Lookup", "Indicators", "YARA rules"]} active={tab} onChange={setTab} />
      {tab === "Lookup" && (
        <div className="card">
          <div className="row">
            <input style={{ flex: 1 }} placeholder="SHA-256, MD5, domain, URL or IP" value={value} onChange={(e) => setValue(e.target.value)}
                   onKeyDown={async (e) => e.key === "Enter" && value && setResult(await run(() => api("intel/lookup", { query: { value, tenant_id: tenantId } })))} />
            <button className="primary" disabled={!value || busy} onClick={async () => setResult(await run(() => api("intel/lookup", { query: { value, tenant_id: tenantId } })))}>Look up</button>
          </div>
          {result && (
            <div style={{ marginTop: 16 }}>
              <div className="row"><Pill value={result.verdict} /> <span className="muted">{result.type} · score {result.score} {result.source && `· ${result.source}`}</span></div>
              <h3 style={{ marginTop: 12 }}>Matches</h3>
              <Table rows={result.matches.map((m: any, i: number) => ({ ...m, id: i }))} empty="No intel match."
                     columns={[{ key: "value", label: "Indicator", render: (m) => <span className="mono">{m.value}</span> }, { key: "verdict", label: "Verdict", render: (m) => <Pill value={m.verdict} /> },
                               { key: "category", label: "Category" }, { key: "source", label: "Source" }, { key: "scope", label: "Scope" }]} />
              <h3 style={{ marginTop: 12 }}>Seen in your telemetry</h3>
              <Table rows={result.sightings.map((s: any) => ({ ...s, id: s.deviceId }))} empty="Not seen on any device."
                     columns={[{ key: "deviceId", label: "Device", render: (s) => <a href={`/devices/${s.deviceId}`}>{s.deviceId}</a> }, { key: "events", label: "Events" }]} />
            </div>
          )}
        </div>
      )}
      {tab === "Indicators" && (
        <div className="card">
          <div className="row" style={{ marginBottom: 10 }}>
            <input placeholder="Filter" value={q} onChange={(e) => setQ(e.target.value)} />
            <span className="muted small">{data?.stats.indicators.map((s: any) => `${s.count} ${s.type} (${s.verdict})`).join(" · ")}</span>
          </div>
          <Table rows={data?.items}
                 columns={[{ key: "type", label: "Type" }, { key: "value", label: "Indicator", render: (r) => <span className="mono small">{r.value}</span> },
                           { key: "verdict", label: "Verdict", render: (r) => <Pill value={r.verdict} /> }, { key: "category", label: "Category" },
                           { key: "source", label: "Source" }, { key: "tenantId", label: "Scope", render: (r) => r.tenantId ? tenantName(r.tenantId) : "Global" },
                           { key: "createdAt", label: "Added", render: (r) => fmtTime(r.createdAt) },
                           { key: "del", label: "", render: (r) => can("configure") && r.source === "manual" &&
                               <button className="small ghost" onClick={async () => { await run(() => api(`intel/indicators/${r.id}`, { method: "DELETE" })); reload(); }}>Remove</button> }]} />
        </div>
      )}
      {tab === "YARA rules" && (
        <div className="card">
          {can("configure") && <button style={{ marginBottom: 10 }} onClick={() => setAddingYara(true)}>Add YARA rule</button>}
          <Table rows={yara} empty="No YARA rules yet. Sync the feed or add your own."
                 columns={[{ key: "name", label: "Rule" }, { key: "origin", label: "Origin" }, { key: "tenantId", label: "Scope", render: (r) => r.tenantId ? tenantName(r.tenantId) : "Global" },
                           { key: "updatedAt", label: "Updated", render: (r) => fmtTime(r.updatedAt) }]} />
        </div>
      )}
      {adding && <AddIndicators onClose={() => { setAdding(false); reload(); }} />}
      {addingYara && <AddYara onClose={() => { setAddingYara(false); reloadYara(); }} />}
    </>
  );
}

function AddIndicators({ onClose }: { onClose: () => void }) {
  const { tenantId } = useApp();
  const [tenant, setTenant] = useState(tenantId);
  const [text, setText] = useState("");
  const [verdict, setVerdict] = useState("malicious");
  const [category, setCategory] = useState("malware");
  const { run, busy } = useAction();
  const submit = async () => {
    const result = await run(() => api<any>("intel/indicators", { body: { tenantId: tenant || null, text, verdict, category } }));
    if (result) onClose();
  };
  return (
    <Modal title="Add indicators" onClose={onClose} footer={<><button onClick={onClose}>Cancel</button><button className="primary" disabled={busy || !text} onClick={submit}>Add</button></>}>
      <div className="form-grid">
        <label className="field">Scope<TenantSelect value={tenant} onChange={setTenant} label="Scope" /></label>
        <label className="field">Verdict<select value={verdict} onChange={(e) => setVerdict(e.target.value)}><option>malicious</option><option>suspicious</option><option value="allow">allow (never block)</option></select></label>
        <label className="field">Category<select value={category} onChange={(e) => setCategory(e.target.value)}>{["malware", "phishing", "command-and-control", "ransomware", "cryptomining", "scam"].map((c) => <option key={c}>{c}</option>)}</select></label>
      </div>
      <label className="field" style={{ marginTop: 12 }}>Hashes, domains, URLs or IPs, one per line<textarea value={text} onChange={(e) => setText(e.target.value)} /></label>
      <p className="small muted">Leave scope as "All tenants" to add globally (platform admins only).</p>
    </Modal>
  );
}

function AddYara({ onClose }: { onClose: () => void }) {
  const { tenantId } = useApp();
  const [name, setName] = useState("");
  const [source, setSource] = useState('rule Example_Ransom_Note\n{\n  strings:\n    $a = "your files have been encrypted" nocase\n  condition:\n    $a\n}');
  const { run, busy } = useAction();
  const submit = async () => { if (await run(() => api("intel/yara", { body: { tenantId: tenantId || null, name, source } }), "YARA rule added")) onClose(); };
  return (
    <Modal title="Add YARA rule" onClose={onClose} footer={<><button onClick={onClose}>Cancel</button><button className="primary" disabled={busy} onClick={submit}>Add</button></>}>
      <label className="field">Name<input value={name} onChange={(e) => setName(e.target.value)} /></label>
      <textarea style={{ marginTop: 10 }} value={source} onChange={(e) => setSource(e.target.value)} />
    </Modal>
  );
}
