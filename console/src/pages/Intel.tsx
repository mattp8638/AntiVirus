import { displayValue } from "../components/DisplayValue";
import { useState } from "react";
import { api, fmtTime, uploadFile } from "../api";
import { useApp } from "../app-context";
import { Modal, PageHead, Pill, Table, Tabs, TenantSelect, useAction, useData, useListData } from "../components/ui";

export default function Intel() {
  const { tenantId, can, tenantName, toast } = useApp();
  const [tab, setTab] = useState("Lookup");
  const { data: feeds, reload: reloadFeeds } = useData<any>("intel/feeds");
  const [value, setValue] = useState("");
  const [result, setResult] = useState<any>(null);
  const [q, setQ] = useState("");
  const { data, reload } = useData<any>("intel/indicators", { tenant_id: tenantId, q, limit: 500 });
  const { data: yara, reload: reloadYara } = useListData<any>("intel/yara");
  const [adding, setAdding] = useState(false);
  const [addingYara, setAddingYara] = useState(false);
  const { run, busy } = useAction();
  const toastSync = (r: any) => toast(`${r.ok} feeds updated${r.failed ? `, ${r.failed} failed (see Feeds)` : ""}`);

  return (
    <>
      <PageHead title="Threat intelligence" subtitle="Free feeds pulled by this server every hour (MalwareBazaar, URLhaus, ThreatFox, Feodo Tracker, IPsum), plus your own indicators and YARA rules. Pushed to agents and DNS protection."
                actions={<>
                  {can("platform") && <button disabled={busy} onClick={async () => {
                    const r = await run(() => api<any>("intel/sync", { body: {} }));
                    if (r) { toastSync(r); reload(); reloadYara(); reloadFeeds(); }
                  }}>Sync feeds now</button>}
                  {can("configure") && <button className="primary" onClick={() => setAdding(true)}>Add indicators</button>}
                </>} />
      <Tabs tabs={["Lookup", "Check a file", "Indicators", "Feeds", "YARA rules"]} active={tab} onChange={setTab} />
      {tab === "Feeds" && <FeedsTab data={feeds} reload={() => { reloadFeeds(); reload(); }} />}
      {tab === "Check a file" && <FileCheck />}
      {tab === "Lookup" && (
        <div className="card">
          <div className="row">
            <input style={{ flex: 1 }} placeholder="SHA-256, MD5, domain, URL or IP" value={value} onChange={(e) => setValue(e.target.value)}
                   onKeyDown={async (e) => e.key === "Enter" && value && setResult(await run(() => api("intel/lookup", { query: { value, tenant_id: tenantId } })))} />
            <button className="primary" disabled={!value || busy} onClick={async () => setResult(await run(() => api("intel/lookup", { query: { value, tenant_id: tenantId } })))}>Look up</button>
          </div>
          {result && (
            <div style={{ marginTop: 16 }}>
              <div className="row"><Pill value={result.verdict} /> <span className="muted">{displayValue(result.type)} · score {displayValue(result.score)} {displayValue(result.source && `· ${result.source}`)}</span></div>
              <h3 style={{ marginTop: 12 }}>Matches</h3>
              <Table rows={result.matches.map((m: any, i: number) => ({ ...m, id: i }))} empty="No intel match."
                     columns={[{ key: "value", label: "Indicator", render: (m) => <span className="mono">{displayValue(m.value)}</span> }, { key: "verdict", label: "Verdict", render: (m) => <Pill value={m.verdict} /> },
                               { key: "category", label: "Category" }, { key: "source", label: "Source" }, { key: "scope", label: "Scope" }]} />
              <h3 style={{ marginTop: 12 }}>Seen in your telemetry</h3>
              <Table rows={result.sightings.map((s: any) => ({ ...s, id: s.deviceId }))} empty="Not seen on any device."
                     columns={[{ key: "deviceId", label: "Device", render: (s) => <a href={`/devices/${s.deviceId}`}>{displayValue(s.deviceId)}</a> }, { key: "events", label: "Events" }]} />
            </div>
          )}
        </div>
      )}
      {tab === "Indicators" && (
        <div className="card">
          <div className="row" style={{ marginBottom: 10 }}>
            <input placeholder="Filter" value={q} onChange={(e) => setQ(e.target.value)} />
            <span className="muted small">{displayValue(data?.stats.indicators.map((s: any) => `${s.count} ${s.type} (${s.verdict})`).join(" · "))}</span>
          </div>
          <Table rows={data?.items}
                 columns={[{ key: "type", label: "Type" }, { key: "value", label: "Indicator", render: (r) => <span className="mono small">{displayValue(r.value)}</span> },
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

const ML_TONE: Record<string, string> = { malicious: "bad", "likely-malicious": "bad", suspicious: "warn", clean: "good" };

// Score a Windows program with Fenrir's static machine-learning model (the one agents use) and look its hash up in
// threat intelligence. The file is read in memory on the server and not kept.
function FileCheck() {
  const { data: model } = useData<any>("ml/model");
  const [result, setResult] = useState<any>(null);
  const [intelHit, setIntelHit] = useState<any>(null);
  const [name, setName] = useState("");
  const { run, busy } = useAction();
  const check = async (file: File | undefined) => {
    if (!file) return;
    setName(file.name); setResult(null); setIntelHit(null);
    const scored = await run(() => uploadFile<any>("ml/score", file));
    if (!scored) return;
    setResult(scored);
    if (scored.sha256) setIntelHit(await api<any>("intel/lookup", { query: { value: scored.sha256 } }).catch(() => null));
  };
  return (
    <div className="card">
      <p className="small muted" style={{ marginTop: 0 }}>
        {model?.available ? <>Model {displayValue(model.version)} · {(Number(model.size || 0) / 1024).toFixed(0)} KB{model.metrics?.auc ? ` · AUC ${model.metrics.auc}` : ""}. </> : "No model is installed on this server, so only the threat intelligence lookup works. "}
        Windows programs (.exe, .dll) up to 64 MB. The file is scored in memory and not stored.
      </p>
      <input type="file" disabled={busy} onChange={(e) => check(e.target.files?.[0])} />
      {busy && <p className="small muted">Checking {displayValue(name)}…</p>}
      {result && <div style={{ marginTop: 12 }}>
        {!result.available ? <p>No model is installed: {displayValue(result.reason)}.</p>
          : !result.pe ? <p>{displayValue(name)} is not a Windows program, so the model does not apply. Look its hash up instead.</p>
          : <p><b>{displayValue(name)}</b>: <Pill value={result.verdict} tone={ML_TONE[result.verdict]} /> score {result.score} (model {displayValue(result.model)})</p>}
        {result.sha256 && <p className="small mono" style={{ wordBreak: "break-all" }}>SHA-256 {result.sha256}</p>}
        {intelHit && <p className="small">Threat intelligence: {intelHit.matches?.length ? <><Pill value={intelHit.verdict} tone={intelHit.verdict === "malicious" ? "bad" : "muted"} /> {displayValue(intelHit.source || "")}</> : "no match"}{intelHit.sightings?.length ? ` · seen on ${intelHit.sightings.length} device(s)` : ""}</p>}
      </div>}
    </div>
  );
}

// The free feeds this server pulls itself, with what each holds and why one is failing.
function FeedsTab({ data, reload }: { data: any; reload: () => void }) {
  const { run, busy } = useAction();
  const toggle = async (feed: any) => { if (await run(() => api(`intel/feeds/${feed.id}`, { method: "PATCH", body: { enabled: !feed.enabled } }))) reload(); };
  if (!data) return <div className="card"><div className="empty">Loading…</div></div>;
  const needsKey = (data.feeds || []).some((f: any) => (f.lastError || "").includes("auth.abuse.ch"));
  return (
    <div className="card">
      <p className="small muted" style={{ marginTop: 0 }}>
        Pulled straight from the publishers, free, {data.scheduled ? "refreshed by the server in the background" : "background refresh is off (FENRIR_INTEL_FEEDS=false); use Sync feeds now"}.
        Hashes are blocked and quarantined by agents; malware domains are blocked by agents and DNS protection; links from feeds are blocked as exact links,
        never whole sites; botnet IPs are firewall-blocked. A failed or truncated download keeps the previous copy.
      </p>
      {needsKey && <p className="small" style={{ color: "var(--warn, #b7791f)" }}>abuse.ch is asking for an Auth-Key. Create a free one at
        {" "}<a href="https://auth.abuse.ch" target="_blank" rel="noreferrer">auth.abuse.ch</a>, put it in the server's <code>deploy/.env</code> as
        {" "}<code>FENRIR_ABUSECH_AUTH_KEY=…</code> and restart (<code>docker compose up -d</code>).</p>}
      {!needsKey && !data.abusechKey && <p className="small muted">No abuse.ch Auth-Key is set. If abuse.ch starts refusing downloads, add a free one as FENRIR_ABUSECH_AUTH_KEY.</p>}
      <Table rows={data.feeds} empty="No feeds."
             columns={[{ key: "name", label: "Feed", render: (f) => <><b>{displayValue(f.name)}</b><div className="small muted">{displayValue(f.description)}</div></> },
                       { key: "indicators", label: "Indicators", render: (f) => Number(f.indicators || 0).toLocaleString() },
                       { key: "lastSuccessAt", label: "Last updated", render: (f) => f.lastSuccessAt ? fmtTime(f.lastSuccessAt) : "never" },
                       { key: "status", label: "Status", render: (f) => !f.enabled ? <Pill value="off" tone="muted" />
                           : f.lastError ? <span title={f.lastError}><Pill value="problem" tone="bad" /> <span className="small">{displayValue(f.lastError)}</span></span>
                           : f.lastSuccessAt ? <Pill value="ok" tone="good" /> : <Pill value="waiting" tone="muted" /> },
                       { key: "toggle", label: "", render: (f) => data.editable && <button className="small" disabled={busy} onClick={() => toggle(f)}>{f.enabled ? "Turn off" : "Turn on"}</button> }]} />
    </div>
  );
}
