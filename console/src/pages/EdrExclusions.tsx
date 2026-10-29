import { useState } from "react";
import { ago, api } from "../api";
import { useApp } from "../app-context";
import { displayValue } from "../components/DisplayValue";
import { ErrorNote, Modal, PageHead, Pill, Table, TenantSelect, useAction, useListData } from "../components/ui";

interface Exclusion {
  id: string; tenantId: string | null; name: string; kind: string; parentImage: string; parentSha256: string[]; childImage: string;
  childSha256: string[]; commandLineContains: string; scopes: string[]; reason: string; profile: string; enabled: boolean;
  expiresAt: string | null; expired: boolean; createdBy: string; hits: number; lastHitAt: string | null;
}

const SCOPES: [string, string][] = [["behavior", "Behaviour rules"], ["antimalware", "Malware verdicts"], ["sigma", "Cloud detections"]];

const hashes = (text: string) => text.split(/[\s,;]+/).map((h) => h.trim()).filter(Boolean);

export default function EdrExclusions() {
  const { tenantId, tenantName, can } = useApp();
  const { data, error, reload } = useListData<Exclusion>("edr/exclusions", { tenant_id: tenantId });
  const { run, busy } = useAction();
  const [profileOpen, setProfileOpen] = useState(false);
  const [ruleOpen, setRuleOpen] = useState(false);
  const canEdit = can("configure");

  const toggle = async (row: Exclusion) => {
    if (await run(() => api(`edr/exclusions/${row.id}`, { method: "PATCH", body: { enabled: !row.enabled } }), row.enabled ? "Exclusion disabled" : "Exclusion enabled")) reload();
  };
  const remove = async (row: Exclusion) => {
    if (!window.confirm(`Delete the exclusion "${row.name}"?`)) return;
    if (await run(() => api(`edr/exclusions/${row.id}`, { method: "DELETE" }), "Exclusion deleted")) reload();
  };

  return (
    <>
      <PageHead title="EDR exclusions"
                subtitle="Strict exclusions for RMM agents and trusted tools. A process-chain rule trusts a child only when its parent's path and SHA-256 both match, so a renamed or replaced binary is never trusted. Every use is reported."
                actions={canEdit && <>
                  <button onClick={() => setProfileOpen(true)}>Add RMM agent</button>
                  <button className="ghost" onClick={() => setRuleOpen(true)}>Add rule</button></>} />
      <ErrorNote error={error} />
      <div className="card">
        <Table rows={data ?? undefined} empty="No exclusions. Add your RMM agent to stop its scripts tripping behaviour rules."
               columns={[
                 { key: "name", label: "Rule", render: (r) => <><b>{displayValue(r.name)}</b><div className="small muted">{r.tenantId ? tenantName(r.tenantId) : "All customers"} · {displayValue(r.reason)}</div></> },
                 { key: "chain", label: "Matches", render: (r) => <div className="small mono">
                   {r.kind === "hash" ? <>file {r.childSha256.map((h) => h.slice(0, 12)).join(", ")}…</> : <>
                     {displayValue(r.parentImage)} <span className="muted">(sha256 {r.parentSha256.map((h) => h.slice(0, 12)).join(", ")}…)</span>
                     {r.childImage && <> → {displayValue(r.childImage)}</>}</>}
                   {r.commandLineContains && <div className="muted">command line contains “{displayValue(r.commandLineContains)}”</div>}</div> },
                 { key: "scopes", label: "Relaxes", render: (r) => r.scopes.map((s) => <Pill key={s} value={s} />) },
                 { key: "state", label: "State", render: (r) => <Pill value={r.expired ? "expired" : r.enabled ? "active" : "disabled"} tone={r.expired ? "warn" : r.enabled ? "good" : "muted"} /> },
                 { key: "hits", label: "Used", className: "right", render: (r) => <>{r.hits}<div className="small muted">{r.lastHitAt ? ago(r.lastHitAt) : "never"}</div></> },
                 ...(canEdit ? [{ key: "actions", label: "", className: "right", render: (r: Exclusion) => <span style={{ display: "inline-flex", gap: 6 }}>
                   <button className="ghost" disabled={busy} onClick={() => toggle(r)}>{r.enabled ? "Disable" : "Enable"}</button>
                   <button className="danger" disabled={busy} onClick={() => remove(r)}>Delete</button></span> }] : []),
               ]} />
      </div>
      <TestCard />
      {profileOpen && <ProfileModal onClose={() => setProfileOpen(false)} onSaved={() => { setProfileOpen(false); reload(); }} />}
      {ruleOpen && <RuleModal onClose={() => setRuleOpen(false)} onSaved={() => { setRuleOpen(false); reload(); }} />}
    </>
  );
}

function ScopePicker({ value, onChange }: { value: string[]; onChange: (scopes: string[]) => void }) {
  return <div className="row">{SCOPES.map(([key, label]) => <label key={key} className="small" style={{ display: "flex", gap: 4, alignItems: "center" }}>
    <input type="checkbox" checked={value.includes(key)} onChange={(e) => onChange(e.target.checked ? [...value, key] : value.filter((s) => s !== key))} />{label}</label>)}</div>;
}

function ProfileModal({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const { tenantId } = useApp();
  const { run, busy } = useAction();
  const [form, setForm] = useState({ tenantId: tenantId || "", name: "", platform: "windows", agentImage: "", agentSha256: "", reason: "", expiresAt: "" });
  const [scopes, setScopes] = useState(["behavior", "sigma"]);
  const set = (key: string) => (e: { target: { value: string } }) => setForm({ ...form, [key]: e.target.value });
  const save = async () => {
    const body = { ...form, tenantId: form.tenantId || null, agentSha256: hashes(form.agentSha256), scopes, expiresAt: form.expiresAt || null };
    if (await run(() => api("edr/exclusions/rmm-profile", { body }), "RMM agent exclusions created")) onSaved();
  };
  return (
    <Modal title="Add an RMM agent" onClose={onClose} wide footer={<button disabled={busy} onClick={save}>Create exclusions</button>}>
      <p className="small muted">Creates one rule per script interpreter (PowerShell, cmd, bash…) pinned to your agent's path and hash. Get the hash on Windows with <span className="mono">Get-FileHash "C:\Path\agent.exe"</span>, or <span className="mono">sha256sum /path/agent</span> on Linux and macOS. Add the hash of each agent version you run.</p>
      <div className="form-grid">
        <label className="field">Customer<TenantSelect value={form.tenantId} onChange={(id) => setForm({ ...form, tenantId: id })} label="Customer" /></label>
        <label className="field">Name<input value={form.name} onChange={set("name")} placeholder="Acme RMM" /></label>
        <label className="field">Platform<select value={form.platform} onChange={set("platform")}><option value="windows">Windows</option><option value="linux">Linux</option><option value="macos">macOS</option></select></label>
        <label className="field">Agent executable (full path)<input value={form.agentImage} onChange={set("agentImage")} placeholder="C:\Program Files\Acme\agent.exe" /></label>
        <label className="field">Agent SHA-256 (one or more)<textarea value={form.agentSha256} onChange={set("agentSha256")} rows={2} /></label>
        <label className="field">Expires (optional)<input type="date" value={form.expiresAt} onChange={set("expiresAt")} /></label>
      </div>
      <label className="field" style={{ marginTop: 12 }}>Why is this safe? (shown to reviewers)<input value={form.reason} onChange={set("reason")} /></label>
      <div style={{ marginTop: 12 }}><div className="small muted">Relaxes</div><ScopePicker value={scopes} onChange={setScopes} /></div>
    </Modal>
  );
}

function RuleModal({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const { tenantId } = useApp();
  const { run, busy } = useAction();
  const [form, setForm] = useState({ tenantId: tenantId || "", name: "", kind: "process-chain", parentImage: "", parentSha256: "", childImage: "",
                                     childSha256: "", commandLineContains: "", reason: "", expiresAt: "" });
  const [scopes, setScopes] = useState(["behavior", "sigma"]);
  const set = (key: string) => (e: { target: { value: string } }) => setForm({ ...form, [key]: e.target.value });
  const save = async () => {
    const body = { ...form, tenantId: form.tenantId || null, parentSha256: hashes(form.parentSha256), childSha256: hashes(form.childSha256), scopes,
                   expiresAt: form.expiresAt || null };
    if (await run(() => api("edr/exclusions", { body }), "Exclusion created")) onSaved();
  };
  return (
    <Modal title="Add an exclusion" onClose={onClose} wide footer={<button disabled={busy} onClick={save}>Create</button>}>
      <div className="form-grid">
        <label className="field">Customer<TenantSelect value={form.tenantId} onChange={(id) => setForm({ ...form, tenantId: id })} label="Customer" /></label>
        <label className="field">Name<input value={form.name} onChange={set("name")} /></label>
        <label className="field">Kind<select value={form.kind} onChange={set("kind")}><option value="process-chain">Process chain (parent → child)</option><option value="hash">One file (hash)</option></select></label>
        {form.kind === "process-chain" && <>
          <label className="field">Parent executable (full path)<input value={form.parentImage} onChange={set("parentImage")} /></label>
          <label className="field">Parent SHA-256<textarea value={form.parentSha256} onChange={set("parentSha256")} rows={2} /></label>
        </>}
        <label className="field">Child executable (optional, * allowed in the file name)<input value={form.childImage} onChange={set("childImage")} /></label>
        <label className="field">Child SHA-256 {form.kind === "hash" ? "" : "(optional)"}<textarea value={form.childSha256} onChange={set("childSha256")} rows={2} /></label>
        <label className="field">Command line contains (optional)<input value={form.commandLineContains} onChange={set("commandLineContains")} /></label>
        <label className="field">Expires (optional)<input type="date" value={form.expiresAt} onChange={set("expiresAt")} /></label>
      </div>
      <label className="field" style={{ marginTop: 12 }}>Why is this safe? (shown to reviewers)<input value={form.reason} onChange={set("reason")} /></label>
      <div style={{ marginTop: 12 }}><div className="small muted">Relaxes</div><ScopePicker value={scopes} onChange={setScopes} /></div>
    </Modal>
  );
}

function TestCard() {
  const { tenantId } = useApp();
  const { run, busy } = useAction();
  const [form, setForm] = useState({ image: "", sha256: "", parentImage: "", parentSha256: "", commandLine: "" });
  const [result, setResult] = useState<any>(null);
  const set = (key: string) => (e: { target: { value: string } }) => setForm({ ...form, [key]: e.target.value });
  const test = async () => setResult(await run(() => api("edr/exclusions/test", { body: { ...form, tenantId: tenantId || null } })));
  return (
    <div className="card">
      <h3>Would this process be excluded?</h3>
      <div className="form-grid">
        <label className="field">Process path<input value={form.image} onChange={set("image")} /></label>
        <label className="field">Process SHA-256<input value={form.sha256} onChange={set("sha256")} /></label>
        <label className="field">Parent path<input value={form.parentImage} onChange={set("parentImage")} /></label>
        <label className="field">Parent SHA-256<input value={form.parentSha256} onChange={set("parentSha256")} /></label>
        <label className="field">Command line<input value={form.commandLine} onChange={set("commandLine")} /></label>
      </div>
      <div className="row" style={{ marginTop: 10 }}>
        <button disabled={busy} onClick={test}>Test</button>
        {result && <span className="small">{result.excluded ? <>Excluded by <b>{result.rule.id}</b> ({result.rule.scopes.join(", ")})</> : "Not excluded"}</span>}
      </div>
    </div>
  );
}
