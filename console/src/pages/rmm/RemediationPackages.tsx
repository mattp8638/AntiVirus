import { useState } from "react";
import { ago, api } from "../../api";
import { useApp } from "../../app-context";
import { displayValue } from "../../components/DisplayValue";
import { ErrorNote, Modal, PageHead, Pill, Table, TenantSelect, useAction, useListData } from "../../components/ui";
import { confirmDialog } from "../../components/dialogs";
import { needsReview, Review, ReviewPanel, ReviewPill } from "../../components/ScriptReview";

interface Package {
  id: string; tenantId: string | null; builtinKey: string | null; name: string; description: string; platforms: string[]; language: string;
  detectionScript: string; remediationScript: string; intervalHours: number; autoRemediate: boolean; ticketOnFailure: boolean;
  enabled: boolean; template: boolean; results?: Record<string, number>; review?: Review;
}

const STATUS_TONE: Record<string, string> = { compliant: "good", remediated: "good", noncompliant: "bad", failed: "bad", pending: "warn", error: "warn" };

export default function RemediationPackages() {
  const { tenantId, tenantName, can } = useApp();
  const { data, error, reload } = useListData<Package>("rmm/remediation-packages", { tenant_id: tenantId });
  const { run, busy } = useAction();
  const [editing, setEditing] = useState<Partial<Package> | null>(null);
  const [enabling, setEnabling] = useState<Package | null>(null);
  const [results, setResults] = useState<Package | null>(null);
  const canEdit = can("configure") && can("scripts");
  const templates = data?.filter((p) => p.template) ?? [];
  const active = data?.filter((p) => !p.template) ?? [];

  const runNow = async (row: Package) => { if (await run(() => api(`rmm/remediation-packages/${row.id}/run`, { body: {} }), "Detection queued")) reload(); };
  const toggle = async (row: Package) => { if (await run(() => api(`rmm/remediation-packages/${row.id}`, { method: "PATCH", body: { enabled: !row.enabled } }))) reload(); };
  const remove = async (row: Package) => {
    if (await confirmDialog(`Delete "${row.name}" and its results?`) && await run(() => api(`rmm/remediation-packages/${row.id}`, { method: "DELETE" }), "Deleted")) reload();
  };

  return (
    <>
      <PageHead title="Remediation packages"
                subtitle="Condition-based background fixes. A detection script runs on schedule; when it finds a problem the remediation script fixes it silently, detection runs again to confirm, and a ticket opens only if the fix does not hold."
                actions={canEdit && <button className="primary" onClick={() => setEditing({ tenantId: tenantId || "", language: "powershell", platforms: ["windows"], intervalHours: 24, autoRemediate: true, ticketOnFailure: true, enabled: true })}>New package</button>} />
      <ErrorNote error={error} />
      <div className="card">
        <h3>Active on customers</h3>
        <Table rows={data ? active : undefined} empty="Nothing enabled yet. Turn on a built-in package below or write your own."
               columns={[
                 { key: "name", label: "Package", render: (r) => <><b>{displayValue(r.name)}</b> <ReviewPill review={r.review} /><div className="small muted">{tenantName(r.tenantId || "")} · {r.platforms.join(", ")} · every {r.intervalHours}h</div></> },
                 { key: "mode", label: "Mode", render: (r) => <Pill value={r.autoRemediate ? "detect and fix" : "detect only"} tone={r.autoRemediate ? "blue" : "muted"} /> },
                 { key: "results", label: "Devices", render: (r) => Object.entries(r.results || {}).map(([s, n]) => <Pill key={s} value={`${n} ${s}`} tone={STATUS_TONE[s]} />) },
                 { key: "enabled", label: "State", render: (r) => <Pill value={r.enabled ? "on" : "paused"} tone={r.enabled ? "good" : "muted"} /> },
                 { key: "actions", label: "", className: "right", render: (r) => <span style={{ display: "inline-flex", gap: 6 }}>
                   <button className="ghost" onClick={() => setResults(r)}>Results</button>
                   {can("scripts") && <button className="ghost" disabled={busy || needsReview(r.review)} onClick={() => runNow(r)}>Run now</button>}
                   {canEdit && <><button className="ghost" onClick={() => setEditing(r)}>Edit</button>
                     <button className="ghost" disabled={busy} onClick={() => toggle(r)}>{r.enabled ? "Pause" : "Resume"}</button>
                     <button className="danger" disabled={busy} onClick={() => remove(r)}>Delete</button></>}</span> },
               ]} />
      </div>
      <div className="card">
        <h3>Built-in packages</h3>
        <Table rows={data ? templates : undefined} empty="No built-in packages."
               columns={[
                 { key: "name", label: "Package", render: (r) => <><b>{displayValue(r.name)}</b><div className="small muted">{displayValue(r.description)}</div></> },
                 { key: "platforms", label: "Platforms", render: (r) => r.platforms.join(", ") },
                 { key: "actions", label: "", className: "right", render: (r) => canEdit && <button onClick={() => setEnabling(r)}>Enable for a customer</button> },
               ]} />
      </div>
      {editing && <PackageEditor value={editing} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); reload(); }} />}
      {enabling && <EnableModal template={enabling} onClose={() => setEnabling(null)} onSaved={() => { setEnabling(null); reload(); }} />}
      {results && <ResultsModal pkg={results} onClose={() => setResults(null)} />}
    </>
  );
}

function EnableModal({ template, onClose, onSaved }: { template: Package; onClose: () => void; onSaved: () => void }) {
  const { tenantId } = useApp();
  const { run, busy } = useAction();
  const [form, setForm] = useState({ tenantId: tenantId || "", intervalHours: template.intervalHours, autoRemediate: true, ticketOnFailure: true });
  const save = async () => { if (await run(() => api(`rmm/remediation-packages/${template.id}/enable`, { body: form }), "Package enabled")) onSaved(); };
  return (
    <Modal title={`Enable ${template.name}`} onClose={onClose}
           footer={<button className="primary" disabled={busy || !form.tenantId} onClick={save}>Enable</button>}>
      <p className="small muted">{displayValue(template.description)}</p>
      <div className="form-grid">
        <TenantSelect value={form.tenantId} allowAll={false} label="Customer" onChange={(id) => setForm({ ...form, tenantId: id })} />
        <label className="field">Check every (hours)<input type="number" min={1} max={720} value={form.intervalHours} onChange={(e) => setForm({ ...form, intervalHours: Number(e.target.value) })} /></label>
      </div>
      <label className="small"><input type="checkbox" checked={form.autoRemediate} onChange={(e) => setForm({ ...form, autoRemediate: e.target.checked })} /> Fix automatically when detection fails</label><br />
      <label className="small"><input type="checkbox" checked={form.ticketOnFailure} onChange={(e) => setForm({ ...form, ticketOnFailure: e.target.checked })} /> Open a ticket when the fix does not hold</label>
    </Modal>
  );
}

function PackageEditor({ value, onClose, onSaved }: { value: Partial<Package>; onClose: () => void; onSaved: () => void }) {
  const { run, busy } = useAction();
  const [form, setForm] = useState<Partial<Package>>(value);
  const set = (key: keyof Package) => (e: { target: { value: string } }) => setForm({ ...form, [key]: e.target.value });
  const save = async () => {
    const body = { tenantId: form.tenantId, name: form.name, description: form.description, language: form.language, platforms: form.platforms,
                   detectionScript: form.detectionScript, remediationScript: form.remediationScript, intervalHours: form.intervalHours,
                   autoRemediate: form.autoRemediate, ticketOnFailure: form.ticketOnFailure };
    if (await run(() => (form.id ? api(`rmm/remediation-packages/${form.id}`, { method: "PATCH", body }) : api("rmm/remediation-packages", { body })), "Package saved")) onSaved();
  };
  const platformsFor = (language: string) => (language === "powershell" ? ["windows"] : language === "zsh" ? ["macos"] : ["linux", "macos"]);
  return (
    <Modal wide title={form.id ? `Edit ${form.name}` : "New remediation package"} onClose={onClose}
           footer={<button className="primary" disabled={busy || !form.name || !form.detectionScript || !form.tenantId} onClick={save}>Save</button>}>
      {form.id && <ReviewPanel review={value.review} path={`rmm/remediation-packages/${form.id}`} onReviewed={onSaved}
                               dirty={form.detectionScript !== value.detectionScript || form.remediationScript !== value.remediationScript || form.language !== value.language} />}
      <div className="form-grid">
        {!form.id && <TenantSelect value={form.tenantId || ""} allowAll={false} label="Customer" onChange={(id) => setForm({ ...form, tenantId: id })} />}
        <label className="field">Name<input value={form.name || ""} onChange={set("name")} /></label>
        <label className="field">Language<select value={form.language} onChange={(e) => setForm({ ...form, language: e.target.value, platforms: platformsFor(e.target.value) })}>
          {["powershell", "bash", "sh", "zsh", "python"].map((l) => <option key={l}>{l}</option>)}</select></label>
        <label className="field">Check every (hours)<input type="number" min={1} max={720} value={form.intervalHours ?? 24} onChange={(e) => setForm({ ...form, intervalHours: Number(e.target.value) })} /></label>
      </div>
      <label className="field">Description<input value={form.description || ""} onChange={set("description")} /></label>
      <label className="field">Detection script (exit 0 = healthy, exit 1 = needs fixing, anything else = could not tell)
        <textarea className="mono" rows={8} value={form.detectionScript || ""} onChange={set("detectionScript")} /></label>
      <label className="field">Remediation script (runs only when detection fails; detection runs again afterwards)
        <textarea className="mono" rows={8} value={form.remediationScript || ""} onChange={set("remediationScript")} /></label>
      <label className="small"><input type="checkbox" checked={!!form.autoRemediate} onChange={(e) => setForm({ ...form, autoRemediate: e.target.checked })} /> Fix automatically</label><br />
      <label className="small"><input type="checkbox" checked={!!form.ticketOnFailure} onChange={(e) => setForm({ ...form, ticketOnFailure: e.target.checked })} /> Open a ticket when the fix does not hold</label>
    </Modal>
  );
}

function ResultsModal({ pkg, onClose }: { pkg: Package; onClose: () => void }) {
  const { data, error } = useListData<any>(`rmm/remediation-packages/${pkg.id}/results`);
  return (
    <Modal wide title={`${pkg.name}: results`} onClose={onClose}>
      <ErrorNote error={error} />
      <Table rows={data} empty="No device has reported yet."
             columns={[
               { key: "hostname", label: "Device", render: (r) => <b>{displayValue(r.hostname || r.deviceId)}</b> },
               { key: "status", label: "Status", render: (r) => <Pill value={r.status} tone={STATUS_TONE[r.status]} /> },
               { key: "lastDetectAt", label: "Last checked", render: (r) => (r.lastDetectAt ? ago(r.lastDetectAt) : "never") },
               { key: "lastRemediatedAt", label: "Last fixed", render: (r) => (r.lastRemediatedAt ? ago(r.lastRemediatedAt) : "-") },
               { key: "output", label: "Output", render: (r) => <details><summary className="small">show</summary><pre className="small" style={{ whiteSpace: "pre-wrap" }}>{displayValue(r.detectOutput)}{r.remediateOutput ? `\n--- remediation ---\n${r.remediateOutput}` : ""}</pre></details> },
               { key: "ticketId", label: "Ticket", render: (r) => (r.ticketId ? <a href={`/tickets/${r.ticketId}`}>open</a> : "") },
             ]} />
    </Modal>
  );
}
