import { displayValue } from "../../components/DisplayValue";
import { useState } from "react";
import { ago, api } from "../../api";
import { useApp } from "../../app-context";
import { emptyTargets, JobDetail, TargetPicker, Targets } from "../../components/rmm";
import { Modal, PageHead, Pill, Table, useAction, useData, useListData } from "../../components/ui";
import { confirmDialog } from "../../components/dialogs";
import { needsReview, ReviewPanel, ReviewPill } from "../../components/ScriptReview";

const LANGS = ["powershell", "cmd", "bash", "sh", "python"];
const LANG_PLATFORMS: Record<string, string[]> = { powershell: ["windows"], cmd: ["windows"], bash: ["linux", "macos"], sh: ["linux", "macos"], python: ["windows", "linux", "macos"] };

export default function Scripts() {
  const { can } = useApp();
  const { data, reload } = useListData<any>("rmm/scripts");
  const [q, setQ] = useState("");
  const [category, setCategory] = useState("");
  const [editing, setEditing] = useState<any>(null);
  const [running, setRunning] = useState<any>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const categories = [...new Set((data || []).map((s) => s.category))].sort();
  const rows = (data || []).filter((s) => (!category || s.category === category) &&
    (!q || `${s.name} ${s.description}`.toLowerCase().includes(q.toLowerCase())));
  return (
    <>
      <PageHead title="Script library" subtitle="Reusable PowerShell, Bash and Python with typed parameters. Run on one device, a group or a whole customer."
                actions={can("configure") && <button className="primary" onClick={() => setEditing({ language: "powershell", platforms: ["windows"], parameters: [], body: "", category: "General", timeoutSeconds: 600 })}>New script</button>} />
      <div className="row" style={{ marginBottom: 12 }}>
        <input placeholder="Search scripts" value={q} onChange={(e) => setQ(e.target.value)} style={{ minWidth: 260 }} />
        <select value={category} onChange={(e) => setCategory(e.target.value)}><option value="">All categories</option>{categories.map((c) => <option key={c}>{displayValue(c)}</option>)}</select>
      </div>
      <div className="card">
        <Table rows={rows} empty="No scripts." onRow={(s) => setEditing(s)}
               columns={[{ key: "name", label: "Script", render: (s) => <><b>{displayValue(s.name)}</b> <ReviewPill review={s.review} /><div className="small muted">{displayValue(s.description)}</div></> },
                         { key: "category", label: "Category" },
                         { key: "language", label: "Language", render: (s) => <span className="mono small">{displayValue(s.language)}</span> },
                         { key: "platforms", label: "Runs on", render: (s) => s.platforms.join(", ") },
                         { key: "parameters", label: "Params", render: (s) => s.parameters.length || "—" },
                         { key: "builtin", label: "", render: (s) => s.builtin ? <Pill value="built-in" tone="blue" /> : <span className="small muted">v{displayValue(s.version)} · {ago(s.updatedAt)}</span> },
                         { key: "run", label: "", render: (s) => can("configure") && <button className="small primary" disabled={needsReview(s.review)}
                             title={needsReview(s.review) ? "A second person has to review this version first" : undefined}
                             onClick={(e) => { e.stopPropagation(); setRunning(s); }}>Run</button> }]} />
      </div>
      {editing && <ScriptEditor script={editing} onClose={() => { setEditing(null); reload(); }} onRun={(s) => { setEditing(null); setRunning(s); }} />}
      {running && <RunScript script={running} onClose={() => setRunning(null)} onStarted={(id) => { setRunning(null); setJobId(id); }} />}
      {jobId && <JobDetail jobId={jobId} onClose={() => setJobId(null)} />}
    </>
  );
}

function ScriptEditor({ script, onClose, onRun }: { script: any; onClose: () => void; onRun: (s: any) => void }) {
  const { can } = useApp();
  const [form, setForm] = useState<any>({ ...script, parameters: [...(script.parameters || [])] });
  const { run, busy } = useAction();
  const { data: saved, reload } = useData<any>(script.id ? `rmm/scripts/${script.id}` : null);
  const review = saved?.review ?? script.review;
  const dirty = ["body", "language", "runAs"].some((k) => (form[k] ?? "") !== (script[k] ?? "")) ||
    JSON.stringify(form.parameters || []) !== JSON.stringify(script.parameters || []);
  const readOnly = !can("configure") || (script.builtin && !can("platform"));
  const save = async (asCopy = false) => {
    const body = { name: asCopy ? `${form.name} (copy)` : form.name, description: form.description, category: form.category, language: form.language,
                   platforms: form.platforms, body: form.body, parameters: form.parameters, runAs: form.runAs, timeoutSeconds: Number(form.timeoutSeconds) };
    const saved = await run(() => (form.id && !asCopy ? api(`rmm/scripts/${form.id}`, { method: "PATCH", body }) : api("rmm/scripts", { body })), "Script saved");
    if (saved) onClose();
  };
  const setParam = (i: number, patch: any) => setForm({ ...form, parameters: form.parameters.map((p: any, j: number) => (i === j ? { ...p, ...patch } : p)) });
  return (
    <Modal title={form.id ? form.name : "New script"} onClose={onClose}
           footer={<>
             {form.id && form.builtin && can("configure") && <button onClick={() => save(true)} disabled={busy}>Duplicate to edit</button>}
             {form.id && !form.builtin && can("configure") && <button className="danger" onClick={async () => { if (await confirmDialog("Delete this script?") && await run(() => api(`rmm/scripts/${form.id}`, { method: "DELETE" }), "Deleted")) onClose(); }}>Delete</button>}
             {form.id && <button disabled={needsReview(review)} onClick={() => onRun(form)}>Run…</button>}
             {!readOnly && <button className="primary" disabled={busy || !form.name || !form.body} onClick={() => save()}>Save</button>}
           </>}>
      {form.id && <ReviewPanel review={review} path={`rmm/scripts/${form.id}`} dirty={dirty} shared={!script.tenantId} onReviewed={reload} />}
      <div className="form-grid">
        <label className="field">Name<input value={form.name || ""} disabled={readOnly} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label>
        <label className="field">Category<input value={form.category || ""} disabled={readOnly} onChange={(e) => setForm({ ...form, category: e.target.value })} /></label>
        <label className="field">Language<select value={form.language} disabled={readOnly} onChange={(e) => setForm({ ...form, language: e.target.value, platforms: LANG_PLATFORMS[e.target.value] })}>
          {LANGS.map((l) => <option key={l}>{l}</option>)}</select></label>
        <label className="field">Timeout (seconds)<input type="number" value={form.timeoutSeconds} disabled={readOnly} onChange={(e) => setForm({ ...form, timeoutSeconds: e.target.value })} /></label>
      </div>
      <label className="field" style={{ marginTop: 10 }}>Description<input value={form.description || ""} disabled={readOnly} onChange={(e) => setForm({ ...form, description: e.target.value })} /></label>
      <h3 style={{ marginTop: 14 }}>Parameters</h3>
      <p className="small muted">Each parameter becomes a variable in the script ({form.language === "powershell" ? "$Name" : form.language === "cmd" ? "%Name%" : "$Name"}) and a field when someone runs it.</p>
      {form.parameters.map((p: any, i: number) => (
        <div key={i} className="row" style={{ marginBottom: 6 }}>
          <input placeholder="Name" value={p.name} disabled={readOnly} onChange={(e) => setParam(i, { name: e.target.value.replace(/[^A-Za-z0-9_]/g, "") })} style={{ width: 140 }} />
          <input placeholder="Label" value={p.label || ""} disabled={readOnly} onChange={(e) => setParam(i, { label: e.target.value })} style={{ width: 160 }} />
          <select value={p.type || "string"} disabled={readOnly} onChange={(e) => setParam(i, { type: e.target.value })}>{["string", "number", "boolean", "choice"].map((t) => <option key={t}>{t}</option>)}</select>
          <input placeholder={p.type === "choice" ? "Choices, comma separated" : "Default"} value={p.type === "choice" ? (p.choices || []).join(",") : p.default || ""} disabled={readOnly}
                 onChange={(e) => setParam(i, p.type === "choice" ? { choices: e.target.value.split(",").map((c) => c.trim()).filter(Boolean) } : { default: e.target.value })} style={{ flex: 1 }} />
          <label className="small"><input type="checkbox" checked={!!p.required} disabled={readOnly} onChange={(e) => setParam(i, { required: e.target.checked })} /> required</label>
          {!readOnly && <button className="small ghost" onClick={() => setForm({ ...form, parameters: form.parameters.filter((_: any, j: number) => j !== i) })}>✕</button>}
        </div>
      ))}
      {!readOnly && <button className="small" onClick={() => setForm({ ...form, parameters: [...form.parameters, { name: "", label: "", type: "string", required: false }] })}>Add parameter</button>}
      <h3 style={{ marginTop: 14 }}>Script</h3>
      <textarea value={form.body || ""} disabled={readOnly} spellCheck={false} onChange={(e) => setForm({ ...form, body: e.target.value })}
                style={{ width: "100%", minHeight: 280, fontFamily: "var(--mono)", fontSize: 12.5 }} />
      {readOnly && script.builtin && <p className="small muted">Built-in scripts are read-only. Duplicate one to change it.</p>}
    </Modal>
  );
}

export function RunScript({ script, onClose, onStarted, presetDeviceId }: { script: any; onClose: () => void; onStarted: (jobId: string) => void; presetDeviceId?: string }) {
  const [targets, setTargets] = useState<Targets>(() => ({ ...emptyTargets(), deviceIds: presetDeviceId ? [presetDeviceId] : [] }));
  const [values, setValues] = useState<Record<string, string>>(() => Object.fromEntries((script.parameters || []).map((p: any) => [p.name, p.default ?? ""])));
  const { run, busy } = useAction();
  const submit = async () => {
    const job = await run(() => api<any>(`rmm/scripts/${script.id}/run`, { body: { targets, parameters: values } }), "Script queued");
    if (job) onStarted(job.id);
  };
  return (
    <Modal title={`Run: ${script.name}`} onClose={onClose}
           footer={<><button onClick={onClose}>Cancel</button><button className="primary" disabled={busy || !(targets.deviceIds.length || targets.groupIds.length || targets.tenantIds.length)} onClick={submit}>Run now</button></>}>
      {(script.parameters || []).length > 0 && <div className="form-grid" style={{ marginBottom: 12 }}>
        {script.parameters.map((p: any) => (
          <label key={p.name} className="field">{displayValue(p.label || p.name)}{p.required ? " *" : ""}
            {p.type === "choice" ? <select value={values[p.name]} onChange={(e) => setValues({ ...values, [p.name]: e.target.value })}>{(p.choices || []).map((c: string) => <option key={c}>{c}</option>)}</select>
             : p.type === "boolean" ? <select value={values[p.name] || "false"} onChange={(e) => setValues({ ...values, [p.name]: e.target.value })}><option>true</option><option>false</option></select>
             : <input type={p.type === "number" ? "number" : "text"} value={values[p.name]} onChange={(e) => setValues({ ...values, [p.name]: e.target.value })} />}
          </label>
        ))}
      </div>}
      {!presetDeviceId && <TargetPicker value={targets} onChange={setTargets} platforms={script.platforms} />}
      <p className="small muted" style={{ marginTop: 8 }}>Runs as {script.runAs === "user" ? "the signed-in user" : "SYSTEM/root"} on {displayValue(script.platforms.join(", "))} devices. Others are skipped. Timeout {Math.round(script.timeoutSeconds / 60)} min.</p>
    </Modal>
  );
}
