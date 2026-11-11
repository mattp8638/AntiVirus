import { displayValue } from "../../components/DisplayValue";
import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
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
  // Opened from search (?id=): show that script.
  const [params, setParams] = useSearchParams();
  useEffect(() => {
    const wanted = params.get("id");
    const script = wanted && data?.find((s) => s.id === wanted);
    if (script) { setEditing(script); setParams({}, { replace: true }); }
  }, [data, params, setParams]);
  const [organising, setOrganising] = useState(false);
  const inCategory = (c: string) => !category || c === category || (c || "").startsWith(category + SEP);
  const rows = (data || []).filter((s) => inCategory(s.category) &&
    (!q || `${s.name} ${s.description} ${s.category}`.toLowerCase().includes(q.toLowerCase())));
  return (
    <>
      <PageHead title="Script library" subtitle="Reusable PowerShell, Bash and Python with typed parameters. Run on one device, a group or a whole customer."
                actions={can("configure") && <>
                  <button onClick={() => setOrganising(true)}>Organise categories</button>
                  <button className="primary" onClick={() => setEditing({ language: "powershell", platforms: ["windows"], parameters: [], body: "", category: "", timeoutSeconds: 600 })}>New script</button>
                </>} />
      <div className="row" style={{ marginBottom: 12 }}>
        <input placeholder="Search scripts" value={q} onChange={(e) => setQ(e.target.value)} style={{ minWidth: 260 }} />
        {category && <span className="small">In <b>{categoryLabel(category)}</b> <button className="small ghost" onClick={() => setCategory("")}>Show all</button></span>}
      </div>
      <div className="row" style={{ alignItems: "flex-start", gap: 12 }}>
      <div className="card" style={{ width: 270, flexShrink: 0, maxHeight: "75vh", overflow: "auto" }} data-testid="script-tree">
        <CategoryTree scripts={data || []} selected={category} onSelect={setCategory} />
      </div>
      <div className="card" style={{ flex: 1, minWidth: 0 }}>
        <Table rows={rows} empty="No scripts." onRow={(s) => setEditing(s)}
               columns={[{ key: "name", label: "Script", render: (s) => <><b>{displayValue(s.name)}</b> <ReviewPill review={s.review} /><div className="small muted">{displayValue(s.description)}</div></> },
                         { key: "category", label: "Category", render: (s) => <span className="small">{categoryLabel(s.category)}</span> },
                         { key: "language", label: "Language", render: (s) => <span className="mono small">{displayValue(s.language)}</span> },
                         { key: "platforms", label: "Runs on", render: (s) => s.platforms.join(", ") },
                         { key: "parameters", label: "Params", render: (s) => s.parameters.length || "—" },
                         { key: "builtin", label: "", render: (s) => s.builtin ? <Pill value="built-in" tone="blue" /> : <span className="small muted">v{displayValue(s.version)} · {ago(s.updatedAt)}</span> },
                         { key: "run", label: "", render: (s) => can("configure") && <button className="small primary" disabled={needsReview(s.review)}
                             title={needsReview(s.review) ? "A second person has to review this version first" : undefined}
                             onClick={(e) => { e.stopPropagation(); setRunning(s); }}>Run</button> }]} />
      </div>
      </div>
      {organising && <OrganiseCategories onClose={(changed) => { setOrganising(false); if (changed) reload(); }} />}
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
        <label className="field">Category<input value={form.category || ""} disabled={readOnly} list="script-categories" placeholder="Left empty: worked out from the script"
          onChange={(e) => setForm({ ...form, category: e.target.value })} title="Operating system / Area / Kind, e.g. Linux / Networking / Fix" /></label>
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
      <p className="small muted">Device custom fields arrive as environment variables: <code>{form.language === "powershell" ? "$env:FENRIR_CF_ASSET_TAG" : "$FENRIR_CF_ASSET_TAG"}</code>,
        plus <code>FENRIR_DEVICE_NAME</code> and <code>FENRIR_CUSTOMER</code>. To set a field, print a line such as <code>FENRIR-FIELD warranty_end=2027-03-01</code>
        (an empty value clears it). Monitors can test fields with the "Custom field" condition.</p>
      {readOnly && script.builtin && <p className="small muted">Built-in scripts are read-only. Duplicate one to change it.</p>}
    </Modal>
  );
}

const SEP = " / ";
export const categoryLabel = (c: string) => (c || "").split(SEP).join(" › ");

type TreeNode = { name: string; path: string; count: number; children: Map<string, TreeNode> };

// Scripts grouped by category path ("Windows / Security / Check"), with a count at each level.
export function buildCategoryTree(scripts: { category: string }[]): TreeNode {
  const root: TreeNode = { name: "All scripts", path: "", count: 0, children: new Map() };
  for (const script of scripts) {
    root.count += 1;
    let node = root;
    for (const part of (script.category || "Uncategorised").split(SEP).map((p) => p.trim()).filter(Boolean)) {
      const path = node.path ? node.path + SEP + part : part;
      if (!node.children.has(part)) node.children.set(part, { name: part, path, count: 0, children: new Map() });
      node = node.children.get(part)!;
      node.count += 1;
    }
  }
  return root;
}

const OS_ORDER = ["Windows", "macOS", "Linux", "Linux & macOS", "All platforms"];
const KIND_ORDER = ["Check", "Fix", "Action", "Response"];
const sortNodes = (nodes: TreeNode[]) => nodes.sort((a, b) => {
  const rank = (n: TreeNode) => { const i = OS_ORDER.indexOf(n.name); const k = KIND_ORDER.indexOf(n.name); return i >= 0 ? i : k >= 0 ? k : 99; };
  return rank(a) - rank(b) || a.name.localeCompare(b.name);
});

function CategoryTree({ scripts, selected, onSelect }: { scripts: any[]; selected: string; onSelect: (path: string) => void }) {
  const root = buildCategoryTree(scripts);
  const [open, setOpen] = useState<Set<string>>(() => new Set(OS_ORDER));
  const toggle = (path: string) => setOpen((o) => { const n = new Set(o); if (n.has(path)) n.delete(path); else n.add(path); return n; });
  const row = (node: TreeNode, depth: number): React.ReactNode => {
    const kids = sortNodes([...node.children.values()]);
    const expanded = depth === 0 || open.has(node.path) || (selected && selected.startsWith(node.path));
    return (
      <div key={node.path || "root"}>
        <div className="row" style={{ paddingLeft: depth * 14, gap: 4, cursor: "pointer", borderRadius: 6,
                                      background: selected === node.path ? "var(--hover, rgba(127,127,127,.15))" : undefined }}
             onClick={() => onSelect(node.path)}>
          {kids.length > 0 && depth > 0
            ? <button className="ghost small" style={{ padding: "0 4px" }} aria-label={expanded ? "Collapse" : "Expand"}
                      onClick={(e) => { e.stopPropagation(); toggle(node.path); }}>{expanded ? "▾" : "▸"}</button>
            : <span style={{ width: 18 }} />}
          <span style={{ flex: 1, fontWeight: depth <= 1 ? 600 : 400 }}>{displayValue(node.name)}</span>
          <span className="small muted">{node.count}</span>
        </div>
        {expanded && kids.map((k) => row(k, depth + 1))}
      </div>
    );
  };
  return <>{row(root, 0)}
    <datalist id="script-categories">{[...new Set(scripts.map((s) => s.category))].sort().map((c) => <option key={c} value={c} />)}</datalist></>;
}

// Re-file scripts as Operating system / Area / Kind, previewed first. Only categories change.
function OrganiseCategories({ onClose }: { onClose: (changed: boolean) => void }) {
  const { data } = useData<any>("rmm/script-categories");
  const { run, busy } = useAction();
  const [skip, setSkip] = useState<Set<string>>(new Set());
  const [edits, setEdits] = useState<Record<string, string>>({});
  const changes: any[] = data?.changes ?? [];
  const chosen = changes.filter((c) => !skip.has(c.id));
  const apply = async () => {
    const overrides = Object.fromEntries(Object.entries(edits).filter(([id]) => !skip.has(id)));
    const result = await run(() => api<any>("rmm/script-categories", { body: { ids: chosen.map((c) => c.id), overrides } }),
                             `${chosen.length} scripts re-filed`);
    if (result) onClose(true);
  };
  return (
    <Modal wide title="Organise script categories" onClose={() => onClose(false)}
           footer={<><button onClick={() => onClose(false)}>Cancel</button>
                     <button className="primary" disabled={busy || !chosen.length} onClick={apply}>Apply {chosen.length} changes</button></>}>
      <p className="small muted">Each script is filed as <b>Operating system › Area › Kind</b>: Check (reports only), Fix (repairs a problem),
        Action (makes a change) or Response (isolate, erase). Only the category changes: reviews and versions stay as they are.
        Untick any you want to leave, or type a different category.</p>
      {data == null ? <div className="empty">Working out categories…</div> : !changes.length ? <div className="empty">Every script is already filed.</div> :
        <Table rows={changes} columns={[
          { key: "use", label: "", render: (c) => <input type="checkbox" checked={!skip.has(c.id)} aria-label={`Re-file ${c.name}`}
              onChange={(e) => setSkip((s) => { const n = new Set(s); if (e.target.checked) n.delete(c.id); else n.add(c.id); return n; })} /> },
          { key: "name", label: "Script", render: (c) => <><b>{displayValue(c.name)}</b>{c.builtin && <> <Pill value="built-in" tone="blue" /></>}</> },
          { key: "current", label: "Now", render: (c) => <span className="small muted">{categoryLabel(c.current) || "—"}</span> },
          { key: "proposed", label: "Will be", render: (c) => <input value={edits[c.id] ?? c.proposed} style={{ width: "100%" }}
              onChange={(e) => setEdits({ ...edits, [c.id]: e.target.value })} /> }]} />}
    </Modal>
  );
}

export function RunScript({ script, onClose, onStarted, presetDeviceId, presetDeviceIds }: { script: any; onClose: () => void; onStarted: (jobId: string) => void; presetDeviceId?: string; presetDeviceIds?: string[] }) {
  const [targets, setTargets] = useState<Targets>(() => ({ ...emptyTargets(), deviceIds: presetDeviceIds ?? (presetDeviceId ? [presetDeviceId] : []) }));
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
