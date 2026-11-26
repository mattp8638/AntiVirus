import { useEffect, useState } from "react";
import { api, fmtTime } from "../../api";
import { useApp } from "../../app-context";
import { displayValue } from "../../components/DisplayValue";
import { confirmDialog } from "../../components/dialogs";
import { EntryField, RecordEditor } from "../../components/RecordEditor";
import { ErrorNote, Modal, Pill, Table, useAction, useData } from "../../components/ui";
import { safeArray } from "../../data-shapes";

/** Organization and scope (ISO 27001 4.1 to 4.3) and the asset register. Needs an ISMS role that can run the programme. */

const yesNo = (v: unknown) => (v ? "yes" : "no");
type Kind = "text" | "textarea" | "bool" | "kind";
type RegisterSpec = { name: string; title: string; help: string; noun: string; fields: { key: string; label: string; kind: Kind; required?: boolean }[] };

const REGISTERS: RegisterSpec[] = [
  { name: "context-issues", title: "Context issues (4.1)", noun: "issue", help: "Internal and external issues that affect what the ISMS must achieve, including whether climate change is relevant.",
    fields: [{ key: "kind", label: "Internal or external", kind: "kind", required: true }, { key: "description", label: "Issue", kind: "textarea", required: true },
             { key: "climateRelated", label: "Climate related", kind: "bool" }, { key: "impact", label: "Effect on the ISMS", kind: "textarea" }] },
  { name: "interested-parties", title: "Interested parties (4.2)", noun: "interested party", help: "Who has an interest in information security, what they need, and how the ISMS addresses it.",
    fields: [{ key: "name", label: "Interested party", kind: "text", required: true }, { key: "requirements", label: "Their requirements", kind: "textarea" },
             { key: "climateRequirements", label: "Climate related requirements", kind: "textarea" }, { key: "addressedBy", label: "Addressed by", kind: "textarea" }] },
  { name: "entities", title: "Legal entities", noun: "entity", help: "The organization's legal entities and whether each is in the ISMS scope.",
    fields: [{ key: "name", label: "Name", kind: "text", required: true }, { key: "address", label: "Address", kind: "textarea" }, { key: "inScope", label: "In scope", kind: "bool" }] },
  { name: "sites", title: "Sites", noun: "site", help: "Offices, data centres and other sites, and whether each is in the ISMS scope.",
    fields: [{ key: "name", label: "Name", kind: "text", required: true }, { key: "address", label: "Address", kind: "textarea" }, { key: "inScope", label: "In scope", kind: "bool" }] },
];

function editorFields(spec: RegisterSpec, row?: any): EntryField[] {
  return spec.fields.map((f) => ({
    key: f.key, label: f.label, required: f.required,
    type: f.kind === "textarea" ? "textarea" : f.kind === "text" ? "text" : "select",
    options: f.kind === "bool" ? ["yes", "no"] : f.kind === "kind" ? ["internal", "external"] : undefined,
    value: row ? (f.kind === "bool" ? yesNo(row[f.key]) : row[f.key] ?? "") : f.kind === "bool" && f.key === "inScope" ? "yes" : undefined,
  }));
}

function toBody(spec: RegisterSpec, form: any) {
  const out: any = {};
  for (const f of spec.fields) out[f.key] = f.kind === "bool" ? form[f.key] === "yes" : form[f.key];
  return out;
}

/** The ISMS role check: shows why the page is empty instead of a bare error. */
function useIsmsAccess(permission: string) {
  const { tenantId } = useApp();
  const { data: me } = useData<any>(tenantId ? "isms/me" : null, { tenant_id: tenantId }, [tenantId]);
  const allowed = !!me && safeArray<string>(me.permissions).includes(permission);
  return { tenantId, me, allowed };
}

function NoAccess({ me }: { me: any }) {
  if (!me) return null;
  return <p className="muted">Your ISMS role in this customer ({displayValue(me.role ?? "none")}) cannot run the programme. Ask an ISMS administrator for the ISMS manager role on the ISMS roles tab.</p>;
}

export function IsmsOrganizationTab() {
  const { tenantId, me, allowed } = useIsmsAccess("programme.manage");
  if (!tenantId) return <p className="muted">Choose a customer in the tenant picker to see its organization and scope.</p>;
  if (!allowed) return <NoAccess me={me} />;
  return <>
    <ScopeCard tenantId={tenantId} />
    {REGISTERS.map((spec) => <RegisterCard key={spec.name} spec={spec} tenantId={tenantId} />)}
  </>;
}

function ScopeCard({ tenantId }: { tenantId: string }) {
  const { data, error, reload } = useData<any>("isms/scope", { tenant_id: tenantId }, [tenantId]);
  const [form, setForm] = useState({ statement: "", boundaries: "", interfaces: "", exclusions: "" });
  const { run, busy } = useAction();
  // Fill the form when the saved scope arrives (the form is only shown after that, so nothing typed is lost).
  useEffect(() => { if (data) setForm({ statement: data.statement, boundaries: data.boundaries, interfaces: data.interfaces, exclusions: data.exclusions }); }, [data]);
  const save = async () => { await run(() => api("isms/scope", { method: "PUT", body: { tenantId, ...form } }), "Scope saved"); reload(); };
  const field = (key: keyof typeof form, label: string) => <label className="field">{label}
    <textarea rows={key === "statement" ? 4 : 2} value={form[key]} onChange={(e) => setForm({ ...form, [key]: e.target.value })} /></label>;
  if (!data) return <div className="card"><h3 style={{ marginTop: 0 }}>ISMS scope (4.3)</h3><ErrorNote error={error} />{!error && <p className="small muted">Loading the scope.</p>}</div>;
  return <div className="card">
    <h3 style={{ marginTop: 0 }}>ISMS scope (4.3)</h3>
    <ErrorNote error={error} />
    <p className="small muted">{data?.version ? `Version ${data.version}, last changed ${fmtTime(data.updatedAt)} by ${displayValue(data.updatedBy)}.` : "No scope recorded yet."} Each change to the wording makes a new version.</p>
    {field("statement", "Scope statement (required)")}
    {field("boundaries", "Boundaries")}
    {field("interfaces", "Interfaces and dependencies")}
    {field("exclusions", "Exclusions and why")}
    <button className="primary" disabled={busy || !form.statement.trim()} onClick={save}>Save scope</button>
  </div>;
}

function RegisterCard({ spec, tenantId }: { spec: RegisterSpec; tenantId: string }) {
  const { data, error, reload } = useData<{ items: any[] }>(`isms/registers/${spec.name}`, { tenant_id: tenantId }, [tenantId]);
  const [editing, setEditing] = useState<any | "new" | null>(null);
  const { run } = useAction();
  const remove = async (row: any) => {
    if (!(await confirmDialog(`Delete this ${spec.noun}?`, { confirmLabel: "Delete", danger: true }))) return;
    await run(() => api(`isms/registers/${spec.name}/${row.id}`, { method: "DELETE" }), "Deleted");
    reload();
  };
  return <div className="card">
    <div className="row" style={{ justifyContent: "space-between" }}>
      <h3 style={{ margin: 0 }}>{spec.title}</h3>
      <button onClick={() => setEditing("new")}>Add {spec.noun}</button>
    </div>
    <p className="small muted">{spec.help}</p>
    <ErrorNote error={error} />
    <Table rows={safeArray<any>(data?.items)} empty={`No ${spec.noun} recorded yet.`} onRow={(r) => setEditing(r)}
      columns={[...spec.fields.map((f) => ({ key: f.key, label: f.label, render: (r: any) => f.kind === "bool" ? <Pill value={yesNo(r[f.key])} tone={r[f.key] ? "good" : "muted"} /> : <span className="small">{displayValue(r[f.key])}</span> })),
                { key: "id", label: "", render: (r: any) => <button className="small" aria-label={`Delete ${spec.noun}`} onClick={(e) => { e.stopPropagation(); remove(r); }}>Delete</button> }]} />
    {editing && <RecordEditor tenant={false} title={editing === "new" ? `Add ${spec.noun}` : `Edit ${spec.noun}`} fields={editorFields(spec, editing === "new" ? undefined : editing)}
      onSave={(form) => editing === "new"
        ? api(`isms/registers/${spec.name}`, { body: { tenantId, ...toBody(spec, form) } })
        : api(`isms/registers/${spec.name}/${editing.id}`, { method: "PATCH", body: toBody(spec, form) })}
      onClose={() => { setEditing(null); reload(); }} />}
  </div>;
}

export function IsmsAssetsTab() {
  const { tenantId, me, allowed } = useIsmsAccess("programme.manage");
  const { data, error, reload } = useData<any>(allowed ? "isms/assets" : null, { tenant_id: tenantId }, [tenantId, allowed]);
  const { data: people } = useData<any>(allowed ? "isms/members" : null, { tenant_id: tenantId }, [tenantId, allowed]);
  const [editing, setEditing] = useState<any | "new" | null>(null);
  const [importing, setImporting] = useState(false);
  const { run } = useAction();
  if (!tenantId) return <p className="muted">Choose a customer in the tenant picker to see its assets.</p>;
  if (!allowed) return <NoAccess me={me} />;
  const owners = safeArray<any>(people?.members);
  const remove = async (a: any) => {
    if (!(await confirmDialog(`Delete the asset "${a.name}"?`, { confirmLabel: "Delete", danger: true }))) return;
    await run(() => api(`isms/assets/${a.id}`, { method: "DELETE" }), "Asset deleted");
    reload();
  };
  return <div className="card">
    <div className="row" style={{ justifyContent: "space-between", marginBottom: 8 }}>
      <span className="small muted">Information, systems, services, people, suppliers and sites, with an owner and a classification.</span>
      <span className="row" style={{ gap: 6 }}><button onClick={() => setImporting(true)}>Import CSV</button><button className="primary" onClick={() => setEditing("new")}>Add asset</button></span>
    </div>
    <ErrorNote error={error} />
    <Table rows={safeArray<any>(data?.items)} empty="No assets recorded yet." onRow={(a) => setEditing(a)} columns={[
      { key: "name", label: "Asset", render: (a) => <><b>{displayValue(a.name)}</b><div className="small muted">{displayValue(a.description)}</div></> },
      { key: "type", label: "Type" },
      { key: "classification", label: "Classification", render: (a) => <Pill value={a.classification} tone={a.classification === "restricted" || a.classification === "confidential" ? "warn" : "muted"} /> },
      { key: "ownerName", label: "Owner", render: (a) => displayValue(a.ownerName ?? "None") },
      { key: "id", label: "", render: (a) => <button className="small" aria-label={`Delete ${a.name}`} onClick={(e) => { e.stopPropagation(); remove(a); }}>Delete</button> }]} />
    {editing && <RecordEditor tenant={false} title={editing === "new" ? "Add an asset" : `Edit ${editing.name}`} fields={[
      { key: "name", label: "Name", required: true, value: editing === "new" ? "" : editing.name },
      { key: "type", label: "Type", type: "select", required: true, options: safeArray<string>(data?.types), value: editing === "new" ? "" : editing.type },
      { key: "classification", label: "Classification", type: "select", options: safeArray<string>(data?.classifications), value: editing === "new" ? "internal" : editing.classification },
      ...(owners.length ? [{ key: "owner", label: "Owner (someone with an ISMS role here)", type: "select" as const, options: owners.map((o) => o.email), value: editing === "new" ? "" : owners.find((o) => o.id === editing.ownerId)?.email ?? "" }] : []),
      { key: "description", label: "Description", type: "textarea", value: editing === "new" ? "" : editing.description ?? "" }]}
      onSave={(form) => {
        const body = { name: form.name, type: form.type, classification: form.classification, description: form.description,
                       ownerId: owners.find((o) => o.email === form.owner)?.id ?? null };
        return editing === "new" ? api("isms/assets", { body: { tenantId, ...body } }) : api(`isms/assets/${editing.id}`, { method: "PATCH", body });
      }}
      onClose={() => { setEditing(null); reload(); }} />}
    {importing && <ImportAssets tenantId={tenantId} columns={safeArray<string>(data?.csvColumns)} onClose={() => { setImporting(false); reload(); }} />}
  </div>;
}

function ImportAssets({ tenantId, columns, onClose }: { tenantId: string; columns: string[]; onClose: () => void }) {
  const [csv, setCsv] = useState("");
  const [result, setResult] = useState<any>(null);
  const { run, busy } = useAction();
  const go = async () => {
    const r = await run(() => api<any>("isms/assets/import", { body: { tenantId, csv } }));
    if (r) setResult(r);
  };
  return <Modal title="Import assets from CSV" onClose={onClose} wide footer={<button className="primary" disabled={busy || !csv.trim()} onClick={go}>Import</button>}>
    <p className="small muted">Columns: {columns.join(", ")}. Name and type are required. Rows with the same type and name as an existing asset update it. If any row has a problem, nothing is imported.</p>
    <label className="field">CSV file<input type="file" accept=".csv,text/csv" onChange={async (e) => { const f = e.target.files?.[0]; if (f) setCsv(await f.text()); }} /></label>
    <label className="field">Or paste the CSV<textarea rows={8} value={csv} onChange={(e) => setCsv(e.target.value)} /></label>
    {result && (result.errors.length
      ? <div role="alert"><p><b>Nothing was imported.</b> Fix these rows and try again:</p><ul>{result.errors.map((e: any, i: number) => <li key={i}>{e.line ? `Line ${e.line}: ` : ""}{displayValue(e.message)}</li>)}</ul></div>
      : <p role="status">{result.created} created, {result.updated} updated.</p>)}
  </Modal>;
}
