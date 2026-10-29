import { Fragment, useEffect, useState } from "react";
import { api } from "../api";
import { useApp } from "../app-context";
import { displayValue } from "./DisplayValue";
import { confirmDialog } from "./dialogs";
import { Modal, Pill, Table, useAction, useListData } from "./ui";

// Saved list views (devices, tickets, alerts) and MSP-defined custom fields on devices and tickets.

interface View { id: string; name: string; filters: Record<string, string>; shared: boolean; mine: boolean; owner: string }

/** A "Saved views" picker for a list page: choose one to apply its filters, or save the current ones under a name. */
export function SavedViews({ page, filters, onApply }: { page: "devices" | "tickets" | "alerts"; filters: Record<string, string>;
                                                       onApply: (filters: Record<string, string>) => void }) {
  const { can } = useApp();
  const { data, reload } = useListData<View>("saved-views", { page });
  const [current, setCurrent] = useState("");
  const [saving, setSaving] = useState(false);
  const { run } = useAction();
  const selected = data?.find((v) => v.id === current);
  const choose = (id: string) => {
    setCurrent(id);
    const view = data?.find((v) => v.id === id);
    if (view) onApply(view.filters);
  };
  const remove = async () => {
    if (!selected || !(await confirmDialog(`Delete the saved view "${selected.name}"?`))) return;
    if (await run(() => api(`saved-views/${selected.id}`, { method: "DELETE" }), "View deleted")) { setCurrent(""); reload(); }
  };
  return (
    <>
      <select value={current} onChange={(e) => choose(e.target.value)} aria-label="Saved views">
        <option value="">Saved views…</option>
        {(data ?? []).filter((v) => v.mine).map((v) => <option key={v.id} value={v.id}>{v.name}{v.shared ? " (shared)" : ""}</option>)}
        {(data ?? []).some((v) => !v.mine) && <optgroup label="Shared with you">
          {(data ?? []).filter((v) => !v.mine).map((v) => <option key={v.id} value={v.id}>{v.name}</option>)}
        </optgroup>}
      </select>
      <button className="small" onClick={() => setSaving(true)} title="Save these filters as a view">Save view</button>
      {selected && (selected.mine || can("configure")) && <button className="small ghost" onClick={remove} aria-label={`Delete view ${selected.name}`}>✕</button>}
      {saving && <SaveViewModal page={page} filters={filters} onClose={(id) => { setSaving(false); if (id) { setCurrent(id); reload(); } }} />}
    </>
  );
}

function SaveViewModal({ page, filters, onClose }: { page: string; filters: Record<string, string>; onClose: (id?: string) => void }) {
  const { can } = useApp();
  const [name, setName] = useState("");
  const [shared, setShared] = useState(false);
  const { run, busy } = useAction();
  const kept = Object.fromEntries(Object.entries(filters).filter(([, v]) => v !== "" && v != null));
  const save = async () => {
    const view = await run(() => api<View>("saved-views", { body: { page, name: name.trim(), filters: kept, shared } }), "View saved");
    if (view) onClose(view.id);
  };
  return (
    <Modal title="Save view" onClose={() => onClose()}
           footer={<><button onClick={() => onClose()}>Cancel</button><button className="primary" disabled={busy || !name.trim()} onClick={save}>Save</button></>}>
      <label className="field">Name<input autoFocus value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. My P1s, Servers offline"
                                          onKeyDown={(e) => { if (e.key === "Enter" && name.trim()) save(); }} /></label>
      <p className="small muted">Filters: {Object.entries(kept).map(([k, v]) => `${k} = ${v}`).join(" · ") || "none (everything)"}</p>
      {can("configure") && <label className="small" style={{ display: "flex", gap: 6, alignItems: "center" }}>
        <input type="checkbox" checked={shared} onChange={(e) => setShared(e.target.checked)} /> Share with everyone in my organisation</label>}
    </Modal>
  );
}

export interface FieldDefinition { id: string; key: string; label: string; fieldType: "text" | "number" | "date" | "select" | "checkbox"; options: string[] }

const show = (field: FieldDefinition, value: unknown) =>
  value === undefined || value === null || value === "" ? <span className="muted">—</span>
    : field.fieldType === "checkbox" ? (value ? "Yes" : "No") : String(value);

/** The MSP's custom fields for one device or ticket, with inline editing. Shows nothing when none are defined. */
export function CustomFieldsCard({ entity, recordId, values }: { entity: "device" | "ticket"; recordId: string; values?: Record<string, unknown> | null }) {
  const { can } = useApp();
  const { data: fields } = useListData<FieldDefinition>("custom-fields", { entity });
  const [saved, setSaved] = useState<Record<string, unknown>>(values || {});
  const [draft, setDraft] = useState<Record<string, unknown> | null>(null);
  const { run, busy } = useAction();
  useEffect(() => { setSaved(values || {}); }, [values]);
  if (!fields?.length) return null;
  const editable = can("configure") || can("respond") || (entity === "ticket" && can("crm"));
  const save = async () => {
    if (!draft) return;
    const changed = Object.fromEntries(fields.map((f) => [f.key, draft[f.key] ?? null]));
    const result = await run(() => api<{ customFields: Record<string, unknown> }>(`custom-fields/values/${entity}/${recordId}`,
                                                                                  { method: "PUT", body: { values: changed } }), "Saved");
    if (result) { setSaved(result.customFields); setDraft(null); }
  };
  const set = (key: string, value: unknown) => setDraft({ ...(draft || {}), [key]: value });
  return (
    <div className="card">
      <div className="row"><h3 style={{ margin: 0, flex: 1 }}>Custom fields</h3>
        {editable && !draft && <button className="small ghost" onClick={() => setDraft({ ...saved })}>Edit</button>}</div>
      {!draft ? (
        <dl className="kv" style={{ marginTop: 8 }}>
          {fields.map((f) => <Fragment key={f.id}><dt>{f.label}</dt><dd>{displayValue(show(f, saved[f.key]))}</dd></Fragment>)}
        </dl>
      ) : (
        <div className="form-grid" style={{ marginTop: 8 }}>
          {fields.map((f) => (
            <label key={f.id} className="field">{f.label}
              {f.fieldType === "checkbox" ? <input type="checkbox" checked={!!draft[f.key]} onChange={(e) => set(f.key, e.target.checked)} />
                : f.fieldType === "select" ? <select value={String(draft[f.key] ?? "")} onChange={(e) => set(f.key, e.target.value)}>
                    <option value="">—</option>{f.options.map((o) => <option key={o}>{o}</option>)}</select>
                : <input type={f.fieldType === "number" ? "number" : f.fieldType === "date" ? "date" : "text"} value={String(draft[f.key] ?? "")}
                         onChange={(e) => set(f.key, f.fieldType === "number" && e.target.value !== "" ? Number(e.target.value) : e.target.value)} />}
            </label>
          ))}
          <div className="row" style={{ gridColumn: "1 / -1" }}>
            <button onClick={() => setDraft(null)}>Cancel</button><button className="primary" disabled={busy} onClick={save}>Save</button>
          </div>
        </div>
      )}
    </div>
  );
}

const TYPE_LABEL: Record<string, string> = { text: "Text", number: "Number", date: "Date", select: "List", checkbox: "Yes / no" };

/** Settings → Custom fields: define the fields every device and ticket gets. */
export function CustomFieldsSettings() {
  const { can } = useApp();
  const { data: device, reload: reloadDevice } = useListData<FieldDefinition>("custom-fields", { entity: "device" });
  const { data: ticket, reload: reloadTicket } = useListData<FieldDefinition>("custom-fields", { entity: "ticket" });
  const [form, setForm] = useState({ entity: "device", label: "", type: "text", options: "" });
  const { run, busy } = useAction();
  const reload = () => { reloadDevice(); reloadTicket(); };
  const add = async () => {
    const body = { entity: form.entity, label: form.label.trim(), type: form.type,
                   options: form.type === "select" ? form.options.split(",").map((o) => o.trim()).filter(Boolean) : [] };
    if (await run(() => api("custom-fields", { body }), "Field added")) { setForm({ ...form, label: "", options: "" }); reload(); }
  };
  const remove = async (f: FieldDefinition) => {
    if (await confirmDialog(`Remove the field "${f.label}"? Values already entered are kept on the records but no longer shown.`)
        && await run(() => api(`custom-fields/${f.id}`, { method: "DELETE" }), "Field removed")) reload();
  };
  const table = (rows: FieldDefinition[] | null) => (
    <Table rows={rows} empty="No custom fields yet."
           columns={[{ key: "label", label: "Field" }, { key: "key", label: "Key", render: (f) => <span className="mono small">{f.key}</span> },
                     { key: "fieldType", label: "Type", render: (f) => <>{TYPE_LABEL[f.fieldType]}{f.fieldType === "select" && <div className="small muted">{f.options.join(", ")}</div>}</> },
                     { key: "actions", label: "", className: "right", render: (f) => can("configure") && <button className="small danger" onClick={() => remove(f)}>Remove</button> }]} />
  );
  return (
    <>
      <p className="small muted">Fields you add here appear on every device or ticket, for every customer: asset tags, cost centres, contract references.
        Device and ticket searches also match their values.</p>
      {can("configure") && <div className="card row" style={{ flexWrap: "wrap", gap: 8, marginBottom: 14 }}>
        <select value={form.entity} onChange={(e) => setForm({ ...form, entity: e.target.value })} aria-label="Record type">
          <option value="device">Device field</option><option value="ticket">Ticket field</option></select>
        <input placeholder="Label, e.g. Asset tag" value={form.label} onChange={(e) => setForm({ ...form, label: e.target.value })} />
        <select value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value })} aria-label="Field type">
          {Object.entries(TYPE_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select>
        {form.type === "select" && <input placeholder="Options, comma separated" value={form.options} onChange={(e) => setForm({ ...form, options: e.target.value })} />}
        <button className="primary" disabled={busy || !form.label.trim()} onClick={add}>Add field</button>
      </div>}
      <div className="grid k2">
        <div className="card"><h3>Device fields <Pill value={String(device?.length ?? 0)} /></h3>{table(device)}</div>
        <div className="card"><h3>Ticket fields <Pill value={String(ticket?.length ?? 0)} /></h3>{table(ticket)}</div>
      </div>
    </>
  );
}
