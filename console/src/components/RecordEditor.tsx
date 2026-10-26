import { useState } from "react";
import { useApp } from "../app-context";
import { safeArray } from "../data-shapes";
import { ErrorNote, Modal, TenantSelect, useAction, useListData } from "./ui";

export type EntryField = { key: string; label: string; type?: "text" | "password" | "number" | "textarea" | "select"; options?: string[]; source?: "configurations" | "documents" | "rules" | "devices"; required?: boolean; value?: string | number };
export function RecordEditor({ title, fields, tenant = true, onSave, onClose }: {
  title: string; fields: EntryField[]; tenant?: boolean; onSave: (value: any) => Promise<unknown>; onClose: () => void;
}) {
  const { tenantId } = useApp();
  const [form, setForm] = useState<any>(() => Object.fromEntries([["tenantId", tenantId], ...fields.map(f => [f.key, f.value ?? ""])]));
  const { run, busy } = useAction();
  const {data: configurations, error: configError} = useListData<any>(fields.some(f=>f.source==="configurations") && form.tenantId ? "psa/configurations" : null, {accountTenantId:form.tenantId});
  const {data: documents, error: docError} = useListData<any>(fields.some(f=>f.source==="documents") && form.tenantId ? "psa/kb" : null, {tenant_id:form.tenantId});
  const {data: rules, error: ruleError} = useListData<any>(fields.some(f=>f.source==="rules") ? "rules" : null);
  const {data: devices, error: deviceError} = useListData<any>(fields.some(f=>f.source==="devices") && form.tenantId ? "devices" : null, {tenant_id:form.tenantId});
  const choices = (f: EntryField) => f.source
    ? safeArray<any>(f.source==="configurations"?configurations:f.source==="documents"?documents:f.source==="devices"?devices:rules)
      .filter(r=>f.source!=="rules" || !r.tenantId || r.tenantId===form.tenantId)
      .map(r=>({value:r.id,label:r.name||r.title||r.hostname}))
    : safeArray<string>(f.options).map(value=>({value,label:value}));
  return <Modal title={title} onClose={onClose}>
    <ErrorNote error={configError || docError || ruleError || deviceError}/><form onSubmit={async e => { e.preventDefault(); if (await run(() => onSave(form), "Saved")) onClose(); }}>
      {tenant && <label className="field">Customer<TenantSelect value={form.tenantId} onChange={id => setForm({ ...form, tenantId: id, ...Object.fromEntries(fields.filter(f=>f.source).map(f=>[f.key,""])) })} /></label>}
      {fields.map(f => <label className="field" key={f.key}>{f.label}
        {f.type === "select" ? <select required={f.required} value={form[f.key]} onChange={e => setForm({ ...form, [f.key]: e.target.value })}><option value="">Choose…</option>{choices(f).map(o => <option key={o.value} value={o.value}>{o.label}</option>)}</select>
          : f.type === "textarea" ? <textarea required={f.required} rows={4} value={form[f.key]} onChange={e => setForm({ ...form, [f.key]: e.target.value })} />
          : <input required={f.required} type={f.type || "text"} autoComplete={f.type === "password" ? "new-password" : undefined} value={form[f.key]} onChange={e => setForm({ ...form, [f.key]: f.type === "number" ? Number(e.target.value) : e.target.value })} />}
      </label>)}
      <button className="primary" disabled={busy || (tenant && !form.tenantId)} type="submit">Save</button>
    </form>
  </Modal>;
}
