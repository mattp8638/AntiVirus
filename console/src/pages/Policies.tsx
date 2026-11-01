import { displayValue } from "../components/DisplayValue";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { Modal, PageHead, Pill, Table, TenantSelect, useAction, useData, useListData } from "../components/ui";

export default function Policies() {
  const { tenantId, tenantName, can } = useApp();
  const navigate = useNavigate();
  const { data } = useListData<any>("policies", { tenant_id: tenantId });
  const { data: schema } = useData<any>("policy-schema");
  const [creating, setCreating] = useState(false);
  return (
    <>
      <PageHead title="Policies"
                subtitle={schema ? `${schema.fieldCount} settings across ${schema.sections.length} protection modules. Layered global → tenant → group → device, with locks.` : ""}
                actions={can("configure") && <button className="primary" onClick={() => setCreating(true)}>New policy</button>} />
      <div className="card">
        <Table rows={data} onRow={(p) => navigate(`/policies/${p.id}`)}
               columns={[{ key: "name", label: "Policy", render: (p) => <><b>{displayValue(p.name)}</b><div className="small muted">{displayValue(p.description)}</div></> },
                         { key: "tenantId", label: "Scope", render: (p) => p.tenantId ? tenantName(p.tenantId) : <Pill value="global" tone="blue" /> },
                         { key: "template", label: "Based on" },
                         { key: "locks", label: "Locks", render: (p) => p.locks.length || "—" },
                         { key: "usage", label: "Applied to", render: (p) => [p.tenants && `${p.tenants} tenant(s)`, p.groups && `${p.groups} group(s)`, p.devices && `${p.devices} device(s)`].filter(Boolean).join(", ") || "—" },
                         { key: "version", label: "Version", render: (p) => `v${p.version}` },
                         { key: "updatedAt", label: "Updated", render: (p) => <>{fmtTime(p.updatedAt)}<div className="small muted">{displayValue(p.updatedBy)}</div></> }]} />
      </div>
      {creating && schema && <CreatePolicy templates={schema.templates} onClose={() => setCreating(false)} />}
    </>
  );
}

function CreatePolicy({ templates, onClose }: { templates: any[]; onClose: () => void }) {
  const { tenantId } = useApp();
  const navigate = useNavigate();
  const [tenant, setTenant] = useState(tenantId);
  const [name, setName] = useState("");
  const [template, setTemplate] = useState("balanced");
  const { run, busy } = useAction();
  const submit = async () => {
    const policy = await run(() => api<any>("policies", { body: { tenantId: tenant || null, name: name || "New policy", template } }), "Policy created");
    if (policy) navigate(`/policies/${policy.id}`);
  };
  return (
    <Modal title="New policy" onClose={onClose} footer={<><button onClick={onClose}>Cancel</button><button className="primary" disabled={busy || !tenant} onClick={submit}>Create</button></>}>
      <div className="form-grid">
        <label className="field">Tenant<TenantSelect value={tenant} onChange={setTenant} allowAll={false} /></label>
        <label className="field">Name<input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Finance laptops" /></label>
      </div>
      <h3 style={{ marginTop: 16 }}>Start from</h3>
      <div className="grid k2">
        {templates.map((t) => (
          <label key={t.key} className="card" style={{ cursor: "pointer", borderColor: template === t.key ? "var(--blue)" : undefined }}>
            <input type="radio" name="template" checked={template === t.key} onChange={() => setTemplate(t.key)} /> <b>{displayValue(t.label)}</b>
            <div className="small muted">{displayValue(t.description)}</div>
          </label>
        ))}
      </div>
      <TemplateDifferences template={template} />
    </Modal>
  );
}

/** "section.key" -> value for every setting, so two policies can be compared line by line. */
export function flattenSettings(settings: Record<string, Record<string, unknown>> | null | undefined): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [section, values] of Object.entries(settings || {})) for (const [key, value] of Object.entries(values || {})) out[`${section}.${key}`] = value;
  return out;
}

export function settingDifferences(before: Record<string, unknown>, after: Record<string, unknown>) {
  const keys = [...new Set([...Object.keys(before), ...Object.keys(after)])].sort();
  return keys.filter((k) => JSON.stringify(before[k]) !== JSON.stringify(after[k])).map((k) => ({ id: k, setting: k, before: before[k], after: after[k] }));
}

export const showSetting = (value: unknown) => value === undefined ? "not set" : Array.isArray(value) ? (value.length ? value.join(", ") : "none") : typeof value === "boolean" ? (value ? "on" : "off") : String(value);

function TemplateDifferences({ template }: { template: string }) {
  const { data: chosen } = useData<any>(`policy-templates/${template}`, {}, [template]);
  const { data: balanced } = useData<any>("policy-templates/balanced");
  if (!chosen || !balanced) return null;
  const rows = settingDifferences(flattenSettings(balanced), flattenSettings(chosen));
  return (
    <details style={{ marginTop: 12 }} open={template !== "balanced"}>
      <summary className="small">{template === "balanced" ? "Balanced is Fenrir's recommended starting point." : `How this template differs from Balanced (${rows.length} setting${rows.length === 1 ? "" : "s"})`}</summary>
      {template !== "balanced" && <Table rows={rows.slice(0, 60)} empty="Same as Balanced."
        columns={[{ key: "setting", label: "Setting", render: (r) => <span className="mono small">{r.setting}</span> },
                  { key: "before", label: "Balanced", render: (r) => <span className="small">{displayValue(showSetting(r.before))}</span> },
                  { key: "after", label: "This template", render: (r) => <span className="small"><b>{displayValue(showSetting(r.after))}</b></span> }]} />}
    </details>
  );
}
