import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { Modal, PageHead, Pill, Table, TenantSelect, useAction, useData } from "../components/ui";

export default function Policies() {
  const { tenantId, tenantName, can } = useApp();
  const navigate = useNavigate();
  const { data } = useData<any[]>("policies", { tenant_id: tenantId });
  const { data: schema } = useData<any>("policy-schema");
  const [creating, setCreating] = useState(false);
  return (
    <>
      <PageHead title="Policies"
                subtitle={schema ? `${schema.fieldCount} settings across ${schema.sections.length} protection modules. Layered global → tenant → group → device, with locks.` : ""}
                actions={can("configure") && <button className="primary" onClick={() => setCreating(true)}>New policy</button>} />
      <div className="card">
        <Table rows={data} onRow={(p) => navigate(`/policies/${p.id}`)}
               columns={[{ key: "name", label: "Policy", render: (p) => <><b>{p.name}</b><div className="small muted">{p.description}</div></> },
                         { key: "tenantId", label: "Scope", render: (p) => p.tenantId ? tenantName(p.tenantId) : <Pill value="global" tone="blue" /> },
                         { key: "template", label: "Based on" },
                         { key: "locks", label: "Locks", render: (p) => p.locks.length || "—" },
                         { key: "usage", label: "Applied to", render: (p) => [p.tenants && `${p.tenants} tenant(s)`, p.groups && `${p.groups} group(s)`, p.devices && `${p.devices} device(s)`].filter(Boolean).join(", ") || "—" },
                         { key: "version", label: "Version", render: (p) => `v${p.version}` },
                         { key: "updatedAt", label: "Updated", render: (p) => <>{fmtTime(p.updatedAt)}<div className="small muted">{p.updatedBy}</div></> }]} />
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
            <input type="radio" name="template" checked={template === t.key} onChange={() => setTemplate(t.key)} /> <b>{t.label}</b>
            <div className="small muted">{t.description}</div>
          </label>
        ))}
      </div>
    </Modal>
  );
}
