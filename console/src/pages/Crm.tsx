import { useState } from "react";
import { api, money } from "../api";
import { useApp } from "../app-context";
import { Modal, PageHead, Pill, Table, Tabs, useAction, useData } from "../components/ui";

const STAGES = ["New", "Contacted", "Qualified", "Proposal", "Won", "Lost"];

export default function Crm() {
  const { can, tenantName } = useApp();
  const [tab, setTab] = useState("Pipeline");
  const { data: leads, reload } = useData<any[]>("crm/leads");
  const { data: contacts, reload: reloadContacts } = useData<any[]>("crm/contacts");
  const { data: projects, reload: reloadProjects } = useData<any[]>("crm/projects");
  const [editing, setEditing] = useState<{ kind: string; row: any } | null>(null);
  const [converting, setConverting] = useState<any>(null);
  const { run } = useAction();

  const move = async (lead: any, stage: string) => {
    await run(() => api(`crm/leads/${lead.id}`, { method: "PATCH", body: { stage } }));
    reload();
  };
  const pipelineValue = leads?.filter((l) => !["Won", "Lost"].includes(l.stage)).reduce((n, l) => n + l.value, 0) ?? 0;

  return (
    <>
      <PageHead title="CRM" subtitle={`Open pipeline ${money(pipelineValue)} · won deals become protected customer tenants in one click.`}
                actions={can("crm") && <button className="primary" onClick={() => setEditing({ kind: tab === "Contacts" ? "contacts" : tab === "Projects" ? "projects" : "leads", row: {} })}>
                  New {tab === "Contacts" ? "contact" : tab === "Projects" ? "project" : "lead"}</button>} />
      <Tabs tabs={["Pipeline", "Contacts", "Projects"]} active={tab} onChange={setTab} />
      {tab === "Pipeline" && (
        <div className="kanban">
          {STAGES.map((stage) => (
            <div key={stage} className="col">
              <div className="row"><b>{stage}</b><span style={{ flex: 1 }} /><span className="small muted">{money(leads?.filter((l) => l.stage === stage).reduce((n, l) => n + l.value, 0) ?? 0)}</span></div>
              {leads?.filter((l) => l.stage === stage).map((lead) => (
                <div key={lead.id} className="lead">
                  <b style={{ cursor: "pointer" }} onClick={() => setEditing({ kind: "leads", row: lead })}>{lead.company}</b>
                  <div className="small muted">{lead.contact} · {lead.seats} seats</div>
                  <div className="small">{money(lead.value)}</div>
                  {lead.convertedTenantId ? <Pill value={`customer: ${tenantName(lead.convertedTenantId)}`} tone="good" /> : can("crm") && (
                    <div className="row" style={{ marginTop: 6 }}>
                      <select className="small" value={lead.stage} onChange={(e) => move(lead, e.target.value)} aria-label="Move stage">{STAGES.map((s) => <option key={s}>{s}</option>)}</select>
                      {can("manage_tenants") && lead.stage !== "Lost" && <button className="small primary" onClick={() => setConverting(lead)}>Convert</button>}
                    </div>
                  )}
                </div>
              ))}
            </div>
          ))}
        </div>
      )}
      {tab === "Contacts" && (
        <div className="card">
          <Table rows={contacts} onRow={(r) => setEditing({ kind: "contacts", row: r })}
                 columns={[{ key: "name", label: "Name", render: (r) => <><b>{r.name}</b> {r.isPrimary && <Pill value="primary" tone="blue" />}</> },
                           { key: "title", label: "Title" }, { key: "email", label: "Email" }, { key: "phone", label: "Phone" },
                           { key: "accountTenantId", label: "Account", render: (r) => r.accountTenantId ? tenantName(r.accountTenantId) : "—" }]} />
        </div>
      )}
      {tab === "Projects" && (
        <div className="card">
          <Table rows={projects} onRow={(r) => setEditing({ kind: "projects", row: r })}
                 columns={[{ key: "name", label: "Project" }, { key: "accountTenantId", label: "Account", render: (r) => r.accountTenantId ? tenantName(r.accountTenantId) : "—" },
                           { key: "status", label: "Status", render: (r) => <Pill value={r.status} tone="blue" /> },
                           { key: "progress", label: "Progress", render: (r) => `${r.progress}%` }, { key: "budget", label: "Budget", render: (r) => money(r.budget) },
                           { key: "dueDate", label: "Due" }]} />
        </div>
      )}
      {editing && <CrmEditor kind={editing.kind} row={editing.row} onClose={() => { setEditing(null); reload(); reloadContacts(); reloadProjects(); }} />}
      {converting && <ConvertLead lead={converting} onClose={() => { setConverting(null); reload(); }} />}
    </>
  );
}

const FIELDS: Record<string, { key: string; label: string; type?: string; options?: string[] }[]> = {
  leads: [{ key: "company", label: "Company" }, { key: "contact", label: "Contact" }, { key: "email", label: "Email" }, { key: "phone", label: "Phone" },
          { key: "stage", label: "Stage", options: STAGES }, { key: "value", label: "Annual value", type: "number" }, { key: "seats", label: "Seats", type: "number" },
          { key: "source", label: "Source" }, { key: "owner", label: "Owner" }, { key: "notes", label: "Notes" }],
  contacts: [{ key: "name", label: "Name" }, { key: "title", label: "Job title" }, { key: "email", label: "Email" }, { key: "phone", label: "Phone" },
             { key: "accountTenantId", label: "Account", type: "tenant" }, { key: "notes", label: "Notes" }],
  projects: [{ key: "name", label: "Name" }, { key: "accountTenantId", label: "Account", type: "tenant" }, { key: "status", label: "Status", options: ["Planning", "In Progress", "On Hold", "Complete"] },
             { key: "progress", label: "Progress %", type: "number" }, { key: "budget", label: "Budget", type: "number" }, { key: "dueDate", label: "Due date", type: "date" }],
};

function CrmEditor({ kind, row, onClose }: { kind: string; row: any; onClose: () => void }) {
  const { me } = useApp();
  const [form, setForm] = useState<any>({ stage: "New", status: "Planning", ...row });
  const { run, busy } = useAction();
  const save = async () => {
    const body: any = {};
    for (const f of FIELDS[kind]) if (form[f.key] !== undefined) body[f.key] = f.type === "number" ? Number(form[f.key]) : form[f.key];
    const ok = row.id ? await run(() => api(`crm/${kind}/${row.id}`, { method: "PATCH", body }), "Saved")
                      : await run(() => api(`crm/${kind}`, { body }), "Created");
    if (ok) onClose();
  };
  const remove = async () => { if (await run(() => api(`crm/${kind}/${row.id}`, { method: "DELETE" }), "Deleted")) onClose(); };
  return (
    <Modal title={row.id ? "Edit" : "New"} onClose={onClose}
           footer={<>{row.id && <button className="danger" onClick={remove}>Delete</button>}<button onClick={onClose}>Cancel</button><button className="primary" disabled={busy} onClick={save}>Save</button></>}>
      <div className="form-grid">
        {FIELDS[kind].map((f) => (
          <label key={f.key} className="field">{f.label}
            {f.options ? <select value={form[f.key] ?? ""} onChange={(e) => setForm({ ...form, [f.key]: e.target.value })}>{f.options.map((o) => <option key={o}>{o}</option>)}</select>
              : f.type === "tenant" ? <select value={form[f.key] ?? ""} onChange={(e) => setForm({ ...form, [f.key]: e.target.value || null })}><option value="">—</option>{me?.tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}</select>
              : <input type={f.type ?? "text"} value={form[f.key] ?? ""} onChange={(e) => setForm({ ...form, [f.key]: e.target.value })} />}
          </label>
        ))}
      </div>
    </Modal>
  );
}

function ConvertLead({ lead, onClose }: { lead: any; onClose: () => void }) {
  const { refreshMe } = useApp();
  const { data: schema } = useData<any>("policy-schema");
  const [template, setTemplate] = useState("balanced");
  const [price, setPrice] = useState(lead.seats ? (lead.value / lead.seats / 12).toFixed(2) : "5.00");
  const { run, busy } = useAction();
  const submit = async () => {
    const result = await run(() => api(`crm/leads/${lead.id}/convert`, { body: { template, pricePerDevice: Number(price) } }), `${lead.company} is now a customer tenant`);
    if (result) { await refreshMe(); onClose(); }
  };
  return (
    <Modal title={`Convert ${lead.company} to a customer`} onClose={onClose} footer={<><button onClick={onClose}>Cancel</button><button className="primary" disabled={busy} onClick={submit}>Convert</button></>}>
      <p className="muted">Creates the customer tenant, its default protection policy, the primary contact and a billing contract. Then create an enrollment token under Deploy agents.</p>
      <div className="form-grid">
        <label className="field">Protection template<select value={template} onChange={(e) => setTemplate(e.target.value)}>{schema?.templates.map((t: any) => <option key={t.key} value={t.key}>{t.label}</option>)}</select></label>
        <label className="field">Price per device / month<input type="number" step="0.01" value={price} onChange={(e) => setPrice(e.target.value)} /></label>
      </div>
    </Modal>
  );
}
