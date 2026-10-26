import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ago, api, fmtTime, money } from "../api";
import { useApp } from "../app-context";
import { Modal, PageHead, Pill, Table, Tabs, useAction, useData } from "../components/ui";

const STAGES = ["New", "Contacted", "Qualified", "Proposal", "Won", "Lost"];
export const OPP_STAGES = ["Prospecting", "Qualification", "Proposal", "Negotiation", "Won", "Lost"];
export const ACTIVITY_KINDS = ["call", "email", "meeting", "note", "task"];
const TABS = ["Accounts", "Opportunities", "Activities", "Leads", "Contacts", "Projects"];
const KIND_FOR_TAB: Record<string, string> = { Accounts: "opportunities", Opportunities: "opportunities", Activities: "activities",
                                               Leads: "leads", Contacts: "contacts", Projects: "projects" };
const NOUN: Record<string, string> = { opportunities: "opportunity", activities: "activity", leads: "lead", contacts: "contact", projects: "project" };

export default function Crm() {
  const { can, tenantName } = useApp();
  const navigate = useNavigate();
  const [tab, setTab] = useState("Accounts");
  const { data: accounts, reload: reloadAccounts } = useData<any[]>("crm/accounts");
  const { data: opps, reload: reloadOpps } = useData<any[]>("crm/opportunities");
  const { data: oppPipeline, reload: reloadPipeline } = useData<any>("crm/opportunity-pipeline");
  const { data: activities, reload: reloadActivities } = useData<any[]>("crm/activities");
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
      <PageHead title="CRM" subtitle={`Open deals ${money(oppPipeline?.openValue ?? 0)} (weighted ${money(oppPipeline?.weightedValue ?? 0)}) · new-business leads ${money(pipelineValue)} · won leads become protected customer tenants in one click.`}
                actions={can("crm") && <button className="primary" onClick={() => setEditing({ kind: KIND_FOR_TAB[tab], row: {} })}>
                  New {NOUN[KIND_FOR_TAB[tab]]}</button>} />
      <Tabs tabs={TABS} active={tab} onChange={setTab} />
      {tab === "Accounts" && (
        <div className="card">
          <Table rows={accounts} onRow={(a) => navigate(`/crm/accounts/${a.id}`)} empty="No customer accounts yet. Convert a won lead or add a customer tenant."
                 columns={[{ key: "name", label: "Account", render: (a) => <><b>{a.name}</b><div className="small muted">{a.plan} · {a.devices} devices</div></> },
                           { key: "accountOwner", label: "Owner", render: (a) => a.accountOwner || <span className="muted">unassigned</span> },
                           { key: "mrr", label: "Contracted MRR", className: "right", render: (a) => money(a.mrr) },
                           { key: "openPipeline", label: "Open deals", className: "right", render: (a) => a.openPipeline ? money(a.openPipeline) : "—" },
                           { key: "openTickets", label: "Open tickets", className: "right" },
                           { key: "openTasks", label: "Open tasks", className: "right" },
                           { key: "lastActivityAt", label: "Last contact", render: (a) => a.lastActivityAt ? ago(a.lastActivityAt) : <span className="muted">never</span> }]} />
        </div>
      )}
      {tab === "Opportunities" && (
        <>
          <div className="grid k4" style={{ marginBottom: 14 }}>
            {OPP_STAGES.filter((st) => !["Won", "Lost"].includes(st)).map((st) => {
              const b = oppPipeline?.stages.find((x: any) => x.stage === st);
              return <div key={st} className="card"><div className="small muted">{st}</div><b>{money(b?.value ?? 0)}</b><div className="small muted">{b?.count ?? 0} deals · weighted {money(b?.weighted ?? 0)}</div></div>;
            })}
          </div>
          <div className="card">
            <div className="small muted" style={{ marginBottom: 8 }}>Win rate (90 days): {oppPipeline?.winRate == null ? "—" : `${oppPipeline.winRate}%`} · won {oppPipeline?.wonLast90Days ?? 0} · lost {oppPipeline?.lostLast90Days ?? 0}</div>
            <Table rows={opps} onRow={(o) => setEditing({ kind: "opportunities", row: o })} empty="No opportunities yet."
                   columns={[{ key: "name", label: "Opportunity", render: (o) => <><b>{o.name}</b><div className="small muted">{o.kind}{o.owner ? ` · ${o.owner}` : ""}</div></> },
                             { key: "accountTenantId", label: "Account", render: (o) => o.accountTenantId ? tenantName(o.accountTenantId) : "—" },
                             { key: "stage", label: "Stage", render: (o) => <Pill value={o.stage} tone={o.stage === "Won" ? "good" : o.stage === "Lost" ? "bad" : "blue"} /> },
                             { key: "value", label: "Value", className: "right", render: (o) => <>{money(o.value)}{o.monthlyValue ? <div className="small muted">+ {money(o.monthlyValue)}/mo</div> : null}</> },
                             { key: "probability", label: "Prob.", className: "right", render: (o) => `${o.probability}%` },
                             { key: "closeDate", label: "Close date" }]} />
          </div>
        </>
      )}
      {tab === "Activities" && <ActivityList rows={activities} onEdit={(r) => setEditing({ kind: "activities", row: r })} onChange={reloadActivities} />}
      {tab === "Leads" && (
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
      {editing && <CrmEditor kind={editing.kind} row={editing.row} onClose={() => {
        setEditing(null); reload(); reloadContacts(); reloadProjects(); reloadOpps(); reloadPipeline(); reloadActivities(); reloadAccounts(); }} />}
      {converting && <ConvertLead lead={converting} onClose={() => { setConverting(null); reload(); }} />}
    </>
  );
}

export function ActivityList({ rows, onEdit, onChange }: { rows: any[] | null; onEdit: (row: any) => void; onChange: () => void }) {
  const { tenantName, can } = useApp();
  const { run } = useAction();
  const toggle = async (row: any) => {
    await run(() => api(`crm/activities/${row.id}`, { method: "PATCH", body: { done: !row.completedAt } }));
    onChange();
  };
  const sorted = rows ? [...rows].sort((a, b) => Number(!!a.completedAt) - Number(!!b.completedAt)) : rows;
  return (
    <div className="card">
      <Table rows={sorted} onRow={onEdit} empty="No activities logged yet. Log calls, emails and meetings, or add follow-up tasks."
             columns={[{ key: "done", label: "", render: (r) => r.kind === "task" && can("crm")
                           ? <input type="checkbox" aria-label="Done" checked={!!r.completedAt} onClick={(e) => e.stopPropagation()} onChange={() => toggle(r)} /> : null },
                       { key: "subject", label: "Activity", render: (r) => <><b style={{ textDecoration: r.kind === "task" && r.completedAt ? "line-through" : undefined }}>{r.subject}</b>
                           <div className="small muted">{r.kind}{r.direction ? ` · ${r.direction}` : ""}{r.owner ? ` · ${r.owner}` : ""}</div></> },
                       { key: "accountTenantId", label: "Account", render: (r) => r.accountTenantId ? tenantName(r.accountTenantId) : "—" },
                       { key: "dueAt", label: "Due / when", render: (r) => r.kind === "task" && !r.completedAt
                           ? <span style={{ color: r.dueAt && new Date(r.dueAt + (r.dueAt.endsWith("Z") ? "" : "Z")) < new Date() ? "#fca5a5" : undefined }}>{r.dueAt ? fmtTime(r.dueAt) : "no due date"}</span>
                           : ago(r.completedAt || r.createdAt) }]} />
    </div>
  );
}

const DEFAULTS: Record<string, any> = { leads: { stage: "New" }, projects: { status: "Planning" },
                                        opportunities: { stage: "Prospecting", kind: "Upsell" }, activities: { kind: "call", direction: "outbound" } };

export const FIELDS: Record<string, { key: string; label: string; type?: string; options?: string[] }[]> = {
  opportunities: [{ key: "name", label: "Name" }, { key: "kind", label: "Type", options: ["New business", "Upsell", "Renewal", "Project"] },
                  { key: "accountTenantId", label: "Account", type: "tenant" }, { key: "stage", label: "Stage", options: OPP_STAGES },
                  { key: "value", label: "One-off value", type: "number" }, { key: "monthlyValue", label: "Monthly recurring value", type: "number" },
                  { key: "probability", label: "Probability %", type: "number" }, { key: "closeDate", label: "Expected close", type: "date" },
                  { key: "owner", label: "Owner" }, { key: "source", label: "Source" }, { key: "lostReason", label: "Lost reason" }, { key: "notes", label: "Notes" }],
  activities: [{ key: "kind", label: "Type", options: ACTIVITY_KINDS }, { key: "direction", label: "Direction", options: ["", "outbound", "inbound"] },
               { key: "subject", label: "Subject" }, { key: "accountTenantId", label: "Account", type: "tenant" },
               { key: "dueAt", label: "Due (tasks)", type: "datetime-local" }, { key: "owner", label: "Owner" }, { key: "body", label: "Notes" }],
  leads: [{ key: "company", label: "Company" }, { key: "contact", label: "Contact" }, { key: "email", label: "Email" }, { key: "phone", label: "Phone" },
          { key: "stage", label: "Stage", options: STAGES }, { key: "value", label: "Annual value", type: "number" }, { key: "seats", label: "Seats", type: "number" },
          { key: "source", label: "Source" }, { key: "owner", label: "Owner" }, { key: "notes", label: "Notes" }],
  contacts: [{ key: "name", label: "Name" }, { key: "title", label: "Job title" }, { key: "email", label: "Email" }, { key: "phone", label: "Phone" },
             { key: "accountTenantId", label: "Account", type: "tenant" }, { key: "notes", label: "Notes" }],
  projects: [{ key: "name", label: "Name" }, { key: "accountTenantId", label: "Account", type: "tenant" }, { key: "status", label: "Status", options: ["Planning", "In Progress", "On Hold", "Complete"] },
             { key: "progress", label: "Progress %", type: "number" }, { key: "budget", label: "Budget", type: "number" }, { key: "dueDate", label: "Due date", type: "date" }],
};

export function CrmEditor({ kind, row, onClose }: { kind: string; row: any; onClose: () => void }) {
  const { me } = useApp();
  const [form, setForm] = useState<any>({ ...DEFAULTS[kind], ...row, dueAt: row.dueAt ? String(row.dueAt).slice(0, 16) : row.dueAt });
  const { run, busy } = useAction();
  const save = async () => {
    const body: any = {};
    for (const f of FIELDS[kind]) if (form[f.key] !== undefined) body[f.key] = f.type === "number" ? Number(form[f.key]) : form[f.key];
    if (kind === "activities" && body.dueAt === "") body.dueAt = null;
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
            {f.options ? <select value={form[f.key] ?? ""} onChange={(e) => setForm({ ...form, [f.key]: e.target.value })}>{f.options.map((o) => <option key={o} value={o}>{o || "—"}</option>)}</select>
              : f.type === "tenant" ? <select value={form[f.key] ?? ""} onChange={(e) => setForm({ ...form, [f.key]: e.target.value || null })}><option value="">—</option>{me?.tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}</select>
              : f.key === "body" || f.key === "notes" ? <textarea rows={3} value={form[f.key] ?? ""} onChange={(e) => setForm({ ...form, [f.key]: e.target.value })} />
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
