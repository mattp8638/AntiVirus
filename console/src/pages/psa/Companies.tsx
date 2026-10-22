import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ago, api, money } from "../../api";
import { useApp } from "../../app-context";
import { Modal, PageHead, Pill, Table, Tabs, useAction, useData } from "../../components/ui";
import { NewTicket, PRIORITY_TONE } from "./ServiceBoard";

export default function Companies() {
  const navigate = useNavigate();
  const { data } = useData<any[]>("psa/companies");
  const [q, setQ] = useState("");
  return (
    <>
      <PageHead title="Companies" subtitle="Customers with their sites, contacts, agreements, configurations and service history." />
      <input placeholder="Search companies" value={q} onChange={(e) => setQ(e.target.value)} style={{ minWidth: 280, marginBottom: 12 }} />
      <div className="card">
        <Table rows={data?.filter((c) => !q || c.name.toLowerCase().includes(q.toLowerCase()))} onRow={(c) => navigate(`/companies/${c.id}`)} empty="No companies."
               columns={[{ key: "name", label: "Company", render: (c) => <><b>{c.name}</b><div className="small muted">{c.website}</div></> },
                         { key: "companyType", label: "Type", render: (c) => <Pill value={c.companyType} tone={c.companyType === "Client" ? "good" : "muted"} /> },
                         { key: "phone", label: "Phone" }, { key: "openTickets", label: "Open tickets" }, { key: "devices", label: "Devices" },
                         { key: "contacts", label: "Contacts" }, { key: "agreements", label: "Agreements" }]} />
      </div>
    </>
  );
}

export function CompanyDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { can, setTenantId } = useApp();
  const { data, reload } = useData<any>(`psa/companies/${id}`);
  const { data: meta } = useData<any>("psa/meta");
  const [tab, setTab] = useState("Tickets");
  const [editing, setEditing] = useState(false);
  const [adding, setAdding] = useState<string | null>(null);
  const [ticket, setTicket] = useState(false);
  if (!data) return <div className="empty">Loading…</div>;
  const c = data.company;
  return (
    <>
      <PageHead title={c.name} subtitle={<>{c.companyType || "Client"}{c.phone ? ` · ${c.phone}` : ""}{c.website ? ` · ${c.website}` : ""} · {data.devices} devices</>}
                actions={<>
                  <button className="primary" onClick={() => setTicket(true)}>New ticket</button>
                  {can("crm") && <button onClick={() => setEditing(true)}>Edit company</button>}
                  <button onClick={() => { setTenantId(c.id); navigate("/devices"); }}>Devices</button>
                </>} />
      <Tabs tabs={["Tickets", "Contacts", "Sites", "Agreements", "Configurations", "Projects"]} active={tab} onChange={setTab} />
      <div className="card">
        {tab === "Tickets" && <Table rows={data.tickets} onRow={(t) => navigate(`/tickets/${t.id}`)} empty="No tickets."
                                     columns={[{ key: "number", label: "#", render: (t) => `#${t.number}` }, { key: "priority", label: "Pri", render: (t) => <Pill value={t.priority} tone={PRIORITY_TONE[t.priority]} /> },
                                               { key: "subject", label: "Summary" }, { key: "status", label: "Status", render: (t) => <Pill value={t.status} tone={t.closed ? "muted" : "blue"} /> },
                                               { key: "assignee", label: "Resource" }, { key: "updatedAt", label: "Updated", render: (t) => ago(t.updatedAt) }]} />}
        {tab === "Contacts" && <>
          <Table rows={data.contacts} empty="No contacts." columns={[{ key: "name", label: "Name", render: (x) => <>{x.name}{x.isPrimary && <> <Pill value="primary" tone="blue" /></>}</> }, { key: "title", label: "Title" }, { key: "email", label: "Email" }, { key: "phone", label: "Phone" }]} />
          {can("crm") && <button style={{ marginTop: 8 }} onClick={() => setAdding("contact")}>Add contact</button>}
        </>}
        {tab === "Sites" && <>
          <Table rows={data.sites} empty="No sites." columns={[{ key: "name", label: "Site", render: (x) => <>{x.name}{x.primary && <> <Pill value="primary" tone="blue" /></>}</> }, { key: "address", label: "Address" }, { key: "city", label: "City" }, { key: "postcode", label: "Postcode" }, { key: "phone", label: "Phone" }]} />
          {can("crm") && <button style={{ marginTop: 8 }} onClick={() => setAdding("site")}>Add site</button>}
        </>}
        {tab === "Agreements" && <Table rows={data.agreements} empty="No agreements. Create one on the Agreements page."
                                        columns={[{ key: "name", label: "Agreement" }, { key: "agreementType", label: "Type" }, { key: "billingCycle", label: "Cycle" },
                                                  { key: "pricePerDevice", label: "Per device", render: (x) => money(x.pricePerDevice, x.currency) }, { key: "includedHours", label: "Hours included" },
                                                  { key: "active", label: "", render: (x) => <Pill value={x.active ? "active" : "ended"} tone={x.active ? "good" : "muted"} /> }]} />}
        {tab === "Configurations" && <Table rows={data.configurations} empty="No configurations."
                                            columns={[{ key: "name", label: "Name" }, { key: "type", label: "Type" }, { key: "manufacturer", label: "Make", render: (x) => `${x.manufacturer} ${x.model}` },
                                                      { key: "serialNumber", label: "Serial" }, { key: "warrantyExpires", label: "Warranty" }, { key: "status", label: "Status" }]} />}
        {tab === "Projects" && <Table rows={data.projects} empty="No projects." onRow={(p) => navigate(`/projects/${p.id}`)}
                                      columns={[{ key: "name", label: "Project" }, { key: "status", label: "Status" }, { key: "progress", label: "Progress", render: (p) => `${p.progress}%` }, { key: "dueDate", label: "Due" }]} />}
      </div>
      {editing && <EditCompany company={c} onClose={() => { setEditing(false); reload(); }} />}
      {adding && <AddChild kind={adding} tenantId={c.id} onClose={() => { setAdding(null); reload(); }} />}
      {ticket && <NewTicket meta={meta} preset={{ accountTenantId: c.id }} onClose={(tid) => { setTicket(false); if (tid) navigate(`/tickets/${tid}`); }} />}
    </>
  );
}

function EditCompany({ company, onClose }: { company: any; onClose: () => void }) {
  const [form, setForm] = useState({ companyType: company.companyType || "Client", phone: company.phone || "", website: company.website || "",
                                     address: company.address || "", emailDomains: (company.emailDomains || []).join(", "), accountManager: company.accountManager || "" });
  const { run, busy } = useAction();
  return (
    <Modal title={`Edit ${company.name}`} onClose={onClose}
           footer={<button className="primary" disabled={busy} onClick={async () => {
             if (await run(() => api(`psa/companies/${company.id}`, { method: "PATCH", body: { ...form, emailDomains: form.emailDomains.split(",").map((d: string) => d.trim().toLowerCase()).filter(Boolean) } }), "Saved")) onClose();
           }}>Save</button>}>
      <div className="form-grid">
        <label className="field">Type<select value={form.companyType} onChange={(e) => setForm({ ...form, companyType: e.target.value })}>{["Client", "Prospect", "Vendor", "Partner", "Former client"].map((t) => <option key={t}>{t}</option>)}</select></label>
        <label className="field">Phone<input value={form.phone} onChange={(e) => setForm({ ...form, phone: e.target.value })} /></label>
        <label className="field">Website<input value={form.website} onChange={(e) => setForm({ ...form, website: e.target.value })} /></label>
        <label className="field">Account manager<input value={form.accountManager} onChange={(e) => setForm({ ...form, accountManager: e.target.value })} /></label>
      </div>
      <label className="field" style={{ marginTop: 10 }}>Address<textarea rows={2} value={form.address} onChange={(e) => setForm({ ...form, address: e.target.value })} /></label>
      <label className="field" style={{ marginTop: 10 }}>Email domains (inbound emails from these become this company's tickets)<input value={form.emailDomains} onChange={(e) => setForm({ ...form, emailDomains: e.target.value })} placeholder="acme.co.uk, acme.com" /></label>
    </Modal>
  );
}

function AddChild({ kind, tenantId, onClose }: { kind: string; tenantId: string; onClose: () => void }) {
  const [form, setForm] = useState<any>({});
  const { run, busy } = useAction();
  const fields = kind === "contact" ? ["name", "title", "email", "phone"] : ["name", "address", "city", "postcode", "phone"];
  const save = async () => {
    const path = kind === "contact" ? "crm/contacts" : "psa/sites";
    if (await run(() => api(path, { body: { ...form, accountTenantId: tenantId } }), "Saved")) onClose();
  };
  return (
    <Modal title={`Add ${kind}`} onClose={onClose} footer={<button className="primary" disabled={busy || !form.name} onClick={save}>Save</button>}>
      <div className="form-grid">
        {fields.map((f) => <label key={f} className="field">{f}<input value={form[f] || ""} onChange={(e) => setForm({ ...form, [f]: e.target.value })} /></label>)}
        <label className="field">Primary<select value={form[kind === "contact" ? "isPrimary" : "primary"] ? "yes" : "no"} onChange={(e) => setForm({ ...form, [kind === "contact" ? "isPrimary" : "primary"]: e.target.value === "yes" })}><option value="no">No</option><option value="yes">Yes</option></select></label>
      </div>
    </Modal>
  );
}

export function Configurations() {
  const { tenantId, tenantName, can } = useApp();
  const { data, reload } = useData<any[]>("psa/configurations", { accountTenantId: tenantId || undefined });
  const [editing, setEditing] = useState<any>(null);
  const { run, busy } = useAction();
  const [type, setType] = useState("");
  return (
    <>
      <PageHead title="Configurations" subtitle="The CMDB: every device, network appliance, licence and service you look after, linked to tickets."
                actions={can("crm") && <>
                  <button disabled={busy} onClick={async () => { const r = await run(() => api<any>("psa/configurations/sync", { body: { tenantId: tenantId || undefined } })); if (r) { window.alert(`${r.created} created, ${r.updated} updated from RMM`); reload(); } }}>Sync from RMM</button>
                  <button className="primary" onClick={() => setEditing({ type: "Firewall", status: "Active", accountTenantId: tenantId })}>New configuration</button>
                </>} />
      <select value={type} onChange={(e) => setType(e.target.value)} style={{ marginBottom: 12 }}><option value="">All types</option>{[...new Set((data || []).map((c) => c.type))].map((t) => <option key={t}>{t}</option>)}</select>
      <div className="card">
        <Table rows={data?.filter((c) => !type || c.type === type)} onRow={setEditing} empty="No configurations. Sync from RMM to import every managed device."
               columns={[{ key: "name", label: "Name", render: (c) => <><b>{c.name}</b>{c.deviceId && <div className="small"><Link to={`/devices/${c.deviceId}`} onClick={(e) => e.stopPropagation()}>managed device</Link></div>}</> },
                         { key: "account", label: "Company", render: (c) => c.account || tenantName(c.accountTenantId) },
                         { key: "type", label: "Type" }, { key: "manufacturer", label: "Make / model", render: (c) => `${c.manufacturer} ${c.model}`.trim() || "—" },
                         { key: "serialNumber", label: "Serial" }, { key: "ipAddress", label: "IP" },
                         { key: "warrantyExpires", label: "Warranty", render: (c) => c.warrantyExpires ? <span style={{ color: new Date(c.warrantyExpires) < new Date() ? "#fecaca" : undefined }}>{c.warrantyExpires}</span> : "—" },
                         { key: "status", label: "Status", render: (c) => <Pill value={c.status} tone={c.status === "Active" ? "good" : "muted"} /> }]} />
      </div>
      {editing && <ConfigEditor config={editing} onClose={() => { setEditing(null); reload(); }} />}
    </>
  );
}

function ConfigEditor({ config, onClose }: { config: any; onClose: () => void }) {
  const [form, setForm] = useState<any>({ ...config });
  const { run, busy } = useAction();
  const { me } = useApp();
  const fields: [string, string][] = [["name", "Name"], ["manufacturer", "Manufacturer"], ["model", "Model"], ["serialNumber", "Serial number"], ["ipAddress", "IP address"],
                                      ["macAddress", "MAC address"], ["os", "OS / firmware"], ["vendor", "Vendor"], ["purchaseDate", "Purchased"], ["warrantyExpires", "Warranty expires"]];
  const save = async () => {
    const body: any = Object.fromEntries([...fields.map(([k]) => [k, form[k] || ""]), ["type", form.type], ["status", form.status], ["notes", form.notes || ""]]);
    if (!form.id) body.accountTenantId = form.accountTenantId;
    if (await run(() => (form.id ? api(`psa/configurations/${form.id}`, { method: "PATCH", body }) : api("psa/configurations", { body })), "Saved")) onClose();
  };
  return (
    <Modal title={form.id ? form.name : "New configuration"} onClose={onClose}
           footer={<>{form.id && <button className="danger" onClick={async () => { if (await run(() => api(`psa/configurations/${form.id}`, { method: "DELETE" }), "Deleted")) onClose(); }}>Delete</button>}
                   <button className="primary" disabled={busy || !form.name || !form.accountTenantId} onClick={save}>Save</button></>}>
      <div className="form-grid">
        {!form.id && <label className="field">Company<select value={form.accountTenantId || ""} onChange={(e) => setForm({ ...form, accountTenantId: e.target.value })}>
          <option value="">Choose…</option>{me?.tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}</select></label>}
        <label className="field">Type<select value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value })}>
          {["Workstation", "Server", "Laptop", "Firewall", "Switch", "Wireless", "Printer", "Phone", "Licence", "Domain", "Certificate", "Application", "Backup", "Other"].map((t) => <option key={t}>{t}</option>)}</select></label>
        <label className="field">Status<select value={form.status} onChange={(e) => setForm({ ...form, status: e.target.value })}>{["Active", "Inactive", "In repair", "Retired"].map((t) => <option key={t}>{t}</option>)}</select></label>
        {fields.map(([k, label]) => <label key={k} className="field">{label}<input type={k.includes("Date") || k === "warrantyExpires" ? "date" : "text"} value={form[k] || ""} onChange={(e) => setForm({ ...form, [k]: e.target.value })} /></label>)}
      </div>
      <label className="field" style={{ marginTop: 10 }}>Notes<textarea rows={3} value={form.notes || ""} onChange={(e) => setForm({ ...form, notes: e.target.value })} /></label>
    </Modal>
  );
}
