import { displayValue } from "./DisplayValue";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, downloadFile } from "../api";
import { useApp } from "../app-context";
import { confirmDialog } from "./dialogs";
import { ErrorNote, Modal, Table, useAction, useData, useListData } from "./ui";

const PLANS = ["essentials", "advanced", "complete", "mdr"];

export interface CustomerSummary {
  id: string; name: string; plan?: string; kind?: string; accountOwner?: string; defaultPolicyId?: string | null;
  archived?: boolean | object | null; profile?: Record<string, string>;
}

/** Edit a customer's name, plan, default policy, account owner and company details. */
export function CustomerEditModal({ customer, onClose }: { customer: CustomerSummary; onClose: (saved: boolean) => void }) {
  const [form, setForm] = useState({
    name: customer.name, plan: customer.plan || "complete", defaultPolicyId: customer.defaultPolicyId || "", accountOwner: customer.accountOwner || "",
    phone: customer.profile?.phone || "", website: customer.profile?.website || "", address: customer.profile?.address || "",
    notes: customer.profile?.notes || "",
  });
  const { data: policies } = useListData<any>("policies", { tenant_id: customer.id }, [customer.id]);
  const { run, busy } = useAction();
  const set = (key: string, value: string) => setForm({ ...form, [key]: value });
  const save = async () => {
    const body = { name: form.name.trim(), plan: form.plan, defaultPolicyId: form.defaultPolicyId || null, accountOwner: form.accountOwner,
      profile: { phone: form.phone, website: form.website, address: form.address, notes: form.notes } };
    if (await run(() => api(`tenants/${customer.id}`, { method: "PATCH", body }), "Customer saved")) onClose(true);
  };
  return (
    <Modal title={`Edit ${customer.name}`} onClose={() => onClose(false)} wide
      footer={<button className="primary" disabled={busy || !form.name.trim()} onClick={save}>Save</button>}>
      <div className="form-grid">
        <label className="field">Name<input value={form.name} onChange={(e) => set("name", e.target.value)} maxLength={200} /></label>
        <label className="field">Plan<select value={form.plan} onChange={(e) => set("plan", e.target.value)}>{PLANS.map((p) => <option key={p}>{p}</option>)}</select></label>
        <label className="field">Account owner<input value={form.accountOwner} onChange={(e) => set("accountOwner", e.target.value)} placeholder="Who looks after this customer" /></label>
        <label className="field">Default protection policy
          <select value={form.defaultPolicyId} onChange={(e) => set("defaultPolicyId", e.target.value)}>
            <option value="">The built-in template</option>
            {policies?.filter((p) => !p.tenantId || p.tenantId === customer.id).map((p) => <option key={p.id} value={p.id}>{displayValue(p.name)}</option>)}
          </select>
          <span className="small muted">Devices and groups without their own policy use this one.</span></label>
        <label className="field">Phone<input value={form.phone} onChange={(e) => set("phone", e.target.value)} /></label>
        <label className="field">Website<input value={form.website} onChange={(e) => set("website", e.target.value)} placeholder="https://" /></label>
        <label className="field">Address<textarea rows={2} value={form.address} onChange={(e) => set("address", e.target.value)} /></label>
        <label className="field">Notes<textarea rows={2} value={form.notes} onChange={(e) => set("notes", e.target.value)} /></label>
      </div>
    </Modal>
  );
}

/** Shows exactly what deleting a customer removes, then deletes it once the name is typed. */
export function CustomerDeleteModal({ customer, onClose, onDeleted }: { customer: CustomerSummary; onClose: () => void; onDeleted: () => void }) {
  const { data: report, error } = useData<any>(`tenants/${customer.id}/deletion`);
  const [typed, setTyped] = useState("");
  const { run, busy } = useAction();
  const blocked = (report?.blockers || []).length > 0;
  const remove = async () => {
    const done = await run(() => api<any>(`tenants/${customer.id}`, { method: "DELETE", body: { confirmName: typed } }), `${customer.name} deleted`);
    if (done) onDeleted();
  };
  return (
    <Modal title={`Delete ${customer.name}`} onClose={onClose} wide
      footer={<button className="danger primary" disabled={busy || blocked || !report || typed.trim() !== customer.name.trim()} onClick={remove}>Delete permanently</button>}>
      <ErrorNote error={error} />
      {!report ? <p className="muted">Working out what would be removed…</p> : <>
        {blocked ? <div className="card" style={{ borderColor: "#fca5a5" }}><b>This customer cannot be deleted:</b>
          <ul>{report.blockers.map((b: string) => <li key={b}>{b}</li>)}</ul></div> : <>
          <p><b>This cannot be undone.</b> Everything below is removed for good. If you might need it later, <b>Archive</b> the customer instead:
            that hides it and stops new devices enrolling, but keeps everything.</p>
          {report.liveDevices > 0 && <p style={{ color: "#fcd34d" }}>{report.liveDevices} device(s) still report to Fenrir. Deleting decommissions them
            first: their agents stop reporting but stay installed. To take the agent off those machines, uninstall it there (on Windows,
            <code>fenrir-agent-service.exe --uninstall</code>, with the uninstall token if protection is on).</p>}
          <Table rows={(report.summary || []).map((r: any) => ({ ...r, id: r.label }))} empty="No records besides the customer itself."
            columns={[{ key: "label", label: "Removed" }, { key: "count", label: "How many" }]} />
          <p className="small muted">{report.total} records in all. {displayValue(report.keeps)} Microsoft 365: Fenrir's app or GDAP relationship in the
            customer's own Microsoft tenant is not removed; remove it there if you no longer manage them.</p>
          <label className="field">Type <b>{customer.name}</b> to confirm<input value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" /></label>
        </>}
      </>}
    </Modal>
  );
}

/** Edit, Archive/Restore and Delete buttons for one customer. */
export function CustomerActions({ customer, onChanged, afterDelete = "/crm", onDeleted, small }: {
  customer: CustomerSummary; onChanged: () => void; afterDelete?: string; onDeleted?: () => void; small?: boolean;
}) {
  const { can, refreshMe } = useApp();
  const navigate = useNavigate();
  const { run, busy } = useAction();
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState(false);
  if (!can("manage_tenants") || (customer.kind && customer.kind !== "customer")) return null;
  const archived = !!customer.archived;
  const toggleArchive = async () => {
    if (!archived && !(await confirmDialog(`Archive ${customer.name}? It is hidden from customer lists and cannot enrol new devices. Nothing is deleted, and you can restore it at any time.`))) return;
    if (await run(() => api(`tenants/${customer.id}/archive`, { body: { archived: !archived } }), archived ? "Customer restored" : "Customer archived")) {
      onChanged(); refreshMe();
    }
  };
  return (
    <span style={{ display: "inline-flex", gap: 6 }} onClick={(e) => e.stopPropagation()}>
      <button className={small ? "small" : ""} onClick={() => setEditing(true)}>{small ? "Edit" : "Edit customer"}</button>
      <button className={small ? "small" : ""} disabled={busy} onClick={toggleArchive}>{archived ? "Restore" : "Archive"}</button>
      <button className={small ? "small" : ""} disabled={busy} title="Everything held about this customer, as a zip of JSON files (secrets left out). Recorded in the audit log."
        onClick={() => run(() => downloadFile(`tenants/${customer.id}/export`, "fenrir-export.zip"), "Export downloaded")}>Export data</button>
      <button className={`danger${small ? " small" : ""}`} onClick={() => setDeleting(true)}>Delete</button>
      {editing && <CustomerEditModal customer={customer} onClose={(saved) => { setEditing(false); if (saved) { onChanged(); refreshMe(); } }} />}
      {deleting && <CustomerDeleteModal customer={customer} onClose={() => setDeleting(false)}
        onDeleted={() => { setDeleting(false); refreshMe(); if (onDeleted) onDeleted(); else navigate(afterDelete); }} />}
    </span>
  );
}
