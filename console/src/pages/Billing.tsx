import { useState } from "react";
import { api, money } from "../api";
import { useApp } from "../app-context";
import { Modal, PageHead, Pill, Stat, Table, Tabs, TenantSelect, useAction, useData } from "../components/ui";

export default function Billing() {
  const { can } = useApp();
  const [tab, setTab] = useState("Contracts");
  const { data: contracts, reload } = useData<any[]>("billing/contracts");
  const { data: invoices, reload: reloadInvoices } = useData<any[]>("billing/invoices");
  const [period, setPeriod] = useState(new Date().toISOString().slice(0, 7));
  const [creating, setCreating] = useState(false);
  const [invoice, setInvoice] = useState<any>(null);
  const { run, busy } = useAction();
  const mrr = contracts?.filter((c) => c.active).reduce((n, c) => n + c.monthlyValue, 0) ?? 0;
  const outstanding = invoices?.filter((i) => ["Sent", "Overdue"].includes(i.status)).reduce((n, i) => n + i.total, 0) ?? 0;
  return (
    <>
      <PageHead title="Billing" subtitle="Per-device pricing that follows the live device count, plus fees and billable time."
                actions={can("billing") && <>
                  <input type="month" value={period} onChange={(e) => setPeriod(e.target.value)} aria-label="Billing period" />
                  <button disabled={busy} onClick={async () => { const r = await run(() => api<any>("billing/invoices/generate", { body: { period } })); if (r) { reloadInvoices(); setTab("Invoices"); } }}>Generate invoices</button>
                  <button className="primary" onClick={() => setCreating(true)}>New contract</button>
                </>} />
      <div className="grid k3">
        <Stat label="Monthly recurring revenue" value={money(mrr)} accent="green" />
        <Stat label="Active contracts" value={contracts?.filter((c) => c.active).length ?? 0} />
        <Stat label="Outstanding" value={money(outstanding)} accent={outstanding ? "amber" : undefined} />
      </div>
      <div style={{ marginTop: 16 }}><Tabs tabs={["Contracts", "Invoices"]} active={tab} onChange={setTab} /></div>
      {tab === "Contracts" ? (
        <div className="card">
          <Table rows={contracts} empty="No contracts. Converting a CRM lead creates one."
                 columns={[{ key: "account", label: "Account" }, { key: "name", label: "Contract" }, { key: "plan", label: "Plan" },
                           { key: "devices", label: "Devices", className: "right" }, { key: "pricePerDevice", label: "Per device", render: (c) => money(c.pricePerDevice, c.currency) },
                           { key: "monthlyFee", label: "Fee", render: (c) => money(c.monthlyFee, c.currency) },
                           { key: "sla", label: "SLA (h)", render: (c) => Object.entries(c.sla || {}).map(([k, v]) => `${k}:${v}`).join(" ") },
                           { key: "monthlyValue", label: "Monthly", render: (c) => <b>{money(c.monthlyValue, c.currency)}</b> },
                           { key: "active", label: "", render: (c) => <Pill value={c.active ? "active" : "inactive"} tone={c.active ? "good" : "muted"} /> }]} />
        </div>
      ) : (
        <div className="card">
          <Table rows={invoices} onRow={setInvoice} empty="No invoices yet."
                 columns={[{ key: "number", label: "Invoice" }, { key: "account", label: "Account" }, { key: "period", label: "Period" },
                           { key: "total", label: "Total", render: (i) => money(i.total, i.currency) }, { key: "dueDate", label: "Due" },
                           { key: "status", label: "Status", render: (i) => <Pill value={i.status} /> }]} />
        </div>
      )}
      {creating && <NewContract onClose={() => { setCreating(false); reload(); }} />}
      {invoice && (
        <Modal title={`${invoice.number} · ${invoice.account}`} onClose={() => setInvoice(null)}
               footer={can("billing") && ["Sent", "Paid", "Void"].map((s) => <button key={s} onClick={async () => { await run(() => api(`billing/invoices/${invoice.id}`, { method: "PATCH", body: { status: s } }), `Marked ${s}`); reloadInvoices(); setInvoice(null); }}>Mark {s}</button>)}>
          <Table rows={invoice.lines.map((l: any, i: number) => ({ ...l, id: i }))}
                 columns={[{ key: "description", label: "Item" }, { key: "quantity", label: "Qty", className: "right" },
                           { key: "unitPrice", label: "Unit", render: (l) => money(l.unitPrice, invoice.currency) }, { key: "amount", label: "Amount", render: (l) => money(l.amount, invoice.currency) }]} />
          <dl className="kv" style={{ marginTop: 12 }}>
            <dt>Subtotal</dt><dd>{money(invoice.subtotal, invoice.currency)}</dd>
            <dt>Tax ({Math.round(invoice.taxRate * 100)}%)</dt><dd>{money(invoice.total - invoice.subtotal, invoice.currency)}</dd>
            <dt>Total</dt><dd><b>{money(invoice.total, invoice.currency)}</b></dd>
          </dl>
        </Modal>
      )}
    </>
  );
}

function NewContract({ onClose }: { onClose: () => void }) {
  const [account, setAccount] = useState("");
  const [form, setForm] = useState({ name: "Managed security", plan: "complete", pricePerDevice: 6, monthlyFee: 0, hourlyRate: 85, includedHours: 2, currency: "GBP" });
  const { run, busy } = useAction();
  const submit = async () => { if (await run(() => api("billing/contracts", { body: { ...form, accountTenantId: account } }), "Contract created")) onClose(); };
  return (
    <Modal title="New contract" onClose={onClose} footer={<><button onClick={onClose}>Cancel</button><button className="primary" disabled={busy || !account} onClick={submit}>Create</button></>}>
      <div className="form-grid">
        <label className="field">Account<TenantSelect value={account} onChange={setAccount} allowAll={false} /></label>
        <label className="field">Name<input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label>
        <label className="field">Plan<select value={form.plan} onChange={(e) => setForm({ ...form, plan: e.target.value })}>{["essentials", "advanced", "complete", "mdr"].map((p) => <option key={p}>{p}</option>)}</select></label>
        {(["pricePerDevice", "monthlyFee", "hourlyRate", "includedHours"] as const).map((k) => (
          <label key={k} className="field">{k.replace(/([A-Z])/g, " $1").toLowerCase()}<input type="number" step="0.01" value={form[k]} onChange={(e) => setForm({ ...form, [k]: Number(e.target.value) })} /></label>
        ))}
        <label className="field">Currency<select value={form.currency} onChange={(e) => setForm({ ...form, currency: e.target.value })}>{["GBP", "EUR", "USD"].map((c) => <option key={c}>{c}</option>)}</select></label>
      </div>
    </Modal>
  );
}
