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
      <PageHead title="Agreements & billing" subtitle="Agreements set SLAs, covered work and included hours. Invoices follow the live device count, additions and billable time."
                actions={can("billing") && <>
                  <input type="month" value={period} onChange={(e) => setPeriod(e.target.value)} aria-label="Billing period" />
                  <button disabled={busy} onClick={async () => { const r = await run(() => api<any>("billing/invoices/generate", { body: { period } })); if (r) { reloadInvoices(); setTab("Invoices"); } }}>Generate invoices</button>
                  <button className="primary" onClick={() => setCreating(true)}>New agreement</button>
                </>} />
      <div className="grid k3">
        <Stat label="Monthly recurring revenue" value={money(mrr)} accent="green" />
        <Stat label="Active agreements" value={contracts?.filter((c) => c.active).length ?? 0} />
        <Stat label="Outstanding" value={money(outstanding)} accent={outstanding ? "amber" : undefined} />
      </div>
      <Renewals />
      <div style={{ marginTop: 16 }}><Tabs tabs={["Agreements", "Invoices"]} active={tab === "Contracts" ? "Agreements" : tab} onChange={(t) => setTab(t === "Agreements" ? "Contracts" : t)} /></div>
      {tab === "Contracts" ? (
        <div className="card">
          <Table rows={contracts} empty="No contracts. Converting a CRM lead creates one."
                 columns={[{ key: "account", label: "Company" }, { key: "name", label: "Agreement", render: (c) => <><b>{c.name}</b><div className="small muted">{c.agreementType || "Managed Services"} · {c.billingCycle || "Monthly"}</div></> }, { key: "plan", label: "Plan" },
                           { key: "includedHours", label: "Hours incl." },
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
  const [form, setForm] = useState<any>({ name: "Managed services", agreementType: "Managed Services", billingCycle: "Monthly", plan: "complete", pricePerDevice: 6,
                                          monthlyFee: 0, hourlyRate: 85, includedHours: 2, currency: "GBP", coveredWorkTypes: "Remote Support, Onsite Support",
                                          coversAfterHours: false, additions: [] as any[], businessStart: 9, businessEnd: 17, respondP1: 0.25, respondP2: 1, respondP3: 4, respondP4: 8,
                                          resolveP1: 4, resolveP2: 8, resolveP3: 24, resolveP4: 72 });
  const { run, busy } = useAction();
  const submit = async () => {
    const body = { name: form.name, agreementType: form.agreementType, billingCycle: form.billingCycle, plan: form.plan, pricePerDevice: Number(form.pricePerDevice),
                   monthlyFee: Number(form.monthlyFee), hourlyRate: Number(form.hourlyRate), includedHours: Number(form.includedHours), currency: form.currency,
                   coveredWorkTypes: form.coveredWorkTypes.split(",").map((w: string) => w.trim()).filter(Boolean), coversAfterHours: form.coversAfterHours,
                   additions: form.additions.map((a: any) => ({ ...a, unitPrice: Number(a.unitPrice), quantity: Number(a.quantity || 0) })),
                   businessHours: { days: [0, 1, 2, 3, 4], start: Number(form.businessStart), end: Number(form.businessEnd), tz: Intl.DateTimeFormat().resolvedOptions().timeZone, p1AllHours: true },
                   sla: { P1: Number(form.resolveP1), P2: Number(form.resolveP2), P3: Number(form.resolveP3), P4: Number(form.resolveP4),
                          respond: { P1: Number(form.respondP1), P2: Number(form.respondP2), P3: Number(form.respondP3), P4: Number(form.respondP4) } },
                   accountTenantId: account };
    if (await run(() => api("billing/contracts", { body }), "Agreement created")) onClose();
  };
  const num = (k: string, label: string, step = "0.01") => <label key={k} className="field">{label}<input type="number" step={step} value={form[k]} onChange={(e) => setForm({ ...form, [k]: e.target.value })} /></label>;
  return (
    <Modal title="New agreement" onClose={onClose} footer={<><button onClick={onClose}>Cancel</button><button className="primary" disabled={busy || !account} onClick={submit}>Create</button></>}>
      <div className="form-grid">
        <label className="field">Company<TenantSelect value={account} onChange={setAccount} allowAll={false} /></label>
        <label className="field">Name<input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label>
        <label className="field">Type<select value={form.agreementType} onChange={(e) => setForm({ ...form, agreementType: e.target.value })}>{["Managed Services", "Block Hours", "Retainer", "Time & Materials"].map((p) => <option key={p}>{p}</option>)}</select></label>
        <label className="field">Billing cycle<select value={form.billingCycle} onChange={(e) => setForm({ ...form, billingCycle: e.target.value })}>{["Monthly", "Quarterly", "Annually"].map((p) => <option key={p}>{p}</option>)}</select></label>
        <label className="field">Security plan<select value={form.plan} onChange={(e) => setForm({ ...form, plan: e.target.value })}>{["essentials", "advanced", "complete", "mdr"].map((p) => <option key={p}>{p}</option>)}</select></label>
        <label className="field">Currency<select value={form.currency} onChange={(e) => setForm({ ...form, currency: e.target.value })}>{["GBP", "EUR", "USD"].map((c) => <option key={c}>{c}</option>)}</select></label>
        {num("pricePerDevice", "Price per device")}{num("monthlyFee", "Monthly fee")}{num("hourlyRate", "Hourly rate")}{num("includedHours", "Hours included per month")}
      </div>
      <label className="field" style={{ marginTop: 10 }}>Covered work types (blank = everything)<input value={form.coveredWorkTypes} onChange={(e) => setForm({ ...form, coveredWorkTypes: e.target.value })} /></label>
      <label className="small" style={{ display: "block", marginTop: 6 }}><input type="checkbox" checked={form.coversAfterHours} onChange={(e) => setForm({ ...form, coversAfterHours: e.target.checked })} /> Covers after-hours work (otherwise billed at 1.5×)</label>
      <h3 style={{ marginTop: 14 }}>SLA (hours, business hours {form.businessStart}:00–{form.businessEnd}:00; P1 runs 24×7)</h3>
      <div className="form-grid">
        {["P1", "P2", "P3", "P4"].map((p) => num(`respond${p}`, `${p} respond`, "0.25"))}
        {["P1", "P2", "P3", "P4"].map((p) => num(`resolve${p}`, `${p} resolve`, "1"))}
        {num("businessStart", "Day starts", "1")}{num("businessEnd", "Day ends", "1")}
      </div>
      <h3 style={{ marginTop: 14 }}>Additions</h3>
      {form.additions.map((a: any, i: number) => (
        <div key={i} className="row" style={{ marginBottom: 4 }}>
          <input value={a.product} placeholder="Product" onChange={(e) => setForm({ ...form, additions: form.additions.map((x: any, j: number) => (i === j ? { ...x, product: e.target.value } : x)) })} style={{ flex: 1 }} />
          <select value={a.autoCount || ""} onChange={(e) => setForm({ ...form, additions: form.additions.map((x: any, j: number) => (i === j ? { ...x, autoCount: e.target.value } : x)) })}>
            <option value="">Fixed quantity</option><option value="devices">Count all devices</option><option value="devices:windows">Count Windows devices</option><option value="devices:linux">Count Linux devices</option><option value="devices:server">Count servers</option></select>
          {!a.autoCount && <input type="number" value={a.quantity || 1} style={{ width: 70 }} onChange={(e) => setForm({ ...form, additions: form.additions.map((x: any, j: number) => (i === j ? { ...x, quantity: e.target.value } : x)) })} />}
          <input type="number" step="0.01" value={a.unitPrice} placeholder="Unit price" style={{ width: 100 }} onChange={(e) => setForm({ ...form, additions: form.additions.map((x: any, j: number) => (i === j ? { ...x, unitPrice: e.target.value } : x)) })} />
          <button className="small ghost" onClick={() => setForm({ ...form, additions: form.additions.filter((_: any, j: number) => j !== i) })}>✕</button>
        </div>
      ))}
      <button className="small" onClick={() => setForm({ ...form, additions: [...form.additions, { product: "Server backup", autoCount: "devices:server", unitPrice: 15 }] })}>Add addition</button>
    </Modal>
  );
}


function Renewals() {
  const { data } = useData<any[]>("billing/renewals", { days: 90 });
  if (!data?.length) return null;
  return (
    <div className="card" style={{ marginTop: 14 }}>
      <h3 style={{ marginTop: 0 }}>Agreements ending in the next 90 days</h3>
      <Table rows={data} columns={[{ key: "account", label: "Company" }, { key: "name", label: "Agreement" }, { key: "endDate", label: "Ends" },
        { key: "daysLeft", label: "Days left", render: (c) => <Pill value={c.daysLeft < 0 ? "ended" : `${c.daysLeft} days`} tone={c.daysLeft < 30 ? "bad" : "warn"} /> },
        { key: "monthlyValue", label: "Monthly fee", render: (c) => money(c.monthlyValue, c.currency) }]} />
    </div>
  );
}
