import { useState } from "react";
import { api, getToken, money } from "../../api";
import { useApp } from "../../app-context";
import { Modal, PageHead, Pill, Table, Tabs, TenantSelect, useAction, useData } from "../../components/ui";

export default function Catalog() {
  const { can } = useApp();
  const [tab, setTab] = useState("Quotes");
  const { data: products, reload: reloadProducts } = useData<any[]>("psa/products");
  const { data: quotes, reload: reloadQuotes } = useData<any[]>("psa/quotes");
  const [product, setProduct] = useState<any>(null);
  const [quote, setQuote] = useState<any>(null);
  return (
    <>
      <PageHead title="Products & quotes" subtitle="A product catalogue with cost and margin, and quotes you can print or send."
                actions={can("crm") && <>
                  <button onClick={() => setProduct({ sku: "", description: "", category: "Service", cost: 0, price: 0, recurring: false })}>New product</button>
                  <button className="primary" onClick={() => setQuote({ title: "", lines: [], accountTenantId: "" })}>New quote</button>
                </>} />
      <Tabs tabs={["Quotes", "Products"]} active={tab} onChange={setTab} />
      <div className="card">
        {tab === "Quotes" ? (
          <Table rows={quotes} onRow={setQuote} empty="No quotes yet."
                 columns={[{ key: "number", label: "Quote" }, { key: "title", label: "Title" }, { key: "account", label: "Company", render: (q) => q.account || "Prospect" },
                           { key: "oneOffTotal", label: "One-off", render: (q) => money(q.oneOffTotal) }, { key: "monthlyTotal", label: "Monthly", render: (q) => money(q.monthlyTotal) },
                           { key: "validUntil", label: "Valid until" }, { key: "status", label: "Status", render: (q) => <Pill value={q.status} tone={q.status === "Accepted" ? "good" : q.status === "Declined" ? "muted" : "blue"} /> }]} />
        ) : (
          <Table rows={products} onRow={setProduct} empty="No products."
                 columns={[{ key: "sku", label: "SKU", render: (p) => <span className="mono">{p.sku}</span> }, { key: "description", label: "Description" }, { key: "category", label: "Category" },
                           { key: "cost", label: "Cost", render: (p) => money(p.cost) }, { key: "price", label: "Price", render: (p) => money(p.price) },
                           { key: "margin", label: "Margin", render: (p) => p.price ? `${Math.round((100 * (p.price - p.cost)) / p.price)}%` : "—" },
                           { key: "recurring", label: "", render: (p) => p.recurring ? <Pill value="monthly" tone="blue" /> : null }]} />
        )}
      </div>
      {product && <ProductEditor product={product} onClose={() => { setProduct(null); reloadProducts(); }} />}
      {quote && <QuoteEditor quote={quote} products={products || []} onClose={() => { setQuote(null); reloadQuotes(); }} />}
    </>
  );
}

function ProductEditor({ product, onClose }: { product: any; onClose: () => void }) {
  const [form, setForm] = useState<any>({ ...product });
  const { run, busy } = useAction();
  const save = async () => {
    const body = { sku: form.sku, description: form.description, category: form.category, cost: Number(form.cost), price: Number(form.price), recurring: form.recurring, vendor: form.vendor || "" };
    if (await run(() => (form.id ? api(`psa/products/${form.id}`, { method: "PATCH", body }) : api("psa/products", { body })), "Saved")) onClose();
  };
  return (
    <Modal title={form.id ? form.sku : "New product"} onClose={onClose} footer={<button className="primary" disabled={busy || !form.sku} onClick={save}>Save</button>}>
      <div className="form-grid">
        <label className="field">SKU<input value={form.sku} onChange={(e) => setForm({ ...form, sku: e.target.value })} /></label>
        <label className="field">Category<select value={form.category} onChange={(e) => setForm({ ...form, category: e.target.value })}>{["Service", "Hardware", "Software", "Licence", "Labour"].map((c) => <option key={c}>{c}</option>)}</select></label>
        <label className="field">Cost<input type="number" step="0.01" value={form.cost} onChange={(e) => setForm({ ...form, cost: e.target.value })} /></label>
        <label className="field">Price<input type="number" step="0.01" value={form.price} onChange={(e) => setForm({ ...form, price: e.target.value })} /></label>
        <label className="field">Vendor<input value={form.vendor || ""} onChange={(e) => setForm({ ...form, vendor: e.target.value })} /></label>
        <label className="field">Billing<select value={form.recurring ? "monthly" : "once"} onChange={(e) => setForm({ ...form, recurring: e.target.value === "monthly" })}><option value="once">One-off</option><option value="monthly">Monthly</option></select></label>
      </div>
      <label className="field" style={{ marginTop: 10 }}>Description<input value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></label>
    </Modal>
  );
}

function QuoteEditor({ quote, products, onClose }: { quote: any; products: any[]; onClose: () => void }) {
  const [form, setForm] = useState<any>({ ...quote, lines: [...(quote.lines || [])] });
  const { run, busy } = useAction();
  const setLine = (i: number, patch: any) => setForm({ ...form, lines: form.lines.map((l: any, j: number) => (i === j ? { ...l, ...patch } : l)) });
  const oneOff = form.lines.filter((l: any) => !l.recurring).reduce((n: number, l: any) => n + Number(l.quantity) * Number(l.unitPrice), 0);
  const monthly = form.lines.filter((l: any) => l.recurring).reduce((n: number, l: any) => n + Number(l.quantity) * Number(l.unitPrice), 0);
  const save = async (status?: string) => {
    const body = { title: form.title, lines: form.lines.map((l: any) => ({ ...l, quantity: Number(l.quantity), unitPrice: Number(l.unitPrice) })), notes: form.notes || "",
                   ...(status ? { status } : {}), ...(form.id ? {} : { accountTenantId: form.accountTenantId || undefined }) };
    if (await run(() => (form.id ? api(`psa/quotes/${form.id}`, { method: "PATCH", body }) : api("psa/quotes", { body })), "Quote saved")) onClose();
  };
  const print = async () => {
    const response = await fetch(`/api/console/psa/quotes/${form.id}/print`, { headers: { Authorization: `Bearer ${getToken()}` } });
    const win = window.open("", "_blank");
    win?.document.write(await response.text());
    win?.document.close();
  };
  return (
    <Modal title={form.id ? `${form.number} · ${form.title}` : "New quote"} onClose={onClose}
           footer={<>{form.id && <><button onClick={print}>Print / PDF</button><button onClick={() => save("Sent")}>Mark sent</button><button onClick={() => save("Accepted")}>Accepted</button><button onClick={() => save("Declined")}>Declined</button></>}
                   <button className="primary" disabled={busy || !form.title} onClick={() => save()}>Save</button></>}>
      <div className="form-grid">
        <label className="field">Title<input value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} /></label>
        {!form.id && <label className="field">Company<TenantSelect value={form.accountTenantId || ""} onChange={(id) => setForm({ ...form, accountTenantId: id })} allowAll /></label>}
      </div>
      <h3 style={{ marginTop: 14 }}>Lines</h3>
      {form.lines.map((l: any, i: number) => (
        <div key={i} className="row" style={{ marginBottom: 6 }}>
          <input value={l.description} onChange={(e) => setLine(i, { description: e.target.value })} style={{ flex: 1 }} />
          <input type="number" value={l.quantity} onChange={(e) => setLine(i, { quantity: e.target.value })} style={{ width: 70 }} />
          <input type="number" step="0.01" value={l.unitPrice} onChange={(e) => setLine(i, { unitPrice: e.target.value })} style={{ width: 100 }} />
          <label className="small"><input type="checkbox" checked={!!l.recurring} onChange={(e) => setLine(i, { recurring: e.target.checked })} /> monthly</label>
          <button className="small ghost" onClick={() => setForm({ ...form, lines: form.lines.filter((_: any, j: number) => j !== i) })}>✕</button>
        </div>
      ))}
      <div className="row">
        <select value="" onChange={(e) => { const p = products.find((x) => x.id === e.target.value); if (p) setForm({ ...form, lines: [...form.lines, { productId: p.id, description: p.description, quantity: 1, unitPrice: p.price, recurring: p.recurring }] }); }}>
          <option value="">Add a product…</option>{products.map((p) => <option key={p.id} value={p.id}>{p.sku} · {p.description}</option>)}</select>
        <button className="small" onClick={() => setForm({ ...form, lines: [...form.lines, { description: "Labour", quantity: 1, unitPrice: 85, recurring: false }] })}>Add custom line</button>
      </div>
      <p style={{ textAlign: "right" }}>One-off <b>{money(oneOff)}</b> · Monthly <b>{money(monthly)}</b> <span className="small muted">ex VAT</span></p>
      <label className="field">Notes<textarea rows={2} value={form.notes || ""} onChange={(e) => setForm({ ...form, notes: e.target.value })} /></label>
    </Modal>
  );
}

export function Knowledge() {
  const { can } = useApp();
  const { data, reload } = useData<any[]>("psa/kb");
  const [editing, setEditing] = useState<any>(null);
  const [q, setQ] = useState("");
  const { run, busy } = useAction();
  return (
    <>
      <PageHead title="Knowledge base" subtitle="Runbooks for the team and how-to articles for customers. Public articles show in the client portal."
                actions={can("crm") && <button className="primary" onClick={() => setEditing({ title: "", body: "", category: "General", public: false })}>New article</button>} />
      <input placeholder="Search articles" value={q} onChange={(e) => setQ(e.target.value)} style={{ minWidth: 280, marginBottom: 12 }} />
      <div className="card">
        <Table rows={data?.filter((a) => !q || `${a.title} ${a.body}`.toLowerCase().includes(q.toLowerCase()))} onRow={setEditing} empty="No articles."
               columns={[{ key: "title", label: "Article", render: (a) => <b>{a.title}</b> }, { key: "category", label: "Category" },
                         { key: "public", label: "Visibility", render: (a) => a.public ? <Pill value="customers" tone="good" /> : <Pill value="internal" tone="muted" /> },
                         { key: "author", label: "Author" }]} />
      </div>
      {editing && (
        <Modal title={editing.id ? editing.title : "New article"} onClose={() => setEditing(null)}
               footer={<>{editing.id && <button className="danger" onClick={async () => { if (await run(() => api(`psa/kb/${editing.id}`, { method: "DELETE" }), "Deleted")) { setEditing(null); reload(); } }}>Delete</button>}
                       <button className="primary" disabled={busy || !editing.title} onClick={async () => {
                         const body = { title: editing.title, body: editing.body, category: editing.category, public: editing.public };
                         if (await run(() => (editing.id ? api(`psa/kb/${editing.id}`, { method: "PATCH", body }) : api("psa/kb", { body })), "Saved")) { setEditing(null); reload(); }
                       }}>Save</button></>}>
          <div className="form-grid">
            <label className="field">Title<input value={editing.title} onChange={(e) => setEditing({ ...editing, title: e.target.value })} /></label>
            <label className="field">Category<input value={editing.category} onChange={(e) => setEditing({ ...editing, category: e.target.value })} /></label>
            <label className="field">Visible to<select value={editing.public ? "yes" : "no"} onChange={(e) => setEditing({ ...editing, public: e.target.value === "yes" })}><option value="no">Team only</option><option value="yes">Customers too</option></select></label>
          </div>
          <textarea rows={14} value={editing.body} onChange={(e) => setEditing({ ...editing, body: e.target.value })} style={{ width: "100%", marginTop: 10, fontFamily: "var(--font)" }} />
        </Modal>
      )}
    </>
  );
}
