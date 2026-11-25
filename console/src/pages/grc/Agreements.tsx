// Agreements and e-signature (GRC-09): templates, signers in order, emailed links with one-time codes, expiry,
// and a hash-chained completion record.
import { useState } from "react";
import { api, fmtTime } from "../../api";
import { useApp } from "../../app-context";
import { Modal, PageHead, Pill, Table, useAction, useData, useListData } from "../../components/ui";
import { COMPLIANCE_SECTION, SectionTabs } from "../../components/sections";

const TONE: Record<string, string> = { draft: "muted", sent: "warn", completed: "good", declined: "bad", expired: "muted", voided: "muted" };

export default function Agreements() {
  const { tenantId, can } = useApp();
  const { data, reload } = useListData<any>("agreements", { tenantId: tenantId || undefined }, [tenantId]);
  const [open, setOpen] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  return (
    <>
      <SectionTabs items={COMPLIANCE_SECTION} />
      <PageHead title="Agreements" subtitle="Agreements from templates, signed in order by email link. Each signer proves their email address with a one-time code before signing; every event goes into a hash-chained completion record." />
      {!tenantId ? <div className="card empty">Choose a customer.</div> : <>
        {can("grc") && <button className="primary" style={{ marginBottom: 10 }} onClick={() => setCreating(true)}>New agreement</button>}
        <Table rows={data} onRow={(a) => setOpen(a.id)} empty="No agreements." columns={[
          { key: "title", label: "Agreement", render: (a) => <b>{a.title}</b> },
          { key: "status", label: "Status", render: (a) => <Pill value={a.status} tone={TONE[a.status]} /> },
          { key: "parties", label: "Signers", render: (a) => a.parties.map((p: any) => `${p.name} (${p.status})`).join(", ") },
          { key: "expiresAt", label: "Expires", render: (a) => a.expiresAt ? fmtTime(a.expiresAt) : "—" }]} />
      </>}
      {creating && <NewAgreement tenantId={tenantId!} onClose={() => { setCreating(false); reload(); }} />}
      {open && <AgreementDetail id={open} onClose={() => { setOpen(null); reload(); }} />}
    </>
  );
}

function NewAgreement({ tenantId, onClose }: { tenantId: string; onClose: () => void }) {
  const { run, busy } = useAction();
  const { data: templates, reload } = useListData<any>("agreements/templates", { tenantId }, [tenantId]);
  const [tpl, setTpl] = useState("");
  const [values, setValues] = useState<Record<string, string>>({});
  const [f, setF] = useState({ title: "", body: "", order: "sequential", expiresOn: "", signers: "" });
  const t = templates?.find((x) => x.id === tpl);
  const parties = f.signers.split("\n").map((l) => l.trim()).filter(Boolean).map((l, i) => { const [name, email] = l.split(/[,;<]/).map((x) => x.replace(">", "").trim()); return { name, email, order: i + 1 }; });
  return (
    <Modal wide title="New agreement" onClose={onClose} footer={<>
      <button disabled={busy} onClick={() => { const n = window.prompt("Template name"); const b = n && window.prompt("Template text (use {{variable}} for blanks)"); if (n && b) run(() => api("agreements/templates", { body: { tenantId, name: n, body: b } }), "Template saved").then(reload); }}>New template…</button>
      <button className="primary" disabled={busy || !parties.length} onClick={() => run(async () => {
        const a = await api<any>("agreements", { body: { tenantId, title: f.title, order: f.order, expiresOn: f.expiresOn || null, parties, ...(tpl ? { templateId: tpl, values } : { body: f.body }) } });
        return api(`agreements/${a.id}/send`, { body: {} });
      }, "Sent to the first signer").then((r) => r && onClose())}>Create and send</button>
    </>}>
      <div className="form-grid">
        <label className="field">Title<input value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} /></label>
        <label className="field">Template<select value={tpl} onChange={(e) => setTpl(e.target.value)}><option value="">None (write the text)</option>{(templates ?? []).map((x: any) => <option key={x.id} value={x.id}>{x.name}</option>)}</select></label>
        <label className="field">Signing order<select value={f.order} onChange={(e) => setF({ ...f, order: e.target.value })}><option value="sequential">One after another</option><option value="parallel">Any order</option></select></label>
        <label className="field">Expires<input type="date" value={f.expiresOn} onChange={(e) => setF({ ...f, expiresOn: e.target.value })} /></label>
      </div>
      {t ? t.variables.map((v: string) => <label key={v} className="field">{v}<input value={values[v] ?? ""} onChange={(e) => setValues({ ...values, [v]: e.target.value })} /></label>)
        : <label className="field">Text<textarea rows={8} value={f.body} onChange={(e) => setF({ ...f, body: e.target.value })} /></label>}
      <label className="field">Signers, in order, one per line: "Name, email"<textarea rows={3} value={f.signers} onChange={(e) => setF({ ...f, signers: e.target.value })} placeholder={"Ann Lee, ann@globex.test\nBob Ray, bob@acme.test"} /></label>
    </Modal>
  );
}

function AgreementDetail({ id, onClose }: { id: string; onClose: () => void }) {
  const { can } = useApp();
  const { run } = useAction();
  const { data: a, reload } = useData<any>(`agreements/${id}`);
  if (!a) return null;
  const download = async () => {
    const c = await api<any>(`agreements/${id}/certificate`);
    const el = document.createElement("a");
    el.href = URL.createObjectURL(new Blob([JSON.stringify(c, null, 2)], { type: "application/json" }));
    el.download = `${a.title}-record.json`;
    el.click();
  };
  return (
    <Modal wide title={a.title} onClose={onClose} footer={<>
      <button onClick={download}>Completion record</button>
      {can("grc") && (a.status === "sent" || a.status === "draft") && <button className="danger" onClick={() => run(() => api(`agreements/${id}/void`, { body: { reason: window.prompt("Reason") ?? "" } }), "Voided").then(reload)}>Void</button>}
    </>}>
      <p className="small"><Pill value={a.status} tone={TONE[a.status]} /> Document SHA-256 <code>{a.sha256}</code></p>
      <Table rows={a.parties} columns={[{ key: "order", label: "#" }, { key: "name", label: "Signer" }, { key: "email", label: "Email" },
        { key: "status", label: "Status", render: (p) => <Pill value={p.status} tone={p.status === "signed" ? "good" : p.status === "declined" ? "bad" : "muted"} /> },
        { key: "signedAt", label: "Signed", render: (p) => p.signedAt ? fmtTime(p.signedAt) : "—" }]} />
      <h4>Record</h4>
      {a.events.map((e: any) => <div key={e.seq} className="small mono">{e.seq}. {fmtTime(e.at)} {e.kind} · {e.actor} · {e.hash.slice(0, 12)}…</div>)}
      <h4>Text</h4><pre className="small" style={{ whiteSpace: "pre-wrap" }}>{a.body}</pre>
    </Modal>
  );
}
