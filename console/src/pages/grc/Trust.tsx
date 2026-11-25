// Trust centre (GRC-14, FLOW-10): a customer's public page of security documents, frozen with their as-of date and
// hash, shown after disclosure approval; gated documents behind NDA access requests that expire and can be revoked.
import { useState } from "react";
import { api, fmtTime } from "../../api";
import { useApp } from "../../app-context";
import { PageHead, Pill, Table, Tabs, useAction, useData, useListData } from "../../components/ui";
import { COMPLIANCE_SECTION, SectionTabs } from "../../components/sections";

export default function Trust() {
  const { tenantId, can } = useApp();
  const { run, busy } = useAction();
  const { data: c, reload } = useData<any>(tenantId ? "trust" : null, { tenantId: tenantId || undefined }, [tenantId]);
  const [tab, setTab] = useState("Settings");
  const [f, setF] = useState<any>(null);
  const form = f ?? { slug: c?.slug ?? "", title: c?.title ?? "", overview: c?.overview ?? "", contact: c?.contact ?? "", ndaText: c?.ndaText ?? "", defaultDays: c?.defaultDays ?? 30, published: c?.published ?? false };
  const save = (extra: any = {}) => run(() => api("trust", { method: "PUT", body: { tenantId, ...form, ...extra } }), "Saved").then(() => { setF(null); reload(); });
  return (
    <>
      <SectionTabs items={COMPLIANCE_SECTION} />
      <PageHead title="Trust centre" subtitle="A public page of the customer's security documents. Each document is frozen with its as-of date and hash and shown only after its disclosure is approved; gated documents are shared after an NDA access request, by links that expire and can be revoked." />
      {!tenantId ? <div className="card empty">Choose a customer.</div> : <>
        {c && <p className="small">Public address: <a href={c.url} target="_blank" rel="noreferrer">{c.url}</a> <Pill value={c.published ? "published" : "not published"} tone={c.published ? "good" : "muted"} /></p>}
        <Tabs tabs={["Settings", "Documents", "Access requests", "Access log"]} active={tab} onChange={setTab} />
        {tab === "Settings" && <div className="card">
          <div className="form-grid">
            <label className="field">Address (/trust/…)<input value={form.slug} onChange={(e) => setF({ ...form, slug: e.target.value })} placeholder="acme" /></label>
            <label className="field">Title<input value={form.title} onChange={(e) => setF({ ...form, title: e.target.value })} /></label>
            <label className="field">Contact<input value={form.contact} onChange={(e) => setF({ ...form, contact: e.target.value })} placeholder="security@acme.test" /></label>
            <label className="field">Access lasts (days)<input type="number" min={1} max={365} value={form.defaultDays} onChange={(e) => setF({ ...form, defaultDays: Number(e.target.value) })} /></label>
          </div>
          <label className="field">Overview<textarea rows={4} value={form.overview} onChange={(e) => setF({ ...form, overview: e.target.value })} /></label>
          <label className="field">Non-disclosure agreement requesters accept<textarea rows={6} value={form.ndaText} onChange={(e) => setF({ ...form, ndaText: e.target.value })} /></label>
          {can("grc") && <div className="row" style={{ gap: 6 }}>
            <button disabled={busy} onClick={() => save()}>Save</button>
            <button className="primary" disabled={busy} onClick={() => save({ published: !form.published })}>{form.published ? "Unpublish" : "Publish"}</button>
          </div>}
        </div>}
        {tab === "Documents" && c && <Documents tenantId={tenantId} docs={c.documents} reload={reload} />}
        {tab === "Access requests" && c && <Table rows={c.requests} empty="No requests." columns={[
          { key: "email", label: "Requester", render: (r) => <><b>{r.name}</b> {r.email}<div className="small muted">{r.company} · {r.reason}</div></> },
          { key: "status", label: "Status", render: (r) => <><Pill value={r.status} tone={r.status === "approved" ? "good" : r.status === "pending" ? "warn" : "muted"} />{r.expiresAt && r.status === "approved" && <div className="small muted">until {fmtTime(r.expiresAt)}</div>}</> },
          { key: "createdAt", label: "Asked", render: (r) => fmtTime(r.createdAt) },
          { key: "id", label: "", render: (r) => can("grc") && <div className="row" style={{ gap: 4 }}>
            {r.status !== "approved" && r.status !== "denied" && <button className="small primary" onClick={() => run(() => api(`trust/requests/${r.id}/decision`, { body: { action: "approve" } }), "Approved: the requester is emailed a link").then(reload)}>Approve</button>}
            {r.status === "pending" && <button className="small" onClick={() => run(() => api(`trust/requests/${r.id}/decision`, { body: { action: "deny" } }), "Denied").then(reload)}>Deny</button>}
            {r.status === "approved" && <button className="small danger" onClick={() => run(() => api(`trust/requests/${r.id}/decision`, { body: { action: "revoke" } }), "Revoked: the link stops working now").then(reload)}>Revoke</button>}
          </div> }]} />}
        {tab === "Access log" && c && <Table rows={c.accessLog} empty="No access yet." columns={[
          { key: "at", label: "When", render: (a) => fmtTime(a.at) },
          { key: "documentId", label: "Document", render: (a) => c.documents.find((d: any) => d.id === a.documentId)?.title ?? a.documentId },
          { key: "email", label: "Who", render: (a) => a.email || "public" },
          { key: "outcome", label: "Outcome", render: (a) => <Pill value={`${a.outcome}${a.reason ? `: ${a.reason}` : ""}`} tone={a.outcome === "served" ? "good" : "bad"} /> },
          { key: "ip", label: "Address" }]} />}
        {!c && tab !== "Settings" && <div className="card empty">Save the settings first.</div>}
      </>}
    </>
  );
}

function Documents({ tenantId, docs, reload }: { tenantId: string; docs: any[]; reload: () => void }) {
  const { can } = useApp();
  const { run, busy } = useAction();
  const { data: policies } = useListData<any>("grc/policies", { tenant_id: tenantId }, [tenantId]);
  const { data: evidence } = useListData<any>("grc/evidence", { tenant_id: tenantId }, [tenantId]);
  const [f, setF] = useState({ kind: "policy", sourceId: "", access: "gated", title: "", text: "" });
  const sources = f.kind === "policy" ? (policies ?? []).filter((p: any) => p.approvedVersion).map((p: any) => [p.id, p.title])
    : f.kind === "evidence" ? (evidence ?? []).filter((e: any) => e.kind === "file").map((e: any) => [e.id, e.title]) : [];
  return (
    <>
      {can("grc") && <div className="card">
        <div className="form-grid">
          <label className="field">Kind<select value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value, sourceId: "" })}><option value="policy">Approved policy</option><option value="evidence">Evidence file</option><option value="note">Written note</option></select></label>
          {f.kind !== "note" && <label className="field">Source<select value={f.sourceId} onChange={(e) => setF({ ...f, sourceId: e.target.value })}><option value="">Choose</option>{sources.map(([id, t]: any) => <option key={id} value={id}>{t}</option>)}</select></label>}
          <label className="field">Access<select value={f.access} onChange={(e) => setF({ ...f, access: e.target.value })}><option value="gated">On request (NDA)</option><option value="public">Public</option></select></label>
          <label className="field">Title (optional)<input value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} /></label>
        </div>
        {f.kind === "note" && <label className="field">Text<textarea rows={4} value={f.text} onChange={(e) => setF({ ...f, text: e.target.value })} /></label>}
        <button className="primary" disabled={busy || (f.kind !== "note" && !f.sourceId) || (f.kind === "note" && !f.text.trim())} onClick={() => run(() => api("trust/documents", { body: { tenantId, ...f, title: f.title || undefined } }), "Added: approve its disclosure to show it").then(reload)}>Add document</button>
        <p className="small muted">The document is copied as it is now (its as-of date and SHA-256 are shown on the page); later edits to the source do not change it.</p>
      </div>}
      <Table rows={docs} empty="No documents." columns={[
        { key: "title", label: "Document", render: (d) => <><b>{d.title}</b><div className="small muted">{d.kind} · as of {fmtTime(d.asOf)} · {d.sha256.slice(0, 12)}…</div></> },
        { key: "access", label: "Access", render: (d) => <Pill value={d.access} tone={d.access === "public" ? "blue" : "muted"} /> },
        { key: "status", label: "Disclosure", render: (d) => <><Pill value={d.status} tone={d.status === "approved" ? "good" : d.status === "pending" ? "warn" : "muted"} />{d.approvedBy && <div className="small muted">{d.approvedBy}</div>}</> },
        { key: "id", label: "", render: (d) => can("grc") && <div className="row" style={{ gap: 4 }}>
          {d.status === "pending" && <button className="small primary" onClick={() => run(() => api(`trust/documents/${d.id}/decision`, { body: { action: "approve" } }), "Disclosure approved").then(reload)}>Approve disclosure</button>}
          <button className="small" onClick={() => run(() => api(`trust/documents/${d.id}/decision`, { body: { action: "access", access: d.access === "public" ? "gated" : "public" } })).then(reload)}>Make {d.access === "public" ? "gated" : "public"}</button>
          {d.status !== "withdrawn" && <button className="small danger" onClick={() => run(() => api(`trust/documents/${d.id}/decision`, { body: { action: "withdraw" } }), "Withdrawn").then(reload)}>Withdraw</button>}
        </div> }]} />
    </>
  );
}
