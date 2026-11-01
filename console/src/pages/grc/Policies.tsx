import { displayValue } from "../../components/DisplayValue";
import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ago, api, downloadFile, fmtTime } from "../../api";
import { useApp } from "../../app-context";
import { Markdown } from "../../components/Markdown";
import { Modal, PageHead, Pill, Table, TenantSelect, useAction, useData, useListData } from "../../components/ui";
import { confirmDialog } from "../../components/dialogs";

const TONE: Record<string, string> = { draft: "muted", in_review: "warn", approved: "good", retired: "muted" };
const FRAMEWORK_SHORT: Record<string, string> = { "iso-27001": "ISO 27001", "cyber-essentials": "CE", "nist-csf-2": "NIST", "uk-gdpr": "GDPR",
  soc2: "SOC 2", "cis-v8-ig1": "CIS IG1", "ncsc-caf": "CAF", "cyber-essentials-plus": "CE+",
  "def-stan-05-138": "MOD CSM", govassure: "GovAssure", "govs-007": "GovS 007", "eu-gdpr": "EU GDPR",
  "pci-dss": "PCI DSS", nis2: "NIS 2", dora: "DORA" };

export function PoliciesTab() {
  const { tenantId, tenantName, can } = useApp();
  const { data, reload } = useListData<any>("grc/policies", { tenant_id: tenantId });
  const [adding, setAdding] = useState(false);
  const navigate = useNavigate();
  return (
    <div className="card">
      <div className="row" style={{ justifyContent: "space-between", marginBottom: 8 }}>
        <span className="small muted">Policies are adopted from Fenrir's library (filled in with the customer's details) or written from scratch, then reviewed and approved. Every approved version is kept.</span>
        {can("grc") && <button className="primary" onClick={() => setAdding(true)}>Add policy</button>}
      </div>
      <Table rows={data} onRow={(p) => navigate(`/governance/policies/${p.id}`)} empty="No policies yet. Adding a framework creates its policies as drafts."
             columns={[{ key: "title", label: "Policy", render: (p) => <><b>{displayValue(p.title)}</b><div className="small muted">{displayValue(p.summary)}</div></> },
                       { key: "tenantId", label: "Customer", render: (p) => tenantName(p.tenantId) },
                       { key: "status", label: "Status", render: (p) => <><Pill value={p.status.replace("_", " ")} tone={TONE[p.status]} />{p.reviewOverdue && <> <Pill value="review overdue" tone="bad" /></>}</> },
                       { key: "version", label: "Version", render: (p) => <span className="small">v{displayValue(p.version)}{p.approvedVersion && p.approvedVersion !== p.version ? ` (v${p.approvedVersion} approved)` : ""}</span> },
                       { key: "owner", label: "Owner" },
                       { key: "reviewDue", label: "Next review", render: (p) => <span className="small">{p.reviewDue ? fmtTime(p.reviewDue).split(",")[0] : "—"}</span> },
                       { key: "mapsTo", label: "Covers", render: (p) => Object.entries(p.mapsTo || {}).filter(([, ids]: any) => ids.length).map(([k, ids]: any) => <span key={k} className="chip" title={ids.join(", ")}>{displayValue(FRAMEWORK_SHORT[k] || k)} {displayValue(ids.length)}</span>) }]} />
      {adding && <AddPolicy onClose={(id) => { setAdding(false); reload(); if (id) navigate(`/governance/policies/${id}`); }} />}
    </div>
  );
}

function AddPolicy({ onClose }: { onClose: (id?: string) => void }) {
  const { tenantId } = useApp();
  const { data: library } = useData<any>("grc/library");
  const [customer, setCustomer] = useState(tenantId);
  const [template, setTemplate] = useState("");
  const [title, setTitle] = useState("");
  const [owner, setOwner] = useState("");
  const [contact, setContact] = useState("");
  const { run, busy } = useAction();
  const save = async () => {
    const created = await run(() => api<any>("grc/policies", { body: { tenantId: customer, templateKey: template || null, title, owner, securityContact: contact } }), "Policy added as a draft");
    if (created) onClose(created.id);
  };
  return (
    <Modal title="Add a policy" onClose={() => onClose()} wide footer={<button className="primary" disabled={busy || !customer || (!template && !title)} onClick={save}>Add</button>}>
      <label className="field">Customer<TenantSelect value={customer} onChange={setCustomer} allowAll={false} /></label>
      <label className="field">From the library<select value={template} onChange={(e) => setTemplate(e.target.value)}>
        <option value="">Blank policy</option>{(library?.policies || []).map((p: any) => <option key={p.key} value={p.key}>{displayValue(p.title)}</option>)}</select></label>
      {template && <p className="small muted">{displayValue(library?.policies.find((p: any) => p.key === template)?.summary)}</p>}
      {!template && <label className="field">Title<input value={title} onChange={(e) => setTitle(e.target.value)} /></label>}
      <div className="grid k2">
        <label className="field">Owner<input value={owner} onChange={(e) => setOwner(e.target.value)} /></label>
        {template && <label className="field">Who staff report incidents to<input value={contact} onChange={(e) => setContact(e.target.value)} /></label>}
      </div>
    </Modal>
  );
}

export function PolicyEditor() {
  const { id = "" } = useParams();
  const { can, tenantName } = useApp();
  const { data, reload } = useData<any>(`grc/policies/${id}`, undefined, [id]);
  const [body, setBody] = useState("");
  const [title, setTitle] = useState("");
  const [owner, setOwner] = useState("");
  const [mode, setMode] = useState<"read" | "edit">("read");
  const [months, setMonths] = useState(12);
  const [note, setNote] = useState("");
  const [viewing, setViewing] = useState<any>(null);
  const { run, busy } = useAction();
  useEffect(() => { if (data) { setBody(data.body); setTitle(data.title); setOwner(data.owner); } }, [data?.id, data?.version, data?.updatedAt]);
  if (!data) return null;
  const dirty = body !== data.body || title !== data.title || owner !== data.owner;
  const editable = can("grc") && data.status !== "retired";
  const act = async (action: string, message: string) => {
    if (await run(() => api(`grc/policies/${id}/workflow`, { body: { action, note, reviewMonths: months } }), message)) { setNote(""); reload(); }
  };
  const save = async () => {
    if (await run(() => api(`grc/policies/${id}`, { method: "PATCH", body: { title, body, owner } }),
      data.status === "approved" ? `Saved as draft v${data.version + 1}; v${data.version} stays published until this is approved` : "Saved")) { setMode("read"); reload(); }
  };
  return (
    <>
      <PageHead title={data.title} subtitle={<>{tenantName(data.tenantId)} · <Link to="/governance?tab=Policies">All policies</Link></>}
                actions={<div className="row">
                  <Pill value={`${data.status.replace("_", " ")} · v${data.version}`} tone={TONE[data.status]} />
                  {data.approvedVersion && <button onClick={() => run(() => downloadFile(`grc/policies/${id}/download`, `${data.title}.md`))}>Download approved</button>}
                  {editable && mode === "read" && <button onClick={() => setMode("edit")}>Edit</button>}
                </div>} />
      <div className="grid side">
        <div className="card">
          {mode === "edit" ? <>
            <label className="field">Title<input value={title} onChange={(e) => setTitle(e.target.value)} /></label>
            <label className="field">Owner<input value={owner} onChange={(e) => setOwner(e.target.value)} /></label>
            <label className="field">Policy (Markdown: # headings, **bold**, - lists, | tables |)<textarea className="policy-editor" value={body} onChange={(e) => setBody(e.target.value)} /></label>
            <div className="row"><button className="primary" disabled={busy || !dirty} onClick={save}>Save</button><button onClick={() => { setMode("read"); setBody(data.body); setTitle(data.title); setOwner(data.owner); }}>Cancel</button></div>
          </> : <Markdown text={data.body} />}
        </div>
        <div>
          <div className="card" style={{ marginBottom: 12 }}>
            <h3 style={{ marginTop: 0 }}>Review and approval</h3>
            <dl className="kv compact">
              <dt>Owner</dt><dd>{displayValue(data.owner || "—")}</dd>
              <dt>Approved</dt><dd>{data.approvedAt ? `v${data.approvedVersion} by ${data.approvedBy}, ${fmtTime(data.approvedAt)}` : "never"}</dd>
              <dt>Next review</dt><dd>{data.reviewDue ? fmtTime(data.reviewDue).split(",")[0] : "—"}{data.reviewOverdue && <> <Pill value="overdue" tone="bad" /></>}</dd>
              <dt>Last edited</dt><dd>{ago(data.updatedAt)} by {displayValue(data.updatedBy)}</dd>
            </dl>
            {can("grc") && <>
              <label className="field">Note (kept with the version)<input value={note} onChange={(e) => setNote(e.target.value)} placeholder="What changed / approved at board meeting…" /></label>
              <div className="row" style={{ flexWrap: "wrap" }}>
                {data.status === "draft" && <button disabled={busy} onClick={() => act("submit", "Sent for review")}>Submit for review</button>}
                {["draft", "in_review"].includes(data.status) && <>
                  <select value={months} onChange={(e) => setMonths(Number(e.target.value))} aria-label="Review period">{[6, 12, 24].map((m) => <option key={m} value={m}>review in {m} months</option>)}</select>
                  <button className="primary" disabled={busy} onClick={() => act("approve", "Approved and published")}>Approve</button></>}
                {data.status === "in_review" && <button disabled={busy} onClick={() => act("reject", "Sent back to draft")}>Send back</button>}
                {data.status !== "retired" ? <button className="danger" disabled={busy} onClick={async () => (await confirmDialog("Retire this policy?")) && act("retire", "Retired")}>Retire</button>
                  : <button disabled={busy} onClick={() => act("restore", "Restored as a draft")}>Restore</button>}
              </div>
            </>}
          </div>
          <div className="card" style={{ marginBottom: 12 }}>
            <h3 style={{ marginTop: 0 }}>Requirements it covers</h3>
            {Object.entries(data.mapsTo || {}).map(([k, ids]: any) => ids.length > 0 && <div key={k} style={{ marginBottom: 6 }}>
              <b className="small">{displayValue(FRAMEWORK_SHORT[k] || k)}</b><div className="row small" style={{ flexWrap: "wrap", gap: 4 }}>
                {ids.map((rid: string) => <Link key={rid} className="chip mono" to={`/governance/${data.tenantId}/${k}`}>{rid}</Link>)}</div></div>)}
          </div>
          <div className="card">
            <h3 style={{ marginTop: 0 }}>Published versions</h3>
            {(data.versions || []).length === 0 && <p className="small muted">None yet.</p>}
            {(data.versions || []).map((v: any) => <div key={v.id} className="row small" style={{ marginBottom: 4 }}>
              <button className="link" onClick={() => setViewing(v)}>v{displayValue(v.version)}</button><span className="muted" style={{ flex: 1 }}>{fmtTime(v.approvedAt)} · {displayValue(v.approvedBy)}</span>
              <button className="small" onClick={() => run(() => downloadFile(`grc/policies/${id}/download?version=${v.version}`, `${v.title}-v${v.version}.md`))}>Download</button>
            </div>)}
          </div>
        </div>
      </div>
      {viewing && <Modal title={`${viewing.title} - v${viewing.version}`} onClose={() => setViewing(null)} wide>
        {viewing.note && <p className="small muted">{displayValue(viewing.note)}</p>}<Markdown text={viewing.body} /></Modal>}
    </>
  );
}
