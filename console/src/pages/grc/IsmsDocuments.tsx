import { useState } from "react";
import { api, downloadFile, fmtTime } from "../../api";
import { useApp } from "../../app-context";
import { displayValue } from "../../components/DisplayValue";
import { Markdown } from "../../components/Markdown";
import { ErrorNote, Modal, Pill, Table, useAction, useData } from "../../components/ui";
import { safeArray } from "../../data-shapes";

/** ISMS documents: generated from live data, reviewed, approved and published. Approved versions never change. */

const STATE_TONE: Record<string, string> = { draft: "muted", in_review: "warn", approved: "good", published: "good", superseded: "muted", withdrawn: "muted" };

function useIsms() {
  const { tenantId } = useApp();
  const { data: me } = useData<any>(tenantId ? "isms/me" : null, { tenant_id: tenantId }, [tenantId]);
  return { tenantId, me, perms: safeArray<string>(me?.permissions) };
}

export function IsmsDocumentsTab() {
  const { tenantId, me, perms } = useIsms();
  const allowed = perms.includes("documents.view");
  const { data, error, reload } = useData<any>(tenantId && allowed ? "isms/documents" : null, { tenant_id: tenantId }, [tenantId, allowed]);
  const [open, setOpen] = useState<string | null>(null);
  const { run, busy } = useAction();
  if (!tenantId) return <p className="muted">Choose a customer in the tenant picker to see its ISMS documents.</p>;
  if (!allowed) return me ? <p className="muted">Your ISMS role in this customer ({displayValue(me.role ?? "none")}) cannot view documents.</p> : null;
  const edit = perms.includes("documents.edit");
  const generate = async (docType: string) => {
    const r = await run(() => api<any>("isms/documents/generate", { body: { tenantId, docType } }), "Draft generated");
    if (r) { reload(); setOpen(r.documentId); }
  };
  const reviewer = edit || perms.includes("documents.approve");  // editors and approvers see drafts; others only published
  const rows = safeArray<any>(data?.documents).filter((d) => reviewer || d.published);
  return <div className="card">
    <ErrorNote error={error} />
    <p className="small muted">Documents are written from the customer's live ISMS data. Regenerating makes a new draft; approved and published versions never change. A document is out of date when the data it uses has changed since its latest version.</p>
    <Table rows={rows.map((d) => ({ ...d, id: d.docType }))} empty="No documents." onRow={(d) => d.documentId && setOpen(d.documentId)} columns={[
      { key: "title", label: "Document", render: (d) => <><b>{displayValue(d.title)}</b><div className="small muted">{d.number ?? "Not generated yet"}{d.source === "imported" ? " (imported from the earlier policies)" : ""}</div></> },
      { key: "latest", label: "Latest", render: (d) => d.latest ? <><Pill value={`v${d.latest.version} ${d.latest.stateLabel}`} tone={STATE_TONE[d.latest.state]} />{d.outOfDate && <> <Pill value="out of date" tone="warn" /></>}</> : "None" },
      { key: "published", label: "Published", render: (d) => d.published ? `v${d.published.version}, ${fmtTime(d.published.publishedAt)}` : "Not yet" },
      { key: "nextReview", label: "Next review", render: (d) => <>{d.nextReview ?? ""}{d.reviewOverdue && <> <Pill value="review overdue" tone="bad" /></>}</> },
      { key: "docType", label: "", render: (d) => edit && d.source !== "imported" && (!d.latest || d.outOfDate || d.latest.state !== "in_review") ?
        <button className="small" disabled={busy || d.latest?.state === "in_review"} onClick={(e) => { e.stopPropagation(); generate(d.docType); }}>{d.latest ? "Regenerate" : "Generate"}</button> : null }]} />
    {open && <DocumentDetail id={open} tenantId={tenantId} perms={perms} onClose={() => { setOpen(null); reload(); }} />}
  </div>;
}

function DocumentDetail({ id, tenantId, perms, onClose }: { id: string; tenantId: string; perms: string[]; onClose: () => void }) {
  const [versionId, setVersionId] = useState<string | undefined>(undefined);
  const { data, error, reload } = useData<any>(`isms/documents/${id}`, versionId ? { version_id: versionId } : {}, [id, versionId]);
  const [editing, setEditing] = useState<{ ref: string; content: string } | null>(null);
  const { run, busy } = useAction();
  const edit = perms.includes("documents.edit"), approve = perms.includes("documents.approve");
  const v = data?.viewing;
  const act = async (action: string) => { if (await run(() => api(`isms/documents/versions/${v.id}/${action}`, { method: "POST" }), "Saved")) reload(); };
  const saveWording = async () => {
    if (!editing) return;
    if (await run(() => api("isms/documents/wording", { method: "PUT", body: { tenantId, docType: data.docType, blockRef: editing.ref, content: editing.content } }), "Wording saved. Regenerate to use it.")) { setEditing(null); reload(); }
  };
  return <Modal title={data ? `${data.number} ${data.title}` : "Document"} wide onClose={onClose}>
    <ErrorNote error={error} />
    {data && <>
      <div className="row" style={{ gap: 8, flexWrap: "wrap", alignItems: "end" }}>
        {safeArray<any>(data.versions).length > 0 && <label className="field">Version<select value={v?.id ?? ""} onChange={(e) => setVersionId(e.target.value)}>
          {safeArray<any>(data.versions).map((x) => <option key={x.id} value={x.id}>v{x.version} {x.stateLabel}</option>)}</select></label>}
        {v && <><button onClick={() => run(() => downloadFile(`isms/documents/versions/${v.id}/file?format=docx`, "document.docx"))}>Word</button>
          {v.hasPdf && <button onClick={() => run(() => downloadFile(`isms/documents/versions/${v.id}/file?format=pdf`, "document.pdf"))}>PDF</button>}</>}
        <span style={{ flex: 1 }} />
        {v?.state === "draft" && edit && <button disabled={busy} onClick={() => act("submit")}>Send for review</button>}
        {v?.state === "in_review" && approve && <><button disabled={busy} onClick={() => act("return")}>Return to draft</button><button className="primary" disabled={busy} onClick={() => act("approve")}>Approve</button></>}
        {v?.state === "approved" && approve && <button className="primary" disabled={busy} onClick={() => act("publish")}>Publish</button>}
        {v?.state === "published" && approve && <button disabled={busy} onClick={() => act("withdraw")}>Withdraw</button>}
      </div>
      {v && <p className="small">Version {v.version}: {v.stateLabel}{v.approvedBy ? `, approved by ${v.approvedBy} on ${fmtTime(v.approvedAt)}` : ""}.{v.changeNote ? ` ${v.changeNote}` : ""}{v.pdfError ? ` ${v.pdfError}` : ""}</p>}
      {safeArray<any>(data.changes).length > 0 && <div className="card"><b>Regenerating would change {data.changes.length} section(s):</b> {safeArray<any>(data.changes).map((c) => `${c.ref} (${c.change})`).join(", ")}</div>}
      <div className="card">{safeArray<any>(data.blocks).map((b) => <section key={b.ref} aria-label={b.ref}>
        <Markdown text={b.markdown} />
        {edit && data.source !== "imported" && <button className="small" onClick={() => setEditing({ ref: b.ref, content: data.overrides?.[b.ref] ?? safeArray<any>(data.templateBlocks).find((t) => t.ref === b.ref)?.body ?? "" })}>
          {data.overrides?.[b.ref] ? "Edit our wording" : "Use our own wording"}</button>}
      </section>)}{!safeArray<any>(data.blocks).length && <p className="muted">No published version to show.</p>}</div>
    </>}
    {editing && <Modal title={`Wording for ${editing.ref}`} wide onClose={() => setEditing(null)} footer={<><button onClick={() => setEditing({ ...editing, content: "" })}>Back to the template text</button><button className="primary" disabled={busy} onClick={saveWording}>Save</button></>}>
      <p className="small muted">Your wording replaces this section in every future version. Placeholders such as {"{{organization.legal_name}}"} still work. Leave it empty to go back to the template text.</p>
      <label className="field">Wording<textarea rows={12} value={editing.content} onChange={(e) => setEditing({ ...editing, content: e.target.value })} /></label>
    </Modal>}
  </Modal>;
}
