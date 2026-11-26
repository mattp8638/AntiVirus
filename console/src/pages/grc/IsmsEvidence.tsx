import { useState } from "react";
import { api, downloadFile, fmtTime, uploadFile } from "../../api";
import { useApp } from "../../app-context";
import { displayValue } from "../../components/DisplayValue";
import { confirmDialog } from "../../components/dialogs";
import { ErrorNote, Modal, Pill, Table, useAction, useData } from "../../components/ui";
import { safeArray } from "../../data-shapes";

/** Evidence for ISMS controls: files (virus scanned), links, notes and Fenrir's automated results. */

const KIND_LABEL: Record<string, string> = { file: "File", link: "Link", note: "Note", connector_result: "Fenrir check" };
const SCAN_LABEL: Record<string, string> = { pending: "Waiting for virus scan", clean: "Scanned clean", infected: "Rejected: virus found", failed: "Scan failed", not_required: "" };

function useIsms() {
  const { tenantId } = useApp();
  const { data: me } = useData<any>(tenantId ? "isms/me" : null, { tenant_id: tenantId }, [tenantId]);
  return { tenantId, me, perms: safeArray<string>(me?.permissions) };
}

export function IsmsEvidenceTab() {
  const { tenantId, me, perms } = useIsms();
  const allowed = perms.includes("evidence.view");
  const { data, error, reload } = useData<any>(tenantId && allowed ? "isms/evidence" : null, { tenant_id: tenantId }, [tenantId, allowed]);
  const { data: ctl } = useData<any>(tenantId && allowed ? "isms/controls" : null, { tenant_id: tenantId }, [tenantId, allowed]);
  const [adding, setAdding] = useState(false);
  const [open, setOpen] = useState<any>(null);
  const [filter, setFilter] = useState("all");
  const { run, busy } = useAction();
  if (!tenantId) return <p className="muted">Choose a customer in the tenant picker to see its evidence.</p>;
  if (!allowed) return me ? <p className="muted">Your ISMS role in this customer ({displayValue(me.role ?? "none")}) cannot view evidence.</p> : null;
  const manage = perms.includes("programme.manage");
  const canAdd = perms.includes("evidence.upload");
  const controls = safeArray<any>(ctl?.controls).filter((c) => c.applicable);
  const rows = safeArray<any>(data?.evidence).filter((e) => filter === "all" || (filter === "expired" ? !e.current : e.kind === filter));
  const importNow = async () => { const r = await run(() => api<any>("isms/evidence/import-fenrir", { body: { tenantId } })); if (r) reload(); };
  return <div className="card">
    <ErrorNote error={error} />
    <div className="row" style={{ gap: 8, flexWrap: "wrap", alignItems: "end", marginBottom: 8 }}>
      <label className="field">Show<select value={filter} onChange={(e) => setFilter(e.target.value)}>
        <option value="all">Everything</option><option value="expired">Not current (expired, failing or not scanned)</option>
        <option value="file">Files</option><option value="link">Links</option><option value="note">Notes</option><option value="connector_result">Fenrir checks</option></select></label>
      <span style={{ flex: 1 }} />
      {manage && <button disabled={busy} onClick={importNow}>Import Fenrir results now</button>}
      {canAdd && <button className="primary" onClick={() => setAdding(true)}>Add evidence</button>}
    </div>
    <p className="small muted">A control counts as implemented with evidence while it is implemented and has current evidence: scanned clean, not expired, and (for Fenrir checks) passing. Fenrir's automated results are imported every hour.</p>
    <Table rows={rows} empty="No evidence yet." onRow={setOpen} columns={[
      { key: "title", label: "Evidence", render: (e) => <><b>{displayValue(e.title)}</b><div className="small muted">{KIND_LABEL[e.kind] ?? e.kind}{e.uploadedBy ? `, ${e.uploadedBy}` : ""}, {fmtTime(e.collectedAt)}</div></> },
      { key: "controls", label: "Controls", render: (e) => <span className="small">{safeArray<any>(e.controls).map((c) => c.ref).join(", ") || "None"}</span> },
      { key: "validUntil", label: "Valid until", render: (e) => <span className="small">{e.validUntil ?? "No end date"}</span> },
      { key: "current", label: "Counts now", render: (e) => <><Pill value={e.current ? "current" : "not current"} tone={e.current ? "good" : "warn"} />{SCAN_LABEL[e.scanStatus] && <div className="small">{SCAN_LABEL[e.scanStatus]}</div>}</> }]} />
    {adding && <AddEvidence tenantId={tenantId} controls={controls} onClose={() => { setAdding(false); reload(); }} />}
    {open && <EvidenceDetail evidence={open} controls={controls} manage={manage} onClose={() => { setOpen(null); reload(); }} />}
  </div>;
}

function ControlPicker({ controls, chosen, onChange }: { controls: any[]; chosen: string[]; onChange: (ids: string[]) => void }) {
  const [q, setQ] = useState("");
  const shown = controls.filter((c) => !q || `${c.ref} ${c.title}`.toLowerCase().includes(q.toLowerCase())).slice(0, 60);
  return <fieldset className="field"><legend>Controls this is evidence for (at least one)</legend>
    <input aria-label="Filter controls" placeholder="Filter" value={q} onChange={(e) => setQ(e.target.value)} />
    <div style={{ maxHeight: 220, overflow: "auto" }}>{shown.map((c) => <label key={c.id} className="row" style={{ gap: 6 }}>
      <input type="checkbox" checked={chosen.includes(c.id)} onChange={(e) => onChange(e.target.checked ? [...chosen, c.id] : chosen.filter((x) => x !== c.id))} />{c.ref} {c.title}</label>)}</div>
  </fieldset>;
}

function AddEvidence({ tenantId, controls, onClose }: { tenantId: string; controls: any[]; onClose: () => void }) {
  const [kind, setKind] = useState("file");
  const [title, setTitle] = useState("");
  const [url, setUrl] = useState("");
  const [note, setNote] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [validUntil, setValidUntil] = useState("");
  const [chosen, setChosen] = useState<string[]>([]);
  const { run, busy } = useAction();
  const save = async () => {
    const result = await run(() => kind === "file" && file
      ? uploadFile<any>("isms/evidence/upload", file, { tenant_id: tenantId, filename: file.name, title, controls: chosen.join(","), valid_until: validUntil })
      : api<any>("isms/evidence", { body: { tenantId, title, kind, url, note, validUntil: validUntil || null, controlIds: chosen } }));
    if (!result) return;
    if (result.scanStatus === "infected") await confirmDialog(`The virus scanner rejected this file (${result.scanDetail}). It was not kept.`, { confirmLabel: "OK" });
    onClose();
  };
  const ready = chosen.length > 0 && (kind === "file" ? !!file : kind === "link" ? !!url.trim() && !!title.trim() : !!note.trim() && !!title.trim());
  return <Modal title="Add evidence" wide onClose={onClose} footer={<button className="primary" disabled={busy || !ready} onClick={save}>Add</button>}>
    <label className="field">Type<select value={kind} onChange={(e) => setKind(e.target.value)}><option value="file">File (up to 25 MB)</option><option value="link">Link</option><option value="note">Note</option></select></label>
    <label className="field">Title{kind === "file" ? " (optional, the file name is used otherwise)" : ""}<input value={title} onChange={(e) => setTitle(e.target.value)} /></label>
    {kind === "file" && <label className="field">File<input type="file" onChange={(e) => setFile(e.target.files?.[0] ?? null)} /></label>}
    {kind === "link" && <label className="field">Web address<input value={url} placeholder="https://" onChange={(e) => setUrl(e.target.value)} /></label>}
    {kind === "note" && <label className="field">Note<textarea rows={4} value={note} onChange={(e) => setNote(e.target.value)} /></label>}
    <label className="field">Valid until (optional)<input type="date" value={validUntil} onChange={(e) => setValidUntil(e.target.value)} /></label>
    <ControlPicker controls={controls} chosen={chosen} onChange={setChosen} />
    {kind === "file" && <p className="small muted">Files are stored encrypted and virus scanned. Program and script files cannot be uploaded.</p>}
  </Modal>;
}

function EvidenceDetail({ evidence, controls, manage, onClose }: { evidence: any; controls: any[]; manage: boolean; onClose: () => void }) {
  const [chosen, setChosen] = useState<string[]>(safeArray<any>(evidence.controls).map((c) => c.id));
  const [validUntil, setValidUntil] = useState(evidence.validUntil ?? "");
  const { run, busy } = useAction();
  const save = async () => { if (await run(() => api(`isms/evidence/${evidence.id}`, { method: "PATCH", body: { controlIds: chosen, validUntil: validUntil || null } }), "Evidence saved")) onClose(); };
  const remove = async () => {
    if (!(await confirmDialog(`Delete "${evidence.title}"? Controls it evidenced may stop counting as evidenced.`, { confirmLabel: "Delete", danger: true }))) return;
    if (await run(() => api(`isms/evidence/${evidence.id}`, { method: "DELETE" }), "Evidence deleted")) onClose();
  };
  const canDownload = evidence.kind === "file" && (evidence.scanStatus === "clean" || evidence.scanStatus === "not_required");
  return <Modal title={evidence.title} wide onClose={onClose} footer={manage && evidence.kind !== "connector_result" && <><button disabled={busy} onClick={remove}>Delete</button><button className="primary" disabled={busy || !chosen.length} onClick={save}>Save</button></>}>
    <p className="small">{KIND_LABEL[evidence.kind]}, collected {fmtTime(evidence.collectedAt)}{evidence.sha256 ? `, SHA-256 ${evidence.sha256}` : ""}.</p>
    {evidence.url && <p><a href={evidence.url} target="_blank" rel="noreferrer noopener">{evidence.url}</a></p>}
    {evidence.note && <p style={{ whiteSpace: "pre-wrap" }}>{displayValue(evidence.note)}</p>}
    {evidence.scanDetail && <p className="small">{SCAN_LABEL[evidence.scanStatus]}: {displayValue(evidence.scanDetail)}</p>}
    {canDownload && <button onClick={() => run(() => downloadFile(`isms/evidence/${evidence.id}/download`, evidence.filename || "evidence"))}>Download {evidence.filename}</button>}
    {manage && evidence.kind !== "connector_result" ? <>
      <label className="field">Valid until<input type="date" value={validUntil} onChange={(e) => setValidUntil(e.target.value)} /></label>
      <ControlPicker controls={controls} chosen={chosen} onChange={setChosen} />
    </> : <p className="small">Controls: {safeArray<any>(evidence.controls).map((c) => `${c.ref} ${c.title}`).join("; ") || "None"}. Valid until: {evidence.validUntil ?? "no end date"}.</p>}
  </Modal>;
}
