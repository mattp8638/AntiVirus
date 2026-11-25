// eDiscovery cases over backups (backup/docs/design/ediscovery.md): custodians' backups held while the case is open,
// searches kept with the case, exports with a manifest of each item's SHA-256, and a chain-of-custody record.
import { useMemo, useState } from "react";
import { api, apiBytes, downloadFile, fmtTime } from "../api";
import { useApp } from "../app-context";
import { downloadKey } from "../backup-seal";
import { ErrorNote, Modal, Pill, Table, useAction, useData, useListData } from "../components/ui";
import { waitFast } from "./BackupFiles";

interface Custodian { device: string; label: string; accounts: string[] }
interface Hit { image_id: string; volume?: { disk: number; partition: number } | null; path: string; size: number; folder?: boolean; account?: string; kind?: string }
interface Case {
  id: string; tenantId: string; name: string; matter: string; description: string; status: string; custodians: Custodian[];
  holdNew: boolean; heldBackups: number; createdBy: string; createdAt: string; closedAt: string | null;
  searches?: { id: string; query: string; by: string; at: string; state: string; hits: Hit[]; truncated?: boolean; locked?: number; notIndexed?: number }[];
  exports?: { id: string; imageId: string; machine: string; what: string; by: string; at: string; jobId: string; state: string; manifestSha256?: string; manifestEntries?: number; ciphertextSha256?: string; receipts?: { by: string; at: string; sha256: string }[]; error?: string }[];
}

// One-time keys of exports started in this browser: only this browser can open them.
const keys = new Map<string, Awaited<ReturnType<typeof downloadKey>>>();

async function sha256Hex(b: Uint8Array): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", b as BufferSource));
  return [...d].map((x) => x.toString(16).padStart(2, "0")).join("");
}

export function BackupCases() {
  const { tenantId, can } = useApp();
  const { data: cases, reload } = useListData<Case>("backup/cases", { tenantId: tenantId || undefined }, [tenantId]);
  const [open, setOpen] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  return (
    <>
      <p className="small muted">An eDiscovery case keeps its custodians' backups on legal hold while it is open (and later backups too, if chosen), keeps its searches, and exports items with a manifest of each one's SHA-256. The case manifest is the chain-of-custody record. Searching and exporting need the repositories unlocked, as for any restore.</p>
      {can("configure") && <button className="primary" style={{ marginBottom: 12 }} onClick={() => setCreating(true)}>New case</button>}
      <Table rows={cases} onRow={(c) => setOpen(c.id)} empty="No cases." columns={[
        { key: "name", label: "Case", render: (c) => <><b>{c.name}</b>{c.matter && <div className="small muted">{c.matter}</div>}</> },
        { key: "status", label: "Status", render: (c) => <Pill value={c.status} tone={c.status === "open" ? "warn" : undefined} /> },
        { key: "custodians", label: "Custodians", render: (c) => c.custodians.map((x) => x.label).join(", ") },
        { key: "heldBackups", label: "Held backups" },
        { key: "createdAt", label: "Opened", render: (c) => fmtTime(c.createdAt) }]} />
      {creating && <CaseEditor onClose={() => { setCreating(false); reload(); }} />}
      {open && <CaseDetail id={open} onClose={() => { setOpen(null); reload(); }} />}
    </>
  );
}

function CustodianPicker({ value, onChange }: { value: Custodian[]; onChange: (v: Custodian[]) => void }) {
  const { tenantId } = useApp();
  const { data } = useData<any>("backup/image-devices", { tenantId: tenantId || undefined }, [tenantId]);
  const devices: any[] = useMemo(() => (Array.isArray(data) ? data : data?.devices ?? []), [data]);
  const has = (k: string) => value.find((c) => c.device === k);
  return (
    <div className="stack">
      {devices.length === 0 && <div className="small muted">No machines or cloud tenants have backups yet.</div>}
      {devices.map((d) => {
        const c = has(d.key);
        return (
          <div key={d.key}>
            <label className="row small" style={{ gap: 6 }}>
              <input type="checkbox" checked={!!c} onChange={() => onChange(c ? value.filter((x) => x.device !== d.key) : [...value, { device: d.key, label: d.name, accounts: [] }])} />
              <b>{d.name}</b> <span className="muted">{d.source === "saas" ? "cloud tenant" : d.source || "machine"} · {d.images} backups</span>
            </label>
            {c && d.source === "saas" && <input className="small" style={{ marginLeft: 22, width: "80%" }} placeholder="Only these accounts (comma-separated; empty: the whole tenant)"
              value={c.accounts.join(", ")} onChange={(e) => onChange(value.map((x) => x.device === d.key ? { ...x, accounts: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) } : x))} />}
          </div>
        );
      })}
    </div>
  );
}

function CaseEditor({ initial, onClose }: { initial?: Case; onClose: () => void }) {
  const { tenantId } = useApp();
  const { run, busy } = useAction();
  const [f, setF] = useState({ name: initial?.name ?? "", matter: initial?.matter ?? "", description: initial?.description ?? "", holdNew: initial?.holdNew ?? true });
  const [custodians, setCustodians] = useState<Custodian[]>(initial?.custodians ?? []);
  const save = () => run(() => initial
    ? api(`backup/cases/${initial.id}`, { method: "PATCH", body: { description: f.description, holdNew: f.holdNew, custodians } })
    : api("backup/cases", { body: { tenantId: tenantId || undefined, ...f, custodians } }), initial ? "Case updated" : "Case opened: the custodians' backups are on hold").then((r) => { if (r) onClose(); });
  return (
    <Modal title={initial ? `Edit ${initial.name}` : "New eDiscovery case"} onClose={onClose}
      footer={<button className="primary" disabled={busy || (!initial && f.name.trim().length < 3)} onClick={save}>{initial ? "Save" : "Open case"}</button>}>
      <div className="form-grid">
        {!initial && <label className="field">Name<input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder="Smith v Acme" /></label>}
        {!initial && <label className="field">Matter reference<input value={f.matter} onChange={(e) => setF({ ...f, matter: e.target.value })} /></label>}
        <label className="field">Description<textarea rows={2} value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></label>
      </div>
      <label className="row small" style={{ gap: 6, margin: "8px 0" }}><input type="checkbox" checked={f.holdNew} onChange={(e) => setF({ ...f, holdNew: e.target.checked })} /> Also hold backups taken while the case is open</label>
      <h4>Custodians</h4>
      <CustodianPicker value={custodians} onChange={setCustodians} />
    </Modal>
  );
}

function CaseDetail({ id, onClose }: { id: string; onClose: () => void }) {
  const { can } = useApp();
  const { run, busy } = useAction();
  const { data: c, reload } = useData<Case>(`backup/cases/${id}`);
  const [query, setQuery] = useState("");
  const [editing, setEditing] = useState(false);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [state, setState] = useState<{ busy?: string; err?: string }>({});
  if (!c) return null;
  const last = c.searches?.[c.searches.length - 1];
  const hits = last?.hits ?? [];
  const search = () => run(async () => {
    const r = await api<{ jobs: string[] }>(`backup/cases/${id}/search`, { body: { query } });
    setSelected(new Set());
    await Promise.all(r.jobs.map((j) => waitFast(j, undefined, 900)));
    reload();
  }, "Search finished");
  const exportSelected = () => run(async () => {
    const chosen = [...selected].map((i) => hits[i]);
    const byImage = new Map<string, Hit[]>();
    for (const h of chosen) byImage.set(`${h.image_id}|${h.volume ? `${h.volume.disk}:${h.volume.partition}` : ""}`, [...(byImage.get(`${h.image_id}|${h.volume ? `${h.volume.disk}:${h.volume.partition}` : ""}`) ?? []), h]);
    for (const group of byImage.values()) {
      const k = await downloadKey();
      const h0 = group[0];
      const body = h0.account
        ? { imageId: h0.image_id, accounts: [...new Set(group.map((h) => h.account))], items: group.map((h) => h.path), recipient: k.publicB64 }
        : { imageId: h0.image_id, disk: h0.volume?.disk, partition: h0.volume?.partition, paths: group.map((h) => h.path), recipient: k.publicB64 };
      const r = await api<{ id: string }>(`backup/cases/${id}/export`, { body });
      keys.set(r.id, k);
    }
    setSelected(new Set());
    reload();
  }, "Export started: download it below when it is ready");
  const save = async (e: NonNullable<Case["exports"]>[number]) => {
    const k = keys.get(e.id);
    if (!k) { setState({ err: "This export was started in another browser or before a reload: only that browser's key opens it. Start the export again here." }); return; }
    setState({ busy: "Downloading and decrypting…" });
    try {
      const job = await waitFast(e.jobId, undefined, 24 * 3600);
      const plain = await k.decrypt(job.result.download, await apiBytes(`backup/jobs/${e.jobId}/download`));
      const sha = await sha256Hex(plain);
      const a = document.createElement("a");
      a.href = URL.createObjectURL(new Blob([plain as BlobPart], { type: "application/x-tar" }));
      a.download = job.result.download.file_name || `ediscovery-${e.id}.tar`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 10_000);
      await api(`backup/cases/${id}/exports/${e.id}/receipt`, { body: { sha256: sha, bytes: plain.length } });
      setState({ busy: `Saved ${a.download} (SHA-256 ${sha.slice(0, 16)}…, recorded with the case).` });
      reload();
    } catch (err) {
      setState({ err: (err as Error).message });
    }
  };
  return (
    <Modal title={`${c.name}${c.matter ? ` · ${c.matter}` : ""}`} onClose={onClose} wide
      footer={<>
        <button onClick={() => downloadFile(`backup/cases/${id}/manifest`, `case-${id.slice(0, 8)}-manifest.json`)}>Chain-of-custody manifest</button>
        {c.status === "open" && can("configure") && <button onClick={() => setEditing(true)}>Custodians…</button>}
        {c.status === "open" && can("configure") && <button className="danger" disabled={busy} onClick={() => run(() => api(`backup/cases/${id}/close`, { body: {} }), "Case closed: its holds are released").then(reload)}>Close case</button>}
      </>}>
      <p className="small"><Pill value={c.status} tone={c.status === "open" ? "warn" : undefined} /> {c.heldBackups} backups held · custodians: {c.custodians.map((x) => `${x.label}${x.accounts.length ? ` (${x.accounts.join(", ")})` : ""}`).join("; ")} · {c.holdNew ? "later backups held too" : "later backups not held"}</p>
      {c.description && <p className="small muted">{c.description}</p>}
      {c.status === "open" && <form className="row" style={{ gap: 8 }} onSubmit={(e) => { e.preventDefault(); if (query.trim()) search(); }}>
        <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Words, *.xlsx, a subject or a path" style={{ maxWidth: 360 }} />
        <button className="primary" disabled={busy || !query.trim()}>Search custodians</button>
      </form>}
      {last && <>
        <p className="small" style={{ marginTop: 8 }}>"{last.query}" by {last.by}, {fmtTime(last.at)}: {last.state === "done" ? `${hits.length} matches` : "running…"}{last.truncated ? " (first 5,000 kept: narrow the search)" : ""}{last.locked ? ` · ${last.locked} backups in locked repositories were not searched` : ""}</p>
        {hits.length > 0 && <div style={{ maxHeight: 280, overflowY: "auto" }}>
          <table className="table small" style={{ width: "100%" }}>
            <thead><tr><th /><th>Item</th><th>Where</th><th>Size</th></tr></thead>
            <tbody>{hits.map((h, i) => (
              <tr key={i}>
                <td><input type="checkbox" disabled={!!h.folder && !h.account} checked={selected.has(i)} onChange={() => { const s = new Set(selected); if (s.has(i)) s.delete(i); else s.add(i); setSelected(s); }} /></td>
                <td className={h.account ? "" : "mono"}>{h.path}</td>
                <td>{h.account ? `${h.kind} · ${h.account}` : h.image_id.slice(0, 8)}</td>
                <td>{h.size}</td>
              </tr>))}
            </tbody>
          </table>
        </div>}
        {c.status === "open" && <button className="primary" style={{ marginTop: 8 }} disabled={busy || selected.size === 0} onClick={exportSelected}>Export {selected.size || ""} selected</button>}
      </>}
      <h4 style={{ marginTop: 14 }}>Exports</h4>
      <Table rows={c.exports ?? []} empty="No exports yet." columns={[
        { key: "what", label: "What", render: (e) => <>{e.what} of {e.machine}<div className="small muted">{e.by}, {fmtTime(e.at)}</div></> },
        { key: "state", label: "State", render: (e) => <Pill value={e.state} tone={e.state === "succeeded" ? "good" : e.state === "failed" ? "bad" : "blue"} /> },
        { key: "manifestSha256", label: "Hashes", render: (e) => <span className="mono small">{e.manifestSha256 ? `manifest ${e.manifestSha256.slice(0, 12)}… (${e.manifestEntries} items)` : ""}{e.receipts?.length ? <div>saved {e.receipts[e.receipts.length - 1].sha256.slice(0, 12)}…</div> : null}</span> },
        { key: "id", label: "", render: (e) => (e.state === "succeeded" || e.state === "warning" || e.state === "queued" || e.state === "running") && keys.has(e.id) ? <button className="small" onClick={() => save(e)}>Download</button> : null }]} />
      {state.busy && <p role="status" className="small">{state.busy}</p>}
      {state.err && <ErrorNote error={state.err} />}
      {editing && <CaseEditor initial={c} onClose={() => { setEditing(false); reload(); }} />}
    </Modal>
  );
}
