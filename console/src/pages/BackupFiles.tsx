// File-level restore: browse the files inside a backup image and restore chosen files or folders, without
// restoring the disk. The machine that reads the image decrypts it with the repository key it was given; this server
// only relays folder listings (kept a day) and never sees file contents.
import { useEffect, useMemo, useState } from "react";
import { api, apiBytes, ApiError } from "../api";
import { confirmDialog } from "../components/dialogs";
import { downloadKey } from "../backup-seal";
import { useApp } from "../app-context";
import { ErrorNote, Modal, Pill, useListData } from "../components/ui";
import { bytes, type BackupAgent } from "./Backups";

/** POST, and when the files asked for are infected (latest malware scan), ask before sending again with allowInfected. */
async function postAllowingInfected<T>(path: string, body: Record<string, unknown>): Promise<T> {
  try {
    return await api<T>(path, { body });
  } catch (e) {
    const d = e instanceof ApiError ? (e.detail as { code?: string; infected?: string[]; count?: number } | undefined) : undefined;
    if (d?.code !== "image_infected") throw e;
    const list = (d.infected ?? []).slice(0, 5).join("\n");
    if (!(await confirmDialog(`The latest malware scan found ${d.count} infected file${d.count === 1 ? "" : "s"} in what you chose:\n${list}${(d.count ?? 0) > 5 ? "\n…" : ""}\n\nRestore them anyway?`))) {
      throw new Error("Not restored: the files include malware found by the latest scan.");
    }
    return api<T>(path, { body: { ...body, allowInfected: true } });
  }
}

interface Volume { disk: number; partition: number; filesystem: string; size: number; mount_points: string[]; name: string; browsable: boolean; note?: string }
interface Entry { name: string; kind: "file" | "dir" | "link" | "other"; size: number; modified?: number; hidden: boolean }
interface Listing { path: string; entries: Entry[]; truncated: boolean; total: number }
interface Job { id: string; state: string; result: any; error: string | null; warnings: string[]; progress: any }
export interface BrowseImage { source?: string; imageId: string; repositoryId: string; agentId: string | null; hostname: string; vmName: string | null; created: number }

const FINAL = ["succeeded", "warning", "failed", "cancelled"];
const FS_LABEL: Record<string, string> = { ntfs: "NTFS", ext: "ext4", fat32: "FAT32", fat16: "FAT", exfat: "exFAT", xfs: "XFS", btrfs: "Btrfs", refs: "ReFS", bitlocker: "BitLocker", luks: "LUKS", swap: "swap" };

/** Poll a job quickly (browsing is interactive). */
async function waitFast(id: string, onProgress?: (j: Job) => void, seconds = 180): Promise<Job> {
  const until = Date.now() + seconds * 1000;
  while (Date.now() < until) {
    await new Promise((r) => setTimeout(r, 700));
    const j = await api<Job>(`backup/jobs/${id}`);
    if (FINAL.includes(j.state)) {
      if (j.state === "failed" || j.state === "cancelled") throw new Error(j.error || `the job was ${j.state}`);
      return j;
    }
    onProgress?.(j);
  }
  throw new Error("The machine did not answer in time. Is it online, or busy with another job (see Activity)?");
}

const volumeLabel = (v: Volume) => v.mount_points[0] || v.name || `Disk ${v.disk + 1}, partition ${v.partition}`;
const joinPath = (dir: string, name: string) => `${dir.replace(/\/+$/, "")}/${name}`;
const when = (t?: number) => (t ? new Date(t * 1000).toLocaleString() : "—");

export function FileBrowser({ image, onClose }: { image: BrowseImage; onClose: () => void }) {
  const [agentId, setAgentId] = useState<string | undefined>(undefined);
  const [agentName, setAgentName] = useState("");
  const [volumes, setVolumes] = useState<Volume[] | null>(null);
  const [volume, setVolume] = useState<Volume | null>(null);
  const [path, setPath] = useState("/");
  const [listing, setListing] = useState<Listing | null>(null);
  const [busy, setBusy] = useState<string | null>("Opening the backup…");
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [showHidden, setShowHidden] = useState(false);
  const [filter, setFilter] = useState("");
  const [restoring, setRestoring] = useState(false);

  const request = async (body: Record<string, unknown>, what: string) => {
    setBusy(what);
    setError(null);
    try {
      const r = await api<{ id: string; agentId: string; agentName: string; agentOnline: boolean }>(`backup/images/${image.imageId}/browse`, { body: { ...body, agentId } });
      setAgentId(r.agentId);
      setAgentName(r.agentName);
      if (!r.agentOnline) setBusy(`${what} ${r.agentName} is offline; waiting for it…`);
      return (await waitFast(r.id)).result;
    } catch (e) {
      setError((e as Error).message);
      return null;
    } finally {
      setBusy(null);
    }
  };

  const openVolume = async (v: Volume, p = "/") => {
    const res = await request({ disk: v.disk, partition: v.partition, path: p }, `Reading ${p === "/" ? volumeLabel(v) : p}…`);
    if (res?.listing) {
      setVolume(v);
      setPath(res.listing.path);
      setListing(res.listing);
      setFilter("");
    }
  };

  useEffect(() => {
    (async () => {
      const res = await request({}, "Opening the backup…");
      if (!res?.volumes) return;
      setVolumes(res.volumes);
      const usable = (res.volumes as Volume[]).filter((v) => v.browsable);
      // Straight into the obvious volume: the only one, or the system drive.
      const pick = usable.length === 1 ? usable[0] : usable.find((v) => v.mount_points.some((m) => /^c:\\?$/i.test(m)));
      if (pick) await openVolume(pick);
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const crumbs = path.split("/").filter(Boolean);
  const rows = (listing?.entries ?? []).filter((e) => (showHidden || !e.hidden) && (!filter || e.name.toLowerCase().includes(filter.toLowerCase())));
  const toggle = (p: string) => setSelected((s) => { const n = new Set(s); if (n.has(p)) n.delete(p); else n.add(p); return n; });
  const allHere = rows.filter((e) => e.kind === "file" || e.kind === "dir").map((e) => joinPath(path, e.name));
  const allSelected = allHere.length > 0 && allHere.every((p) => selected.has(p));

  return (
    <Modal wide title={`Files in ${image.vmName ?? image.hostname} · ${new Date(image.created * 1000).toLocaleString()}`} onClose={onClose}
      footer={volume && <>
        <span className="small muted" style={{ marginRight: "auto" }}>{selected.size ? `${selected.size} selected` : "Tick files or folders to restore them"}</span>
        {selected.size > 0 && <button onClick={() => setSelected(new Set())}>Clear</button>}
        <button className="primary" disabled={!selected.size} onClick={() => setRestoring(true)}>Restore {selected.size || ""} item{selected.size === 1 ? "" : "s"}…</button>
      </>}>
      <div className="small muted" style={{ marginBottom: 8 }}>
        Read from the encrypted backup by {agentName || "a machine with access"}; nothing on any disk is changed until you restore.
      </div>
      <ErrorNote error={error} />
      {busy && <div role="status" className="small" style={{ margin: "8px 0" }}>{busy}</div>}

      {volumes && (
        <div className="row" style={{ gap: 6, flexWrap: "wrap", marginBottom: 10 }}>
          {volumes.map((v) => (
            <button key={`${v.disk}-${v.partition}`} className={`small${volume === v ? " primary" : ""}`} disabled={!v.browsable || !!busy}
              title={v.note ?? ""} onClick={() => { setSelected(new Set()); openVolume(v); }}>
              {volumeLabel(v)} <span className="muted">{FS_LABEL[v.filesystem] ?? v.filesystem} · {bytes(v.size)}</span>
            </button>
          ))}
        </div>
      )}
      {volumes && !volume && !busy && (
        <div className="small muted">{volumes.some((v) => v.browsable) ? "Choose a volume." : "None of this image's volumes can be browsed. " + (volumes.find((v) => v.note)?.note ?? "")}</div>
      )}

      {volume && listing && (
        <>
          <div className="row" style={{ gap: 4, flexWrap: "wrap", marginBottom: 8 }}>
            <button className="small ghost" disabled={!!busy} onClick={() => openVolume(volume, "/")}>{volumeLabel(volume)}</button>
            {crumbs.map((c, i) => (
              <span key={i}>› <button className="small ghost" disabled={!!busy || i === crumbs.length - 1} onClick={() => openVolume(volume, "/" + crumbs.slice(0, i + 1).join("/"))}>{c}</button></span>
            ))}
            <span style={{ flex: 1 }} />
            <input className="small" placeholder="Filter this folder" value={filter} onChange={(e) => setFilter(e.target.value)} style={{ width: 180 }} />
            <label className="row small" style={{ gap: 4 }}><input type="checkbox" checked={showHidden} onChange={(e) => setShowHidden(e.target.checked)} /> Hidden and system</label>
          </div>
          <div className="table-wrap" style={{ maxHeight: 420, overflowY: "auto" }}>
            <table>
              <thead><tr>
                <th style={{ width: 28 }}><input type="checkbox" aria-label="Select all in this folder" checked={allSelected} onChange={() => setSelected((s) => { const n = new Set(s); allHere.forEach((p) => (allSelected ? n.delete(p) : n.add(p))); return n; })} /></th>
                <th>Name</th><th>Size</th><th>Modified</th>
              </tr></thead>
              <tbody>
                {path !== "/" && <tr className="clickable" onClick={() => !busy && openVolume(volume, "/" + crumbs.slice(0, -1).join("/"))}><td /><td>⬑ ..</td><td /><td /></tr>}
                {rows.map((e) => {
                  const full = joinPath(path, e.name);
                  const restorable = e.kind === "file" || e.kind === "dir";
                  return (
                    <tr key={e.name} className={e.kind === "dir" ? "clickable" : ""} onClick={() => e.kind === "dir" && !busy && openVolume(volume, full)}>
                      <td onClick={(ev) => ev.stopPropagation()}>{restorable && <input type="checkbox" aria-label={`Select ${e.name}`} checked={selected.has(full)} onChange={() => toggle(full)} />}</td>
                      <td style={{ opacity: e.hidden ? 0.6 : 1 }}>{e.kind === "dir" ? "📁" : e.kind === "link" ? "↪" : "📄"} {e.name}</td>
                      <td className="small">{e.kind === "dir" ? "" : bytes(e.size)}</td>
                      <td className="small">{when(e.modified)}</td>
                    </tr>
                  );
                })}
                {rows.length === 0 && <tr><td colSpan={4} className="empty">{filter ? "Nothing matches." : "Empty folder."}</td></tr>}
              </tbody>
            </table>
          </div>
          {listing.truncated && <div className="small muted">Showing the first {listing.entries.length} of {listing.total} entries; use the filter to find others.</div>}
        </>
      )}
      {restoring && volume && (
        <RestoreFiles image={image} volume={volume} paths={[...selected].sort()} browsingAgent={agentId}
          onClose={(done) => { setRestoring(false); if (done) setSelected(new Set()); }} />
      )}
    </Modal>
  );
}

function RestoreFiles({ image, volume, paths, browsingAgent, onClose }: { image: BrowseImage; volume: Volume; paths: string[]; browsingAgent?: string; onClose: (done: boolean) => void }) {
  const { can, tenantId } = useApp();
  const agents = useListData<BackupAgent>("backup/agents", { tenantId: tenantId || undefined }, [tenantId]);
  const repos = useListData<any>("backup/repositories", { tenantId: tenantId || undefined }, [tenantId]);
  const repo = repos.data?.find((r: any) => r.id === image.repositoryId);
  const pool = useMemo(() => (agents.data ?? []).filter((a) => repo?.agents.some((x: any) => x.id === a.id) && a.capabilities.includes("restore_files")), [agents.data, repo]);
  const [agentId, setAgentId] = useState<string>("");
  const agent = pool.find((a) => a.id === (agentId || image.agentId || browsingAgent)) ?? pool[0];
  // A backup of files and folders knows where each item was; a disk image's volume, its mount point.
  const folderBackup = image.source === "files";
  const original = folderBackup ? "@original" : volume.mount_points[0];
  // A VM's image belongs to its Hyper-V host's agent: its "original location" is inside the VM, not on the host.
  const sameMachine = agent && agent.id === image.agentId && !image.vmName;
  const [where, setWhere] = useState<"folder" | "original">("folder");
  const windows = agent?.os.family === "windows";
  const stamp = new Date(image.created * 1000).toISOString().slice(0, 10);
  const [folder, setFolder] = useState("");
  const defaultFolder = windows ? `C:\\Restored\\${stamp}` : `/var/tmp/restored/${stamp}`;
  const [keep, setKeep] = useState(true);
  const [conflict, setConflict] = useState<"rename" | "skip" | "overwrite">("rename");
  const [state, setState] = useState<{ busy?: boolean; job?: Job; err?: string; progress?: string }>({});
  const target = where === "original" ? original : folder.trim() || defaultFolder;

  const go = async () => {
    setState({ busy: true });
    try {
      const { id } = await postAllowingInfected<{ id: string }>(`backup/images/${image.imageId}/restore-files`, {
        agentId: agent!.id, disk: volume.disk, partition: volume.partition, paths, target,
        keepStructure: where === "original" ? true : keep, conflict });
      const job = await waitFast(id, (j) => setState({ busy: true, progress: j.progress?.message }), 24 * 3600);
      setState({ job });
    } catch (e) {
      setState({ err: (e as Error).message });
    }
  };
  // Download here: the machine encrypts the files for a one-time key made in this browser; the server only
  // relays ciphertext (up to 4 GiB, as a .tar).
  const download = async () => {
    setState({ busy: true, progress: "Preparing…" });
    try {
      const k = await downloadKey();
      const { id } = await postAllowingInfected<{ id: string }>(`backup/images/${image.imageId}/download-files`, {
        agentId: agent!.id, disk: volume.disk, partition: volume.partition, paths, recipient: k.publicB64 });
      const job = await waitFast(id, (j) => setState({ busy: true, progress: j.progress?.message }), 24 * 3600);
      if (job.state !== "succeeded" && job.state !== "warning") throw new Error(job.error || "the machine could not prepare the files");
      const header = job.result?.download;
      if (!header?.sealed_key) throw new Error("the machine did not send a download");
      setState({ busy: true, progress: "Downloading and decrypting…" });
      const plain = await k.decrypt(header, await apiBytes(`backup/jobs/${id}/download`));
      const a = document.createElement("a");
      a.href = URL.createObjectURL(new Blob([plain as BlobPart], { type: "application/x-tar" }));
      a.download = header.file_name || "restore.tar";
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 10_000);
      setState({ progress: `Downloaded ${a.download}.` });
    } catch (e) {
      setState({ err: (e as Error).message });
    }
  };
  const r = state.job?.result;
  return (
    <Modal title={`Restore ${paths.length} item${paths.length === 1 ? "" : "s"}`} onClose={() => onClose(!!state.job)}
      footer={state.job ? <button className="primary" onClick={() => onClose(true)}>Done</button>
        : <>
          <button disabled={!agent || state.busy} onClick={download} title="The machine encrypts the files for this browser; the server only relays them (up to 4 GiB, as a .tar)">Download here</button>
          <button className={conflict === "overwrite" ? "danger" : "primary"} disabled={!agent || state.busy || !target} onClick={go}>{state.busy ? "Working…" : "Restore"}</button>
        </>}>
      <div className="small mono" style={{ maxHeight: 90, overflowY: "auto", marginBottom: 10 }}>{paths.map((p) => <div key={p}>{p}</div>)}</div>
      {!state.job && <>
        <div className="form-grid">
          <label className="field">Restore on
            <select value={agent?.id ?? ""} onChange={(e) => { setAgentId(e.target.value); setWhere("folder"); }}>
              {pool.length === 0 && <option value="">No machine with access can restore files</option>}
              {pool.map((a) => <option key={a.id} value={a.id}>{a.name}{a.id === image.agentId ? " (where the backup came from)" : ""}{a.online ? "" : " (offline)"}</option>)}
            </select>
          </label>
          <label className="field">To
            <select value={where} onChange={(e) => setWhere(e.target.value as any)}>
              <option value="folder">A folder</option>
              {original && sameMachine && <option value="original">{folderBackup ? "Where each item was" : `Original location (${original})`}</option>}
            </select>
          </label>
          {where === "folder" && <label className="field">Folder on {agent?.name ?? "the machine"}<input value={folder} placeholder={defaultFolder} onChange={(e) => setFolder(e.target.value)} /></label>}
          <label className="field">If a file already exists
            <select value={conflict} onChange={(e) => setConflict(e.target.value as any)}>
              <option value="rename">Keep both (restored copy gets “(restored)”)</option>
              <option value="skip">Skip it</option>
              {can("destructive") && <option value="overwrite">Replace it with the backup copy</option>}
            </select>
          </label>
        </div>
        {where === "folder" && <label className="row small" style={{ gap: 6, marginTop: 8 }}><input type="checkbox" checked={keep} onChange={(e) => setKeep(e.target.checked)} /> Recreate the original folders inside it (e.g. …\Users\anna\Documents\report.docx)</label>}
        {where === "original" && <p className="small muted">Each item goes back to the folder it was in. {conflict === "rename" ? "Files that exist now are kept; the backup copy is written next to them." : conflict === "skip" ? "Files that exist now are left alone." : "Files that exist now are replaced. You will be asked for your password."}</p>}
      </>}
      {(state.busy || state.progress) && <p role="status" className="small">{state.progress || `Waiting for ${agent?.name}…`}</p>}
      {state.err && <ErrorNote error={state.err} />}
      {state.job && r && (
        <div className="stack">
          <p><Pill value={state.job.state} tone={state.job.state === "succeeded" ? "good" : "warn"} /> {r.files} file{r.files === 1 ? "" : "s"} ({bytes(r.bytes)}) restored to <span className="mono">{r.target}</span> on {agent?.name}.
            {r.renamed > 0 && ` ${r.renamed} written beside an existing file.`}{r.skipped > 0 && ` ${r.skipped} skipped (already there).`}</p>
          {r.failed_total > 0 && <div className="small">
            <b>{r.failed_total} could not be restored:</b>
            {r.failed.map((f: any, i: number) => <div key={i}><span className="mono">{f.path}</span>: {f.error}</div>)}
          </div>}
        </div>
      )}
    </Modal>
  );
}
