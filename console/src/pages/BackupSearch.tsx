// Search across a machine's backups: one job per repository runs on a machine with access, over the file catalogues
// it keeps for each backup. Only the matches come back here (and are dropped from the server after a day).
import { Fragment, useMemo, useState } from "react";
import { api } from "../api";
import { ErrorNote } from "../components/ui";
import { bytes } from "./Backups";
import { waitFast, type BrowseStart } from "./BackupFiles";

interface SearchJob { id: string; repositoryId: string; agentName: string; agentOnline: boolean; images: number }
interface Hit {
  image_id: string; volume?: { label: string; disk: number; partition: number } | null; path: string; size: number;
  modified?: number | null; folder: boolean;
  /** Cloud-service backups: the mailbox, drive, site or org, and what the item is. */
  account?: string; kind?: string;
}
const KIND_LABEL: Record<string, string> = { mail: "Mail", file: "File", "site-file": "SharePoint", record: "Record", "teams-message": "Teams", directory: "Entra ID" };
interface ImageRef { imageId: string; created: number }

const when = (t?: number | null) => (t ? new Date(t * 1000).toLocaleString() : "—");

/** Matches grouped by item (volume and path), each with the backups that hold it, newest first. */
function group(hits: Hit[], created: Map<string, number>) {
  const m = new Map<string, { key: string; volume: Hit["volume"]; path: string; folder: boolean; account?: string; kind?: string; versions: Hit[] }>();
  for (const h of hits) {
    const key = `${h.account ? `${h.kind}:${h.account}` : h.volume?.label}|${h.path.toLowerCase()}`;
    const g = m.get(key) ?? { key, volume: h.volume, path: h.path, folder: h.folder, account: h.account, kind: h.kind, versions: [] };
    g.versions.push(h);
    m.set(key, g);
  }
  const out = [...m.values()];
  for (const g of out) g.versions.sort((a, b) => (created.get(b.image_id) ?? 0) - (created.get(a.image_id) ?? 0));
  return out.sort((a, b) => a.path.localeCompare(b.path));
}

export function SearchBackups({ device, images, onOpen }: {
  device: string; images: ImageRef[]; onOpen: (imageId: string, start: BrowseStart) => void;
}) {
  const [query, setQuery] = useState("");
  const [state, setState] = useState<{ busy?: string; err?: string; hits?: Hit[]; notIndexed?: number; truncated?: boolean; searched?: number }>({});
  const [open, setOpen] = useState<string | null>(null);
  const created = useMemo(() => new Map(images.map((i) => [i.imageId, i.created])), [images]);

  const go = async () => {
    const q = query.trim();
    if (!q) return;
    setState({ busy: "Searching…" });
    setOpen(null);
    try {
      const { jobs } = await api<{ jobs: SearchJob[] }>("backup/search", { body: { query: q, device } });
      const offline = jobs.filter((j) => !j.agentOnline).map((j) => j.agentName);
      setState({ busy: offline.length ? `Waiting for ${offline.join(", ")} (offline)…` : `Searching ${jobs.reduce((n, j) => n + j.images, 0)} backups…` });
      const results = await Promise.all(jobs.map((j) => waitFast(j.id, (p) => setState((s) => ({ ...s, busy: p.progress?.message ? `Searching… ${p.progress.message}` : s.busy })), 600)));
      const hits = results.flatMap((r) => (r.result?.hits ?? []) as Hit[]);
      setState({
        hits,
        searched: results.reduce((n, r) => n + (r.result?.searched ?? 0), 0),
        notIndexed: results.reduce((n, r) => n + (r.result?.not_indexed?.length ?? 0), 0),
        truncated: results.some((r) => r.result?.truncated),
      });
    } catch (e) {
      setState({ err: (e as Error).message });
    }
  };

  const groups = state.hits ? group(state.hits, created) : null;
  const parent = (p: string) => p.replace(/\/[^/]*$/, "") || "/";
  return (
    <div className="card" style={{ marginBottom: 10 }}>
      <form className="row" style={{ gap: 8 }} onSubmit={(e) => { e.preventDefault(); go(); }}>
        <label htmlFor="backup-search" className="small">Find a file in these backups</label>
        <input id="backup-search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="budget 2026, *.xlsx or Documents/report" style={{ maxWidth: 320 }} />
        <button className="primary" disabled={!!state.busy || !query.trim()}>Search</button>
        {state.busy && <span role="status" className="small muted">{state.busy}</span>}
      </form>
      <p className="small muted" style={{ margin: "6px 0 0" }}>Words match file and folder names in any order; * and ? are wildcards; include a / to match the path. The search runs on a machine with access to the backups: only the matches come back, and they are not kept after a day.</p>
      {state.err && <ErrorNote error={state.err} />}
      {groups && <>
        <p className="small" style={{ marginTop: 8 }}>
          {groups.length === 0 ? "Nothing found" : `${groups.length} item${groups.length === 1 ? "" : "s"} found`} in {state.searched} backup{state.searched === 1 ? "" : "s"}.
          {state.truncated && " Only the first 500 matches are shown: make the search more specific."}
          {!!state.notIndexed && ` ${state.notIndexed} older backup${state.notIndexed === 1 ? " is" : "s are"} not indexed yet; search again to include ${state.notIndexed === 1 ? "it" : "them"}.`}
        </p>
        {groups.length > 0 && <table className="table" style={{ width: "100%" }}>
          <thead><tr><th scope="col">Item</th><th scope="col">In backups</th><th scope="col">Newest</th><th scope="col"></th></tr></thead>
          <tbody>
            {groups.map((g) => <Fragment key={g.key}>
              <tr>
                <td>{g.account ? <><span className="small">{g.path}</span><div className="small muted">{KIND_LABEL[g.kind ?? ""] ?? g.kind} · {g.account}</div></> : <span className="mono small">{g.volume?.label} {g.path}</span>}{g.folder && <span className="small muted"> (folder)</span>}</td>
                <td>{g.versions.length}</td>
                <td className="small">{when(created.get(g.versions[0].image_id))}{!g.folder && ` · ${bytes(g.versions[0].size)}`}</td>
                <td><div className="row" style={{ gap: 4 }}>
                  {g.account ? <span className="small muted">Restore it from Apps and clusters</span> : g.volume && <button className="small primary" onClick={() => onOpen(g.versions[0].image_id, { disk: g.volume!.disk, partition: g.volume!.partition, folder: g.folder ? g.path : parent(g.path), select: g.folder ? undefined : g.path })}>Open newest</button>}
                  {g.versions.length > 1 && <button className="small" aria-expanded={open === g.key} onClick={() => setOpen(open === g.key ? null : g.key)}>{open === g.key ? "Hide versions" : "All versions"}</button>}
                </div></td>
              </tr>
              {open === g.key && g.versions.map((v) => (
                <tr key={`${g.key}|${v.image_id}`} className="small">
                  <td style={{ paddingLeft: 24 }}>Backup of {when(created.get(v.image_id))}</td>
                  <td>{g.folder ? "" : bytes(v.size)}</td>
                  <td>{v.modified ? `changed ${when(v.modified)}` : ""}</td>
                  <td>{v.volume && <button className="small" onClick={() => onOpen(v.image_id, { disk: v.volume!.disk, partition: v.volume!.partition, folder: g.folder ? g.path : parent(g.path), select: g.folder ? undefined : g.path })}>Open</button>}</td>
                </tr>
              ))}
            </Fragment>)}
          </tbody>
        </table>}
      </>}
    </div>
  );
}
