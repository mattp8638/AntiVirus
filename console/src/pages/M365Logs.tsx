import { displayValue } from "../components/DisplayValue";
import { useState } from "react";
import { api, fmtTime } from "../api";
import { ErrorNote, Modal, Pill, Table, useAction, useData } from "../components/ui";

const KINDS: Record<string, string> = { signin: "Sign-ins", audit: "Directory changes" };
const PAGE = 200;

function csv(rows: any[], kind: string): string {
  const head = ["Time", kind === "signin" ? "User" : "Changed by", "App or service", "IP", "Location", "Result", kind === "signin" ? "Reason" : "Activity", "Target"];
  const cell = (v: any) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  return [head.join(","), ...rows.map((r) => [r.at, r.actor, r.app, r.ip, r.location, r.result, r.activity, r.target].map(cell).join(","))].join("\n");
}

function download(name: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/csv" }));
  const a = document.createElement("a");
  a.href = url; a.download = name; a.click();
  URL.revokeObjectURL(url);
}

/** The sign-in and audit records Fenrir has copied from Microsoft, kept beyond Microsoft's own 7 to 30 days. */
export function M365Logs({ connection, onCollected }: { connection: any; onCollected: () => void }) {
  const [kind, setKind] = useState("signin");
  const [q, setQ] = useState("");
  const [result, setResult] = useState("");
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");
  const [offset, setOffset] = useState(0);
  const [open, setOpen] = useState<any>(null);
  const { run, busy } = useAction();
  const base = `m365/connections/${connection.id}/logs`;
  const filters = { kind, q, result, since: since ? new Date(since).toISOString() : undefined, until: until ? new Date(until).toISOString() : undefined };
  const { data, error, reload } = useData<any>(base, { ...filters, limit: PAGE, offset });
  const state = connection.logState?.[kind] || {};
  const counts = connection.logCounts || {};
  const exportAll = async () => {
    const all = await run(() => api<any>(base, { query: { ...filters, limit: 5000, offset: 0 } }));
    if (all) download(`${connection.name}-${kind}-log.csv`.replace(/[^\w.-]+/g, "_"), csv(all.rows || [], kind));
  };
  return <>
    <p>Fenrir copies these from Microsoft every hour and keeps them (Microsoft itself keeps 7 days without Entra ID P1, 30 with it).
      {counts.oldest && <> Stored since {fmtTime(counts.oldest)}: {counts.stored?.signin ?? 0} sign-ins, {counts.stored?.audit ?? 0} directory changes.</>}</p>
    {state.available === false && <p style={{ color: "#fcd34d" }}>{displayValue(state.error || "Microsoft does not provide this log for this tenant.")}</p>}
    {state.available !== false && state.error && <p className="small" style={{ color: "#fcd34d" }}>Last collection: {displayValue(state.error)}</p>}
    {state.gaps?.length > 0 && <p className="small muted">Still catching up on older records; this finishes over the next few hours.</p>}
    <div className="row" style={{ gap: 8, flexWrap: "wrap", alignItems: "flex-end" }}>
      <label className="field">Log<select value={kind} onChange={(e) => { setKind(e.target.value); setResult(""); setOffset(0); }}>
        {Object.entries(KINDS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
      <label className="field">Search<input value={q} onChange={(e) => { setQ(e.target.value); setOffset(0); }} placeholder="User, app, IP, place, activity" /></label>
      <label className="field">Result<select value={result} onChange={(e) => { setResult(e.target.value); setOffset(0); }}>
        <option value="">Any</option><option value="success">Success</option><option value="failure">Failure</option>
        {kind === "signin" && <option value="interrupted">Interrupted (MFA asked)</option>}</select></label>
      <label className="field">From<input type="datetime-local" value={since} onChange={(e) => { setSince(e.target.value); setOffset(0); }} /></label>
      <label className="field">To<input type="datetime-local" value={until} onChange={(e) => { setUntil(e.target.value); setOffset(0); }} /></label>
      <button disabled={busy} onClick={exportAll}>Export CSV</button>
      <button disabled={busy} onClick={async () => {
        const out = await run(() => api<any>(`m365/connections/${connection.id}/logs/collect`, { method: "POST" }));
        if (out) { reload(); onCollected(); }
      }}>Collect now</button>
    </div>
    <p className="small muted">{state.lastRunAt ? `Last collected ${fmtTime(state.lastRunAt)}` : "Not collected yet: the first hourly run, or Collect now, fetches the last 30 days."}</p>
    <ErrorNote error={error} />
    <Table rows={data?.rows} onRow={setOpen} empty="No records match." columns={[
      { key: "at", label: "Time", render: (r: any) => fmtTime(r.at) },
      { key: "actor", label: kind === "signin" ? "User" : "Changed by" },
      { key: "app", label: kind === "signin" ? "App" : "Service" },
      ...(kind === "signin" ? [{ key: "location", label: "Where", render: (r: any) => <>{displayValue(r.location)}<div className="small muted mono">{displayValue(r.ip)}</div></> }] : []),
      { key: "result", label: "Result", render: (r: any) => <Pill value={r.result} tone={r.result === "success" ? "good" : r.result === "failure" ? "bad" : "warn"} /> },
      { key: "activity", label: kind === "signin" ? "Reason" : "Activity" },
      { key: "target", label: kind === "signin" ? "Resource" : "Target" },
    ]} />
    {data && <div className="row" style={{ gap: 8, marginTop: 8 }}>
      <span className="small muted">{data.total} records{data.total > PAGE ? ` · showing ${offset + 1}–${Math.min(offset + PAGE, data.total)}` : ""}</span>
      <button className="small" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>Newer</button>
      <button className="small" disabled={offset + PAGE >= data.total} onClick={() => setOffset(offset + PAGE)}>Older</button>
    </div>}
    {open && <Modal title={`${KINDS[kind]} · ${fmtTime(open.at)}`} onClose={() => setOpen(null)}>
      <p><b>{displayValue(open.actor)}</b> · {displayValue(open.app)} · {displayValue(open.result)}</p>
      {open.activity && <p>{displayValue(open.activity)}</p>}
      <pre className="mono small" style={{ whiteSpace: "pre-wrap" }}>{JSON.stringify(open.details, null, 2)}</pre>
    </Modal>}
  </>;
}
