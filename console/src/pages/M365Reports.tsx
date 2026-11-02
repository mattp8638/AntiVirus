import { displayValue } from "../components/DisplayValue";
import { useEffect, useState } from "react";
import { api, getToken } from "../api";
import { useApp } from "../app-context";
import { ErrorNote, Table, useAction, useData } from "../components/ui";

// Microsoft 365 reports for one connection, read live from Microsoft, with CSV download and emailed schedules.
export default function M365Reports({ connection }: { connection: any }) {
  const { can } = useApp();
  const { data: catalogue } = useData<any[]>("m365/reports", {}, [], true);
  const [key, setKey] = useState("licences");
  const { data, error, reload } = useData<any>(`m365/connections/${connection.id}/reports/${key}`, {}, [key]);
  const download = async () => {
    const response = await fetch(`/api/console/m365/connections/${connection.id}/reports/${key}/csv`, { headers: { Authorization: `Bearer ${getToken()}` } });
    if (!response.ok) return;
    const url = URL.createObjectURL(await response.blob());
    const link = document.createElement("a");
    link.href = url; link.download = `${key}.csv`; link.click();
    URL.revokeObjectURL(url);
  };
  return (
    <div className="grid" style={{ gap: 14 }}>
      <div className="card">
        <div className="row" style={{ gap: 8, flexWrap: "wrap", marginBottom: 8 }}>
          <select value={key} onChange={(e) => setKey(e.target.value)}>
            {(catalogue || []).map((r) => <option key={r.key} value={r.key}>{r.title}</option>)}
          </select>
          <button className="small" onClick={reload}>Refresh</button>
          <button className="small" disabled={!data} onClick={download}>Download CSV</button>
          {data && <span className="small muted">{displayValue(data.summary)}</span>}
        </div>
        <ErrorNote error={error} />
        {data && <div className="table-wrap"><Table rows={data.rows.map((r: any, i: number) => ({ ...r, id: String(i) }))} empty="Nothing to report."
          columns={data.columns.map((c: string) => ({ key: c, label: c.replace(/([A-Z])/g, " $1").toLowerCase(),
            render: (r: any) => typeof r[c] === "boolean" ? (r[c] ? "yes" : "no") : displayValue(r[c]) }))} /></div>}
      </div>
      {can("m365_admin") && <Schedules tenantId={connection.tenantId} catalogue={catalogue || []} />}
    </div>
  );
}

function Schedules({ tenantId, catalogue }: { tenantId: string; catalogue: any[] }) {
  const { data, reload } = useData<any>("m365/report-schedules", { tenant_id: tenantId }, [tenantId]);
  const { run, busy } = useAction();
  const [rows, setRows] = useState<any[]>([]);
  useEffect(() => { if (data) setRows(data.schedules.map((s: any) => ({ ...s, toText: (s.to || []).join(", ") }))); }, [data]);
  const save = async () => {
    const schedules = rows.map((s) => ({ reports: s.reports, every: s.every, to: String(s.toText).split(/[,\s]+/).filter(Boolean) }));
    if (await run(() => api("m365/report-schedules", { method: "PUT", body: { tenantId, schedules } }), "Schedules saved")) reload();
  };
  const update = (i: number, patch: any) => setRows(rows.map((r, j) => j === i ? { ...r, ...patch } : r));
  return (
    <div className="card">
      <h3 style={{ marginTop: 0 }}>Emailed reports</h3>
      <p className="small muted">Fenrir emails the chosen reports as CSV files, with a summary, weekly or monthly.</p>
      {rows.map((s, i) => (
        <div key={i} className="card" style={{ marginBottom: 8 }}>
          <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
            {catalogue.map((r) => <label key={r.key} className="small"><input type="checkbox" checked={s.reports.includes(r.key)}
              onChange={(e) => update(i, { reports: e.target.checked ? [...s.reports, r.key] : s.reports.filter((k: string) => k !== r.key) })} /> {r.title}</label>)}
          </div>
          <div className="row" style={{ gap: 6, marginTop: 6 }}>
            <select value={s.every} onChange={(e) => update(i, { every: e.target.value })}><option value="weekly">Weekly</option><option value="monthly">Monthly</option></select>
            <input style={{ flex: 1 }} placeholder="Send to (emails)" value={s.toText} onChange={(e) => update(i, { toText: e.target.value })} />
            <button className="small danger" onClick={() => setRows(rows.filter((_, j) => j !== i))}>Remove</button>
          </div>
          {s.lastSentAt && <div className="small muted">Last sent {displayValue(s.lastSentAt)}</div>}
        </div>
      ))}
      <div className="row" style={{ gap: 6 }}>
        <button className="small" onClick={() => setRows([...rows, { reports: ["licences", "mfa"], every: "monthly", toText: "" }])}>Add a schedule</button>
        <button className="primary" disabled={busy || rows.some((s) => !s.reports.length || !String(s.toText).trim())} onClick={save}>Save</button>
      </div>
    </div>
  );
}
