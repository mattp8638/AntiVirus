// Server and workload protection (AV-21): file integrity monitoring and container runtime posture on Linux and macOS.
import { useEffect, useState } from "react";
import { api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { PageHead, Pill, Table, useAction, useData } from "../components/ui";

export default function WorkloadProtection() {
  const { tenantId } = useApp();
  const { run, busy } = useAction();
  const { data: conf, reload: reloadConf } = useData<any>(tenantId ? `workload/settings/${tenantId}` : null, undefined, [tenantId]);
  const { data: devices } = useData<any[]>(tenantId ? "devices" : null, { tenant_id: tenantId || undefined }, [tenantId]);
  const [f, setF] = useState({ fim: false, containers: false, paths: "" });
  const [device, setDevice] = useState<string>("");
  const { data: state, reload } = useData<any>(device ? `workload/devices/${device}` : null, undefined, [device]);
  useEffect(() => { if (conf) setF({ fim: !!conf.fim, containers: !!conf.containers, paths: (conf.paths || []).join("\n") }); }, [conf]);
  const servers = (devices || []).filter((d: any) => d.platform === "linux" || d.platform === "macos");
  return (
    <>
      <PageHead title="Workload protection" subtitle="File integrity monitoring of system files and the runtime settings of containers, on Linux and macOS. The baseline is kept in Fenrir, not on the device." />
      {!tenantId ? <div className="card empty">Choose a customer.</div> : <>
        <div className="card"><div className="form-grid">
          <label className="field"><span><input type="checkbox" checked={f.fim} onChange={(e) => setF({ ...f, fim: e.target.checked })} /> Daily file integrity scans</span></label>
          <label className="field"><span><input type="checkbox" checked={f.containers} onChange={(e) => setF({ ...f, containers: e.target.checked })} /> Daily container inventory</span></label>
          <label className="field">Watched paths (one per line; empty = Fenrir's defaults)<textarea value={f.paths} onChange={(e) => setF({ ...f, paths: e.target.value })} /></label>
        </div><button className="primary" disabled={busy} onClick={() => run(() => api(`workload/settings/${tenantId}`, { method: "PUT", body: { fim: f.fim, containers: f.containers,
          paths: f.paths.split("\n").map((x) => x.trim()).filter(Boolean) } }), "Saved").then(reloadConf)}>Save</button></div>
        <div className="row" style={{ gap: 8 }}><select value={device} onChange={(e) => setDevice(e.target.value)}><option value="">Choose a Linux or macOS device…</option>
          {servers.map((d: any) => <option key={d.id} value={d.id}>{d.hostname}</option>)}</select>
          {device && <><button disabled={busy} onClick={() => run(() => api(`workload/devices/${device}/scan`, { body: { kind: "fim" } }), "Scan requested")}>Scan files</button>
            <button disabled={busy} onClick={() => run(() => api(`workload/devices/${device}/scan`, { body: { kind: "containers" } }), "Inventory requested")}>List containers</button>
            {state?.baseline && <button disabled={busy} onClick={() => run(() => api(`workload/devices/${device}/accept-baseline`, { method: "POST" }), "Baseline accepted").then(reload)}>Accept latest scan as baseline</button>}</>}</div>
        {state && <>
          <p className="small muted">{state.baseline ? `Baseline of ${state.baseline.files} files set ${fmtTime(state.baseline.setAt)} by ${state.baseline.setBy}.` : "No baseline yet: the first scan becomes it."}</p>
          <Table rows={state.reports} empty="No scans yet." columns={[
            { key: "createdAt", label: "When", render: (r: any) => fmtTime(r.createdAt) },
            { key: "kind", label: "Kind", render: (r: any) => (r.kind === "fim" ? "File integrity" : `Containers (${r.data.runtime || "no runtime"})`) },
            { key: "findings", label: "Found", render: (r: any) => <span className="small">{r.findings.length === 0 ? "nothing" : r.findings.map((x: any, i: number) => (
              <div key={i}>{x.change === "baseline" ? `baseline of ${x.files} files` : x.path ? <><Pill value={x.change} tone={x.change === "changed" ? "warn" : "bad"} /> {x.path}</> :
                <>{x.container} ({x.image}): {x.risks.join(", ")}</>}</div>))}</span> },
          ]} />
        </>}
      </>}
    </>
  );
}
