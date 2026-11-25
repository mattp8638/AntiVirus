// Attack paths (VULN-19): from the internet to the customer's critical systems, from the evidence Fenrir holds.
// Each step is observed (seen in data) or inferred (deduced); nothing is exploited.
import { useState } from "react";
import { api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { PageHead, Pill, useAction, useData } from "../components/ui";

export default function AttackPaths() {
  const { tenantId } = useApp();
  const { run, busy } = useAction();
  const { data, error, reload } = useData<any>(tenantId ? "attack-paths/latest" : null, { tenantId }, [tenantId]);
  const [open, setOpen] = useState<string | null>(null);
  return (
    <>
      <PageHead title="Attack paths" subtitle="How an attacker could get from the internet to what matters most: exposed services, devices with exploitable vulnerabilities, movement within a site or subnet, and administrators without MFA. This is analysis of Fenrir's records, not a test that was carried out."
        actions={tenantId && <button className="primary" disabled={busy} onClick={() => run(() => api("attack-paths/analyse", { body: { tenantId } }), "Analysed").then(reload)}>Analyse now</button>} />
      {!tenantId && <div className="card empty">Choose a customer.</div>}
      {tenantId && error && !data && <div className="card empty">Not analysed yet.</div>}
      {data && <>
        <p className="small muted">Analysed {fmtTime(data.createdAt)} · {data.inputs.devices} devices, {data.inputs.exposures} exposed services, {data.inputs.footholds} devices with exploitable weaknesses, {data.inputs.criticalTargets} critical targets.
          {data.new.length > 0 && <> <Pill value={`${data.new.length} new`} tone="bad" /></>}{data.resolved.length > 0 && <> <Pill value={`${data.resolved.length} resolved`} tone="good" /></>}</p>
        {data.paths.length === 0 && <div className="card empty">No path from the internet to a critical system was found in the current data.</div>}
        {data.paths.map((p: any) => (
          <div key={p.id} className="card" style={{ cursor: "pointer" }} onClick={() => setOpen(open === p.id ? null : p.id)}>
            <div className="row" style={{ gap: 8, flexWrap: "wrap" }}><b>{p.target}</b>{data.new.includes(p.id) && <Pill value="new" tone="bad" />}<span className="small muted">{p.observed} observed, {p.inferred} inferred step(s) · score {p.score}</span></div>
            <div className="small">{p.hops.join(" → ")}</div>
            {p.foothold.length > 0 && <div className="small muted">Foothold: {p.foothold.join("; ")}</div>}
            {open === p.id && p.steps.map((s: any, i: number) => <div key={i} className="small" style={{ marginTop: 4 }}><Pill value={s.kind} tone={s.kind === "observed" ? "warn" : "blue"} /> {s.from} → {s.to}: {s.evidence}</div>)}
          </div>
        ))}
        {data.resolved.length > 0 && <div className="card"><h3>Resolved since the previous analysis</h3>{data.resolved.map((r: any) => <div key={r.id} className="small">{r.hops.join(" → ")}</div>)}</div>}
      </>}
    </>
  );
}
