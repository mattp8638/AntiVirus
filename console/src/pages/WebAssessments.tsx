// Safe web application assessment (VULN-08) of sites on attested external assets. Findings are confirmed (the response
// proves them) or suspected (a person should check); OWASP categories that were not tested are listed with the reason.
import { useState } from "react";
import { api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { PageHead, Pill, Table, useAction, useData } from "../components/ui";

const TONE: Record<string, string> = { confirmed: "bad", suspected: "warn", completed: "good", failed: "bad", queued: "blue", running: "blue" };

export default function WebAssessments() {
  const { tenantId } = useApp();
  const { run, busy } = useAction();
  const { data: assets } = useData<any[]>(tenantId ? "exposure/assets" : null, { tenant_id: tenantId || undefined }, [tenantId]);
  const { data: rows, reload } = useData<any[]>(tenantId ? "web-assessments" : null, { tenantId: tenantId || undefined }, [tenantId]);
  const [f, setF] = useState({ assetId: "", url: "", profile: "passive", authHeader: "", authValue: "" });
  const [open, setOpen] = useState<any>(null);
  return (
    <>
      <PageHead title="Web application assessment" subtitle="A safe assessment of a website on one of the customer's attested external assets: GET requests only, same host, robots.txt respected, limited pages and time. Nothing is attacked." />
      {!tenantId ? <div className="card empty">Choose a customer.</div> : <>
        <div className="card">
          <div className="form-grid">
            <label className="field">Asset<select value={f.assetId} onChange={(e) => { const a = (assets || []).find((x: any) => x.id === e.target.value); setF({ ...f, assetId: e.target.value, url: a ? `https://${a.target}/` : "" }); }}>
              <option value="">Choose…</option>{(assets || []).map((a: any) => <option key={a.id} value={a.id}>{a.label || a.target}</option>)}</select></label>
            <label className="field">Address<input value={f.url} onChange={(e) => setF({ ...f, url: e.target.value })} /></label>
            <label className="field">Profile<select value={f.profile} onChange={(e) => setF({ ...f, profile: e.target.value })}>
              <option value="passive">Passive: read only</option><option value="standard">Standard: plus harmless reflection and CORS probes</option></select></label>
            <label className="field">Sign-in header (optional)<select value={f.authHeader} onChange={(e) => setF({ ...f, authHeader: e.target.value })}>
              <option value="">None</option><option>Authorization</option><option>Cookie</option></select></label>
            {f.authHeader && <label className="field">Header value (kept encrypted until the run ends)<input type="password" value={f.authValue} onChange={(e) => setF({ ...f, authValue: e.target.value })} /></label>}
          </div>
          <button className="primary" disabled={busy || !f.assetId} onClick={() => run(() => api("web-assessments", { body: { tenantId, assetId: f.assetId, url: f.url, profile: f.profile,
            ...(f.authHeader ? { authHeader: f.authHeader, authValue: f.authValue } : {}) } }), "Queued: it starts within a minute").then(reload)}>Assess</button>
        </div>
        <Table rows={rows || []} empty="No assessments yet." onRow={(r: any) => setOpen(r)} columns={[
          { key: "url", label: "Address" }, { key: "profile", label: "Profile" },
          { key: "status", label: "Status", render: (r: any) => <Pill value={r.status} tone={TONE[r.status]} /> },
          { key: "summary", label: "Findings", render: (r: any) => r.summary?.pages != null ? `${r.summary.confirmed} confirmed, ${r.summary.suspected} suspected (${r.summary.pages} pages)` : r.error },
          { key: "createdAt", label: "Queued", render: (r: any) => fmtTime(r.createdAt) },
        ]} />
        {open && <div className="card">
          <div className="row"><h3 style={{ flex: 1, margin: 0 }}>{open.url}</h3><button className="link" onClick={() => setOpen(null)}>Close</button></div>
          <Table rows={open.findings} empty="No findings." columns={[
            { key: "status", label: "", render: (x: any) => <Pill value={x.status} tone={TONE[x.status]} /> },
            { key: "title", label: "Finding", render: (x: any) => <>{x.title}<div className="small muted">{x.owasp} {x.category} · {x.severity}</div></> },
            { key: "evidence", label: "Evidence", render: (x: any) => <span className="small">{x.request} → HTTP {x.responseStatus}: {x.evidence}</span> },
            { key: "advice", label: "Fix", render: (x: any) => <span className="small">{x.advice}</span> },
          ]} />
          <h4>Not tested</h4>{open.untested.map((u: any, i: number) => <div key={i} className="small">{u.owasp} {u.category}: {u.reason}</div>)}
        </div>}
      </>}
    </>
  );
}
