// Client 360: one health score for a customer from every module, its trend, and the reports built from the same data.
import { useState } from "react";
import { Link } from "react-router-dom";
import { api, fmtTime, getToken } from "../api";
import { useApp } from "../app-context";
import { displayValue } from "./DisplayValue";
import { Sparkline } from "./rmm";
import { ErrorNote, Pill, Table, useAction, useData, useListData } from "./ui";

interface Part { key: string; label: string; score: number | null; status: string; value: string; detail: string; link: string; weight: number; renewalSoon?: boolean }
interface Health { score: number | null; status: string; parts: Part[]; measured: number; of: number; trend: { at: string; score: number | null }[] }

const TONE: Record<string, string> = { good: "good", warn: "warn", bad: "bad", none: "muted" };
const COLOUR: Record<string, string> = { good: "#22c55e", warn: "#f59e0b", bad: "#ef4444", none: "#6b7280" };

export function HealthBadge({ score }: { score: number | null | undefined }) {
  if (score === null || score === undefined) return <span className="small muted">—</span>;
  const status = score >= 80 ? "good" : score >= 60 ? "warn" : "bad";
  return <Pill value={`${Math.round(score)}`} tone={TONE[status]} />;
}

async function openReport(path: string) {
  const response = await fetch(`/api/console/${path}`, { headers: { Authorization: `Bearer ${getToken()}` } });
  if (!response.ok) throw new Error(`Report failed (${response.status})`);
  const url = URL.createObjectURL(new Blob([await response.text()], { type: "text/html" }));
  window.open(url, "_blank", "noopener");
}

export function ClientHealth({ tenantId }: { tenantId: string }) {
  const { can, setTenantId } = useApp();
  const { data, error } = useData<Health>(`clients/${tenantId}/health`, {}, [tenantId]);
  const { data: reports, reload } = useListData<any>(`clients/${tenantId}/reports`, {}, [tenantId]);
  const { run, busy } = useAction();
  const [quarter, setQuarter] = useState("");
  if (error) return <ErrorNote error={error} />;
  if (!data) return <div className="empty">Working out health…</div>;
  const trend = data.trend.filter((t) => t.score !== null).map((t) => t.score as number);
  const keep = async (kind: string) => {
    if (await run(() => api(`clients/${tenantId}/reports`, { body: { kind, period: kind === "quarterly" ? quarter || undefined : undefined } }), "Report saved")) reload();
  };
  return (
    <>
      <div className="row" style={{ gap: 24, alignItems: "center", flexWrap: "wrap", marginBottom: 12 }}>
        <div>
          <div className="small muted">Health</div>
          <div style={{ fontSize: 48, fontWeight: 700, color: COLOUR[data.status] }}>{data.score ?? "—"}<span className="small muted"> / 100</span></div>
          <div className="small muted">from {data.measured} of {data.of} areas</div>
        </div>
        <div style={{ flex: 1, minWidth: 220 }}>
          <div className="small muted">Last year</div>
          {trend.length > 1 ? <Sparkline points={trend} color={COLOUR[data.status]} height={56} /> : <p className="small muted">The trend fills in as daily scores are kept.</p>}
        </div>
        <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
          <button onClick={() => run(() => openReport(`clients/${tenantId}/reports/monthly.html`))}>Last month: what we did</button>
          <select value={quarter} onChange={(e) => setQuarter(e.target.value)} aria-label="Quarter">
            <option value="">Last quarter</option>
            {recentQuarters().map((q) => <option key={q} value={q}>{q.replace("-", " ")}</option>)}
          </select>
          <button className="primary" onClick={() => run(() => openReport(`clients/${tenantId}/reports/quarterly.html${quarter ? `?quarter=${quarter}` : ""}`))}>Quarterly review</button>
          {(can("crm") || can("respond")) && <button className="ghost" disabled={busy} onClick={() => keep("quarterly")} title="Keep a copy of the quarterly review as sent">Save review</button>}
        </div>
      </div>
      <div className="grid k3">
        {data.parts.map((p) => (
          <div key={p.key} className="card" style={{ borderLeft: `4px solid ${COLOUR[p.status]}` }}>
            <div className="row" style={{ justifyContent: "space-between" }}>
              <b>{p.label}</b>{p.score === null ? <Pill value="not set up" tone="muted" /> : <Pill value={`${Math.round(p.score)}`} tone={TONE[p.status]} />}
            </div>
            <div style={{ margin: "6px 0" }}>{displayValue(p.value)}{p.renewalSoon && <> <Pill value="renewal soon" tone="warn" /></>}</div>
            {p.detail && <div className="small muted">{displayValue(p.detail)}</div>}
            <Link className="small" to={p.link} onClick={() => setTenantId(tenantId)}>Open</Link>
          </div>
        ))}
      </div>
      <h3 style={{ marginTop: 16 }}>Saved reports</h3>
      <Table rows={reports} empty="None yet. Last month's report is kept automatically at the start of each month."
             onRow={(r) => run(() => openReport(`clients/${tenantId}/reports/${r.id}.html`))}
             columns={[{ key: "kind", label: "Report", render: (r) => (r.kind === "monthly" ? "What we did for you" : "Quarterly review") },
                       { key: "period", label: "Period" }, { key: "createdBy", label: "By" },
                       { key: "createdAt", label: "Kept", render: (r) => fmtTime(r.createdAt) }]} />
    </>
  );
}

function recentQuarters(): string[] {
  const now = new Date();
  let year = now.getFullYear();
  let q = Math.floor(now.getMonth() / 3) + 1;
  const out: string[] = [];
  for (let i = 0; i < 6; i++) {
    out.push(`${year}-Q${q}`);
    q -= 1;
    if (q === 0) { q = 4; year -= 1; }
  }
  return out;
}
