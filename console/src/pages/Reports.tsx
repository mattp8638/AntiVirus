// Customer reports: executive summary, monthly "what we did", quarterly review and vulnerability report, each as a
// branded PDF or printable page, and schedules that email them as PDFs.
import { displayValue } from "../components/DisplayValue";
import { useEffect, useState } from "react";
import { api, downloadFile, fmtTime, getToken } from "../api";
import { useApp } from "../app-context";
import { confirmDialog } from "../components/dialogs";
import { PageHead, Pill, Stat, Table, TenantSelect, useAction, useData } from "../components/ui";

const KINDS: { kind: string; label: string }[] = [
  { kind: "executive", label: "Executive summary" },
  { kind: "monthly", label: "What we did for you (monthly)" },
  { kind: "quarterly", label: "Quarterly business review" },
  { kind: "vulnerability", label: "Vulnerability report" },
];
const KIND_LABEL = Object.fromEntries(KINDS.map((k) => [k.kind, k.label]));
const EVERY = ["weekly", "monthly", "quarterly"];

function recentMonths(count = 12): string[] {
  const out: string[] = [];
  const now = new Date();
  for (let i = 1; i <= count; i++) {
    const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
    out.push(`${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`);
  }
  return out;
}

function recentQuarters(count = 6): string[] {
  const out: string[] = [];
  const now = new Date();
  let year = now.getFullYear();
  let quarter = Math.floor(now.getMonth() / 3);  // the last complete quarter
  for (let i = 0; i < count; i++) {
    if (quarter === 0) { quarter = 4; year -= 1; }
    out.push(`${year}-Q${quarter}`);
    quarter -= 1;
  }
  return out;
}

function monthLabel(value: string) {
  const [y, m] = value.split("-").map(Number);
  return new Date(y, m - 1, 1).toLocaleDateString(undefined, { month: "long", year: "numeric" });
}

export default function Reports() {
  const { tenantId, me } = useApp();
  const [tenant, setTenant] = useState(tenantId || me?.user.tenantId || "");
  const [kind, setKind] = useState("executive");
  const [days, setDays] = useState(30);
  const [month, setMonth] = useState("");
  const [quarter, setQuarter] = useState("");
  const { run, busy } = useAction();
  const { data } = useData<any>(kind === "executive" && tenant ? "reports/executive" : null, { tenant_id: tenant, days }, [tenant, days, kind]);
  const query = () => {
    const params = new URLSearchParams({ tenant_id: tenant });
    if (kind === "executive") params.set("days", String(days));
    if (kind === "monthly" && month) params.set("period", month);
    if (kind === "quarterly" && quarter) params.set("period", quarter);
    return params.toString();
  };
  const openHtml = () => run(async () => {
    const response = await fetch(`/api/console/reports/${kind}.html?${query()}`, { headers: { Authorization: `Bearer ${getToken()}` } });
    if (!response.ok) throw new Error(`Report failed (${response.status})`);
    const url = URL.createObjectURL(new Blob([await response.text()], { type: "text/html" }));
    window.open(url, "_blank", "noopener");
  });
  const downloadPdf = () => run(() => downloadFile(`reports/${kind}.pdf?${query()}`, `${kind}-report.pdf`));

  return (
    <>
      <PageHead title="Reports" subtitle="Branded reports for customers, as PDF or a printable page, and schedules that email them."
                actions={<TenantSelect value={tenant} onChange={setTenant} allowAll={false} />} />
      <div className="card">
        <div className="row" style={{ gap: 8, flexWrap: "wrap", alignItems: "end" }}>
          <label className="field" style={{ minWidth: 240 }}>Report
            <select value={kind} onChange={(e) => setKind(e.target.value)}>{KINDS.map((k) => <option key={k.kind} value={k.kind}>{k.label}</option>)}</select>
          </label>
          {kind === "executive" && <label className="field">Period
            <select value={days} onChange={(e) => setDays(Number(e.target.value))}>{[7, 30, 90].map((d) => <option key={d} value={d}>Last {d} days</option>)}</select></label>}
          {kind === "monthly" && <label className="field">Month
            <select value={month} onChange={(e) => setMonth(e.target.value)}>
              <option value="">Last month</option>{recentMonths().map((m) => <option key={m} value={m}>{monthLabel(m)}</option>)}</select></label>}
          {kind === "quarterly" && <label className="field">Quarter
            <select value={quarter} onChange={(e) => setQuarter(e.target.value)}>
              <option value="">Last quarter</option>{recentQuarters().map((q) => <option key={q} value={q}>{q.replace("-", " ")}</option>)}</select></label>}
          <button className="primary" disabled={busy || !tenant} onClick={downloadPdf}>Download PDF</button>
          <button disabled={busy || !tenant} onClick={openHtml}>Open printable page</button>
        </div>
        <p className="small muted" style={{ marginBottom: 0 }}>Reports carry your logo, colours and contact details from Settings › Branding.</p>
      </div>
      {kind === "executive" && data && (
        <div className="grid k4" style={{ marginTop: 16 }}>
          <Stat label="Protected devices" value={data.devices.total} hint={`${data.devices.highRisk} high risk`} />
          <Stat label="Threat events stopped" value={data.threatEvents} accent="green" />
          <Stat label="Devices fully patched" value={`${data.patching?.compliancePercent ?? 0}%`} hint={`${data.patching?.missingCriticalOrSecurity ?? 0} missing security updates`} />
          <Stat label="Known-exploited to fix" value={data.knownExploited ?? 0} accent={data.knownExploited ? "red" : "green"}
                hint={`${data.service.slaMet === null ? "n/a" : `${data.service.slaMet}%`} of tickets within SLA`} />
        </div>
      )}
      {tenant && <Schedules tenant={tenant} />}
    </>
  );
}

interface Schedule { id?: string; kind: string; every: string; to: string[]; lastSentAt?: string | null; lastError?: string | null }

function Schedules({ tenant }: { tenant: string }) {
  const { can } = useApp();
  const { data, error, reload } = useData<{ schedules: Schedule[] }>("reports/schedules", { tenant_id: tenant }, [tenant]);
  const [draft, setDraft] = useState({ kind: "executive", every: "monthly", to: "" });
  const { run, busy } = useAction();
  useEffect(() => { setDraft({ kind: "executive", every: "monthly", to: "" }); }, [tenant]);
  if (error) return <div className="card" style={{ marginTop: 16 }}><h3>Scheduled reports</h3><p className="small muted">{displayValue(error)}</p></div>;
  const schedules = data?.schedules ?? [];
  const editable = can("configure");
  const save = (next: Schedule[], message: string) => run(() => api("reports/schedules", { method: "PUT", query: { tenant_id: tenant }, body: { schedules: next } }), message)
    .then((ok) => { if (ok) reload(); return ok; });
  const add = async () => {
    const to = draft.to.split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean);
    if (await save([...schedules, { kind: draft.kind, every: draft.every, to }], "Schedule added")) setDraft({ ...draft, to: "" });
  };
  return (
    <div className="card" style={{ marginTop: 16 }}>
      <h3>Scheduled reports</h3>
      <p className="small muted">Each schedule emails its report as a PDF once a week, month or quarter (checked hourly). Monthly and quarterly
        reports cover the last complete month or quarter; the executive summary covers the last 7, 30 or 90 days.</p>
      <Table rows={schedules.map((s) => ({ ...s, id: s.id ?? `${s.kind}-${s.every}` }))} empty="No schedules for this customer."
             columns={[
               { key: "kind", label: "Report", render: (s) => KIND_LABEL[s.kind] ?? s.kind },
               { key: "every", label: "Every", render: (s) => s.every },
               { key: "to", label: "Sent to", render: (s) => s.to.join(", ") },
               { key: "lastSentAt", label: "Last sent", render: (s) => s.lastError ? <Pill value="failed" tone="bad" /> : s.lastSentAt ? fmtTime(s.lastSentAt) : "not yet" },
               { key: "lastError", label: "", render: (s) => s.lastError ? <span className="small muted">{displayValue(s.lastError)}</span> : null },
               { key: "actions", label: "", render: (s) => !editable ? null : <span className="row" style={{ gap: 6 }}>
                   <button className="small" disabled={busy} onClick={(e) => { e.stopPropagation(); run(() => api(`reports/schedules/${s.id}/send`, { method: "POST", query: { tenant_id: tenant } }), "Sent").then(reload); }}>Send now</button>
                   <button className="small ghost" disabled={busy} onClick={async (e) => { e.stopPropagation();
                     if (await confirmDialog(`Stop emailing ${KIND_LABEL[s.kind] ?? s.kind} to ${s.to.join(", ")}?`))
                       save(schedules.filter((x) => x.id !== s.id), "Schedule removed"); }}>Remove</button>
                 </span> },
             ]} />
      {editable && <div className="row" style={{ gap: 8, flexWrap: "wrap", alignItems: "end", marginTop: 12 }}>
        <label className="field">Report<select value={draft.kind} onChange={(e) => setDraft({ ...draft, kind: e.target.value })}>{KINDS.map((k) => <option key={k.kind} value={k.kind}>{k.label}</option>)}</select></label>
        <label className="field">Every<select value={draft.every} onChange={(e) => setDraft({ ...draft, every: e.target.value })}>{EVERY.map((x) => <option key={x}>{x}</option>)}</select></label>
        <label className="field" style={{ flex: 1, minWidth: 240 }}>Email to (comma separated)
          <input value={draft.to} onChange={(e) => setDraft({ ...draft, to: e.target.value })} placeholder="director@customer.example, it@customer.example" /></label>
        <button className="primary" disabled={busy || !draft.to.trim() || schedules.length >= 10} onClick={add}>Add schedule</button>
      </div>}
    </div>
  );
}
