import { useState } from "react";
import { Link } from "react-router-dom";
import { ago, api } from "../api";
import { useApp } from "../app-context";
import { displayValue } from "../components/DisplayValue";
import { ErrorNote, PageHead, Pill, Stat, Table, Tabs, useAction, useData, useListData } from "../components/ui";

const PII_LABEL: Record<string, string> = { "payment-card": "Payment cards", "uk-nino": "NI numbers", "nhs-number": "NHS numbers", iban: "IBANs", email: "Emails" };
const RISK_TONE: Record<string, string> = { high: "bad", medium: "warn", low: "muted" };

export default function Exposure() {
  const [tab, setTab] = useState("Dark web");
  return (
    <>
      <PageHead title="Data and identity exposure"
                subtitle="Breached customer accounts and devices holding personal data. Both raise the priority of vulnerabilities on the devices concerned." />
      <Tabs tabs={["Dark web", "Personal data"]} active={tab} onChange={setTab} />
      {tab === "Dark web" ? <DarkWeb /> : <PersonalData />}
    </>
  );
}

function DarkWeb() {
  const { tenantId, can } = useApp();
  const [status, setStatus] = useState("open");
  const { data, error, reload } = useListData<any>("darkweb/exposures", { tenant_id: tenantId, status });
  const { run, busy } = useAction();
  const high = data?.filter((e) => e.risk === "high").length ?? 0;
  const setRowStatus = async (row: any, next: string) => {
    if (await run(() => api(`darkweb/exposures/${row.id}`, { method: "PATCH", body: { status: next } }), "Updated")) reload();
  };
  return (
    <>
      <div className="grid k3" style={{ marginTop: 12 }}>
        <Stat label="Exposed accounts" value={new Set(data?.map((e) => e.email) ?? []).size} />
        <Stat label="High risk" value={high} accent={high ? "red" : "green"} hint="Password exposed and no MFA, or an admin" />
        <Stat label="Breaches" value={new Set(data?.map((e) => e.breach) ?? []).size} />
      </div>
      {tenantId ? <DarkWebSettings tenantId={tenantId} onSynced={reload} /> : <p className="small muted">Choose a customer to configure monitored domains.</p>}
      <ErrorNote error={error} />
      <div className="card">
        <div className="row" style={{ marginBottom: 10 }}>
          <h3 style={{ margin: 0, flex: 1 }}>Exposed accounts</h3>
          <select value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status"><option value="open">Open</option><option value="remediated">Remediated</option><option value="dismissed">Dismissed</option><option value="">All</option></select>
        </div>
        <Table rows={data ?? undefined} empty="No breached accounts found for the monitored domains."
               columns={[
                 { key: "risk", label: "Risk", render: (e) => <Pill value={e.risk} tone={RISK_TONE[e.risk]} /> },
                 { key: "email", label: "Account", render: (e) => <><b>{displayValue(e.email)}</b><div className="small muted">
                   {e.correlation.m365User ? `Microsoft 365 ${e.correlation.accountEnabled === false ? "(disabled)" : "account"}` : "Not in the synced directory"}
                   {e.correlation.mfaRegistered === false && " · no MFA"}{e.correlation.admin && " · admin"}{e.correlation.consoleUser && " · Fenrir user"}</div></> },
                 { key: "breach", label: "Breach", render: (e) => <>{displayValue(e.breachTitle)}<div className="small muted">{displayValue(e.breachDate)} · {displayValue(e.dataClasses.join(", "))}</div></> },
                 { key: "devices", label: "Devices", render: (e) => (e.correlation.deviceIds || []).map((id: string, i: number) =>
                   <div key={id}><Link to={`/devices/${id}`}>{displayValue(e.correlation.hostnames?.[i] || id)}</Link></div>) },
                 { key: "ticket", label: "", render: (e) => e.ticketId && <Link to={`/tickets/${e.ticketId}`}><Pill value="ticket" tone="blue" /></Link> },
                 ...(can("respond") ? [{ key: "act", label: "", className: "right", render: (e: any) => e.status === "open" ? <span style={{ display: "inline-flex", gap: 6 }}>
                   <button disabled={busy} onClick={() => setRowStatus(e, "remediated")}>Mark remediated</button>
                   <button className="ghost" disabled={busy} onClick={() => setRowStatus(e, "dismissed")}>Dismiss</button></span>
                   : <button className="ghost" disabled={busy} onClick={() => setRowStatus(e, "open")}>Reopen</button> }] : []),
               ]} />
      </div>
    </>
  );
}

function DarkWebSettings({ tenantId, onSynced }: { tenantId: string; onSynced: () => void }) {
  const { can } = useApp();
  const { data, reload } = useData<any>("darkweb/settings", { tenant_id: tenantId });
  const [domains, setDomains] = useState<string | null>(null);
  const { run, busy } = useAction();
  if (!data) return null;
  const text = domains ?? data.domains.join(", ");
  const save = async (enabled: boolean) => {
    const body = { tenantId, enabled, autoTicket: data.autoTicket, domains: text.split(/[\s,]+/).filter(Boolean) };
    if (await run(() => api("darkweb/settings", { method: "PUT", body }), "Monitoring updated")) { setDomains(null); reload(); }
  };
  return (
    <div className="card">
      <h3>Monitoring</h3>
      {!data.providerConfigured && <p className="small" style={{ color: "var(--amber, #f59e0b)" }}>No breach data provider is configured. Set FENRIR_HIBP_API_KEY (a Have I Been Pwned subscription key) on the server and verify each domain in HIBP.</p>}
      <div className="row">
        <input value={text} onChange={(e) => setDomains(e.target.value)} placeholder="acme.co.uk, acme.com" style={{ minWidth: 280 }} disabled={!can("configure")} />
        {can("configure") && <button disabled={busy} onClick={() => save(true)}>{data.enabled ? "Save" : "Turn on"}</button>}
        {can("configure") && data.enabled && <button className="ghost" disabled={busy} onClick={() => save(false)}>Turn off</button>}
        {can("respond") && data.enabled && <button className="ghost" disabled={busy || !data.providerConfigured} onClick={async () => {
          if (await run(() => api("darkweb/sync", { body: { tenantId } }), "Checked for breached accounts")) { reload(); onSynced(); }
        }}>Check now</button>}
        <span className="small muted">{data.lastSyncAt ? `Last checked ${ago(data.lastSyncAt)}` : "Never checked"}</span>
      </div>
      {data.lastError && <p className="small" style={{ color: "var(--red)" }}>{displayValue(data.lastError)}</p>}
    </div>
  );
}

function PersonalData() {
  const { tenantId, can } = useApp();
  const { data, error, reload } = useListData<any>("pii/scans", { tenant_id: tenantId });
  const { run, busy } = useAction();
  const high = data?.filter((s) => s.sensitivity === "high").length ?? 0;
  return (
    <>
      <div className="grid k3" style={{ marginTop: 12 }}>
        <Stat label="Devices scanned" value={data?.filter((s) => s.status === "completed").length ?? "—"} />
        <Stat label="Holding sensitive data" value={high} accent={high ? "amber" : "green"} hint="Cards, NI or NHS numbers, IBANs" />
        <Stat label="Files with personal data" value={data?.reduce((n, s) => n + (s.filesWithPii || 0), 0) ?? 0} />
      </div>
      <ErrorNote error={error} />
      <div className="card">
        <div className="row" style={{ marginBottom: 10 }}>
          <h3 style={{ margin: 0, flex: 1 }}>Latest scan per device</h3>
          {can("respond") && <button disabled={busy} onClick={async () => {
            const r = await run(() => api<any>("pii/scans", { body: { tenantId: tenantId || undefined } }));
            if (r) reload();
          }}>Scan devices</button>}
        </div>
        <p className="small muted">Scans users' Documents, Desktop and Downloads for payment cards, NI and NHS numbers, IBANs and email addresses. Only counts and file paths leave the device.</p>
        <Table rows={data ?? undefined} empty="No scans yet."
               columns={[
                 { key: "sensitivity", label: "Sensitivity", render: (s) => <Pill value={s.status === "completed" ? s.sensitivity : s.status} tone={s.sensitivity === "high" ? "bad" : undefined} /> },
                 { key: "hostname", label: "Device", render: (s) => <Link to={`/devices/${s.deviceId}`}>{displayValue(s.hostname)}</Link> },
                 { key: "counts", label: "Found", render: (s) => <span className="small">{Object.entries(s.counts || {}).map(([k, v]) => `${PII_LABEL[k] || k}: ${v}`).join(" · ") || "—"}</span> },
                 { key: "files", label: "Files", render: (s) => <span className="small">{s.filesWithPii} of {s.filesScanned}{s.truncated ? " (partial)" : ""}
                   {s.files?.[0] && <div className="muted mono">{displayValue(s.files[0].path)}{s.files.length > 1 ? ` +${s.files.length - 1}` : ""}</div>}</span> },
                 { key: "completedAt", label: "When", render: (s) => s.completedAt ? ago(s.completedAt) : ago(s.requestedAt) },
                 { key: "error", label: "", render: (s) => s.error && <span className="small" style={{ color: "var(--red)" }}>{displayValue(s.error)}</span> },
               ]} />
      </div>
    </>
  );
}
