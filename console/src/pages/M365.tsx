import { displayValue } from "../components/DisplayValue";
import { M365Connect } from "../components/M365Connect";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useEffect, useState } from "react";
import { api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { RecordEditor } from "../components/RecordEditor";
import { ErrorNote, PageHead, Pill, Stat, Table, useData } from "../components/ui";
import { M365_SECTION, SectionTabs } from "../components/sections";

const pct = (value: any) => (value === null || value === undefined ? "—" : `${value}%`);

/** Every customer's Microsoft 365 at a glance; open one for its workspace. */
export default function M365() {
  const { tenantId, can, toast } = useApp();
  const navigate = useNavigate();
  const { data, error, reload } = useData<any>(can("configure") ? "m365/overview" : null, { tenant_id: tenantId });
  const [create, setCreate] = useState(false);
  const [connect, setConnect] = useState(false);
  const [query, setQuery] = useState("");
  const [params, setParams] = useSearchParams();
  useEffect(() => {
    const outcome = params.get("signin");
    if (!outcome) return;
    const messages: Record<string, [string, boolean]> = {
      connected: ["Microsoft 365 connected. Sync it now, or wait for the next scheduled sync.", false],
      failed: ["Microsoft sign-in did not complete. Try again, and approve the permissions when Microsoft asks.", true],
      expired: ["That sign-in link expired. Start again.", true],
      duplicate: ["That Microsoft tenant is already connected for this customer.", true],
    };
    const [text, isError] = messages[outcome] || ["Sign-in finished.", false];
    toast(text, isError);
    setParams({}, { replace: true });
    reload();
  }, [params]);
  if (!can("configure")) return <PageHead title="Microsoft 365" subtitle="Configuration access is required." />;
  const totals = data?.totals || {};
  const rows = (data?.rows || []).filter((r: any) =>
    `${r.name} ${r.customer} ${r.tenantName} ${r.directoryId}`.toLowerCase().includes(query.toLowerCase()));
  return <>
    <SectionTabs items={M365_SECTION} />
    <PageHead title="Microsoft 365" subtitle="Every customer tenant at a glance. Open one to manage its users, run onboarding or offboarding, and search its sign-in and audit logs."
      actions={<button className="primary" onClick={() => setConnect(true)}>Connect Microsoft 365</button>} />
    <ErrorNote error={error} />
    <div className="grid k4" style={{ marginBottom: 12 }}>
      <Stat label="Tenants" value={totals.tenants ?? "—"} hint={totals.needsAttention ? `${totals.needsAttention} need attention` : "all healthy"} accent={totals.needsAttention ? "amber" : undefined} />
      <Stat label="Enabled users" value={totals.users ?? "—"} hint={`${totals.inactiveLicensed ?? 0} licensed but inactive 90+ days`} />
      <Stat label="Unused licences" value={totals.licencesUnused ?? "—"} hint="paid for, not assigned" accent={totals.licencesUnused ? "amber" : undefined} />
      <Stat label="Admins without MFA" value={totals.adminsWithoutMfa ?? "—"} hint={`${totals.serviceIssues ?? 0} open Microsoft service issues`} accent={totals.adminsWithoutMfa ? "red" : undefined} />
    </div>
    <label className="field">Search<input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Customer, tenant or directory ID" /></label>
    <Table rows={rows} onRow={(r: any) => navigate(`/m365/${r.id}`)} empty="No Microsoft 365 tenants connected yet. Connect one to begin."
      columns={[
        { key: "name", label: "Tenant", render: (r: any) => <><b>{displayValue(r.name)}</b><div className="small muted">{displayValue(r.customer)}{r.tenantName && r.tenantName !== r.name ? ` · ${r.tenantName}` : ""}</div></> },
        { key: "status", label: "Status", render: (r: any) => <><Pill value={r.status} />{r.permissionsMissing ? <div className="small" style={{ color: "#fcd34d" }}>{r.permissionsMissing} features need permissions</div> : null}</> },
        { key: "users", label: "Users", render: (r: any) => <>{displayValue(r.insights?.enabledUsers ?? "—")}<div className="small muted">{r.insights?.guests ?? 0} guests</div></> },
        { key: "mfa", label: "MFA", render: (r: any) => <span style={{ color: r.insights?.mfa?.adminsWithoutMfa?.length ? "#fca5a5" : undefined }}>{pct(r.insights?.mfa?.percent)}{r.insights?.mfa?.adminsWithoutMfa?.length ? <div className="small">{r.insights.mfa.adminsWithoutMfa.length} admins without</div> : null}</span> },
        { key: "score", label: "Secure Score", render: (r: any) => pct(r.insights?.secureScore?.percent) },
        { key: "licences", label: "Unused licences", render: (r: any) => <>{displayValue(r.insights?.licencesUnused ?? "—")}{r.insights?.inactiveLicensed ? <div className="small muted">{r.insights.inactiveLicensed} inactive users</div> : null}</> },
        { key: "admins", label: "Global admins", render: (r: any) => displayValue(r.insights?.admins?.globalAdmins?.length ?? "—") },
        { key: "health", label: "Service issues", render: (r: any) => displayValue(r.insights?.serviceIssues ?? "—") },
        { key: "logs", label: "Logs", render: (r: any) => <span className="small">{r.logs?.signin?.available === false ? "Sign-ins: not available" : r.logs?.signin?.lastRunAt ? "Collecting" : "Not started"}</span> },
        { key: "syncedAt", label: "Synced", render: (r: any) => fmtTime(r.syncedAt) },
      ]} />
    {connect && <M365Connect onClose={() => { setConnect(false); reload(); }} onManual={() => { setConnect(false); setCreate(true); }} />}
    {create && <RecordEditor title="Connect Microsoft 365" fields={[{ key: "name", label: "Name", required: true }, { key: "directoryId", label: "Directory (tenant) UUID", required: true }, { key: "clientId", label: "Application (client) UUID", required: true }, { key: "clientSecret", label: "Client secret", type: "password", required: true }]}
      onSave={(body) => api("m365/connections", { body })} onClose={() => { setCreate(false); reload(); }} />}
  </>;
}
