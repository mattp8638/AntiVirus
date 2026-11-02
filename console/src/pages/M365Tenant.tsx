import { displayValue } from "../components/DisplayValue";
import { M365Administration } from "./M365Administration";
import { M365Lifecycle } from "./M365Lifecycle";
import { M365Logs } from "./M365Logs";
import { M365Connect } from "../components/M365Connect";
import { Link, useParams } from "react-router-dom";
import { useState } from "react";
import { api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { RecordEditor } from "../components/RecordEditor";
import { safeArray } from "../data-shapes";
import { ErrorNote, Modal, PageHead, Pill, Stat, Table, Tabs, useAction, useData } from "../components/ui";
import { M365_SECTION, SectionTabs } from "../components/sections";

const UNAVAILABLE: Record<string, string> = { mfaRegistration: "MFA registration", managedDevices: "Intune devices", domains: "Domains",
  organization: "Organisation", directoryRoles: "Administrators", serviceIssues: "Service health", signInActivity: "Last sign-in per user",
  defenderAlerts: "Defender alerts" };
const MODES: Record<string, string> = { platform: "Fenrir app (admin consent)", provisioned: "Admin sign-in", gdap: "Partner (GDAP)", app: "Manual app" };

function Overview({ ws }: { ws: any }) {
  const i = ws.insights || {};
  const mfa = i.mfa, score = i.secureScore;
  return <>
    <div className="grid k4" style={{ marginBottom: 12 }}>
      <Stat label="Users" value={i.enabledUsers ?? "—"} hint={`enabled of ${i.users ?? "—"} · ${i.guests ?? 0} guests`} />
      <Stat label="Unused licences" value={i.licencesUnused ?? "—"} hint={`${i.licencesAssigned ?? "—"} of ${i.licencesPurchased ?? "—"} assigned`} accent={i.licencesUnused ? "amber" : undefined} />
      <Stat label="MFA registered" value={mfa ? `${mfa.percent ?? "—"}%` : "—"} hint={mfa ? `${mfa.notRegistered} without MFA` : "needs Entra ID P1/P2"} accent={mfa?.adminsWithoutMfa?.length ? "red" : undefined} />
      <Stat label="Secure Score" value={score ? `${score.percent}%` : "—"} hint={score ? `${score.current} of ${score.max}` : "not available"} />
    </div>
    {mfa?.adminsWithoutMfa?.length > 0 && <p style={{ color: "#fca5a5" }}><b>Admins without MFA:</b> {displayValue(mfa.adminsWithoutMfa.join(", "))}</p>}
    {Object.keys(ws.unavailable || {}).length > 0 && <details className="small" style={{ marginBottom: 8 }}>
      <summary>{Object.keys(ws.unavailable).length} parts of the last sync were not available</summary>
      <ul>{Object.entries(ws.unavailable as Record<string, string>).map(([k, v]) => <li key={k}><b>{UNAVAILABLE[k] || k}:</b> {displayValue(v)}</li>)}</ul>
    </details>}
    {i.disabledButLicensed?.length > 0 && <p className="small"><b>Disabled accounts still holding licences ({i.disabledButLicensed.length}):</b> {displayValue(i.disabledButLicensed.join(", "))}</p>}
    <div className="grid k2">
      <div className="card">
        <h3 style={{ marginTop: 0 }}>Tenant</h3>
        {ws.organization ? <p className="small">{displayValue(ws.organization.displayName)} · {displayValue(ws.organization.countryLetterCode)}
          {ws.organization.onPremisesSyncEnabled ? <> · synced from on-premises AD (last {fmtTime(ws.organization.onPremisesLastSyncDateTime)})</> : <> · cloud only</>}</p>
          : <p className="small muted">Not read yet.</p>}
        <p className="small muted mono">{displayValue(ws.directoryId)}</p>
        <Table rows={safeArray<any>(ws.domains)} empty="Domains need Domain.Read.All." columns={[{ key: "id", label: "Domain" }, { key: "isDefault", label: "Default", render: (r: any) => r.isDefault ? "Yes" : "" }, { key: "isVerified", label: "Verified", render: (r: any) => r.isVerified ? "Yes" : "No" }, { key: "authenticationType", label: "Sign-in" }]} />
      </div>
      <div className="card">
        <h3 style={{ marginTop: 0 }}>Microsoft service health</h3>
        {ws.serviceIssues === null || ws.serviceIssues === undefined ? <p className="small muted">Needs ServiceHealth.Read.All (see Permissions).</p> :
          <Table rows={safeArray<any>(ws.serviceIssues)} empty="No open Microsoft incidents or advisories." columns={[{ key: "service", label: "Service" }, { key: "title", label: "Issue" }, { key: "classification", label: "Type" }, { key: "status", label: "Status" }]} />}
      </div>
    </div>
    <h3>Administrators</h3>
    {ws.admins === null || ws.admins === undefined ? <p className="small muted">Needs RoleManagement.Read.Directory or Directory.Read.All.</p> :
      <Table rows={safeArray<any>(ws.admins).flatMap((r: any) => safeArray<any>(r.members).map((m: any) => ({ ...m, role: r.role, key: r.role + m.id })))}
        columns={[{ key: "role", label: "Role" }, { key: "displayName", label: "Name" }, { key: "userPrincipalName", label: "Sign-in" }, { key: "type", label: "Type" }]} />}
    <h3>Licensed but inactive for {ws.inactiveUsers?.days ?? 90}+ days</h3>
    {!ws.inactiveUsers ? <p className="small muted">Needs Entra ID P1/P2 and AuditLog.Read.All.</p> :
      <Table rows={safeArray<any>(ws.inactiveUsers.users)} empty="Every licensed user has signed in recently." columns={[{ key: "userPrincipalName", label: "User" }, { key: "lastSignIn", label: "Last sign-in", render: (r: any) => r.lastSignIn ? fmtTime(r.lastSignIn) : "Never" }, { key: "days", label: "Days", render: (r: any) => r.days ?? "—" }, { key: "licences", label: "Licences" }]} />}
  </>;
}

function Permissions({ ws, reload, onSignIn }: { ws: any; reload: () => void; onSignIn: () => void }) {
  const { can, toast } = useApp();
  const { run, busy } = useAction();
  const [answer, setAnswer] = useState<any>(null);
  const check = ws.permissions;
  const update = async () => {
    const result = await run(() => api<any>(`m365/connections/${ws.id}/permissions/update`, { method: "POST" }));
    if (!result) return;
    if (result.action === "signin") onSignIn();
    else if (result.action === "done") { toast(result.message); reload(); }
    else setAnswer(result);
  };
  return <>
    <p>What this connection can do, read from the access token Microsoft issues to Fenrir. Through GDAP, the technician's own GDAP roles also apply.</p>
    <div className="row" style={{ gap: 8 }}>
      <button disabled={busy} onClick={async () => { if (await run(() => api(`m365/connections/${ws.id}/permissions/check`, { method: "POST" }), "Permissions checked")) reload(); }}>Check permissions</button>
      {can("m365_admin") && <button className="primary" disabled={busy} onClick={update}>Update permissions</button>}
      {check && <span className="small muted">Checked {fmtTime(check.checkedAt)} · {check.mode === "delegated" ? "delegated (GDAP)" : "application"} permissions</span>}
    </div>
    {!check ? <p className="small muted">Not checked yet. Press Check permissions or Sync.</p> :
      <Table rows={safeArray<any>(check.features)} columns={[
        { key: "area", label: "Area" }, { key: "title", label: "Feature" },
        { key: "available", label: "Status", render: (r: any) => <Pill value={r.available ? "available" : r.unsupported ? "not possible here" : "missing"} tone={r.available ? "good" : r.unsupported ? "muted" : "warn"} /> },
        { key: "missing", label: "Needs", render: (r: any) => <span className="small mono">{safeArray<string>(r.missing).join(", ")}</span> },
        { key: "note", label: "Note", render: (r: any) => <span className="small">{displayValue(r.note)}</span> }]} />}
    {answer && <Modal title="Update permissions" onClose={() => setAnswer(null)} footer={answer.action === "consent" ? <button className="primary" onClick={() => { setAnswer(null); onSignIn(); }}>Sign in with Microsoft</button> : undefined}>
      <p>{displayValue(answer.message)}</p>
      <div className="row small" style={{ flexWrap: "wrap" }}>{safeArray<string>(answer.permissions).map((p) => <span key={p} className="chip mono">{p}</span>)}</div>
    </Modal>}
  </>;
}

export default function M365Tenant() {
  const { connectionId } = useParams();
  const { can } = useApp();
  const { data: ws, error, reload } = useData<any>(can("configure") && connectionId ? `m365/connections/${connectionId}/workspace` : null);
  const [tab, setTab] = useState("Overview");
  const [secret, setSecret] = useState(false);
  const [signIn, setSignIn] = useState(false);
  const { run, busy } = useAction();
  if (!can("configure")) return <PageHead title="Microsoft 365" subtitle="Configuration access is required." />;
  if (!ws) return <><SectionTabs items={M365_SECTION} /><ErrorNote error={error} /><p className="muted">Loading…</p></>;
  const missing = safeArray<any>(ws.permissions?.features).filter((f: any) => !f.available && !f.unsupported).length;
  return <>
    <SectionTabs items={M365_SECTION} />
    <PageHead title={ws.name} subtitle={<><Link to="/m365">All tenants</Link> · {MODES[ws.authMode] || ws.authMode}{ws.consentedBy ? ` by ${ws.consentedBy}` : ""} · synced {fmtTime(ws.syncedAt)}</>}
      actions={<>
        {["app", "provisioned"].includes(ws.authMode) && <button onClick={() => setSecret(true)}>Replace secret</button>}
        <button className="primary" disabled={busy} onClick={async () => { if (await run(() => api(`m365/connections/${ws.id}/sync`, { method: "POST" }), "Directory synchronised")) reload(); }}>Sync now</button>
      </>} />
    <ErrorNote error={error || ws.lastError || null} />
    {missing > 0 && <p className="small" style={{ color: "#fcd34d" }}>{missing} features need permissions this connection does not have. <button className="link" onClick={() => setTab("Permissions")}>See which</button></p>}
    {ws.secretExpiresAt && <p className="small muted">App secret expires {fmtTime(ws.secretExpiresAt)}.</p>}
    <Tabs tabs={["Overview", "Users and groups", "Onboarding and offboarding", "Logs", "Permissions"]} active={tab} onChange={setTab} />
    {tab === "Overview" && <Overview ws={ws} />}
    {tab === "Users and groups" && <M365Administration key={ws.id} connection={ws} />}
    {tab === "Onboarding and offboarding" && <M365Lifecycle key={ws.id} connection={ws} />}
    {tab === "Logs" && <M365Logs key={ws.id} connection={ws} onCollected={reload} />}
    {tab === "Permissions" && <Permissions ws={ws} reload={reload} onSignIn={() => setSignIn(true)} />}
    {secret && <RecordEditor title="Replace application secret" tenant={false} fields={[{ key: "clientSecret", label: "New client secret", type: "password", required: true }]}
      onSave={({ clientSecret }) => api(`m365/connections/${ws.id}/secret`, { method: "PUT", body: { clientSecret } })} onClose={() => setSecret(false)} />}
    {signIn && <M365Connect reconnect customerId={ws.tenantId} presetName={ws.name} onClose={() => { setSignIn(false); reload(); }} />}
  </>;
}
