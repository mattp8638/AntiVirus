import { useState } from "react";
import { Link } from "react-router-dom";
import { ago, api } from "../api";
import { useApp } from "../app-context";
import { displayValue } from "../components/DisplayValue";
import { ErrorNote, PageHead, Pill, Stat, Table, Tabs, useAction, useData } from "../components/ui";

const STATUS_TONE: Record<string, string> = { compliant: "good", drifted: "bad", deployed: "blue", failed: "bad", unknown: "muted", active: "good" };

export default function M365Partner() {
  const { can } = useApp();
  const tabs = [...(can("manage_tenants") && can("m365_admin") ? ["Partner (GDAP)"] : []), "Identity standards", "Reconciliation"];
  const [tab, setTab] = useState(tabs[0]);
  return (
    <>
      <PageHead title="Microsoft 365 across customers"
                subtitle="Partner access through GDAP, MFA and Conditional Access standards deployed to many tenants at once, and reconciliation of each directory with Fenrir's records." />
      <Tabs tabs={tabs} active={tab} onChange={setTab} />
      {tab === "Partner (GDAP)" && <Partner />}
      {tab === "Identity standards" && <Standards />}
      {tab === "Reconciliation" && <Reconciliation />}
    </>
  );
}

function Partner() {
  const { data, error, reload } = useData<any>("m365/partner");
  const { run, busy } = useAction();
  const [form, setForm] = useState({ directoryId: "", clientId: "", clientSecret: "" });
  const [code, setCode] = useState<any>(null);
  const partner = data?.partner;
  if (!data) return <ErrorNote error={error} />;
  if (!partner) return (
    <div className="card" style={{ marginTop: 12 }}>
      <h3>Connect your partner tenant</h3>
      <p className="small muted">Register an app in your Microsoft partner (CSP) tenant: multi-tenant, "Allow public client flows" on, with delegated Graph permissions DelegatedAdminRelationship.ReadWrite.All, Directory.Read.All and Group.ReadWrite.All plus offline_access, the customer-side permissions you administer (for example Policy.ReadWrite.ConditionalAccess, DeviceManagementConfiguration.ReadWrite.All, User.ReadWrite.All), and the Microsoft Partner Center permission user_impersonation (so Fenrir can consent its app in customer tenants). Grant admin consent. Then sign in once with an account that belongs to the partner tenant and is an Admin Agent in Partner Center.</p>
      <div className="form-grid">
        <label className="field">Partner tenant ID<input value={form.directoryId} onChange={(e) => setForm({ ...form, directoryId: e.target.value })} /></label>
        <label className="field">App (client) ID<input value={form.clientId} onChange={(e) => setForm({ ...form, clientId: e.target.value })} /></label>
        <label className="field">Client secret (only if public client flows are off)<input type="password" value={form.clientSecret} onChange={(e) => setForm({ ...form, clientSecret: e.target.value })} /></label>
      </div>
      <button style={{ marginTop: 10 }} disabled={busy} onClick={async () => { if (await run(() => api("m365/partner", { body: form }), "Partner app saved")) reload(); }}>Save</button>
    </div>
  );
  const signin = async () => setCode(await run(() => api<any>("m365/partner/signin", { method: "POST" })));
  const poll = async () => {
    const r = await run(() => api<any>("m365/partner/signin/poll", { method: "POST" }));
    if (r?.status === "ok") { setCode(null); reload(); }
  };
  return (
    <>
      <div className="card" style={{ marginTop: 12 }}>
        <div className="row"><h3 style={{ margin: 0, flex: 1 }}>Partner tenant {displayValue(partner.partnerDirectoryId)}</h3>
          <Pill value={partner.status} tone={partner.status === "connected" ? "good" : "warn"} /></div>
        <p className="small muted">{partner.signedInAs ? `Signed in as ${partner.signedInAs}` : "Not signed in"}{partner.refreshedAt ? ` · token refreshed ${ago(partner.refreshedAt)}` : ""}{partner.lastError ? ` · ${partner.lastError}` : ""}</p>
        <div className="row">
          <button disabled={busy} onClick={signin}>{partner.status === "connected" ? "Sign in again" : "Sign in as partner admin"}</button>
          <button className="ghost" disabled={busy || partner.status !== "connected"} onClick={async () => { if (await run(() => api("m365/partner/role-groups", { method: "POST" }), "Role groups ready")) reload(); }}>Create role groups</button>
        </div>
        {code && <p>Go to <a href={code.verificationUri} target="_blank" rel="noreferrer">{code.verificationUri}</a> and enter <b className="mono">{code.userCode}</b>, then <button className="ghost" disabled={busy} onClick={poll}>I've signed in</button></p>}
        {Object.keys(partner.roleGroups || {}).length > 0 && <p className="small muted">{Object.keys(partner.roleGroups).length} role groups: add partner staff to "Fenrir GDAP - …" groups to give them that role in customer tenants.</p>}
      </div>
      {partner.status === "connected" && <><PartnerCheck partner={partner} onChecked={reload} /><Customers partner={partner} onChanged={reload} /><Relationships /></>}
    </>
  );
}

function PartnerCheck({ partner, onChecked }: { partner: any; onChecked: () => void }) {
  const { run, busy } = useAction();
  const check = partner.check;
  const runCheck = async () => { if (await run(() => api<any>("m365/partner/check"))) onChecked(); };
  return (
    <div className="card">
      <div className="row"><h3 style={{ margin: 0, flex: 1 }}>Partner check</h3>
        {check && <Pill value={check.problems.length ? `${check.problems.length} to fix` : "ready for GDAP"} tone={check.problems.length ? "bad" : "good"} />}
        <button className="ghost" disabled={busy} onClick={runCheck}>{check ? "Check again" : "Run check"}</button></div>
      {!check ? <p className="small muted">Checks that the signed-in account can manage customers: the tenant is your Partner Center (CSP) tenant, the account is a member and an Admin Agent, the app's permissions are consented, and Partner Center accepts the sign-in.</p> : <>
        <p className="small muted">{displayValue(check.organization || "Unknown organisation")}{check.partnerTenantType ? ` · partner type ${check.partnerTenantType}` : ""}
          {check.user ? ` · ${check.user} (${check.userType || "member"}${check.adminAgent ? ", Admin Agent" : ""})` : ""} · checked {ago(check.checkedAt)}</p>
        {check.problems.length > 0 && <ul className="small">{check.problems.map((p: string, i: number) => <li key={i} className="error">{displayValue(p)}</li>)}</ul>}
      </>}
    </div>
  );
}

function Relationships() {
  const { data, error, reload } = useData<any[]>("m365/partner/relationships");
  const { run, busy } = useAction();
  const [name, setName] = useState("");
  const [customer, setCustomer] = useState("");
  return (
    <div className="card">
      <h3>GDAP relationships</h3>
      <ErrorNote error={error} />
      <div className="row" style={{ marginBottom: 10 }}>
        <input placeholder="Relationship name" value={name} onChange={(e) => setName(e.target.value)} />
        <input placeholder="Customer tenant ID (optional)" value={customer} onChange={(e) => setCustomer(e.target.value)} />
        <button disabled={busy || !name} onClick={async () => {
          const rel = await run(() => api<any>("m365/partner/relationships", { body: { displayName: name, customerTenantId: customer || undefined } }), "Relationship created: send the invitation link to the customer's Global Administrator");
          if (rel) { setName(""); setCustomer(""); reload(); }
        }}>Create with recommended roles</button>
      </div>
      <Table rows={data ?? undefined} empty="No relationships."
             columns={[{ key: "displayName", label: "Relationship", render: (r) => <><b>{displayValue(r.displayName)}</b><div className="small muted">{displayValue(r.customer)}</div></> },
                       { key: "status", label: "Status", render: (r) => <><Pill value={r.status} tone={STATUS_TONE[r.status]} />{r.expiringSoon && <Pill value="expiring" tone="warn" />}</> },
                       { key: "roles", label: "Roles", render: (r) => <span className="small">{r.roles.length}{r.missingRoles.length ? ` (missing ${r.missingRoles.length})` : ""}</span> },
                       { key: "endDateTime", label: "Ends", render: (r) => r.endDateTime ? displayValue(String(r.endDateTime).slice(0, 10)) : "—" },
                       { key: "act", label: "", render: (r) => r.invitationUrl ? <a href={r.invitationUrl} target="_blank" rel="noreferrer">Invitation link</a>
                         : r.status === "active" && <button className="ghost" disabled={busy} onClick={async () => {
                           const res = await run(() => api<any>(`m365/partner/relationships/${r.id}/assign`, { method: "POST" }));
                           if (res) reload();
                         }}>Assign role groups</button> }]} />
    </div>
  );
}

const GDAP_TONE: Record<string, string> = { active: "good", pending: "warn", expired: "bad", none: "muted" };

function Customers({ partner, onChanged }: { partner: any; onChanged: () => void }) {
  const { data, error, reload } = useData<any>("m365/partner/discover");
  const { run, busy } = useAction();
  const [results, setResults] = useState<any[] | null>(null);
  const customers: any[] = data?.customers ?? [];
  const importNow = async (directoryIds?: string[], createRelationships = false) => {
    const r = await run(() => api<any[]>("m365/partner/import", { body: { directoryIds, createRelationships } }));
    if (r) { setResults(r); reload(); }
  };
  const toggleAuto = async () => { if (await run(() => api("m365/partner/settings", { method: "PUT", body: { autoImport: !partner.autoImport } }))) onChanged(); };
  const unlinked = customers.filter((c) => !c.connectionId);
  return (
    <div className="card">
      <div className="row"><h3 style={{ margin: 0, flex: 1 }}>Customers in your partner tenant</h3>
        <label className="small"><input type="checkbox" checked={!!partner.autoImport} disabled={busy} onChange={toggleAuto} /> Import new GDAP customers automatically</label>
        <button className="primary" disabled={busy || !unlinked.length} title="Creates a Fenrir customer for each, consents the Fenrir app through Partner Center and connects Microsoft 365 where GDAP is active"
                onClick={() => importNow()}>Import all ({unlinked.length})</button></div>
      <p className="small muted">From your CSP customer list and GDAP. Customers with active GDAP are connected straight away; the others are created in Fenrir and can be sent a GDAP invitation.{partner.lastImportAt ? ` Last import ${ago(partner.lastImportAt)}.` : ""}</p>
      <ErrorNote error={error} />
      {data?.errors && Object.entries(data.errors).map(([source, message]) => <p key={source} className="error small">{source === "contracts" ? "CSP customer list" : source === "relationships" ? "GDAP relationships" : "GDAP customers"}: {displayValue(message as string)}</p>)}
      {results && <div className="card" style={{ background: "transparent" }}>
        <b>Import results</b>
        <Table rows={results.map((r) => ({ ...r, id: r.tenantId }))} columns={[
          { key: "displayName", label: "Customer" },
          { key: "status", label: "Result", render: (r) => <><Pill value={r.status} tone={r.status === "linked" || r.status === "already linked" ? "good" : r.status === "needs attention" ? "bad" : "warn"} />{r.createdCustomer && <span className="small muted"> new Fenrir customer</span>}</> },
          { key: "detail", label: "", render: (r) => r.invitationUrl ? <a href={r.invitationUrl} target="_blank" rel="noreferrer">Invitation link for the customer's Global Administrator</a>
            : <span className="small muted">{displayValue(r.error || (r.consent && r.consent !== "consented" && r.consent !== "already" ? `App consent ${r.consent}` : ""))}</span> },
        ]} />
        <button className="small ghost" onClick={() => setResults(null)}>Close</button>
      </div>}
      <Table rows={customers.map((c) => ({ ...c, id: c.tenantId })) ?? undefined} empty={data ? "Your partner tenant lists no customers. Run the partner check above." : "Loading…"}
             columns={[{ key: "displayName", label: "Customer", render: (c) => <><b>{displayValue(c.displayName || c.defaultDomain)}</b><div className="small muted mono">{c.defaultDomain || c.tenantId}</div></> },
                       { key: "gdap", label: "GDAP", render: (c) => <Pill value={c.gdap} tone={GDAP_TONE[c.gdap]} /> },
                       { key: "sources", label: "Listed in", render: (c) => <span className="small">{c.sources.map((s: string) => s === "contract" ? "CSP" : s === "gdap" ? "GDAP customers" : "GDAP relationships").join(", ")}</span> },
                       { key: "fenrir", label: "Fenrir", render: (c) => c.connectionId ? <Pill value={`linked: ${c.fenrirTenantName}`} tone="good" /> : <span className="small muted">not linked</span> },
                       { key: "act", label: "", className: "right", render: (c) => !c.connectionId && <span className="row" style={{ gap: 6, justifyContent: "flex-end" }}>
                         <button className="small" disabled={busy} onClick={() => importNow([c.tenantId])}>Import</button>
                         {c.gdap !== "active" && c.gdap !== "pending" && <button className="small ghost" disabled={busy} onClick={() => importNow([c.tenantId], true)}>Import and invite to GDAP</button>}</span> }]} />
    </div>
  );
}

function Standards() {
  const { tenantId, can, me } = useApp();
  const tenants = me?.tenants ?? [];
  const { data, reload } = useData<any>("m365/standards", { tenant_id: tenantId });
  const { run, busy } = useAction();
  const [deploy, setDeploy] = useState<{ standard: string; tenantIds: string[]; enforce: boolean; exclude: string } | null>(null);
  const [results, setResults] = useState<any[] | null>(null);
  if (!data) return null;
  const assign = async (standard: string, mode: string) => {
    if (await run(() => api("m365/standards/assignments", { method: "PUT", body: { tenantId, standard, mode } }), "Assignment saved")) reload();
  };
  const latest = (standard: string) => (data.latest || []).filter((r: any) => r.standard === standard && r.action === "evaluate");
  return (
    <>
      <div className="card" style={{ marginTop: 12 }}>
        <div className="row"><h3 style={{ margin: 0, flex: 1 }}>Standards</h3>
          {tenantId && <button className="ghost" disabled={busy} onClick={async () => { if (await run(() => api("m365/standards/evaluate", { body: { tenantId } }), "Checked")) reload(); }}>Check now</button>}</div>
        {!tenantId && <p className="small muted">Choose a customer to assign standards and see their state. Deploy works across many customers at once.</p>}
        <Table rows={data.standards} columns={[
          { key: "title", label: "Standard", render: (s) => <><b>{s.title}</b><div className="small muted">Needs {s.permissions.join(", ")}</div></> },
          ...(tenantId ? [
            { key: "state", label: "State", render: (s: any) => latest(s.id).map((r: any) => <div key={r.connectionId} className="small"><Pill value={r.status} tone={STATUS_TONE[r.status]} /> {displayValue(r.details?.detail || r.details?.error || "")}</div>) },
            { key: "mode", label: "Mode", render: (s: any) => can("m365_admin") ? <select value={data.assignments?.[s.id]?.mode || "off"} onChange={(e) => assign(s.id, e.target.value)} aria-label="Mode">
                {["off", ...data.modes].map((m: string) => <option key={m}>{m}</option>)}</select> : displayValue(data.assignments?.[s.id]?.mode || "off") }] : []),
          ...(can("m365_admin") ? [{ key: "deploy", label: "", render: (s: any) => <button className="ghost" onClick={() => setDeploy({ standard: s.id, tenantIds: tenantId ? [tenantId] : [], enforce: false, exclude: "" })}>Deploy…</button> }] : []),
        ]} />
        <p className="small muted">Report: record state daily. Alert: open a ticket on drift. Remediate: redeploy when drifted. Conditional Access is always deployed report-only unless you choose to enforce it, so its effect can be checked in sign-in logs first.</p>
      </div>
      {deploy && (
        <div className="card">
          <h3>Deploy {displayValue(data.standards.find((s: any) => s.id === deploy.standard)?.title)}</h3>
          <div className="small muted">Customers</div>
          <div className="row" style={{ flexWrap: "wrap" }}>{tenants.filter((t) => t.kind === "customer").map((t) => <label key={t.id} className="small" style={{ display: "flex", gap: 4 }}>
            <input type="checkbox" checked={deploy.tenantIds.includes(t.id)} onChange={(e) => setDeploy({ ...deploy, tenantIds: e.target.checked ? [...deploy.tenantIds, t.id] : deploy.tenantIds.filter((x) => x !== t.id) })} />{t.name}</label>)}</div>
          {deploy.standard !== "intune.windows-compliance" && <>
            <label className="field" style={{ marginTop: 10 }}>Break-glass account object IDs to exclude (comma separated)<input value={deploy.exclude} onChange={(e) => setDeploy({ ...deploy, exclude: e.target.value })} /></label>
            <label className="small" style={{ display: "flex", gap: 6, marginTop: 8 }}><input type="checkbox" checked={deploy.enforce} onChange={(e) => setDeploy({ ...deploy, enforce: e.target.checked })} />Enforce now (otherwise report-only)</label></>}
          <div className="row" style={{ marginTop: 10 }}>
            <button disabled={busy || !deploy.tenantIds.length} onClick={async () => {
              const options = { enforce: deploy.enforce, excludeUserIds: deploy.exclude.split(/[\s,]+/).filter(Boolean) };
              const r = await run(() => api<any>("m365/standards/deploy", { body: { standard: deploy.standard, tenantIds: deploy.tenantIds, options } }));
              if (r) { setResults(r.results); reload(); }
            }}>Deploy to {deploy.tenantIds.length} customer{deploy.tenantIds.length === 1 ? "" : "s"}</button>
            <button className="ghost" onClick={() => { setDeploy(null); setResults(null); }}>Close</button>
          </div>
          {results && <Table rows={results.map((r, i) => ({ ...r, id: String(i) }))} columns={[
            { key: "tenantId", label: "Customer", render: (r) => displayValue(tenants.find((t) => t.id === r.tenantId)?.name || r.tenantId) },
            { key: "status", label: "Result", render: (r) => <Pill value={r.status} tone={STATUS_TONE[r.status]} /> },
            { key: "detail", label: "", render: (r) => <span className="small">{displayValue(r.error || `${r.action || ""} ${r.state || ""}`)}</span> }]} />}
        </div>
      )}
    </>
  );
}

function Reconciliation() {
  const { tenantId, can } = useApp();
  const { data, error, reload } = useData<any>(tenantId ? "m365/reconcile" : null, { tenant_id: tenantId });
  const { run, busy } = useAction();
  if (!tenantId) return <p className="small muted" style={{ marginTop: 12 }}>Choose a customer to reconcile their Microsoft 365 directory with Fenrir.</p>;
  if (!data) return <ErrorNote error={error} />;
  const s = data.summary;
  const apply = async (body: any, message: string) => { if (await run(() => api("m365/reconcile/apply", { body: { tenantId, ...body } }), message)) reload(); };
  return (
    <>
      <div className="grid k4" style={{ marginTop: 12 }}>
        <Stat label="New starters without a contact" value={s.newStarters} />
        <Stat label="Contacts who have left" value={s.leavers} accent={s.leavers ? "amber" : "green"} />
        <Stat label="Without MFA" value={s.withoutMfa} accent={s.adminsWithoutMfa ? "red" : s.withoutMfa ? "amber" : "green"} hint={`${s.adminsWithoutMfa} admins`} />
        <Stat label="Intune devices without Fenrir" value={s.devicesWithoutAgent} accent={s.devicesWithoutAgent ? "amber" : "green"} />
      </div>
      {data.synced === 0 && <p className="small muted">No synced Microsoft 365 connection for this customer yet.</p>}
      <p className="small muted">{!data.coverage.mfa && "MFA registration needs AuditLog.Read.All. "}{!data.coverage.intune && "Device comparison needs DeviceManagementManagedDevices.Read.All. "}</p>
      <div className="grid k2">
        <div className="card"><div className="row"><h3 style={{ margin: 0, flex: 1 }}>New starters</h3>
          {can("crm") && data.newStarters.length > 0 && <button disabled={busy} onClick={() => apply({ addContacts: data.newStarters.map((x: any) => x.userPrincipalName) }, "Contacts added")}>Add all as contacts</button>}</div>
          <Table rows={data.newStarters.map((x: any) => ({ ...x, id: x.userPrincipalName }))} empty="Every licensed user has a contact."
                 columns={[{ key: "displayName", label: "Name" }, { key: "userPrincipalName", label: "Account" }]} /></div>
        <div className="card"><h3>Leavers</h3>
          <Table rows={data.leavers.map((x: any) => ({ ...x, id: x.contactId }))} empty="No contacts have left."
                 columns={[{ key: "name", label: "Contact" }, { key: "reason", label: "Why" },
                           ...(can("crm") ? [{ key: "act", label: "", render: (x: any) => <button className="ghost" disabled={busy} onClick={() => apply({ retireContacts: [x.contactId] }, "Contact marked as left")}>Mark left</button> }] : [])]} /></div>
        <div className="card"><h3>Without MFA</h3>
          <Table rows={data.withoutMfa.map((x: any) => ({ ...x, id: x.userPrincipalName }))} empty="Everyone is registered."
                 columns={[{ key: "userPrincipalName", label: "Account" }, { key: "admin", label: "", render: (x) => x.admin && <Pill value="admin" tone="bad" /> }]} /></div>
        <div className="card"><h3>Intune devices without the Fenrir agent</h3>
          <Table rows={data.devicesWithoutAgent.map((x: any, i: number) => ({ ...x, id: String(i) }))} empty="Every managed device has the agent."
                 columns={[{ key: "deviceName", label: "Device" }, { key: "os", label: "OS" }, { key: "user", label: "User" }]} />
          {data.devicesWithoutAgent.length > 0 && <p className="small"><Link to="/deploy">Deploy the agent</Link></p>}</div>
      </div>
      {data.disabledLicensed.length > 0 && <div className="card"><h3>Disabled accounts still licensed</h3><p className="small">{data.disabledLicensed.join(", ")}</p>
        <p className="small muted">Remove licences through Microsoft 365 administration (reviewed actions).</p></div>}
    </>
  );
}
