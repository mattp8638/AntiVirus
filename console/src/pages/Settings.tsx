import { displayValue } from "../components/DisplayValue";
import { useState } from "react";
import { ago, api, downloadFile, fmtTime, setToken } from "../api";
import { useApp } from "../app-context";
import { Modal, PageHead, Pill, Table, Tabs, TenantSelect, useAction, useData, useListData } from "../components/ui";
import { confirmDialog, promptDialog } from "../components/dialogs";
import { CustomFieldsSettings, RegionSettings } from "../components/Customization";
import { useSearchParams } from "react-router-dom";

const ROLES = ["platform_admin", "msp_admin", "soc_analyst", "technician", "billing", "tenant_admin", "tenant_analyst", "viewer"];

export default function Settings() {
  const { can } = useApp();
  const tabs = ["Tenants", "Users", "Groups", "Custom fields", "Region & holidays", "Webhooks", ...(can("configure") ? ["API credentials"] : []), "Approvals", "Agent releases", "Audit log", ...(can("configure") ? ["Platform"] : []), "Account"];
  const [params] = useSearchParams();
  const [tab, setTab] = useState(() => { const asked = params.get("tab"); return asked && tabs.includes(asked) ? asked : "Tenants"; });
  return (
    <>
      <PageHead title="Settings" subtitle="Tenants, people, device groups, integrations, releases and the tamper-evident audit trail." />
      <Tabs tabs={tabs} active={tab} onChange={setTab} />
      {tab === "Tenants" && <TenantsTab />}
      {tab === "Users" && <UsersTab />}
      {tab === "Groups" && <GroupsTab />}
      {tab === "Custom fields" && <CustomFieldsSettings />}
      {tab === "Region & holidays" && <RegionSettings />}
      {tab === "Webhooks" && <WebhooksTab />}
      {tab === "API credentials" && <ApiCredentialsTab />}
      {tab === "Approvals" && <ApprovalsTab />}
      {tab === "Agent releases" && <>{can("platform") && <RolloutsCard />}<ReleasesTab canPublish={can("platform")} /></>}
      {tab === "Audit log" && <AuditTab />}
      {tab === "Platform" && <PlatformTab />}
      {tab === "Account" && <AccountTab />}
    </>
  );
}

function TenantsTab() {
  const { can, tenantName, refreshMe } = useApp();
  const { data, reload } = useListData<any>("tenants");
  const { data: schema } = useData<any>("policy-schema");
  const [form, setForm] = useState<any>(null);
  const { run, busy } = useAction();
  return (
    <div className="card">
      {can("manage_tenants") && <button className="primary" style={{ marginBottom: 10 }} onClick={() => setForm({ name: "", template: "balanced", plan: "complete" })}>New tenant</button>}
      <Table rows={data} columns={[{ key: "name", label: "Tenant" }, { key: "kind", label: "Type", render: (t) => <Pill value={t.kind} tone={t.kind === "msp" ? "blue" : "muted"} /> },
        { key: "plan", label: "Plan" }, { key: "parentId", label: "Managed by", render: (t) => t.parentId ? tenantName(t.parentId) : "—" }, { key: "createdAt", label: "Created", render: (t) => fmtTime(t.createdAt) }]} />
      {form && (
        <Modal title="New tenant" onClose={() => setForm(null)} footer={<button className="primary" disabled={busy || !form.name}
               onClick={async () => { if (await run(() => api("tenants", { body: form }), "Tenant created")) { setForm(null); reload(); refreshMe(); } }}>Create</button>}>
          <div className="form-grid">
            <label className="field">Name<input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label>
            <label className="field">Plan<select value={form.plan} onChange={(e) => setForm({ ...form, plan: e.target.value })}>{["essentials", "advanced", "complete", "mdr"].map((p) => <option key={p}>{p}</option>)}</select></label>
            <label className="field">Protection template<select value={form.template} onChange={(e) => setForm({ ...form, template: e.target.value })}>{schema?.templates.map((t: any) => <option key={t.key} value={t.key}>{displayValue(t.label)}</option>)}</select></label>
          </div>
        </Modal>
      )}
    </div>
  );
}

function UsersTab() {
  const { tenantId, can, tenantName, me } = useApp();
  const { data, reload } = useData<any[]>("users", { tenant_id: tenantId });
  const { data: roleData, reload: reloadRoles } = useData<any>(can("configure") ? "roles" : null);
  const [form, setForm] = useState<any>(null);
  const [assigning, setAssigning] = useState<any>(null);
  const [roleForm, setRoleForm] = useState<any>(null);
  const { run, busy } = useAction();
  const customRoles: any[] = roleData?.custom || [];
  const roleLabel = (role: string) => customRoles.find((r) => r.role === role)?.name || role.replace(/_/g, " ");
  const roleOptions = [...ROLES.map((r) => ({ value: r, label: r.replace(/_/g, " ") })), ...customRoles.map((r) => ({ value: r.role, label: `${r.name} (custom)` }))];
  return (
    <div className="card">
      {can("configure") && roleData && (
        <details style={{ marginBottom: 12 }}>
          <summary className="row" style={{ cursor: "pointer" }}><b style={{ flex: 1 }}>Custom roles</b><span className="small muted">{customRoles.length}</span></summary>
          <p className="small muted">A custom role gives exactly the permissions you tick, never more than your own. Use it for least-privilege support staff,
            e.g. remote support without running scripts.</p>
          <button style={{ marginBottom: 8 }} onClick={() => setRoleForm({ tenantId: me?.user.tenantId, name: "", description: "", permissions: ["read"] })}>New custom role</button>
          <Table rows={customRoles} empty="No custom roles." columns={[{ key: "name", label: "Role" }, { key: "tenantId", label: "Owned by", render: (r: any) => tenantName(r.tenantId) },
            { key: "permissions", label: "Permissions", render: (r: any) => r.permissions.join(", ") }, { key: "users", label: "Users" },
            { key: "act", label: "", render: (r: any) => <span className="row" style={{ gap: 6 }}>
              <button className="small" onClick={() => setRoleForm({ ...r })}>Edit</button>
              <button className="small danger" disabled={r.users > 0} title={r.users ? "Move its users to another role first" : ""}
                      onClick={async () => { if (await confirmDialog(`Delete the role ${r.name}?`) && await run(() => api(`roles/${r.id}`, { method: "DELETE" }), "Role deleted")) reloadRoles(); }}>Delete</button></span> }]} />
        </details>
      )}
      {can("configure") && <button className="primary" style={{ marginBottom: 10 }} onClick={() => setForm({ email: "", name: "", role: "tenant_analyst", tenantId, password: "" })}>Invite user</button>}
      <Table rows={data} columns={[{ key: "email", label: "Email" }, { key: "name", label: "Name" },
        { key: "role", label: "Role", render: (u) => <>{roleLabel(u.role)}{u.assignedTenantIds?.length ? <div className="small muted">limited to {u.assignedTenantIds.map(tenantName).join(", ")}</div> : null}</> },
        { key: "tenantId", label: "Tenant", render: (u) => tenantName(u.tenantId) }, { key: "active", label: "Status", render: (u) => <Pill value={u.active ? "active" : "disabled"} tone={u.active ? "good" : "muted"} /> },
        { key: "lastLoginAt", label: "Last sign-in", render: (u) => fmtTime(u.lastLoginAt) },
        { key: "mfaEnabled", label: "MFA", render: (u) => <Pill value={u.mfaEnabled ? "on" : "off"} tone={u.mfaEnabled ? "good" : "warn"} /> },
        { key: "act", label: "", render: (u) => <span className="row" style={{ gap: 6 }}>
          {can("configure") && <button className="small" onClick={async () => { await run(() => api(`users/${u.id}`, { method: "PATCH", body: { active: !u.active } }), "User updated"); reload(); }}>{u.active ? "Disable" : "Enable"}</button>}
          {can("configure") && <button className="small" onClick={() => setAssigning({ id: u.id, email: u.email, role: u.role, tenantId: u.tenantId, assignedTenantIds: u.assignedTenantIds || [] })}>Role &amp; customers</button>}
          {can("manage_tenants") && u.mfaEnabled && <button className="small" title="For a user who lost their phone" onClick={async () => { if (await confirmDialog(`Reset MFA for ${u.email}? They will need to set it up again.`)) { await run(() => api(`users/${u.id}/mfa/reset`, { method: "POST" }), "MFA reset"); reload(); } }}>Reset MFA</button>}
        </span> }]} />
      {form && (
        <Modal title="Invite user" onClose={() => setForm(null)} footer={<button className="primary" disabled={busy}
               onClick={async () => { if (await run(() => api("users", { body: form }), "User created")) { setForm(null); reload(); } }}>Create</button>}>
          <div className="form-grid">
            <label className="field">Email<input type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></label>
            <label className="field">Name<input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label>
            <label className="field">Tenant<TenantSelect value={form.tenantId} onChange={(id) => setForm({ ...form, tenantId: id })} allowAll={false} /></label>
            <label className="field">Role<select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>{roleOptions.map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}</select></label>
            <label className="field">Temporary password (12+)<input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></label>
          </div>
        </Modal>
      )}
      {assigning && (
        <Modal title={`Role and customers: ${assigning.email}`} onClose={() => setAssigning(null)} footer={<button className="primary" disabled={busy}
               onClick={async () => { if (await run(() => api(`users/${assigning.id}`, { method: "PATCH", body: { role: assigning.role, assignedTenantIds: assigning.assignedTenantIds } }), "User updated")) { setAssigning(null); reload(); } }}>Save</button>}>
          <label className="field">Role<select value={assigning.role} onChange={(e) => setAssigning({ ...assigning, role: e.target.value })}>{roleOptions.map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}</select></label>
          <div className="field">Limit to these customers (none ticked: every customer under {tenantName(assigning.tenantId)})
            {(me?.tenants || []).filter((t: any) => t.id !== assigning.tenantId).map((t: any) => <label key={t.id} className="row" style={{ gap: 6 }}>
              <input type="checkbox" checked={assigning.assignedTenantIds.includes(t.id)} onChange={(e) => setAssigning({ ...assigning, assignedTenantIds: e.target.checked
                ? [...assigning.assignedTenantIds, t.id] : assigning.assignedTenantIds.filter((x: string) => x !== t.id) })} />{t.name}</label>)}</div>
        </Modal>
      )}
      {roleForm && (
        <Modal title={roleForm.id ? `Edit ${roleForm.name}` : "New custom role"} onClose={() => setRoleForm(null)} footer={<button className="primary" disabled={busy || !roleForm.name || !roleForm.permissions.length}
               onClick={async () => { const body = { name: roleForm.name, description: roleForm.description, permissions: roleForm.permissions, ...(roleForm.id ? {} : { tenantId: roleForm.tenantId }) };
                 if (await run(() => api(roleForm.id ? `roles/${roleForm.id}` : "roles", { method: roleForm.id ? "PATCH" : "POST", body }), "Role saved")) { setRoleForm(null); reloadRoles(); } }}>Save</button>}>
          <label className="field">Name<input value={roleForm.name} onChange={(e) => setRoleForm({ ...roleForm, name: e.target.value })} placeholder="e.g. Remote support" /></label>
          {!roleForm.id && <label className="field">Owned by<TenantSelect allowAll={false} value={roleForm.tenantId} onChange={(id) => setRoleForm({ ...roleForm, tenantId: id })} /></label>}
          <label className="field">Description<input value={roleForm.description} onChange={(e) => setRoleForm({ ...roleForm, description: e.target.value })} /></label>
          <div className="field">Permissions
            {(roleData?.permissions || []).map((p: any) => <label key={p.key} className="row" style={{ gap: 6, opacity: p.grantable ? 1 : 0.5 }}>
              <input type="checkbox" disabled={!p.grantable} checked={roleForm.permissions.includes(p.key)} onChange={(e) => setRoleForm({ ...roleForm, permissions: e.target.checked
                ? [...roleForm.permissions, p.key] : roleForm.permissions.filter((x: string) => x !== p.key) })} /><b>{p.key}</b> <span className="small muted">{p.label}</span></label>)}</div>
        </Modal>
      )}
    </div>
  );
}

function GroupsTab() {
  const { tenantId, can, tenantName } = useApp();
  const { data, reload } = useListData<any>("groups", { tenant_id: tenantId });
  const { data: policies } = useListData<any>("policies", { tenant_id: tenantId });
  const [form, setForm] = useState<any>(null);
  const { run, busy } = useAction();
  return (
    <div className="card">
      {can("configure") && <button className="primary" style={{ marginBottom: 10 }} onClick={() => setForm({ name: "", tenantId, policyId: "" })}>New group</button>}
      <Table rows={data} empty="No groups. Groups let you apply different policies to servers, laptops, kiosks…"
             columns={[{ key: "name", label: "Group" }, { key: "tenantId", label: "Tenant", render: (g) => tenantName(g.tenantId) },
                       { key: "policyId", label: "Policy", render: (g) => policies?.find((p) => p.id === g.policyId)?.name ?? "Inherit" }]} />
      {form && (
        <Modal title="New group" onClose={() => setForm(null)} footer={<button className="primary" disabled={busy || !form.tenantId}
               onClick={async () => { if (await run(() => api("groups", { body: { ...form, policyId: form.policyId || null } }), "Group created")) { setForm(null); reload(); } }}>Create</button>}>
          <div className="form-grid">
            <label className="field">Tenant<TenantSelect value={form.tenantId} onChange={(id) => setForm({ ...form, tenantId: id })} allowAll={false} /></label>
            <label className="field">Name<input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label>
            <label className="field">Policy<select value={form.policyId} onChange={(e) => setForm({ ...form, policyId: e.target.value })}><option value="">Inherit from tenant</option>
              {policies?.filter((p) => p.tenantId === form.tenantId).map((p) => <option key={p.id} value={p.id}>{displayValue(p.name)}</option>)}</select></label>
          </div>
        </Modal>
      )}
    </div>
  );
}

function WebhooksTab() {
  const { can, tenantId } = useApp();
  const { data, reload } = useListData<any>("webhooks");
  const [form, setForm] = useState<any>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const { run, busy } = useAction();
  return (
    <div className="card">
      {can("configure") && <button className="primary" style={{ marginBottom: 10 }} onClick={() => setForm({ name: "", url: "https://", kind: "slack", events: ["incident.created"], tenantId })}>Add webhook</button>}
      {secret && <p>Signing secret (shown once): <code>{secret}</code>. Verify the <code>X-Fenrir-Signature</code> header with HMAC-SHA256.</p>}
      <Table rows={data} empty="No webhooks. Send incidents to Slack, Teams or your own systems."
             columns={[{ key: "name", label: "Name" }, { key: "kind", label: "Type" }, { key: "url", label: "URL", render: (w) => <span className="mono small">{displayValue(w.url)}</span> },
                       { key: "events", label: "Events", render: (w) => w.events.join(", ") },
                       { key: "del", label: "", render: (w) => can("configure") && <button className="small danger" onClick={async () => { await run(() => api(`webhooks/${w.id}`, { method: "DELETE" }), "Removed"); reload(); }}>Remove</button> }]} />
      {form && (
        <Modal title="Add webhook" onClose={() => setForm(null)} footer={<button className="primary" disabled={busy}
               onClick={async () => { const r = await run(() => api<any>("webhooks", { body: form }), "Webhook added"); if (r) { setSecret(r.secret); setForm(null); reload(); } }}>Add</button>}>
          <div className="form-grid">
            <label className="field">Name<input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label>
            <label className="field">Type<select value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value })}><option>slack</option><option>teams</option><option>generic</option></select></label>
            <label className="field">URL<input value={form.url} onChange={(e) => setForm({ ...form, url: e.target.value })} /></label>
            <label className="field">Events<select multiple value={form.events} onChange={(e) => setForm({ ...form, events: [...e.target.selectedOptions].map((o) => o.value) })}>
              <option>incident.created</option><option>alert.automation</option><option value="*">everything</option></select></label>
          </div>
        </Modal>
      )}
    </div>
  );
}

const APPROVAL_TONE: Record<string, string> = { pending: "warn", approved: "good", executed: "muted", rejected: "bad", expired: "muted" };

// Two-person approval (CORE-15): held requests, decisions, "Run now" for the requester, and the customer's policy.
function ApprovalsTab() {
  const { tenantId, tenantName, can } = useApp();
  const { data, reload } = useData<any[]>("approvals", { tenant_id: tenantId });
  const { data: policy, reload: reloadPolicy } = useData<any>(tenantId ? `tenants/${tenantId}/approval-policy` : null, {}, [tenantId]);
  const { run, busy } = useAction();
  const decide = async (id: string, verdict: "approve" | "reject") => {
    const reason = verdict === "reject" ? await promptDialog("Why reject it?") : "";
    if (reason === null) return;
    if (await run(() => api(`approvals/${id}/${verdict}`, { body: { reason } }), verdict === "approve" ? "Approved: the requester can now run it" : "Rejected")) reload();
  };
  const runNow = async (a: any) => {
    const { _route, ...request } = a.request;
    if (await run(() => api(_route, { body: { ...request, approvalId: a.id } }), "Started")) reload();
  };
  return (
    <>
      {tenantId && policy && (
        <div className="card" style={{ marginBottom: 14 }}>
          <div className="row" style={{ gap: 10, flexWrap: "wrap" }}>
            <b style={{ flex: 1 }}>Two-person approval for {tenantName(tenantId)}</b>
            <Pill value={policy.effective.twoPerson ? `on${policy.effective.tenantId !== tenantId ? ` (from ${tenantName(policy.effective.tenantId)})` : ""}` : "off"} tone={policy.effective.twoPerson ? "good" : "muted"} />
            {can("configure") && can("approve") && <button disabled={busy} onClick={async () => {
              const threshold = policy.twoPerson ? null : await promptDialog("Hold scripts and bulk actions that reach at least how many devices?", String(policy.bulkThreshold));
              if (!policy.twoPerson && threshold === null) return;
              if (await run(() => api(`tenants/${tenantId}/approval-policy`, { method: "PUT", body: { twoPerson: !policy.twoPerson, bulkThreshold: Number(threshold || policy.bulkThreshold) } }), "Approval policy saved")) reloadPolicy();
            }}>{policy.twoPerson ? "Turn off" : "Turn on"}</button>}
          </div>
          <p className="small muted" style={{ marginBottom: 0 }}>When on, destructive device actions and scripts or bulk actions reaching {policy.bulkThreshold}+ devices wait for someone other than the
            requester to approve. The approval covers exactly that request and those devices, for one hour, once.</p>
        </div>
      )}
      <div className="card">
        <Table rows={data} empty="Nothing waiting for approval."
               columns={[{ key: "summary", label: "Request", render: (a: any) => <>{a.summary}<div className="small muted">{a.kind} · {a.devices} device(s) · {tenantName(a.tenantId)}</div></> },
                         { key: "requestedBy", label: "Requested by", render: (a: any) => <>{a.requestedBy}<div className="small muted">{fmtTime(a.requestedAt)}</div></> },
                         { key: "status", label: "Status", render: (a: any) => <><Pill value={a.status} tone={APPROVAL_TONE[a.status]} />{a.decidedBy && <div className="small muted">{a.decidedBy}{a.reason ? `: ${a.reason}` : ""}</div>}</> },
                         { key: "expiresAt", label: "Valid until", render: (a: any) => ["pending", "approved"].includes(a.status) ? fmtTime(a.expiresAt) : "—" },
                         { key: "act", label: "", render: (a: any) => <span className="row" style={{ gap: 6 }}>
                           {a.status === "pending" && !a.mine && can("approve") && <><button className="small primary" disabled={busy} onClick={() => decide(a.id, "approve")}>Approve</button>
                             <button className="small" disabled={busy} onClick={() => decide(a.id, "reject")}>Reject</button></>}
                           {a.status === "approved" && a.mine && <button className="small primary" disabled={busy} onClick={() => runNow(a)}>Run now</button>}
                         </span> }]} />
      </div>
    </>
  );
}

const CREDENTIAL_TONE: Record<string, string> = { active: "good", expired: "warn", revoked: "muted" };

// Scoped API credentials (CORE-04): an integration signs in as its own service identity with only the permissions
// chosen here, within one customer, until it expires. The token is shown once.
function ApiCredentialsTab() {
  const { tenantId, tenantName } = useApp();
  const { data, reload } = useData<any>("api-credentials");
  const [form, setForm] = useState<any>(null);
  const [shown, setShown] = useState<any>(null);
  const { run, busy } = useAction();
  const create = async () => {
    const made = await run(() => api<any>("api-credentials", { body: { ...form, expiresDays: Number(form.expiresDays) } }), "API credential created");
    if (made) { setForm(null); setShown(made); reload(); }
  };
  const rotate = async (id: string) => {
    if (!await confirmDialog("Rotate this credential? The current token stops working immediately.")) return;
    const made = await run(() => api<any>(`api-credentials/${id}/rotate`, { body: {} }), "Credential rotated");
    if (made) { setShown(made); reload(); }
  };
  const revoke = async (id: string) => {
    if (await confirmDialog("Revoke this credential? Integrations using it stop working.") && await run(() => api(`api-credentials/${id}/revoke`, { body: {} }), "Credential revoked")) reload();
  };
  return (
    <div className="card">
      <p className="small muted" style={{ marginTop: 0 }}>For integrations (PSA, documentation, scripts). Each credential acts as its own service identity with only the
        permissions you choose, for one customer, until it expires. It can never reveal secrets, approve sensitive actions or manage the platform.</p>
      <button className="primary" style={{ marginBottom: 10 }} onClick={() => setForm({ tenantId, name: "", scopes: ["read"], expiresDays: 90 })}>New API credential</button>
      <Table rows={data?.credentials} empty="No API credentials."
             columns={[{ key: "name", label: "Name", render: (c: any) => <>{displayValue(c.name)}<div className="small mono muted">{displayValue(c.prefix)}…</div></> },
                       { key: "tenantId", label: "Customer", render: (c: any) => tenantName(c.tenantId) },
                       { key: "scopes", label: "Permissions", render: (c: any) => c.scopes.join(", ") },
                       { key: "state", label: "State", render: (c: any) => <Pill value={c.state} tone={CREDENTIAL_TONE[c.state]} /> },
                       { key: "expiresAt", label: "Expires", render: (c: any) => fmtTime(c.expiresAt) },
                       { key: "lastUsedAt", label: "Last used", render: (c: any) => c.lastUsedAt ? <>{ago(c.lastUsedAt)}<div className="small muted">{displayValue(c.lastUsedIp)} · {displayValue(c.useCount)} calls</div></> : "never" },
                       { key: "actions", label: "", render: (c: any) => c.state !== "revoked" && <div className="row" style={{ gap: 4 }}>
                         <button disabled={busy} onClick={() => rotate(c.id)}>Rotate</button><button className="danger" disabled={busy} onClick={() => revoke(c.id)}>Revoke</button></div> }]} />
      {form && (
        <Modal title="New API credential" onClose={() => setForm(null)} footer={<button className="primary" disabled={busy || !form.name || !form.scopes.length} onClick={create}>Create</button>}>
          <label className="field">Name<input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="e.g. Documentation sync" /></label>
          <label className="field">Customer<TenantSelect allowAll={false} value={form.tenantId} onChange={(v: string) => setForm({ ...form, tenantId: v })} /></label>
          <div className="field">Permissions
            {(data?.grantable || []).map((s: string) => <label key={s} className="row" style={{ gap: 6 }}><input type="checkbox" checked={form.scopes.includes(s)}
              onChange={(e) => setForm({ ...form, scopes: e.target.checked ? [...form.scopes, s] : form.scopes.filter((x: string) => x !== s) })} />{s}</label>)}</div>
          <label className="field">Expires after (days)<input type="number" min={1} max={365} value={form.expiresDays} onChange={(e) => setForm({ ...form, expiresDays: e.target.value })} /></label>
        </Modal>
      )}
      {shown && (
        <Modal title="Copy the token now" onClose={() => setShown(null)}>
          <p className="small">This is the only time the token is shown. Store it in the integration's secret store.</p>
          <input readOnly className="mono" value={shown.token} onFocus={(e) => e.target.select()} style={{ width: "100%" }} />
        </Modal>
      )}
    </div>
  );
}

const ROLLOUT_TONE: Record<string, string> = { active: "warn", paused: "bad", stopped: "bad", complete: "good", superseded: "muted" };

// Staged agent rollouts (AGT-04): each new build goes canary -> beta -> stable -> lts by the devices' "Release ring"
// policy, and pauses itself if a device in the current stage fails to come back on the new build.
function RolloutsCard() {
  const { data, reload } = useData<any>("agent-rollouts");
  const { run, busy } = useAction();
  const act = async (id: string, action: string, ask?: string) => {
    const reason = ask ? await promptDialog(ask) : "";
    if (reason === null) return;
    if (await run(() => api(`agent-rollouts/${id}/action`, { body: { action, reason: reason || "" } }), "Rollout updated")) reload();
  };
  return (
    <div className="card" style={{ marginBottom: 14 }}>
      <h3 style={{ marginTop: 0 }}>Agent rollouts</h3>
      <p className="small muted">New agent builds reach devices ring by ring ({displayValue((data?.stages || []).join(" → "))}), set by each device's
        Release ring policy. A failure in the current ring pauses the rollout before the next ring gets the build.</p>
      <Table rows={data?.rollouts} empty="No agent build has been rolled out yet."
             columns={[{ key: "platform", label: "Platform" }, { key: "version", label: "Build", render: (r: any) => <>{displayValue(r.version || "—")} <span className="mono small muted">{displayValue(r.build.slice(0, 10))}</span></> },
                       { key: "stage", label: "Ring reached" },
                       { key: "state", label: "State", render: (r: any) => <><Pill value={r.state} tone={ROLLOUT_TONE[r.state]} />{r.reason && <div className="small muted">{displayValue(r.reason)}</div>}</> },
                       { key: "devices", label: "Devices", render: (r: any) => `${r.devices.updated} updated · ${r.devices.pending} pending · ${r.devices.failed} failed` },
                       { key: "startedAt", label: "Started", render: (r: any) => fmtTime(r.startedAt) },
                       { key: "actions", label: "", render: (r: any) => <div className="row" style={{ gap: 4 }}>
                         {r.state === "active" && <button disabled={busy} onClick={() => act(r.id, "pause", "Why pause this rollout?")}>Pause</button>}
                         {r.state === "paused" && <button disabled={busy} onClick={() => act(r.id, "resume")}>Resume</button>}
                         {["active", "paused"].includes(r.state) && r.stage !== "lts" && <button disabled={busy} onClick={() => act(r.id, "advance")}>Next ring</button>}
                         {["active", "paused", "complete"].includes(r.state) && <button className="danger" disabled={busy} onClick={() => act(r.id, "stop", "Emergency stop: why? Devices will not be offered this build again.")}>Stop</button>}
                       </div> }]} />
    </div>
  );
}

function ReleasesTab({ canPublish }: { canPublish: boolean }) {
  const { data, reload } = useListData<any>("releases");
  const [form, setForm] = useState<any>(null);
  const { run, busy } = useAction();
  return (
    <div className="card">
      {canPublish && <button className="primary" style={{ marginBottom: 10 }} onClick={() => setForm({ platform: "windows", channel: "stable", component: "agent", version: "", url: "", sha256: "", notes: "" })}>Publish release</button>}
      <Table rows={data} empty="No releases published. Agents keep their current version."
             columns={[{ key: "platform", label: "Platform" }, { key: "component", label: "Component" }, { key: "version", label: "Version" }, { key: "channel", label: "Ring" },
                       { key: "sha256", label: "SHA-256", render: (r) => <span className="mono small">{displayValue(r.sha256.slice(0, 16))}…</span> }, { key: "publishedAt", label: "Published", render: (r) => fmtTime(r.publishedAt) }]} />
      {form && (
        <Modal title="Publish release" onClose={() => setForm(null)} footer={<button className="primary" disabled={busy}
               onClick={async () => { if (await run(() => api("releases", { body: form }), "Release published")) { setForm(null); reload(); } }}>Publish</button>}>
          <div className="form-grid">
            {["platform", "channel", "component", "version", "url", "sha256", "signature", "notes"].map((k) => (
              <label key={k} className="field">{k}<input value={form[k] ?? ""} onChange={(e) => setForm({ ...form, [k]: e.target.value })} /></label>
            ))}
          </div>
          <p className="small muted">The URL should point at a signed update manifest (see agent/windows/installer/GenerateUpdateManifest.ps1).</p>
        </Modal>
      )}
    </div>
  );
}

const BREAK_LABEL: Record<string, string> = { modified: "entry changed after it was written", deleted: "entries missing",
  "legacy-race": "old concurrent-write race (not tampering)", relinked: "entries inserted or reordered", checkpoint: "rewritten since a checkpoint" };

function AuditTab() {
  const { tenantId, can } = useApp();
  const { data, reload } = useListData<any>("audit", { tenant_id: tenantId });
  const [verify, setVerify] = useState<any>(null);
  const { run, busy } = useAction();
  return (
    <>
      <div className="card" style={{ marginBottom: 14 }}>
        <div className="row" style={{ marginBottom: 10, flexWrap: "wrap" }}>
          {can("manage_tenants") && <button disabled={busy} onClick={async () => setVerify(await run(() => api("audit/verify")))}>Verify integrity</button>}
          {can("manage_tenants") && <button disabled={busy} onClick={async () => { if (await run(() => api("audit/checkpoints", { body: { reason: "manual" } }), "Checkpoint recorded and sent to webhooks")) reload(); }}>Record checkpoint</button>}
          {can("configure") && <button disabled={busy} onClick={() => run(() => downloadFile("audit/export", "fenrir-audit.jsonl"))}>Export (verifiable)</button>}
          {verify && (verify.valid ? <Pill value={`chain intact · ${verify.checked} entries${verify.anchor ? ` since position ${verify.anchor.seq}` : ""}`} tone="good" />
            : <Pill value={verify.tampered ? "tampering detected" : "only old race breaks (not tampering)"} tone={verify.tampered ? "bad" : "warn"} />)}
        </div>
        {verify && !verify.valid && (
          <ul className="small">{verify.breaks.slice(0, 20).map((b: any, i: number) => <li key={i}>Position {displayValue(b.seq ?? "?")}: {displayValue(BREAK_LABEL[b.kind] || b.kind)}{b.at ? ` (${fmtTime(b.at)})` : ""}</li>)}</ul>
        )}
        <p className="small muted" style={{ margin: 0 }}>Checkpoints record the chain's newest hash and are sent to your webhooks, so a copy lives outside Fenrir.
          Check an export offline with <span className="mono">scripts/verify_audit_export.py</span>; other customers' entries in it are reduced to their hashes.</p>
        {can("platform") && <AuditPolicyCard />}
      </div>
      <div className="card">
        <Table rows={data} columns={[{ key: "at", label: "When", render: (r) => fmtTime(r.at) }, { key: "actor", label: "Who" }, { key: "action", label: "Action" },
          { key: "target", label: "Target" }, { key: "details", label: "Details", render: (r) => <span className="mono small">{JSON.stringify(r.details).slice(0, 120)}</span> }]} />
      </div>
    </>
  );
}

function AuditPolicyCard() {
  const { data, reload } = useData<any>("audit/policy");
  const [form, setForm] = useState<any>(null);
  const { run, busy } = useAction();
  if (!data) return null;
  const save = async () => {
    const body = { retentionDays: form.retentionDays ? Number(form.retentionDays) : null, legalHold: form.legalHold, holdReason: form.holdReason };
    if (await run(() => api("audit/policy", { method: "PUT", body }), "Audit retention saved")) { setForm(null); reload(); }
  };
  return (
    <div className="row" style={{ marginTop: 10, gap: 10, flexWrap: "wrap" }}>
      <span className="small">Retention: <b>{data.retentionDays ? `${data.retentionDays} days` : "keep everything"}</b></span>
      {data.legalHold && <Pill value={`legal hold: ${data.holdReason}`} tone="warn" />}
      <button onClick={() => setForm({ retentionDays: data.retentionDays ?? "", legalHold: data.legalHold, holdReason: data.holdReason })}>Change</button>
      {form && (
        <Modal title="Audit retention and legal hold" onClose={() => setForm(null)} footer={<button className="primary" disabled={busy} onClick={save}>Save</button>}>
          <label className="field">Keep entries for (days, 365 to 3650; empty keeps everything)<input type="number" min={365} max={3650} value={form.retentionDays}
            onChange={(e) => setForm({ ...form, retentionDays: e.target.value })} /></label>
          <p className="small muted">Old entries are removed only up to a checkpoint, which then anchors verification.</p>
          <label className="field row" style={{ gap: 8 }}><input type="checkbox" checked={form.legalHold} onChange={(e) => setForm({ ...form, legalHold: e.target.checked })} />Legal hold (nothing is removed)</label>
          {form.legalHold && <label className="field">Reason<input value={form.holdReason} onChange={(e) => setForm({ ...form, holdReason: e.target.value })} /></label>}
        </Modal>
      )}
    </div>
  );
}

function MfaCard() {
  const { me, refreshMe } = useApp();
  const [setup, setSetup] = useState<{ secret: string; otpauthUri: string } | null>(null);
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const { run, busy } = useAction();
  const enabled = !!me?.user.mfaEnabled;
  return (
    <div className="card" style={{ maxWidth: 520, marginTop: 14 }}>
      <h3 style={{ marginTop: 0 }}>Two-step sign-in (MFA) <Pill value={enabled ? "on" : "off"} tone={enabled ? "good" : "warn"} /></h3>
      {!enabled && !setup && <>
        <p className="muted">Use an authenticator app (Microsoft Authenticator, Google Authenticator, 1Password…) for a code at each sign-in.</p>
        <button className="primary" disabled={busy} onClick={async () => setSetup((await run(() => api("auth/mfa/setup", { method: "POST" }))) ?? null)}>Set up MFA</button>
      </>}
      {!enabled && setup && <>
        <p>In your authenticator app, add an account with this key (or open the link on your phone):</p>
        <p className="mono" style={{ wordBreak: "break-all", fontSize: 16 }}>{setup.secret.replace(/(.{4})/g, "$1 ").trim()}</p>
        <p className="small"><a href={setup.otpauthUri}>Open in authenticator app</a></p>
        <label className="field">Code from the app<input inputMode="numeric" maxLength={6} value={code} onChange={(e) => setCode(e.target.value)} /></label>
        <button className="primary" style={{ marginTop: 10 }} disabled={busy || code.length !== 6}
                onClick={async () => { if (await run(() => api("auth/mfa/enable", { body: { code } }), "MFA is on")) { setSetup(null); setCode(""); refreshMe(); } }}>Turn on MFA</button>
      </>}
      {enabled && <>
        <p className="muted">To turn MFA off, confirm your password and a current code.</p>
        <div className="form-grid">
          <label className="field">Password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} /></label>
          <label className="field">Code<input inputMode="numeric" maxLength={6} value={code} onChange={(e) => setCode(e.target.value)} /></label>
        </div>
        <button className="danger" style={{ marginTop: 10 }} disabled={busy || !password || code.length !== 6}
                onClick={async () => { if (await run(() => api("auth/mfa/disable", { body: { password, code } }), "MFA is off")) { setPassword(""); setCode(""); refreshMe(); } }}>Turn off MFA</button>
      </>}
    </div>
  );
}

function ReadinessCard() {
  const { data } = useData<any>("platform/readiness");
  if (!data) return null;
  return (
    <div className="card" style={{ marginBottom: 14 }}>
      <div className="row"><b style={{ flex: 1 }}>Production readiness</b>
        <Pill value={data.environment} tone={data.environment === "production" ? "good" : "warn"} />
        <Pill value={`schema ${data.schemaVersion}/${data.expectedSchemaVersion}`} tone={data.schemaVersion === data.expectedSchemaVersion ? "good" : "bad"} /></div>
      {data.warnings.length ? <ul className="small">{data.warnings.map((w: string) => <li key={w}>{w}</li>)}</ul>
        : <p className="small muted">No warnings. Unsafe settings stop the server from starting in production.</p>}
    </div>
  );
}

function PlatformTab() {
  const { can } = useApp();
  const { data, error, reload } = useData<any>("platform/status");
  const { data: dead, reload: reloadDead } = useListData<any>("platform/events", { status: "dead" });
  const { run } = useAction();
  return (
    <>
      {can("platform") && <ReadinessCard />}
      <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))" }}>
        <div className="card"><div className="label muted small">Vault encryption</div>
          <p><b>{displayValue(data?.vault.algorithm ?? "…")}</b></p>
          <p>Key {displayValue(data?.vault.keyId)} · {data?.vault.source === "derived" ? <Pill value="derived from FENRIR_SECRET_KEY" tone="warn" /> : <Pill value={`from ${data?.vault.source ?? "…"}`} tone="good" />}</p>
          {data && !data.vault.productionReady && <p className="small muted">Set FENRIR_VAULT_KEY (openssl rand -base64 32) before storing production secrets.</p>}
        </div>
        <div className="card"><div className="label muted small">Automation events</div>
          <p>{displayValue(data?.events.pending ?? 0)} waiting · {displayValue(data?.events.done ?? 0)} done · <b>{displayValue(data?.events.dead ?? 0)} failed</b></p></div>
        <div className="card"><div className="label muted small">Event handlers</div>
          <p className="small">{Object.entries(data?.handlers ?? {}).map(([k, v]: any) => `${k} (${v.length})`).join(", ") || "none"}</p></div>
      </div>
      {error && <p className="muted">{error}</p>}
      {can("platform") && <div className="card" style={{ marginTop: 14 }}>
        <h3 style={{ marginTop: 0 }}>Background jobs</h3>
        <p className="small muted">Scheduled work the server runs by itself. Each job runs on its own, so one failing job does not stop the others.</p>
        <Table rows={(data?.jobs ?? []).map((j: any) => ({ ...j, id: j.name }))} empty="No job has run yet. Jobs start about 30 seconds after the server starts."
               columns={[{ key: "name", label: "Job", render: (j) => <span className="mono small">{j.name}</span> },
                         { key: "ok", label: "Last run", render: (j) => <Pill value={j.ok ? "ok" : j.failures > 1 ? `failed ${j.failures}× in a row` : "failed"} tone={j.ok ? "good" : "bad"} /> },
                         { key: "lastRunAt", label: "When", render: (j) => j.lastRunAt ? ago(j.lastRunAt) : "" },
                         { key: "lastOkAt", label: "Last success", render: (j) => j.lastOkAt ? ago(j.lastOkAt) : "never" },
                         { key: "durationMs", label: "Took", className: "right", render: (j) => `${(j.durationMs / 1000).toFixed(1)} s` },
                         { key: "error", label: "Error", render: (j) => <span className="small">{displayValue(j.error)}</span> }]} />
      </div>}
      <div className="card" style={{ marginTop: 14 }}>
        <h3 style={{ marginTop: 0 }}>Failed automation events</h3>
        <Table rows={dead} empty="No failed events."
               columns={[{ key: "id", label: "#" }, { key: "type", label: "Type" }, { key: "attempts", label: "Attempts" },
                         { key: "lastError", label: "Last error", render: (e) => <span className="small">{displayValue(e.lastError)}</span> },
                         { key: "createdAt", label: "Raised", render: (e) => fmtTime(e.createdAt) },
                         { key: "retry", label: "", render: (e) => <button className="small" onClick={async () => { await run(() => api(`platform/events/${e.id}/retry`, { method: "POST" }), "Queued for retry"); reload(); reloadDead(); }}>Retry</button> }]} />
      </div>
    </>
  );
}

function AccountTab() {
  const { me } = useApp();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const { run, busy } = useAction();
  return (
    <>
    <div className="card" style={{ maxWidth: 520 }}>
      <p>Signed in as <b>{me?.user.email}</b> ({me?.user.role.replace(/_/g, " ")}).</p>
      <label className="field">Current password<input type="password" value={current} onChange={(e) => setCurrent(e.target.value)} /></label>
      <label className="field" style={{ marginTop: 10 }}>New password (12+ characters)<input type="password" value={next} onChange={(e) => setNext(e.target.value)} /></label>
      <button className="primary" style={{ marginTop: 12 }} disabled={busy || next.length < 12}
              onClick={async () => { const result = await run(() => api<any>("auth/password", { body: { currentPassword: current, newPassword: next } }), "Password changed. Your other sessions were signed out.");
                if (result) { if (result.token) setToken(result.token); setCurrent(""); setNext(""); } }}>Change password</button>
    </div>
    <MfaCard />
    <SessionsCard />
    </>
  );
}

function SessionsCard() {
  const { data, reload } = useListData<any>("auth/sessions");
  const { run, busy } = useAction();
  return (
    <div className="card" style={{ maxWidth: 720, marginTop: 16 }}>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h3 style={{ margin: 0 }}>Where you're signed in</h3>
        {(data || []).length > 1 && <button className="small" disabled={busy} onClick={async () => { if (await run(() => api("auth/sessions/revoke-others", { method: "POST" }), "Signed out everywhere else")) reload(); }}>Sign out everywhere else</button>}
      </div>
      {(data || []).map((s) => (
        <div key={s.id} className="row small" style={{ padding: "6px 0", borderBottom: "1px solid var(--line)" }}>
          <span style={{ flex: 1 }}><b>{displayValue(s.current ? "This browser" : s.userAgent.split(")")[0].replace("(", "· ") || "Unknown browser")}</b>
            <div className="muted">{displayValue(s.ip || "unknown address")} · signed in {fmtTime(s.createdAt)} · active {ago(s.lastSeenAt)}</div></span>
          {!s.current && <button className="small" disabled={busy} onClick={async () => { if (await run(() => api(`auth/sessions/${s.id}`, { method: "DELETE" }), "Signed out")) reload(); }}>Sign out</button>}
        </div>
      ))}
    </div>
  );
}
