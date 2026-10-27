import { useState } from "react";
import { ago, api, fmtTime, setToken } from "../api";
import { useApp } from "../app-context";
import { Modal, PageHead, Pill, Table, Tabs, TenantSelect, useAction, useData } from "../components/ui";

const ROLES = ["platform_admin", "msp_admin", "soc_analyst", "technician", "billing", "tenant_admin", "tenant_analyst", "viewer"];

export default function Settings() {
  const { can } = useApp();
  const tabs = ["Tenants", "Users", "Groups", "Webhooks", "Agent releases", "Audit log", ...(can("configure") ? ["Platform"] : []), "Account"];
  const [tab, setTab] = useState("Tenants");
  return (
    <>
      <PageHead title="Settings" subtitle="Tenants, people, device groups, integrations, releases and the tamper-evident audit trail." />
      <Tabs tabs={tabs} active={tab} onChange={setTab} />
      {tab === "Tenants" && <TenantsTab />}
      {tab === "Users" && <UsersTab />}
      {tab === "Groups" && <GroupsTab />}
      {tab === "Webhooks" && <WebhooksTab />}
      {tab === "Agent releases" && <ReleasesTab canPublish={can("platform")} />}
      {tab === "Audit log" && <AuditTab />}
      {tab === "Platform" && <PlatformTab />}
      {tab === "Account" && <AccountTab />}
    </>
  );
}

function TenantsTab() {
  const { can, tenantName, refreshMe } = useApp();
  const { data, reload } = useData<any[]>("tenants");
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
            <label className="field">Protection template<select value={form.template} onChange={(e) => setForm({ ...form, template: e.target.value })}>{schema?.templates.map((t: any) => <option key={t.key} value={t.key}>{t.label}</option>)}</select></label>
          </div>
        </Modal>
      )}
    </div>
  );
}

function UsersTab() {
  const { tenantId, can, tenantName } = useApp();
  const { data, reload } = useData<any[]>("users", { tenant_id: tenantId });
  const [form, setForm] = useState<any>(null);
  const { run, busy } = useAction();
  return (
    <div className="card">
      {can("configure") && <button className="primary" style={{ marginBottom: 10 }} onClick={() => setForm({ email: "", name: "", role: "tenant_analyst", tenantId, password: "" })}>Invite user</button>}
      <Table rows={data} columns={[{ key: "email", label: "Email" }, { key: "name", label: "Name" }, { key: "role", label: "Role", render: (u) => u.role.replace(/_/g, " ") },
        { key: "tenantId", label: "Tenant", render: (u) => tenantName(u.tenantId) }, { key: "active", label: "Status", render: (u) => <Pill value={u.active ? "active" : "disabled"} tone={u.active ? "good" : "muted"} /> },
        { key: "lastLoginAt", label: "Last sign-in", render: (u) => fmtTime(u.lastLoginAt) },
        { key: "mfaEnabled", label: "MFA", render: (u) => <Pill value={u.mfaEnabled ? "on" : "off"} tone={u.mfaEnabled ? "good" : "warn"} /> },
        { key: "act", label: "", render: (u) => <span className="row" style={{ gap: 6 }}>
          {can("configure") && <button className="small" onClick={async () => { await run(() => api(`users/${u.id}`, { method: "PATCH", body: { active: !u.active } }), "User updated"); reload(); }}>{u.active ? "Disable" : "Enable"}</button>}
          {can("manage_tenants") && u.mfaEnabled && <button className="small" title="For a user who lost their phone" onClick={async () => { if (confirm(`Reset MFA for ${u.email}? They will need to set it up again.`)) { await run(() => api(`users/${u.id}/mfa/reset`, { method: "POST" }), "MFA reset"); reload(); } }}>Reset MFA</button>}
        </span> }]} />
      {form && (
        <Modal title="Invite user" onClose={() => setForm(null)} footer={<button className="primary" disabled={busy}
               onClick={async () => { if (await run(() => api("users", { body: form }), "User created")) { setForm(null); reload(); } }}>Create</button>}>
          <div className="form-grid">
            <label className="field">Email<input type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></label>
            <label className="field">Name<input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label>
            <label className="field">Tenant<TenantSelect value={form.tenantId} onChange={(id) => setForm({ ...form, tenantId: id })} allowAll={false} /></label>
            <label className="field">Role<select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>{ROLES.map((r) => <option key={r} value={r}>{r.replace(/_/g, " ")}</option>)}</select></label>
            <label className="field">Temporary password (12+)<input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></label>
          </div>
        </Modal>
      )}
    </div>
  );
}

function GroupsTab() {
  const { tenantId, can, tenantName } = useApp();
  const { data, reload } = useData<any[]>("groups", { tenant_id: tenantId });
  const { data: policies } = useData<any[]>("policies", { tenant_id: tenantId });
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
              {policies?.filter((p) => p.tenantId === form.tenantId).map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}</select></label>
          </div>
        </Modal>
      )}
    </div>
  );
}

function WebhooksTab() {
  const { can, tenantId } = useApp();
  const { data, reload } = useData<any[]>("webhooks");
  const [form, setForm] = useState<any>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const { run, busy } = useAction();
  return (
    <div className="card">
      {can("configure") && <button className="primary" style={{ marginBottom: 10 }} onClick={() => setForm({ name: "", url: "https://", kind: "slack", events: ["incident.created"], tenantId })}>Add webhook</button>}
      {secret && <p>Signing secret (shown once): <code>{secret}</code>. Verify the <code>X-Fenrir-Signature</code> header with HMAC-SHA256.</p>}
      <Table rows={data} empty="No webhooks. Send incidents to Slack, Teams or your own systems."
             columns={[{ key: "name", label: "Name" }, { key: "kind", label: "Type" }, { key: "url", label: "URL", render: (w) => <span className="mono small">{w.url}</span> },
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

function ReleasesTab({ canPublish }: { canPublish: boolean }) {
  const { data, reload } = useData<any[]>("releases");
  const [form, setForm] = useState<any>(null);
  const { run, busy } = useAction();
  return (
    <div className="card">
      {canPublish && <button className="primary" style={{ marginBottom: 10 }} onClick={() => setForm({ platform: "windows", channel: "stable", component: "agent", version: "", url: "", sha256: "", notes: "" })}>Publish release</button>}
      <Table rows={data} empty="No releases published. Agents keep their current version."
             columns={[{ key: "platform", label: "Platform" }, { key: "component", label: "Component" }, { key: "version", label: "Version" }, { key: "channel", label: "Ring" },
                       { key: "sha256", label: "SHA-256", render: (r) => <span className="mono small">{r.sha256.slice(0, 16)}…</span> }, { key: "publishedAt", label: "Published", render: (r) => fmtTime(r.publishedAt) }]} />
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

function AuditTab() {
  const { tenantId, can } = useApp();
  const { data } = useData<any[]>("audit", { tenant_id: tenantId });
  const [verify, setVerify] = useState<any>(null);
  const { run } = useAction();
  return (
    <div className="card">
      {can("manage_tenants") && (
        <div className="row" style={{ marginBottom: 10 }}>
          <button onClick={async () => setVerify(await run(() => api("audit/verify")))}>Verify integrity</button>
          {verify && (verify.valid ? <Pill value={`chain intact · ${verify.checked} entries`} tone="good" /> : <Pill value={`chain broken at entry ${verify.brokenAt}`} tone="bad" />)}
        </div>
      )}
      <Table rows={data} columns={[{ key: "at", label: "When", render: (r) => fmtTime(r.at) }, { key: "actor", label: "Who" }, { key: "action", label: "Action" },
        { key: "target", label: "Target" }, { key: "details", label: "Details", render: (r) => <span className="mono small">{JSON.stringify(r.details).slice(0, 120)}</span> }]} />
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

function PlatformTab() {
  const { data, error, reload } = useData<any>("platform/status");
  const { data: dead, reload: reloadDead } = useData<any[]>("platform/events", { status: "dead" });
  const { run } = useAction();
  return (
    <>
      <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))" }}>
        <div className="card"><div className="label muted small">Vault encryption</div>
          <p><b>{data?.vault.algorithm ?? "…"}</b></p>
          <p>Key {data?.vault.keyId} · {data?.vault.source === "derived" ? <Pill value="derived from FENRIR_SECRET_KEY" tone="warn" /> : <Pill value={`from ${data?.vault.source ?? "…"}`} tone="good" />}</p>
          {data && !data.vault.productionReady && <p className="small muted">Set FENRIR_VAULT_KEY (openssl rand -base64 32) before storing production secrets.</p>}
        </div>
        <div className="card"><div className="label muted small">Automation events</div>
          <p>{data?.events.pending ?? 0} waiting · {data?.events.done ?? 0} done · <b>{data?.events.dead ?? 0} failed</b></p></div>
        <div className="card"><div className="label muted small">Event handlers</div>
          <p className="small">{Object.entries(data?.handlers ?? {}).map(([k, v]: any) => `${k} (${v.length})`).join(", ") || "none"}</p></div>
      </div>
      {error && <p className="muted">{error}</p>}
      <div className="card" style={{ marginTop: 14 }}>
        <h3 style={{ marginTop: 0 }}>Failed automation events</h3>
        <Table rows={dead} empty="No failed events."
               columns={[{ key: "id", label: "#" }, { key: "type", label: "Type" }, { key: "attempts", label: "Attempts" },
                         { key: "lastError", label: "Last error", render: (e) => <span className="small">{e.lastError}</span> },
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
  const { data, reload } = useData<any[]>("auth/sessions");
  const { run, busy } = useAction();
  return (
    <div className="card" style={{ maxWidth: 720, marginTop: 16 }}>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h3 style={{ margin: 0 }}>Where you're signed in</h3>
        {(data || []).length > 1 && <button className="small" disabled={busy} onClick={async () => { if (await run(() => api("auth/sessions/revoke-others", { method: "POST" }), "Signed out everywhere else")) reload(); }}>Sign out everywhere else</button>}
      </div>
      {(data || []).map((s) => (
        <div key={s.id} className="row small" style={{ padding: "6px 0", borderBottom: "1px solid var(--line)" }}>
          <span style={{ flex: 1 }}><b>{s.current ? "This browser" : s.userAgent.split(")")[0].replace("(", "· ") || "Unknown browser"}</b>
            <div className="muted">{s.ip || "unknown address"} · signed in {fmtTime(s.createdAt)} · active {ago(s.lastSeenAt)}</div></span>
          {!s.current && <button className="small" disabled={busy} onClick={async () => { if (await run(() => api(`auth/sessions/${s.id}`, { method: "DELETE" }), "Signed out")) reload(); }}>Sign out</button>}
        </div>
      ))}
    </div>
  );
}
