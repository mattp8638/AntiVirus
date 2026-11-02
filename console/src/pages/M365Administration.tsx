import { displayValue } from "../components/DisplayValue";
import { useEffect, useState } from "react";
import { api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { safeArray } from "../data-shapes";
import { ErrorNote, Modal, Pill, Table, Tabs, useAction, useListData } from "../components/ui";

const OPERATIONS: [string, string][] = [
  ["user.update", "Edit user profile"], ["user.manager", "Set manager"], ["user.signin", "Enable or block sign-in"],
  ["user.revoke_sessions", "Sign out everywhere"], ["user.reset_password", "Reset password"], ["user.reset_mfa", "Reset MFA"],
  ["user.tap", "Issue a Temporary Access Pass"], ["user.temp_admin", "Grant a temporary admin role"],
  ["license.add", "Assign licence"], ["license.remove", "Remove licence"], ["group.add_member", "Add to group"], ["group.remove_member", "Remove from group"],
];
const NO_VALUE = ["user.revoke_sessions", "user.reset_mfa", "user.reset_password", "user.tap"];
const BLANK_USER = { displayName: "", userPrincipalName: "", mailNickname: "", usageLocation: "GB" };

function describe(job: any): string {
  const p = job.parameters || {}, pv = job.preview || {};
  switch (job.operation) {
    case "user.create": return `Create ${p.displayName} (${p.userPrincipalName}) in ${p.usageLocation}`;
    case "group.create": return `Create ${p.kind === "m365" ? "Microsoft 365 group" : "security group"} "${p.displayName}" (${p.mailNickname})${pv.owner ? ` owned by ${pv.owner.userPrincipalName}` : ""}`;
    case "guest.invite": return `Invite ${p.email} as a guest${p.sendEmail === false ? " (no email; you send the link)" : ""}`;
    case "user.revoke_sessions": return "Sign this user out of every session; future sign-ins remain allowed";
    case "user.reset_password": return `Set a new random password${p.forceChange ? " that must be changed at next sign-in" : ""}. You see it once, after it is set.`;
    case "user.reset_mfa": return `Remove: ${safeArray<any>(pv.methods).map((m) => `${m.label}${m.detail ? ` (${m.detail})` : ""}`).join(", ")}. The password stays; the user registers MFA again at next sign-in.`;
    case "user.tap": return `Issue a ${p.lifetimeMinutes}-minute Temporary Access Pass${p.usableOnce ? ", usable once" : ""}. You see it once.`;
    case "user.temp_admin": return `Grant ${pv.role?.name || p.roleId} for ${p.hours} hours; Fenrir removes it at ${fmtTime(pv.expiresAt)}`;
    case "user.manager": return `Set manager to ${pv.manager?.displayName || p.managerId}`;
    case "user.update": return Object.entries(p).map(([key, value]) => `${key}: ${pv.user?.[key] || "(empty)"} → ${value || "(empty)"}`).join("; ");
    case "user.signin": return `${pv.user?.accountEnabled ? "Sign-in allowed" : "Sign-in blocked"} → ${p.accountEnabled ? "Allow sign-in" : "Block sign-in"}`;
    case "license.add": return `Assign ${pv.license?.name || "the selected licence"}`;
    case "license.remove": return `Remove ${pv.license?.name || "the selected licence"}`;
    case "group.add_member": return `Add to ${pv.group?.displayName || "the selected group"}`;
    default: return `Remove from ${pv.group?.displayName || "the selected group"}`;
  }
}

export function M365Administration({ connection }: { connection: any }) {
  const { can } = useApp();
  const base = "m365/connections/" + connection.id;
  const [tab, setTab] = useState("Users"), [query, setQuery] = useState(""), [selected, setSelected] = useState<any>(null);
  const [operation, setOperation] = useState("user.update"), [value, setValue] = useState(""), [extra, setExtra] = useState<Record<string, any>>({});
  const [profileField, setProfileField] = useState("displayName");
  const [job, setJob] = useState<any>(null), [secret, setSecret] = useState(""), [confirmed, setConfirmed] = useState(false);
  const [creating, setCreating] = useState<"" | "user" | "group" | "guest">("");
  const [form, setForm] = useState<Record<string, any>>(BLANK_USER);
  const [temporaryPassword, setTemporaryPassword] = useState("");
  const [requestId, setRequestId] = useState(() => crypto.randomUUID());
  const { run, busy } = useAction();
  const { data: users, error: userError, reload: reloadUsers } = useListData<any>(base + "/inventory/users");
  const needGroups = tab === "Groups" || operation.startsWith("group.") || creating === "group";
  const { data: groups, error: groupError, reload: reloadGroups } = useListData<any>(needGroups ? base + "/inventory/groups" : null);
  const { data: licenses, error: licenseError } = useListData<any>(tab === "Licences" || operation.startsWith("license.") ? base + "/inventory/licenses" : null);
  const { data: roles } = useListData<any>(operation === "user.temp_admin" && can("m365_admin") ? base + "/temp-admin-roles" : null);
  const { data: history, error: historyError, reload: reloadHistory } = useListData<any>(can("m365_admin") ? base + "/actions" : null);
  useEffect(() => { setSelected(null); setJob(null); setConfirmed(false); setCreating(""); setTemporaryPassword(""); setSecret(""); }, [connection.id]);
  const fresh = () => setRequestId(crypto.randomUUID());
  const choose = (row: any) => { setSelected(row); setOperation("user.update"); setProfileField("displayName"); setValue(row.displayName || ""); setExtra({}); setJob(null); setConfirmed(false); setSecret(""); fresh(); };
  const parameters = () => {
    switch (operation) {
      case "user.update": return { [profileField]: value };
      case "user.signin": return { accountEnabled: value === "true" };
      case "user.revoke_sessions": case "user.reset_mfa": return {};
      case "user.reset_password": return { forceChange: extra.forceChange !== false };
      case "user.tap": return { lifetimeMinutes: Number(extra.lifetimeMinutes || 60), usableOnce: extra.usableOnce !== false };
      case "user.temp_admin": return { roleId: value, hours: Number(extra.hours || 4) };
      case "user.manager": return { managerId: value };
      default: return operation.startsWith("license.") ? { skuId: value } : { groupId: value };
    }
  };
  const prepare = async () => {
    const result = await run(() => api(base + "/actions", { body: { requestId, operation, targetId: selected.id, parameters: parameters() } }), "Action prepared");
    if (result) { setJob(result); reloadHistory(); }
  };
  const prepareNew = async () => {
    const op = creating === "user" ? "user.create" : creating === "group" ? "group.create" : "guest.invite";
    const body = Object.fromEntries(Object.entries(form).filter(([, v]) => v !== "" && v !== undefined));
    const result = await run(() => api(base + "/actions", { body: { requestId, operation: op, parameters: body } }), "Prepared for review");
    if (result) { setCreating(""); setJob(result); setConfirmed(false); reloadHistory(); }
  };
  const execute = async () => {
    const result = await run(() => api<any>(base + "/actions/" + job.id + "/execute", { body: { confirmed: true, ...(job.operation === "user.create" ? { temporaryPassword } : {}) } }), "Action status updated");
    setTemporaryPassword("");
    if (result) { setSecret(result.secret || ""); setJob(result); setConfirmed(false); reloadUsers(); reloadHistory(); if (job.operation === "group.create") reloadGroups(); }
  };
  const endRole = async () => {
    const result = await run(() => api(base + "/actions/" + job.id + "/end-role", { method: "POST" }), "Role removed");
    if (result) { setJob(result); reloadHistory(); }
  };
  const startCreate = (kind: "user" | "group" | "guest") => {
    setCreating(kind); setSelected(null); setJob(null); setTemporaryPassword(""); setSecret(""); fresh();
    setForm(kind === "user" ? BLANK_USER : kind === "group" ? { displayName: "", mailNickname: "", description: "", kind: "security" } : { email: "", displayName: "", sendEmail: true });
  };
  const closeJob = () => { setJob(null); setSelected(null); setTemporaryPassword(""); setSecret(""); };
  const field = (key: string, label: string, upper = false) => <label className="field" key={key}>{label}
    <input value={form[key] ?? ""} onChange={(e) => { setForm({ ...form, [key]: upper ? e.target.value.toUpperCase() : e.target.value }); fresh(); }} /></label>;
  const needsValue = !NO_VALUE.includes(operation);
  return <section>
    <p>Live from Microsoft. Every change is shown for review first and needs you to confirm your password.</p>
    <Tabs tabs={["Users", "Groups", "Licences", "Actions"]} active={tab} onChange={setTab} />
    <ErrorNote error={userError || groupError || licenseError || historyError} />
    {["Users", "Groups", "Licences"].includes(tab) && <label className="field">Search<input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Name, sign-in or product" /></label>}
    {can("m365_admin") && tab === "Users" && <div className="row" style={{ gap: 8 }}><button onClick={() => startCreate("user")}>New user</button><button onClick={() => startCreate("guest")}>Invite guest</button></div>}
    {can("m365_admin") && tab === "Groups" && <button onClick={() => startCreate("group")}>New group</button>}
    {tab === "Users" && <Table rows={users?.filter((r) => `${r.displayName} ${r.userPrincipalName}`.toLowerCase().includes(query.toLowerCase()))} onRow={can("m365_admin") ? choose : undefined}
      columns={[{ key: "displayName", label: "Name" }, { key: "userPrincipalName", label: "Sign-in" }, { key: "userType", label: "Type" },
        { key: "source", label: "Managed in", render: (r) => r.onPremisesSyncEnabled ? <Pill value="Active Directory" tone="blue" /> : <span className="small muted">Microsoft 365</span> },
        { key: "accountEnabled", label: "Sign-in enabled" }, { key: "department", label: "Department" }]} />}
    {tab === "Groups" && <><p className="small muted">Change membership from a user. Dynamic, role-assignable, synced and Exchange-managed groups need other tools.</p>
      <Table rows={groups?.filter((r) => r.displayName?.toLowerCase().includes(query.toLowerCase()))} columns={[{ key: "displayName", label: "Group" }, { key: "groupTypes", label: "Type", render: (r) => safeArray<string>(r.groupTypes).includes("Unified") ? "Microsoft 365" : safeArray<string>(r.groupTypes).join(", ") || (r.mailEnabled ? "Mail-enabled" : "Security") }, { key: "isAssignableToRole", label: "Role assignable" }, { key: "onPremisesSyncEnabled", label: "Synced" }]} /></>}
    {tab === "Licences" && <Table rows={licenses?.filter((r) => r.skuPartNumber?.toLowerCase().includes(query.toLowerCase()))} columns={[{ key: "skuPartNumber", label: "Product" }, { key: "consumedUnits", label: "Assigned" }, { key: "available", label: "Available", render: (r) => Math.max(0, (r.prepaidUnits?.enabled || 0) - (r.consumedUnits || 0)) }]} />}
    {tab === "Actions" && <><p className="small muted">Running or unknown outcomes are never replayed: check Microsoft before preparing another action.</p><button onClick={reloadHistory}>Refresh</button>
      <Table rows={history} onRow={(r) => { setJob(r); setSelected(null); setConfirmed(false); setSecret(""); }} columns={[{ key: "operation", label: "Action" }, { key: "target", label: "For", render: (r) => r.preview?.user?.userPrincipalName || r.preview?.group?.displayName || r.targetId }, { key: "status", label: "Status", render: (r) => <Pill value={r.status} /> }, { key: "executedBy", label: "By" }, { key: "createdAt", label: "Prepared", render: (r) => fmtTime(r.createdAt) }]} /></>}

    {creating && <Modal title={creating === "user" ? "New Microsoft 365 user" : creating === "group" ? "New group" : "Invite a guest"} onClose={() => setCreating("")}>
      {creating === "user" && <><p>A cloud user in a verified domain. For licences, groups and a manager in one go, use Onboarding instead.</p>
        <div className="form-grid">{[["displayName", "Display name"], ["userPrincipalName", "Sign-in name (user@domain)"], ["mailNickname", "Mail alias"], ["givenName", "First name"], ["surname", "Surname"], ["department", "Department"], ["jobTitle", "Job title"]].map(([k, l]) => field(k, l))}{field("usageLocation", "Usage location (two-letter country code)", true)}</div></>}
      {creating === "group" && <div className="form-grid">{field("displayName", "Name")}{field("mailNickname", "Alias (letters, numbers, . _ -)")}{field("description", "Description")}
        <label className="field">Type<select value={form.kind} onChange={(e) => { setForm({ ...form, kind: e.target.value }); fresh(); }}><option value="security">Security group</option><option value="m365">Microsoft 365 group (mailbox, Teams-ready)</option></select></label>
        <label className="field">Owner (optional)<select value={form.ownerId || ""} onChange={(e) => { setForm({ ...form, ownerId: e.target.value }); fresh(); }}><option value="">None</option>{users?.filter((u) => u.userType === "Member").map((u) => <option key={u.id} value={u.id}>{displayValue(u.userPrincipalName)}</option>)}</select></label></div>}
      {creating === "guest" && <div className="form-grid">{field("email", "Their email address")}{field("displayName", "Name (optional)")}{field("message", "Message in the invitation (optional)")}
        <label><input type="checkbox" checked={form.sendEmail !== false} onChange={(e) => { setForm({ ...form, sendEmail: e.target.checked }); fresh(); }} /> Microsoft emails the invitation</label></div>}
      <button className="primary" disabled={busy || (creating === "user" ? !["displayName", "userPrincipalName", "mailNickname", "usageLocation"].every((k) => form[k]?.trim()) : creating === "group" ? !form.displayName?.trim() || !form.mailNickname?.trim() : !form.email?.trim())} onClick={prepareNew}>Review</button>
    </Modal>}

    {selected && !job && <Modal title={selected.userPrincipalName} onClose={() => setSelected(null)}>
      {selected.onPremisesSyncEnabled && <p className="small" style={{ color: "#93c5fd" }}>Synced from Active Directory ({displayValue(selected.onPremisesSamAccountName)}): its name, sign-in and password belong to AD, so Microsoft refuses those changes here. Use <b>Offboarding</b>, which makes them on the domain controller, or change them in AD.</p>}
      <label className="field">Action<select value={operation} onChange={(e) => { setOperation(e.target.value); setValue(""); setExtra({}); fresh(); }}>
        {OPERATIONS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></label>
      {operation === "user.update" && <label className="field">Profile field<select value={profileField} onChange={(e) => { setProfileField(e.target.value); setValue(selected[e.target.value] || ""); fresh(); }}><option value="displayName">Display name</option><option value="department">Department</option><option value="jobTitle">Job title</option><option value="usageLocation">Usage location</option></select></label>}
      {needsValue && <label className="field">{operation === "user.update" ? profileField : operation === "user.temp_admin" ? "Role" : operation === "user.manager" ? "Manager" : "New setting"}
        {operation === "user.update" ? <input value={value} onChange={(e) => { setValue(e.target.value); fresh(); }} /> :
          <select value={value} onChange={(e) => { setValue(e.target.value); fresh(); }}><option value="">Choose…</option>
            {operation === "user.signin" ? <><option value="true">Allow sign-in</option><option value="false">Block sign-in</option></> :
              operation === "user.temp_admin" ? roles?.map((r) => <option key={r.id} value={r.id}>{displayValue(r.name)}</option>) :
              operation === "user.manager" ? users?.filter((u) => u.id !== selected.id && u.userType === "Member").map((u) => <option key={u.id} value={u.id}>{displayValue(u.displayName)} ({displayValue(u.userPrincipalName)})</option>) :
              operation.startsWith("license.") ? licenses?.map((r) => <option key={r.skuId} value={r.skuId}>{displayValue(r.skuPartNumber)}</option>) :
              groups?.map((r) => <option key={r.id} value={r.id}>{displayValue(r.displayName)}</option>)}
          </select>}
      </label>}
      {operation === "user.temp_admin" && <label className="field">For how many hours (1–72)<input type="number" min={1} max={72} value={extra.hours ?? 4} onChange={(e) => { setExtra({ ...extra, hours: e.target.value }); fresh(); }} /><span className="small muted">Fenrir removes the role when the time is up. It refuses a role the user already holds.</span></label>}
      {operation === "user.tap" && <><label className="field">Valid for (minutes, 10–1440)<input type="number" min={10} max={1440} value={extra.lifetimeMinutes ?? 60} onChange={(e) => { setExtra({ ...extra, lifetimeMinutes: e.target.value }); fresh(); }} /></label>
        <label><input type="checkbox" checked={extra.usableOnce !== false} onChange={(e) => { setExtra({ ...extra, usableOnce: e.target.checked }); fresh(); }} /> Usable once</label>
        <p className="small muted">Lets the user sign in and register MFA or a passkey without their password. Temporary Access Pass must be on in the tenant's Authentication methods policy.</p></>}
      {operation === "user.reset_password" && <label><input type="checkbox" checked={extra.forceChange !== false} onChange={(e) => { setExtra({ ...extra, forceChange: e.target.checked }); fresh(); }} /> Make them change it at next sign-in</label>}
      {operation === "user.reset_mfa" && <p className="small">Removes every MFA method (authenticator app, phone, security keys…). The user registers again at next sign-in. The review shows exactly what goes.</p>}
      {operation === "user.revoke_sessions" && <p className="small">Ends the user's sessions on every device. Takes a few minutes and does not block future sign-ins.</p>}
      <button className="primary" disabled={busy || (needsValue && !value)} onClick={prepare}>Review change</button>
    </Modal>}

    {job && <Modal title="Review Microsoft action" onClose={closeJob}>
      <p><b>Tenant:</b> {displayValue(connection.name)} <span className="small muted mono">{displayValue(connection.directoryId)}</span></p>
      <p><b>For:</b> {displayValue(job.preview?.user?.userPrincipalName || job.preview?.group?.displayName)} · <b>Status:</b> <Pill value={job.status} /></p>
      <p><b>Change:</b> {describe(job)}</p>
      <p className="small muted">Microsoft permissions used: {displayValue(job.preview?.requiredPermissions?.join(", "))}</p>
      {job.result?.message && <p>{displayValue(job.result.message)}</p>}
      {safeArray<any>(job.result?.failed).length > 0 && <ul className="small">{job.result.failed.map((f: any) => <li key={f.label}>{displayValue(f.label)}: {displayValue(f.reason)}</li>)}</ul>}
      {job.result?.redeemUrl && <p className="small">Redeem link: <code className="mono">{displayValue(job.result.redeemUrl)}</code></p>}
      {secret && <div className="card" style={{ borderColor: "#fcd34d" }}>
        <p><b>{job.operation === "user.tap" ? "Temporary Access Pass" : "New password"}</b> (shown once; Fenrir does not keep it):</p>
        <div className="mono" style={{ fontSize: 22, letterSpacing: 1, margin: "8px 0" }}>{secret}</div>
        <button className="small" onClick={() => navigator.clipboard?.writeText(secret)}>Copy</button>
      </div>}
      {job.operation === "user.temp_admin" && job.status?.startsWith("succeeded") && <p>
        {job.result?.removedAt ? <>Role removed {fmtTime(job.result.removedAt)} ({displayValue(job.result.removedBy)}).</> :
          <>Role held until {fmtTime(job.result?.expiresAt)}. {can("m365_admin") && <button className="small" disabled={busy} onClick={endRole}>End it now</button>}</>}
        {job.result?.removeError && <span style={{ color: "#fca5a5" }}> Last removal attempt failed: {displayValue(job.result.removeError)}</span>}</p>}
      {job.status === "prepared" && can("m365_admin") && <><p className="small">This changes the customer's tenant. The review expires after ten minutes.</p>
        {job.operation === "user.create" && <label className="field">Temporary password<input type="password" autoComplete="new-password" minLength={12} maxLength={128} value={temporaryPassword} onChange={(e) => setTemporaryPassword(e.target.value)} /><span>12–128 characters. Fenrir does not store it; they change it at first sign-in.</span></label>}
        <label><input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} /> I have checked the tenant, the user and the change.</label>
        <p><button className="primary" disabled={busy || !confirmed || (job.operation === "user.create" && temporaryPassword.length < 12)} onClick={execute}>Confirm and run</button></p></>}
      {["running", "unknown"].includes(job.status) && <p>Check Microsoft before doing this again. This record will not run a second time.</p>}
    </Modal>}
  </section>;
}
