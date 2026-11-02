import { displayValue } from "../components/DisplayValue";
import { useState } from "react";
import { api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { safeArray } from "../data-shapes";
import { ErrorNote, Modal, Pill, Table, useAction, useData, useListData } from "../components/ui";

const KIND: Record<string, string> = { offboard: "Offboarding", onboard: "New starter", bulk_create: "Bulk import" };
const STEP_TONE: Record<string, string> = { done: "good", skipped: "muted", pending: "warn", running: "blue", waiting: "blue", failed: "bad", unknown: "bad" };
const WHERE: Record<string, string> = { ad: "Active Directory", m365: "Microsoft 365", fenrir: "Fenrir" };
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const OFFBOARD_DEFAULTS = { blockSignIn: true, revokeSessions: true, resetPassword: true, removeMfa: true, outOfOffice: false, outOfOfficeMessage: "",
  removeGroups: true, removeRoles: true, removeLicences: false, markContact: true, reviewEstate: true, openTicket: true,
  convertToShared: false, mailboxDelegate: "", forwardTo: "", onedriveDelegate: "" };
const OFFBOARD_STEPS: [string, string][] = [["blockSignIn", "Block sign-in"], ["revokeSessions", "Sign out everywhere"], ["resetPassword", "Reset the password to a random one"],
  ["removeMfa", "Remove MFA methods"], ["outOfOffice", "Set an out-of-office reply (app connections only)"], ["removeGroups", "Remove from groups"],
  ["removeRoles", "Remove admin roles"], ["removeLicences", "Remove licences (read the warning in the review)"], ["markContact", "Mark the Fenrir contact as left"],
  ["reviewEstate", "List their devices, flag their stored credentials for rotation and show the billing effect"],
  ["openTicket", "Record it all on a ticket"]];
const USER_FIELDS: [string, string][] = [["displayName", "Display name"], ["userPrincipalName", "Sign-in name (user@domain)"], ["mailNickname", "Mail alias"],
  ["givenName", "First name"], ["surname", "Surname"], ["jobTitle", "Job title"], ["department", "Department"], ["usageLocation", "Usage location (e.g. GB)"]];

/** Parse a CSV of new users. Columns by header name; mailNickname defaults to the part of the sign-in name before @. */
function parseCsv(text: string): { rows: any[]; errors: string[] } {
  const lines = text.split(/\r?\n/).filter((l) => l.trim());
  if (lines.length < 2) return { rows: [], errors: ["Add a header line and at least one user."] };
  const split = (line: string) => {
    const out: string[] = []; let cur = "", quoted = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (c === '"') { if (quoted && line[i + 1] === '"') { cur += '"'; i++; } else quoted = !quoted; }
      else if (c === "," && !quoted) { out.push(cur); cur = ""; } else cur += c;
    }
    out.push(cur);
    return out.map((v) => v.trim());
  };
  const known = Object.fromEntries(USER_FIELDS.map(([k]) => [k.toLowerCase(), k]));
  const head = split(lines[0]).map((h) => known[h.replace(/\s+/g, "").toLowerCase()] || "");
  const errors: string[] = [];
  if (!head.includes("displayName") || !head.includes("userPrincipalName")) errors.push("The header needs at least displayName and userPrincipalName.");
  const rows = lines.slice(1).map((line, n) => {
    const row: any = {};
    split(line).forEach((v, i) => { if (head[i] && v) row[head[i]] = v; });
    row.mailNickname = row.mailNickname || String(row.userPrincipalName || "").split("@")[0].replace(/[^A-Za-z0-9._-]/g, "");
    row.usageLocation = String(row.usageLocation || "GB").toUpperCase();
    if (!row.displayName || !/^[^@\s]+@[^@\s]+$/.test(row.userPrincipalName || "")) errors.push(`Line ${n + 2}: needs a display name and a sign-in name.`);
    return row;
  });
  return { rows, errors };
}

function download(name: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/csv" }));
  const a = document.createElement("a");
  a.href = url; a.download = name; a.click();
  URL.revokeObjectURL(url);
}

function Picker({ items, chosen, onChange, label }: { items: any[]; chosen: string[]; onChange: (ids: string[]) => void; label: (x: any) => string }) {
  return <div className="small" style={{ maxHeight: 160, overflow: "auto", border: "1px solid var(--line, #333)", padding: 6 }}>
    {items.map((x) => <label key={x.id} style={{ display: "block" }}><input type="checkbox" checked={chosen.includes(x.id)}
      onChange={(e) => onChange(e.target.checked ? [...chosen, x.id] : chosen.filter((c) => c !== x.id))} /> {displayValue(label(x))}</label>)}
  </div>;
}

export function M365Lifecycle({ connection }: { connection: any }) {
  const { can } = useApp();
  const base = `m365/connections/${connection.id}`;
  const { run, busy } = useAction();
  const { data: flows, error, reload } = useListData<any>(can("m365_admin") ? base + "/workflows" : null);
  const [form, setForm] = useState<"" | "offboard" | "onboard" | "bulk">("");
  const { data: users } = useListData<any>(form ? base + "/inventory/users" : null);
  const { data: groups } = useListData<any>(form === "onboard" || form === "bulk" ? base + "/inventory/groups" : null);
  const { data: licenses } = useListData<any>(form === "onboard" || form === "bulk" ? base + "/inventory/licenses" : null);
  const [target, setTarget] = useState(""), [find, setFind] = useState("");
  const [off, setOff] = useState<Record<string, any>>(OFFBOARD_DEFAULTS);
  const [profile, setProfile] = useState<Record<string, string>>({ usageLocation: "GB" });
  const [extras, setExtras] = useState<{ managerId: string; skuIds: string[]; groupIds: string[]; addContact: boolean; openTicket: boolean }>({ managerId: "", skuIds: [], groupIds: [], addContact: true, openTicket: true });
  const [csv, setCsv] = useState(""), [flow, setFlow] = useState<any>(null), [confirmed, setConfirmed] = useState(false);
  const [secrets, setSecrets] = useState<any[]>([]), [running, setRunning] = useState(false), [waiting, setWaiting] = useState("");
  const { data: directory, reload: reloadDirectory } = useData<any>(form ? base + "/directory" : null);
  const [createIn, setCreateIn] = useState<"cloud" | "ad">("cloud");
  const [ad, setAd] = useState<{ sam: string; ou: string; groups: string[] }>({ sam: "", ou: "", groups: [] });
  const loadDirectory = async () => { if (await run(() => api(base + "/directory/refresh", { method: "POST" }), "Asked the domain controller for its OUs and groups")) {
    for (let i = 0; i < 15; i++) { await sleep(2000); const d = await api<any>(base + "/directory"); if (d.options && !d.optionsCommandId) break; }
    reloadDirectory(); } };
  if (!can("m365_admin")) return <p className="muted">Onboarding and offboarding need the Microsoft 365 administration permission.</p>;
  const parsed = form === "bulk" ? parseCsv(csv) : { rows: [], errors: [] };
  const simpleGroups = (groups || []).filter((g: any) => !g.isAssignableToRole && !g.onPremisesSyncEnabled && !safeArray<string>(g.groupTypes).includes("DynamicMembership") && (!g.mailEnabled || safeArray<string>(g.groupTypes).includes("Unified")));

  const plan = async () => {
    let body: any;
    if (form === "offboard") body = { kind: "offboard", targetId: target, options: off };
    else if (form === "onboard") body = { kind: "onboard", options: { profile: { ...profile, mailNickname: profile.mailNickname || String(profile.userPrincipalName || "").split("@")[0] }, ...extras, managerId: extras.managerId || undefined,
      ...(createIn === "ad" ? { createIn: "ad", ad: { sam: ad.sam || String(profile.userPrincipalName || "").split("@")[0].slice(0, 20), ou: ad.ou, groups: ad.groups } } : {}) } };
    else body = { kind: "bulk_create", options: { rows: parsed.rows, skuIds: extras.skuIds, groupIds: extras.groupIds } };
    const result = await run(() => api<any>(base + "/workflows", { body }), "Plan ready for review");
    if (result) { setForm(""); setFlow(result); setConfirmed(false); setSecrets([]); reload(); }
  };
  const go = async () => {
    setRunning(true);
    let current = flow, made: any[] = [];
    try {
      const started = Date.now();
      for (let i = 0; i < 400; i++) {
        const out = await run(() => api<any>(`m365/workflows/${current.id}/run`, { body: { confirmed: true } }));
        if (!out) break;
        current = out.workflow; made = [...made, ...safeArray<any>(out.secrets)];
        setFlow(current); setSecrets(made); setWaiting(out.waiting || "");
        if (!out.more) break;
        if (out.waiting) {
          if (Date.now() - started > 4 * 60 * 1000) { setWaiting(out.waiting + " — this carries on by itself; you can close this window and check History later."); break; }
          await sleep(3000);
        }
      }
    } finally { setRunning(false); setConfirmed(false); reload(); }
  };
  const resolve = async (index: number, outcome: string) => {
    const result = await run(() => api<any>(`m365/workflows/${flow.id}/steps/${index}/resolve`, { body: { outcome } }));
    if (result) { setFlow(result); reload(); }
  };
  const runnable = flow && ["prepared", "partial"].includes(flow.status) && safeArray<any>(flow.steps).some((s: any) => ["pending", "failed", "waiting"].includes(s.status));

  return <section>
    <p>Each one is planned first: Fenrir reads the tenant and lists every change. Nothing changes until you confirm. If a step fails, the rest still run
      and you can retry it; if Fenrir loses Microsoft's answer, the step waits for you to check and mark it.</p>
    <div className="row" style={{ gap: 8 }}>
      <button className="primary" onClick={() => { setForm("offboard"); setTarget(""); setOff(OFFBOARD_DEFAULTS); }}>Offboard a user</button>
      <button onClick={() => { setForm("onboard"); setProfile({ usageLocation: "GB" }); setExtras({ managerId: "", skuIds: [], groupIds: [], addContact: true, openTicket: true }); }}>New starter</button>
      <button onClick={() => { setForm("bulk"); setCsv(""); setExtras({ managerId: "", skuIds: [], groupIds: [], addContact: false, openTicket: false }); }}>Bulk import from CSV</button>
    </div>
    <ErrorNote error={error} />
    <h3>History</h3>
    <Table rows={flows} onRow={(r: any) => { setFlow(r); setSecrets([]); setConfirmed(false); }} empty="No onboarding or offboarding yet." columns={[
      { key: "kind", label: "Type", render: (r: any) => KIND[r.kind] || r.kind }, { key: "targetName", label: "Who" },
      { key: "status", label: "Status", render: (r: any) => <Pill value={r.status} tone={r.status === "completed" ? "good" : r.status === "partial" ? "warn" : undefined} /> },
      { key: "requestedBy", label: "Planned by" }, { key: "createdAt", label: "When", render: (r: any) => fmtTime(r.createdAt) }]} />

    {form === "offboard" && <Modal title="Offboard a user" onClose={() => setForm("")} wide>
      <label className="field">Find<input value={find} onChange={(e) => setFind(e.target.value)} placeholder="Name or sign-in" /></label>
      <label className="field">User<select value={target} onChange={(e) => setTarget(e.target.value)}><option value="">Choose…</option>
        {(users || []).filter((u: any) => u.userType === "Member" && `${u.displayName} ${u.userPrincipalName}`.toLowerCase().includes(find.toLowerCase()))
          .map((u: any) => <option key={u.id} value={u.id}>{displayValue(u.displayName)} ({displayValue(u.userPrincipalName)})</option>)}</select></label>
      {(() => { const person = (users || []).find((u: any) => u.id === target); return person?.onPremisesSyncEnabled ? <div className="card" style={{ borderColor: "#93c5fd", margin: "8px 0" }}>
        <b>Synced from Active Directory ({displayValue(person.onPremisesSamAccountName)}).</b>
        {directory?.controller ? <p className="small">Fenrir disables the account, sets a random password and removes its AD groups on <b>{displayValue(directory.controller.hostname)}</b>{directory.controller.online ? "" : " (offline now: those steps wait for it)"},
          then {directory.syncServer ? <>starts an Entra Connect sync on <b>{displayValue(directory.syncServer.hostname)}</b></> : "Entra Connect syncs within 30 minutes"}. The Microsoft 365 steps follow.</p>
          : <p className="small" style={{ color: "#fcd34d" }}>No domain controller with the Fenrir agent is known for this customer, so disable the account and reset its password in Active Directory yourself. The Microsoft 365 steps still run.</p>}
        {directory?.controller && <>
          <label className="field">Move the account to (optional)<select value={off.adMoveOu || ""} onChange={(e) => setOff({ ...off, adMoveOu: e.target.value })}>
            <option value="">Leave it where it is</option>
            {safeArray<any>(directory?.options?.ous).map((o: any) => <option key={o.dn} value={o.dn}>{displayValue(o.name)} — {displayValue(o.dn)}</option>)}</select>
            {!directory?.options && <span className="small"><button className="link" onClick={loadDirectory}>Load the OUs from the domain controller</button></span>}</label>
          <label style={{ display: "block" }}><input type="checkbox" checked={!!off.hideFromAddressBook} onChange={(e) => setOff({ ...off, hideFromAddressBook: e.target.checked })} /> Hide from the address book (where AD has Exchange attributes)</label>
        </>}
      </div> : null; })()}
      {OFFBOARD_STEPS.map(([k, l]) => <label key={k} style={{ display: "block" }}><input type="checkbox" checked={!!off[k]} onChange={(e) => setOff({ ...off, [k]: e.target.checked })} /> {l}</label>)}
      {off.outOfOffice && <label className="field">Out-of-office message<textarea rows={3} value={off.outOfOfficeMessage} onChange={(e) => setOff({ ...off, outOfOfficeMessage: e.target.value })} placeholder="Jo has left Acme. Please contact sales@acme.example." /></label>}
      <div className="card" style={{ margin: "8px 0" }}>
        <b className="small">Mailbox and OneDrive hand-over</b>
        <label style={{ display: "block" }}><input type="checkbox" checked={!!off.convertToShared} onChange={(e) => setOff({ ...off, convertToShared: e.target.checked })} /> Convert the mailbox to shared (keeps the mail; no licence needed)</label>
        <label className="field">Give full access to (optional)<input placeholder="manager@domain" value={off.mailboxDelegate || ""} onChange={(e) => setOff({ ...off, mailboxDelegate: e.target.value.trim() })} /></label>
        <label className="field">Forward new mail to (optional)<input placeholder="colleague@domain" value={off.forwardTo || ""} onChange={(e) => setOff({ ...off, forwardTo: e.target.value.trim() })} /></label>
        <label className="field">Share their OneDrive with (optional)<input placeholder="manager@domain" value={off.onedriveDelegate || ""} onChange={(e) => setOff({ ...off, onedriveDelegate: e.target.value.trim() })} /></label>
      </div>
      <button className="primary" disabled={busy || !target || (off.outOfOffice && !off.outOfOfficeMessage.trim())} onClick={plan}>Plan offboarding</button>
    </Modal>}

    {form === "onboard" && <Modal title="New starter" onClose={() => setForm("")} wide>
      {directory?.available && <div className="card" style={{ marginBottom: 10 }}>
        <b className="small">Where the account lives</b>
        <label style={{ display: "block" }}><input type="radio" checked={createIn === "cloud"} onChange={() => setCreateIn("cloud")} /> Microsoft 365 only (cloud account)</label>
        <label style={{ display: "block" }}><input type="radio" checked={createIn === "ad"} onChange={() => setCreateIn("ad")} /> Active Directory, synced to Microsoft 365 by Entra Connect
          <span className="small muted"> — created on {displayValue(directory.controller?.hostname)}{directory.syncServer ? `, synced from ${directory.syncServer.hostname}` : ""}</span></label>
        {createIn === "ad" && <>
          {!directory.options && <p className="small">Fenrir needs this domain's OUs and groups. <button className="small" disabled={busy} onClick={loadDirectory}>Load them from the domain controller</button></p>}
          {directory.options && <p className="small muted">Sign-in suffixes in this directory: {displayValue(safeArray<string>(directory.options.upnSuffixes).join(", "))}</p>}
          <div className="form-grid">
            <label className="field">Logon name (sAMAccountName)<input value={ad.sam} maxLength={20} onChange={(e) => setAd({ ...ad, sam: e.target.value })} placeholder={String(profile.userPrincipalName || "").split("@")[0].slice(0, 20) || "e.g. nnew"} /></label>
            <label className="field">Organisational unit<select value={ad.ou} onChange={(e) => setAd({ ...ad, ou: e.target.value })}>
              <option value="">{directory.options?.usersContainer ? `Default (${directory.options.usersContainer})` : "Default Users container"}</option>
              {safeArray<any>(directory.options?.ous).map((o: any) => <option key={o.dn} value={o.dn}>{displayValue(o.name)} — {displayValue(o.dn)}</option>)}</select></label>
          </div>
          {safeArray<any>(directory.options?.groups).length > 0 && <><b className="small">Active Directory groups</b>
            <Picker items={safeArray<any>(directory.options.groups).map((g: any) => ({ ...g, id: g.dn }))} chosen={ad.groups} onChange={(groups) => setAd({ ...ad, groups })} label={(g) => `${g.name} (${g.category})`} /></>}
          <p className="small muted">The account is created in AD with a temporary password Fenrir shows once, Entra Connect brings it into Microsoft 365, then the licences and Microsoft 365 groups below are applied. The run carries on by itself while it waits for the sync.</p>
        </>}
      </div>}
      <div className="form-grid">{USER_FIELDS.map(([k, l]) => <label className="field" key={k}>{l}<input value={profile[k] || ""} onChange={(e) => setProfile({ ...profile, [k]: k === "usageLocation" ? e.target.value.toUpperCase() : e.target.value })} placeholder={k === "mailNickname" ? "Defaults to the part before @" : undefined} /></label>)}</div>
      <label className="field">Manager<select value={extras.managerId} onChange={(e) => setExtras({ ...extras, managerId: e.target.value })}><option value="">None</option>
        {(users || []).filter((u: any) => u.userType === "Member").map((u: any) => <option key={u.id} value={u.id}>{displayValue(u.displayName)} ({displayValue(u.userPrincipalName)})</option>)}</select></label>
      <div className="grid k2">
        <div><b className="small">Licences</b><Picker items={(licenses || []).map((l: any) => ({ ...l, id: l.skuId }))} chosen={extras.skuIds} onChange={(skuIds) => setExtras({ ...extras, skuIds })} label={(l) => `${l.skuPartNumber} (${Math.max(0, (l.prepaidUnits?.enabled || 0) - (l.consumedUnits || 0))} free)`} /></div>
        <div><b className="small">Groups</b><Picker items={simpleGroups} chosen={extras.groupIds} onChange={(groupIds) => setExtras({ ...extras, groupIds })} label={(g) => g.displayName} /></div>
      </div>
      <label style={{ display: "block" }}><input type="checkbox" checked={extras.addContact} onChange={(e) => setExtras({ ...extras, addContact: e.target.checked })} /> Add them as a Fenrir contact for this customer</label>
      <label style={{ display: "block" }}><input type="checkbox" checked={extras.openTicket} onChange={(e) => setExtras({ ...extras, openTicket: e.target.checked })} /> Record it on a ticket</label>
      <p className="small muted">Fenrir makes a temporary password and shows it once at the end. They change it at first sign-in.</p>
      <button className="primary" disabled={busy || !profile.displayName?.trim() || !profile.userPrincipalName?.includes("@") || !/^[A-Z]{2}$/.test(profile.usageLocation || "")} onClick={plan}>Plan new starter</button>
    </Modal>}

    {form === "bulk" && <Modal title="Bulk import from CSV" onClose={() => setForm("")} wide>
      <p className="small">Paste or load a CSV with a header line. Columns: <code>displayName, userPrincipalName</code> (required), and optionally <code>givenName, surname, jobTitle, department, usageLocation, mailNickname</code>. Up to 200 users.</p>
      <input type="file" accept=".csv,text/csv" onChange={async (e) => { const f = e.target.files?.[0]; if (f) setCsv(await f.text()); }} />
      <textarea rows={6} className="mono small" style={{ width: "100%" }} value={csv} onChange={(e) => setCsv(e.target.value)} placeholder={"displayName,userPrincipalName,jobTitle\nNia New,nia@acme.co.uk,Sales"} />
      {csv && parsed.errors.length > 0 && <ul className="small" style={{ color: "#fca5a5" }}>{parsed.errors.slice(0, 8).map((e) => <li key={e}>{e}</li>)}</ul>}
      {csv && parsed.errors.length === 0 && <p className="small">{parsed.rows.length} users read.</p>}
      <div className="grid k2">
        <div><b className="small">Licences for everyone</b><Picker items={(licenses || []).map((l: any) => ({ ...l, id: l.skuId }))} chosen={extras.skuIds} onChange={(skuIds) => setExtras({ ...extras, skuIds })} label={(l) => `${l.skuPartNumber} (${Math.max(0, (l.prepaidUnits?.enabled || 0) - (l.consumedUnits || 0))} free)`} /></div>
        <div><b className="small">Groups for everyone</b><Picker items={simpleGroups} chosen={extras.groupIds} onChange={(groupIds) => setExtras({ ...extras, groupIds })} label={(g) => g.displayName} /></div>
      </div>
      <button className="primary" disabled={busy || !parsed.rows.length || parsed.errors.length > 0} onClick={plan}>Check and plan</button>
    </Modal>}

    {flow && <Modal title={`${KIND[flow.kind] || flow.kind}: ${flow.targetName}`} onClose={() => { if (!secrets.length || window.confirm("Close? The passwords are not shown again.")) { setFlow(null); setSecrets([]); } }} wide>
      <p><b>Tenant:</b> {displayValue(connection.name)} · <b>Status:</b> <Pill value={flow.status} /> · planned by {displayValue(flow.requestedBy)} {fmtTime(flow.createdAt)}</p>
      <Table rows={safeArray<any>(flow.steps).map((s: any, i: number) => ({ ...s, i }))} columns={[
        { key: "title", label: "Step", render: (s: any) => <><b>{displayValue(s.title)}</b> {s.where && <Pill value={WHERE[s.where] || s.where} tone={s.where === "ad" ? "blue" : "muted"} />}<div className="small muted">{displayValue(s.detail)}</div>{s.warning && <div className="small" style={{ color: "#fcd34d" }}>{displayValue(s.warning)}</div>}</> },
        { key: "status", label: "Status", render: (s: any) => <Pill value={s.status} tone={STEP_TONE[s.status]} /> },
        { key: "result", label: "Outcome", render: (s: any) => <span className="small">{displayValue(s.result)}</span> },
        { key: "actions", label: "", render: (s: any) => ["failed", "unknown"].includes(s.status) && flow.status !== "running" ? <span className="row" style={{ gap: 4 }}>
          <button className="small" onClick={() => resolve(s.i, "done")} title="You checked Microsoft and it is done">Mark done</button>
          <button className="small" onClick={() => resolve(s.i, "retry")}>Retry</button>
          <button className="small" onClick={() => resolve(s.i, "skip")}>Skip</button></span> : null }]} />
      {secrets.length > 0 && <div className="card" style={{ borderColor: "#fcd34d", marginTop: 12 }}>
        <p><b>Temporary passwords</b> (shown once; Fenrir does not keep them). They must change them at first sign-in.</p>
        <Table rows={secrets.map((s) => ({ ...s, id: s.userPrincipalName }))} columns={[{ key: "displayName", label: "Name" }, { key: "userPrincipalName", label: "Sign-in" }, { key: "where", label: "Account in", render: (s: any) => s.where || "Microsoft 365" }, { key: "password", label: "Password", render: (s: any) => <span className="mono">{s.password}</span> }]} />
        <button onClick={() => download("new-users.csv", ["displayName,userPrincipalName,password", ...secrets.map((s) => [s.displayName, s.userPrincipalName, s.password].map((v) => `"${String(v).replace(/"/g, '""')}"`).join(","))].join("\n"))}>Download as CSV</button>
      </div>}
      {waiting && <p className="small" style={{ color: "#93c5fd" }}>{displayValue(waiting)}</p>}
      {flow.ticketId && <p className="small">Recorded on a ticket (see Service desk).</p>}
      {runnable && <>
        {flow.status === "prepared" && <p className="small">This changes the customer's tenant. The plan must be run within 30 minutes; after that, plan it again.</p>}
        <label><input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} /> I have checked the tenant, the person and every step above.</label>
        <p><button className="primary" disabled={busy || running || !confirmed} onClick={go}>{running ? "Running…" : flow.status === "prepared" ? "Confirm and run" : "Run the remaining steps"}</button></p>
      </>}
    </Modal>}
  </section>;
}
