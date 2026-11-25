// Enterprise apps, app registrations, consent and directory extensions (M365-11).
// Every permission is shown as application (no signed-in user, tenant-wide) or delegated (as the signed-in user).
import { useState } from "react";
import { api, fmtTime } from "../api";
import { promptDialog } from "../components/dialogs";
import { ErrorNote, Pill, Table, useAction, useData } from "../components/ui";

const STATE_TONE: Record<string, string> = { expired: "bad", expiring: "warn", ok: "good" };

export default function M365Apps({ connection }: { connection: any }) {
  const base = `m365/connections/${connection.id}/apps`;
  const { data, error, reload } = useData<any>(base);
  const { run, busy } = useAction();
  const [open, setOpen] = useState<string | null>(null);
  const act = async (action: string, id: string, name: string, keyId?: string) => {
    const typed = await promptDialog(`Type the app's name (${name}) to confirm`);
    if (typed === null) return;
    if (await run(() => api(`${base}/actions`, { body: { action, id, keyId, confirmName: typed } }), "Done")) {
      await run(() => api(`${base}/refresh`, { method: "POST" }));
      reload();
    }
  };
  return (
    <div style={{ marginTop: 12 }}>
      <div className="row"><p className="small muted" style={{ flex: 1 }}>
        {data?.takenAt ? `Checked ${fmtTime(data.takenAt)}. ` : "Not checked yet. "}Fenrir checks apps daily and raises an alert for each app secret or certificate that has expired or expires within 30 days.</p>
        <button className="primary" disabled={busy} onClick={() => run(() => api(`${base}/refresh`, { method: "POST" }), "Checked").then(reload)}>Check now</button></div>
      <ErrorNote error={error} />
      {data?.summary && <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
        <Pill value={`${data.summary.registrations} app registrations`} /><Pill value={`${data.summary.servicePrincipals} enterprise apps`} />
        {data.summary.expired > 0 && <Pill value={`${data.summary.expired} expired credentials`} tone="bad" />}
        {data.summary.expiring > 0 && <Pill value={`${data.summary.expiring} expiring`} tone="warn" />}
        {data.summary.highPrivilegeApps > 0 && <Pill value={`${data.summary.highPrivilegeApps} third-party apps with high privilege`} tone="warn" />}
        {data.summary.consentRequests > 0 && <Pill value={`${data.summary.consentRequests} consent requests`} tone="blue" />}
      </div>}
      {Object.entries(data?.unavailable || {}).map(([k, v]: any) => <p key={k} className="small"><Pill value="not readable" tone="warn" /> {k}: {v}</p>)}
      {data && !data.canManage && <p className="small muted">Actions need Application.ReadWrite.All and DelegatedPermissionGrant.ReadWrite.All, which Fenrir does not request by default.</p>}
      <h3>App registrations</h3>
      <Table rows={data?.registrations || []} empty="None." columns={[
        { key: "displayName", label: "App" }, { key: "audience", label: "Who can sign in" },
        { key: "credentials", label: "Secrets and certificates", render: (a: any) => <span className="small">{a.credentials.map((c: any) => (
          <span key={c.keyId} style={{ marginRight: 8 }}><Pill value={c.state} tone={STATE_TONE[c.state]} /> {c.type} {c.name} {c.endDateTime?.slice(0, 10)}
            {c.state === "expired" && data.canManage && <button className="link" disabled={busy} onClick={() => act("credential.remove", a.id, a.displayName, c.keyId)}>remove</button>}</span>))}</span> },
        { key: "extensions", label: "Directory extensions", render: (a: any) => <span className="small">{a.extensions.map((e: any) => `${e.name} (${e.dataType} on ${e.targetObjects.join("/")})`).join(", ")}</span> },
      ]} />
      <h3>Enterprise apps and permissions</h3>
      <Table rows={data?.servicePrincipals || []} empty="None." onRow={(s: any) => setOpen(open === s.id ? null : s.id)} columns={[
        { key: "displayName", label: "App", render: (s: any) => <>{s.displayName}{!s.enabled && <> <Pill value="off" tone="neutral" /></>}</> },
        { key: "publisher", label: "Publisher" },
        { key: "contract", label: "Acts as" },
        { key: "highPrivilege", label: "High privilege", render: (s: any) => s.highPrivilege.map((p: string) => <Pill key={p} value={p} tone="warn" />) },
        { key: "id", label: "", render: (s: any) => data.canManage && s.publisher !== "Microsoft" ? <button className="link" disabled={busy}
          onClick={(e) => { e.stopPropagation(); act(s.enabled ? "sp.disable" : "sp.enable", s.id, s.displayName); }}>{s.enabled ? "Turn off" : "Turn on"}</button> : null },
      ]} />
      {open && (() => { const s = data.servicePrincipals.find((x: any) => x.id === open); return s && (
        <div className="card"><h4>{s.displayName}: permissions</h4>
          {s.permissions.length === 0 && <p className="small muted">{s.permissionsChecked ? "No permissions granted." : "Not checked (Microsoft first-party app)."}</p>}
          {s.permissions.map((p: any, i: number) => <div key={i} className="small"><Pill value={p.kind} tone={p.kind === "application" ? "warn" : "blue"} /> {p.resource}: {p.permission}
            {p.consent && <span className="muted"> · consent: {p.consent}</span>}{p.highPrivilege && <> <Pill value="high privilege" tone="bad" /></>}
            {p.grantId && data.canManage && <button className="link" disabled={busy} onClick={() => act("grant.revoke", p.grantId, s.displayName)}>revoke consent</button>}</div>)}
        </div>); })()}
      {data?.consentRequests?.length > 0 && <><h3>Pending admin consent requests</h3>
        <Table rows={data.consentRequests} columns={[{ key: "appDisplayName", label: "App" }, { key: "scopes", label: "Asks for", render: (r: any) => r.scopes.join(", ") }]} />
        <p className="small muted">Review and approve requests in the Entra admin centre (Enterprise apps → Admin consent requests).</p></>}
    </div>
  );
}
