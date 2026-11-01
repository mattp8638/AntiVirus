// Phone app protection: every app on an Android phone with Fenrir's verdict, and what can be done about each.
import { useState } from "react";
import { ago, api } from "../api";
import { useApp } from "../app-context";
import { confirmDialog } from "./dialogs";
import { displayValue } from "./DisplayValue";
import { ErrorNote, Modal, Pill, Table, useAction, useData } from "./ui";

const VERDICT_TONE: Record<string, string> = { malicious: "bad", suspicious: "bad", risky: "bad", review: "warn", clean: "good", trusted: "blue" };

export function MobileApps({ deviceId }: { deviceId: string }) {
  const { can } = useApp();
  const { data, error, reload } = useData<any>(`devices/${deviceId}/mobile-apps`, {}, [deviceId]);
  const { run, busy } = useAction();
  const [open, setOpen] = useState<any>(null);
  const [showAll, setShowAll] = useState(false);
  if (error) return <ErrorNote error={error} />;
  if (!data) return <div className="empty">Loading…</div>;
  const command = (type: string, payload: Record<string, unknown>, message: string) =>
    run(() => api(`devices/${deviceId}/commands`, { body: { type, payload, reason: message } }), message);
  const scan = async () => { if (await command("app.scan", {}, "The phone is checking its apps")) window.setTimeout(reload, 4000); };
  const worth = (a: any) => ["malicious", "suspicious", "risky", "review"].includes(a.verdict);
  const rows = (showAll ? data.apps : data.apps.filter(worth)).map((a: any) => ({ ...a, id: a.package }));
  const c = data.counts;
  return (
    <>
      <div className="row" style={{ gap: 8, flexWrap: "wrap", marginBottom: 10 }}>
        {c.malicious > 0 && <Pill value={`${c.malicious} malicious`} tone="bad" />}
        {c.risky + c.suspicious > 0 && <Pill value={`${c.risky + c.suspicious} risky`} tone="bad" />}
        {c.review > 0 && <Pill value={`${c.review} worth a look`} tone="warn" />}
        <span className="small muted">{data.apps.length} apps · {data.deviceOwner ? "company-owned phone: apps can be removed or suspended silently" : "removing an app asks the phone's user"}</span>
        <span className="spacer" />
        <label className="small"><input type="checkbox" checked={showAll} onChange={(e) => setShowAll(e.target.checked)} /> Show every app</label>
        {can("respond") && <button disabled={busy} onClick={scan}>Check apps now</button>}
      </div>
      <Table rows={rows} onRow={setOpen} empty={showAll ? "The phone has not reported its apps yet." : "Nothing risky on this phone."}
             columns={[
               { key: "label", label: "App", render: (a) => <><b>{displayValue(a.label || a.package)}</b><div className="small muted mono">{a.package}</div></> },
               { key: "verdict", label: "Verdict", render: (a) => <><Pill value={a.verdict} tone={VERDICT_TONE[a.verdict]} />{a.suspended && <> <Pill value="suspended" tone="muted" /></>}</> },
               { key: "reasons", label: "Why", render: (a) => <span className="small">{displayValue(a.verdictReason || a.risk.reasons[0] || "")}</span> },
               { key: "installer", label: "From", render: (a) => <span className="small">{a.sideloaded ? `sideloaded${a.installer ? ` (${a.installer})` : ""}` : (a.system ? "system" : "app store")}</span> },
               { key: "lastSeen", label: "Checked", render: (a) => ago(a.lastSeen) },
             ]} />
      {open && <AppDetail app={open} deviceOwner={data.deviceOwner} onClose={() => setOpen(null)} busy={busy}
        onRemove={async () => {
          if (!(await confirmDialog(`Remove ${open.label || open.package} from this phone?${data.deviceOwner ? "" : " The phone's user will be asked to confirm."}`))) return;
          if (await command("app.uninstall", { package: open.package }, data.deviceOwner ? "Removing the app" : "The phone's user has been asked to remove it")) setOpen(null);
        }}
        onSuspend={async (suspended: boolean) => {
          if (await command("app.suspend", { package: open.package, suspended }, suspended ? "Suspending the app" : "Letting the app run again")) setOpen(null);
        }}
        onTrust={async () => {
          if (!(await confirmDialog(`Trust ${open.label || open.package} for this customer? Its alert closes and this exact app stops being flagged.`))) return;
          if (await run(() => api(`devices/${deviceId}/mobile-apps/trust`, { body: { package: open.package } }), "Trusted")) { setOpen(null); reload(); }
        }} />}
    </>
  );
}

function AppDetail({ app, deviceOwner, busy, onClose, onRemove, onSuspend, onTrust }: {
  app: any; deviceOwner: boolean; busy: boolean; onClose: () => void; onRemove: () => void; onSuspend: (s: boolean) => void; onTrust: () => void;
}) {
  const { can } = useApp();
  const abilities = Object.entries(app.abilities || {}).filter(([, on]) => on).map(([k]) => ({ accessibility: "controls the screen", deviceAdmin: "device administrator",
    notificationAccess: "reads notifications", hidden: "no app icon" } as Record<string, string>)[k] ?? k);
  return (
    <Modal wide title={app.label || app.package} onClose={onClose}
           footer={can("respond") && <>
             {app.verdict !== "trusted" && <button disabled={busy} onClick={onTrust}>Trust</button>}
             {deviceOwner && <button disabled={busy} onClick={() => onSuspend(!app.suspended)}>{app.suspended ? "Let it run" : "Suspend"}</button>}
             <button className="danger" disabled={busy} onClick={onRemove}>Remove from phone</button>
           </>}>
      <div className="row" style={{ gap: 8, flexWrap: "wrap", marginBottom: 8 }}>
        <Pill value={app.verdict} tone={VERDICT_TONE[app.verdict]} /> <span className="small muted mono">{app.package}</span>
        <span className="small">version {displayValue(app.version)}</span>
        <span className="small">{app.sideloaded ? `sideloaded${app.installer ? ` by ${app.installer}` : ""}` : `from ${app.installer || "the system"}`}</span>
      </div>
      {app.verdictReason && <p>{displayValue(app.verdictReason)}</p>}
      {app.risk.reasons.length > 0 && <><h3>What the phone found (risk {app.risk.score}/100)</h3><ul>{app.risk.reasons.map((r: string) => <li key={r}>{r}</li>)}</ul></>}
      {abilities.length > 0 && <p className="small">Abilities: {abilities.join(", ")}</p>}
      {app.permissions.length > 0 && <p className="small">Notable permissions: {app.permissions.map((p: string) => p.replace("android.permission.", "")).join(", ")}</p>}
      <p className="small muted mono" style={{ wordBreak: "break-all" }}>APK SHA-256 {app.sha256 || "not read"}<br />Signer SHA-256 {app.signer || "unknown"}</p>
      <p className="small muted">To block this app everywhere, add <span className="mono">{app.sha256 || `android:${app.package}`}</span> as a malicious indicator in Threat intel.</p>
    </Modal>
  );
}
