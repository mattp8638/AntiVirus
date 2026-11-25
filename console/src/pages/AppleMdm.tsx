// Apple device management (MDM-02): Apple's MDM protocol with Fenrir's own enrolment identities. Apple's push
// certificate and Apple Business Manager are dependencies shown with their state and expiry.
import { useState } from "react";
import { api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { promptDialog } from "../components/dialogs";
import { PageHead, Pill, Table, useAction, useData } from "../components/ui";

export default function AppleMdm() {
  const { tenantId } = useApp();
  const { run, busy } = useAction();
  const { data: cfg, reload } = useData<any>(tenantId ? `apple-mdm/config/${tenantId}` : null, undefined, [tenantId]);
  const { data: devices, reload: reloadDevices } = useData<any[]>(tenantId ? "apple-mdm/devices" : null, { tenantId: tenantId || undefined }, [tenantId]);
  const [f, setF] = useState({ serverUrl: "", pushCertificatePem: "", pushKeyPem: "", abmTokenExpiresAt: "" });
  const save = () => run(() => api(`apple-mdm/config/${tenantId}`, { method: "PUT", body: Object.fromEntries(Object.entries({
    ...f, abmTokenExpiresAt: f.abmTokenExpiresAt ? new Date(f.abmTokenExpiresAt).toISOString() : "" }).filter(([, v]) => v)) }), "Saved").then(reload);
  const profile = async () => {
    const out = await run(() => api<any>(`apple-mdm/config/${tenantId}/enrollments`, { body: { label: "" } }));
    if (!out) return;
    const link = document.createElement("a");
    link.href = `data:application/x-apple-aspen-config;base64,${out.profileBase64}`;
    link.download = out.filename;
    link.click();
  };
  const command = async (d: any, requestType: string) => {
    const body: any = { requestType };
    if (requestType === "EraseDevice") {
      const typed = await promptDialog(`Erasing removes everything on ${d.model} ${d.serialNumber}. Type its serial number to confirm.`);
      if (!typed) return;
      body.confirmSerial = typed;
    }
    const out = await run(() => api<any>(`apple-mdm/devices/${d.id}/commands`, { body }), "Queued");
    if (out && !out.push.pushed) await run(async () => { throw new Error(`Queued, but not pushed: ${out.push.reason}`); });
    reloadDevices();
  };
  const dep = cfg?.dependencies || {};
  return (
    <>
      <PageHead title="Apple devices (MDM)" subtitle="Manage iPhones, iPads and Macs with Apple's MDM protocol: enrolment profiles, inventory, profiles, enterprise apps, lock and erase." />
      {!tenantId ? <div className="card empty">Choose a customer.</div> : <>
        <div className="card">
          <h3>Apple dependencies</h3>
          <div className="small"><Pill value={dep.apnsPushCertificate ? "configured" : "missing"} tone={dep.apnsPushCertificate ? "good" : "bad"} /> APNs MDM push certificate
            {cfg?.pushExpiresAt && ` · expires ${fmtTime(cfg.pushExpiresAt)} · topic ${cfg.pushTopic}`}</div>
          <div className="small"><Pill value={dep.appleBusinessManager ? "token recorded" : "not set"} tone={dep.appleBusinessManager ? "good" : "neutral"} /> Apple Business Manager
            {cfg?.abmTokenExpiresAt && ` · token expires ${fmtTime(cfg.abmTokenExpiresAt)}`}</div>
          <div className="small"><Pill value="not built" tone="neutral" /> Automated device enrolment (ADE) sync: devices enrol with a profile for now</div>
          <div className="form-grid" style={{ marginTop: 8 }}>
            <label className="field">Public server address<input placeholder="https://fenrir.example.com" value={f.serverUrl} onChange={(e) => setF({ ...f, serverUrl: e.target.value })} /></label>
            <label className="field">Push certificate (PEM, from identity.apple.com/pushcert)<textarea value={f.pushCertificatePem} onChange={(e) => setF({ ...f, pushCertificatePem: e.target.value })} /></label>
            <label className="field">Push certificate private key (PEM)<textarea value={f.pushKeyPem} onChange={(e) => setF({ ...f, pushKeyPem: e.target.value })} /></label>
            <label className="field">ABM server token expires<input type="date" value={f.abmTokenExpiresAt} onChange={(e) => setF({ ...f, abmTokenExpiresAt: e.target.value })} /></label>
          </div>
          <div className="row" style={{ gap: 8 }}><button className="primary" disabled={busy} onClick={save}>Save</button>
            <button disabled={busy || !dep.apnsPushCertificate} onClick={profile}>Download an enrolment profile (one device, 7 days)</button></div>
        </div>
        <Table rows={devices || []} empty="No Apple devices enrolled." columns={[
          { key: "model", label: "Device", render: (d: any) => <>{d.info?.DeviceName || d.model}<div className="small muted">{d.model} · {d.serialNumber}</div></> },
          { key: "osVersion", label: "OS" },
          { key: "status", label: "Status", render: (d: any) => <Pill value={d.status} tone={d.status === "enrolled" ? "good" : "neutral"} /> },
          { key: "lastSeenAt", label: "Last seen", render: (d: any) => (d.lastSeenAt ? fmtTime(d.lastSeenAt) : "") },
          { key: "id", label: "", render: (d: any) => d.status === "enrolled" ? <span className="row" style={{ gap: 4 }}>
            <button className="link" onClick={() => command(d, "DeviceInformation")}>Refresh</button>
            <button className="link" onClick={() => command(d, "SecurityInfo")}>Security</button>
            <button className="link" onClick={() => command(d, "DeviceLock")}>Lock</button>
            <button className="link" onClick={() => command(d, "EraseDevice")}>Erase…</button></span> : null },
        ]} />
      </>}
    </>
  );
}
