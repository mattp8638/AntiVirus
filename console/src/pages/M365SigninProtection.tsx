import { displayValue } from "../components/DisplayValue";
import { useEffect, useState } from "react";
import { api, ago } from "../api";
import { useApp } from "../app-context";
import { ErrorNote, Pill, Sev, useAction, useData } from "../components/ui";

const KIND: Record<string, string> = { "impossible-travel": "Impossible travel", "new-country": "New country", "spray-success": "Success after many failures" };

// Impossible travel and unusual sign-ins, worked out by Fenrir from the tenant's sign-in logs (no Entra ID P2 needed).
export default function M365SigninProtection({ connection }: { connection: any }) {
  const tenantId = connection.tenantId;
  const { can } = useApp();
  const { data, error, reload } = useData<any>("m365/signin-protection", { tenant_id: tenantId }, [tenantId]);
  const { run, busy } = useAction();
  const [form, setForm] = useState<any>(null);
  useEffect(() => { if (data?.settings) setForm({ ...data.settings, trusted: (data.settings.trustedCountries || []).join(", "), networks: (data.settings.ignoreNetworks || []).join("\n") }); }, [data]);
  if (error) return <ErrorNote error={error} />;
  if (!form) return <p className="muted">Loading…</p>;
  const pb = form.playbook || {};
  const save = async () => {
    const body = { tenantId, enabled: form.enabled, maxSpeedKmh: Number(form.maxSpeedKmh), minDistanceKm: Number(form.minDistanceKm),
      newCountry: form.newCountry, sprayFailures: Number(form.sprayFailures),
      trustedCountries: String(form.trusted).split(/[,\s]+/).filter(Boolean), ignoreNetworks: String(form.networks).split(/[\n,\s]+/).filter(Boolean),
      playbook: pb };
    if (await run(() => api("m365/signin-protection", { method: "PUT", body }), "Sign-in protection saved")) reload();
  };
  const set = (k: string, v: any) => setForm({ ...form, [k]: v });
  const setPb = (k: string, v: any) => setForm({ ...form, playbook: { ...pb, [k]: v } });
  const editable = can("m365_admin");
  return (
    <div className="grid k2" style={{ gap: 14, alignItems: "start" }}>
      <div className="card">
        <h3 style={{ marginTop: 0 }}>Sign-in protection</h3>
        <p className="small muted">Fenrir checks this tenant's sign-ins every 10 minutes for <b>impossible travel</b> (two sign-ins further apart than anyone could travel in the time between them),
          sign-ins from a <b>country the user has not used</b> in 90 days, and a <b>successful sign-in straight after many failures</b>. Microsoft only offers this with Entra ID P2.</p>
        <label style={{ display: "block" }}><input type="checkbox" disabled={!editable} checked={!!form.enabled} onChange={(e) => set("enabled", e.target.checked)} /> <b>On for this customer</b></label>
        <div className="grid k2" style={{ gap: 8, marginTop: 8 }}>
          <label className="field">Faster than (km/h)<input type="number" disabled={!editable} value={form.maxSpeedKmh} onChange={(e) => set("maxSpeedKmh", e.target.value)} /></label>
          <label className="field">And at least (km apart)<input type="number" disabled={!editable} value={form.minDistanceKm} onChange={(e) => set("minDistanceKm", e.target.value)} /></label>
          <label className="field">Failures before a success counts<input type="number" disabled={!editable} value={form.sprayFailures} onChange={(e) => set("sprayFailures", e.target.value)} /></label>
          <label style={{ alignSelf: "end" }}><input type="checkbox" disabled={!editable} checked={!!form.newCountry} onChange={(e) => set("newCountry", e.target.checked)} /> Flag new countries</label>
        </div>
        <label className="field">Trusted countries (two-letter codes; never unusual)<input disabled={!editable} placeholder="GB, IE" value={form.trusted} onChange={(e) => set("trusted", e.target.value)} /></label>
        <label className="field">Ignore these IP addresses or ranges (office, VPN exits)<textarea rows={3} disabled={!editable} placeholder={"81.2.69.0/24\n203.0.113.9"} value={form.networks} onChange={(e) => set("networks", e.target.value)} /></label>
        <h4>Playbook (runs on every finding)</h4>
        <p className="small muted">An alert is always raised in the inbox. Then:</p>
        <label style={{ display: "block" }}><input type="checkbox" disabled={!editable} checked={!!pb.revokeSessions} onChange={(e) => setPb("revokeSessions", e.target.checked)} /> Sign the user out everywhere</label>
        <label style={{ display: "block" }}><input type="checkbox" disabled={!editable} checked={!!pb.blockSignIn} onChange={(e) => setPb("blockSignIn", e.target.checked)} /> Block their sign-in until someone checks (not possible in the cloud for users synced from AD: the ticket says so)</label>
        <label style={{ display: "block" }}><input type="checkbox" disabled={!editable} checked={!!pb.openTicket} onChange={(e) => setPb("openTicket", e.target.checked)} /> Open a ticket for Security Operations</label>
        <label className="field">Also email (optional)<input disabled={!editable} placeholder="security@your-msp.example" value={pb.notifyEmail || ""} onChange={(e) => setPb("notifyEmail", e.target.value.trim())} /></label>
        {editable && <button className="primary" disabled={busy} onClick={save}>Save</button>}
      </div>
      <div className="card">
        <h3 style={{ marginTop: 0 }}>Findings</h3>
        {data.findings.length === 0 && <p className="small muted">Nothing found{form.enabled ? " yet" : ": protection is off"}.</p>}
        {data.findings.map((f: any) => (
          <div key={f.id} className="small" style={{ padding: "6px 0", borderBottom: "1px solid var(--line)" }}>
            <div className="row" style={{ gap: 6 }}><Sev level={f.severity} /> <b style={{ flex: 1 }}>{KIND[f.kind] || f.kind}</b> <Pill value={f.status} /> <span className="muted">{ago(f.at)}</span></div>
            <div>{displayValue(f.summary)}</div>
            {f.actions.length > 0 && <div className="muted">Done: {f.actions.join("; ")}</div>}
          </div>
        ))}
      </div>
    </div>
  );
}
