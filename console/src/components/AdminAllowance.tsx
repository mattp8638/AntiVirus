import { useState } from "react";
import { api } from "../api";
import { Modal, useAction } from "./ui";

export const ALLOW_KINDS: Record<string, string> = { any: "Admin access and running programs", session: "Admin access only", run: "Running programs as admin" };

// Lets a user (or anyone) on this device, or on every device of its customer, get admin access without approval.
export function AllowanceForm({ device, tenantId, onClose, onSaved }: { device?: any; tenantId?: string; onClose: () => void; onSaved: () => void }) {
  const signedIn = device?.metrics?.loggedOnUser || "";
  const [form, setForm] = useState({ who: signedIn ? "signed-in" : "named", user: "", scope: device ? "device" : "customer", kinds: "any",
                                     programs: "", minutes: 60, hours: "8", note: "" });
  const { run, busy } = useAction();
  const save = async () => {
    const body: Record<string, unknown> = { kinds: form.kinds, minutes: form.minutes, hours: form.hours === "0" ? null : Number(form.hours),
                                            note: form.note.trim(), programs: form.programs.split("\n").map((p) => p.trim()).filter(Boolean),
                                            anyUser: form.who === "anyone" };
    if (form.scope === "device" && device) body.deviceId = device.id; else body.tenantId = tenantId || device?.tenantId;
    if (form.who === "signed-in") { body.user = signedIn; body.userSid = device?.metrics?.loggedOnUserSid || ""; }
    if (form.who === "named") body.user = form.user.trim();
    if (await run(() => api("elevation-allowances", { body }), "Allowed: their next request is granted straight away")) onSaved();
  };
  const valid = form.note.trim().length >= 4 && (form.who !== "named" || form.user.trim().length > 0);
  return (
    <Modal title="Allow admin access without approval" onClose={onClose}
           footer={<><button onClick={onClose}>Cancel</button><button className="primary" disabled={busy || !valid} onClick={save}>Allow</button></>}>
      <p className="small muted">Requests that match are granted straight away, whatever the policy says. The user starts programs as administrator
        from the agent window, the PAM tray or by right-clicking a program and choosing <b>Run as administrator with Fenrir</b>.</p>
      <label className="field">Who<select value={form.who} onChange={(e) => setForm({ ...form, who: e.target.value })}>
        {signedIn && <option value="signed-in">{signedIn} (signed in now)</option>}
        <option value="named">A user I name</option>
        <option value="anyone">Anyone who signs in</option></select></label>
      {form.who === "named" && <label className="field">User name<input autoFocus value={form.user} placeholder="jo, CONTOSO\jo or PC1\jo"
                                                                       onChange={(e) => setForm({ ...form, user: e.target.value })} /></label>}
      {device && <label className="field">Where<select value={form.scope} onChange={(e) => setForm({ ...form, scope: e.target.value })}>
        <option value="device">This device ({device.hostname})</option>
        <option value="customer">Every device of this customer</option></select></label>}
      <label className="field">What<select value={form.kinds} onChange={(e) => setForm({ ...form, kinds: e.target.value })}>
        {Object.entries(ALLOW_KINDS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
      {form.kinds === "run" && <label className="field">Only these programs (optional, one per line: path, C:\Program Files\Vendor\* or SHA-256)
        <textarea rows={3} value={form.programs} onChange={(e) => setForm({ ...form, programs: e.target.value })} /></label>}
      <label className="field">Each admin session lasts<select value={form.minutes} onChange={(e) => setForm({ ...form, minutes: Number(e.target.value) })}>
        {[15, 30, 60, 120, 240, 480].map((m) => <option key={m} value={m}>{m < 60 ? `${m} minutes` : `${m / 60} hour${m > 60 ? "s" : ""}`}</option>)}</select></label>
      <label className="field">Allowed for<select value={form.hours} onChange={(e) => setForm({ ...form, hours: e.target.value })}>
        {[["1", "1 hour"], ["8", "8 hours"], ["24", "1 day"], ["168", "1 week"], ["720", "30 days"], ["0", "Until I remove it"]].map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></label>
      <label className="field">Why (kept in the audit log)<input value={form.note} placeholder="e.g. Developer laptop, installs tools daily"
                                                                onChange={(e) => setForm({ ...form, note: e.target.value })} /></label>
    </Modal>
  );
}

