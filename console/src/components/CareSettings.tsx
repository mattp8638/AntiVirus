// Care for one phone (on its Location tab): how closely to track it, who looks after it, and when to raise the alarm.
import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { useApp } from "../app-context";
import { displayValue } from "./DisplayValue";
import { Modal, Pill, useAction, useData } from "./ui";

const TRACKING: Record<string, string> = {
  close: "Close: every minute while moving or near a safe zone's edge, every 5 minutes when still",
  standard: "Standard: every 5 minutes",
  saver: "Battery saver: every 15 minutes",
};

function People({ label, people, chosen, onChange }: { label: string; people: any[]; chosen: string[]; onChange: (ids: string[]) => void }) {
  return (
    <fieldset style={{ marginTop: 10 }}>
      <legend>{label}</legend>
      {!people.length && <p className="small muted">Nobody can see this customer yet. Add a user with the carer role in Settings → Users.</p>}
      {people.map((p) => <label key={p.id} className="row small">
        <input type="checkbox" checked={chosen.includes(p.id)} onChange={() => onChange(chosen.includes(p.id) ? chosen.filter((x) => x !== p.id) : [...chosen, p.id])} />
        {displayValue(p.name)} <span className="muted">{p.pushDevices ? `· notifications on` : "· notifications not turned on yet"}</span></label>)}
    </fieldset>
  );
}

export function CareSettings({ device }: { device: any }) {
  const { can } = useApp();
  const { data, reload } = useData<any>(`devices/${device.id}/care`);
  const [form, setForm] = useState<any>(null);
  const { run, busy } = useAction();
  if (!data) return null;
  const care = data.care;
  const name = (id: string) => data.recipients.find((p: any) => p.id === id)?.name || "someone";
  const save = async () => {
    const body = { ...form, quietMinutes: Number(form.quietMinutes), lowBattery: Number(form.lowBattery), escalateAfter: Number(form.escalateAfter),
      emails: String(form.emailsText || "").split(/[,\s;]+/).map((e: string) => e.trim()).filter(Boolean) };
    delete body.emailsText;
    if (await run(() => api(`devices/${device.id}/care`, { method: "PUT", body }), "Care settings saved")) { setForm(null); reload(); }
  };
  return (
    <div className="card">
      <div className="row"><h3 style={{ margin: 0, flex: 1 }}>Care {data.enabled ? <Pill value="on" tone="good" /> : <Pill value="off" tone="muted" />}</h3>
        {can("respond") && !device.retired && <button className="small" onClick={() => setForm({ ...care, emailsText: (care.emails || []).join(", ") })}>{data.enabled ? "Change" : "Turn on"}</button>}</div>
      {data.sos?.active && <p style={{ color: "#fecaca" }}><b>Asked for help</b> — see the <Link to={`/care?device=${device.id}`}>Care page</Link>.</p>}
      {!data.enabled ? <p className="small muted" style={{ marginBottom: 0 }}>For someone being looked after (an older relative, a child): closer tracking, a Help button on
        their phone, and alerts to their carers if they ask for help, go quiet, run low on battery or turn location off.</p>
        : <dl className="kv compact" style={{ marginBottom: 0 }}>
          <dt>Tracking</dt><dd>{TRACKING[care.tracking].split(":")[0]}</dd>
          <dt>Carers</dt><dd>{care.carers.length ? care.carers.map(name).join(", ") : "none chosen"}</dd>
          <dt>Gone quiet</dt><dd>{care.quietMinutes ? `after ${care.quietMinutes} minutes` : "off"}</dd>
          <dt>Low battery</dt><dd>{care.lowBattery ? `at ${care.lowBattery}%` : "off"}</dd>
          <dt>Escalate</dt><dd>{care.escalateAfter && care.escalateTo.length ? `to ${care.escalateTo.map(name).join(", ")} after ${care.escalateAfter} minutes unanswered` : "off"}</dd>
        </dl>}
      {form && <Modal title={`Care · ${device.hostname}`} onClose={() => setForm(null)}
        footer={<>{data.enabled && <button className="danger" disabled={busy} onClick={async () => { if (await run(() => api(`devices/${device.id}/care`, { method: "PUT", body: { enabled: false } }), "Care turned off")) { setForm(null); reload(); } }}>Turn off</button>}
          <button onClick={() => setForm(null)}>Cancel</button><button className="primary" disabled={busy} onClick={save}>Save</button></>}>
        <label className="field">How closely to track
          <select value={form.tracking} onChange={(e) => setForm({ ...form, tracking: e.target.value })}>
            {Object.entries(TRACKING).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select></label>
        <p className="small muted">Close uses more battery; it slows down by itself while the phone is still. During a request for help the phone always reports every minute.</p>
        <People label="Carers (notified of every care alert)" people={data.recipients} chosen={form.carers} onChange={(carers) => setForm({ ...form, carers })} />
        <div className="form-grid compact" style={{ marginTop: 10 }}>
          <label className="field">Alert if not heard from for (minutes, 0 = off)<input type="number" min={0} max={1440} value={form.quietMinutes} onChange={(e) => setForm({ ...form, quietMinutes: e.target.value })} /></label>
          <label className="field">Alert at battery % (0 = off)<input type="number" min={0} max={50} value={form.lowBattery} onChange={(e) => setForm({ ...form, lowBattery: e.target.value })} /></label>
          <label className="field">Escalate if unanswered for (minutes, 0 = off)<input type="number" min={0} max={1440} value={form.escalateAfter} onChange={(e) => setForm({ ...form, escalateAfter: e.target.value })} /></label>
        </div>
        <People label="Escalate to" people={data.recipients} chosen={form.escalateTo} onChange={(escalateTo) => setForm({ ...form, escalateTo })} />
        <label className="field" style={{ marginTop: 10 }}>Also email (comma-separated, needs email set up on the server)
          <input value={form.emailsText} onChange={(e) => setForm({ ...form, emailsText: e.target.value })} /></label>
        <p className="small muted">Location turned off always alerts the carers. The person sees on their phone that their location is shared.</p>
      </Modal>}
    </div>
  );
}
