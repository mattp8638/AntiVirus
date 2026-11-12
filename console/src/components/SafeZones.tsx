// Safe zones (geofences) for a phone: alert when it leaves or arrives somewhere, at the times that matter, and
// push a notification to the people chosen. Shown on the phone's Location tab.
import { useEffect, useRef, useState } from "react";
import L from "leaflet";
import { ago, api } from "../api";
import { useApp } from "../app-context";
import { displayValue } from "./DisplayValue";
import { confirmDialog } from "./dialogs";
import { Modal, Pill, useAction, useData } from "./ui";

const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const ALERT_ON: Record<string, string> = { exit: "leaves", enter: "arrives", both: "leaves or arrives" };
const metres = (m: number) => (m >= 1000 ? `${(m / 1000).toFixed(m >= 10000 ? 0 : 1)} km` : `${Math.round(m)} m`);

export type Zone = {
  id?: string; name: string; latitude: number; longitude: number; radius: number; alertOn: string; severity: string;
  schedule: { days?: number[]; start?: string; end?: string }; notify: { users: string[]; emails: string[]; phone: boolean };
  enabled?: boolean; state?: string; stateAt?: string | null; lastAlertAt?: string | null;
};

export function scheduleText(schedule: Zone["schedule"]) {
  if (!schedule?.days?.length) return "any time";
  const days = schedule.days.length === 7 ? "every day" : schedule.days.join(",") === "0,1,2,3,4" ? "weekdays"
    : schedule.days.join(",") === "5,6" ? "weekends" : schedule.days.map((d) => DAYS[d]).join(", ");
  return `${days}, ${schedule.start}–${schedule.end}`;
}

/** A small map to place the zone: click to move the centre; the circle follows the radius. */
function ZonePicker({ zone, onMove }: { zone: Zone; onMove: (lat: number, lon: number) => void }) {
  const box = useRef<HTMLDivElement>(null);
  const map = useRef<L.Map | null>(null);
  const circle = useRef<L.Circle | null>(null);
  const move = useRef(onMove);
  move.current = onMove;
  useEffect(() => {
    if (!box.current || map.current) return;
    map.current = L.map(box.current).setView([zone.latitude, zone.longitude], 16);
    L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {
      maxZoom: 19, attribution: "&copy; OpenStreetMap contributors", referrerPolicy: "strict-origin-when-cross-origin",
    }).addTo(map.current);
    circle.current = L.circle([zone.latitude, zone.longitude], { radius: zone.radius, color: "#22c55e", weight: 2, fillOpacity: 0.15 }).addTo(map.current);
    map.current.on("click", (e: L.LeafletMouseEvent) => move.current(e.latlng.lat, e.latlng.lng));
    return () => { map.current?.remove(); map.current = null; };
  }, []);  // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    circle.current?.setLatLng([zone.latitude, zone.longitude]).setRadius(zone.radius);
    if (map.current && circle.current) map.current.fitBounds(circle.current.getBounds().pad(0.3), { maxZoom: 17 });
  }, [zone.latitude, zone.longitude, zone.radius]);
  return <div ref={box} className="track-map" style={{ height: 240 }} role="img" aria-label="Map of the safe zone: click to move it" />;
}

function ZoneForm({ device, zone, recipients, emailConfigured, onClose }: {
  device: any; zone: Zone; recipients: any[]; emailConfigured: boolean; onClose: (saved: boolean) => void;
}) {
  const [form, setForm] = useState<Zone>(zone);
  const [timed, setTimed] = useState(Boolean(zone.schedule?.days?.length));
  const [emails, setEmails] = useState((zone.notify?.emails || []).join(", "));
  const { run, busy } = useAction();
  const set = (patch: Partial<Zone>) => setForm({ ...form, ...patch });
  const schedule = form.schedule?.days?.length ? form.schedule : { days: [0, 1, 2, 3, 4], start: "08:30", end: "15:30" };
  const toggleUser = (id: string) => set({ notify: { ...form.notify, users: form.notify.users.includes(id) ? form.notify.users.filter((u) => u !== id) : [...form.notify.users, id] } });
  const save = async () => {
    const body = { name: form.name, latitude: form.latitude, longitude: form.longitude, radius: Number(form.radius), alertOn: form.alertOn,
      severity: form.severity, schedule: timed ? schedule : {},
      notify: { ...form.notify, emails: emails.split(/[,\s;]+/).map((e) => e.trim()).filter(Boolean) } };
    const path = `devices/${device.id}/geofences${zone.id ? `/${zone.id}` : ""}`;
    if (await run(() => api(path, { method: zone.id ? "PATCH" : "POST", body }), zone.id ? "Safe zone saved" : "Safe zone added")) onClose(true);
  };
  return (
    <Modal title={zone.id ? `Safe zone · ${zone.name}` : `New safe zone · ${device.hostname}`} onClose={() => onClose(false)}
      footer={<><button onClick={() => onClose(false)}>Cancel</button><button className="primary" disabled={busy || !form.name.trim()} onClick={save}>Save</button></>}>
      <label className="field">Name<input value={form.name} maxLength={120} onChange={(e) => set({ name: e.target.value })} placeholder="Office, Warehouse, Home…" autoFocus /></label>
      <p className="small muted" style={{ margin: "10px 0 6px" }}>Click the map to move the centre.</p>
      <ZonePicker zone={form} onMove={(latitude, longitude) => set({ latitude, longitude })} />
      <label className="field" style={{ marginTop: 10 }}>Radius: {metres(Number(form.radius))}
        <input type="range" min={50} max={2000} step={10} value={Math.min(Number(form.radius), 2000)} onChange={(e) => set({ radius: Number(e.target.value) })} /></label>
      <div className="form-grid compact" style={{ marginTop: 10 }}>
        <label className="field">Alert when the phone
          <select value={form.alertOn} onChange={(e) => set({ alertOn: e.target.value })}>
            <option value="exit">leaves</option><option value="enter">arrives</option><option value="both">leaves or arrives</option>
          </select></label>
        <label className="field">Priority
          <select value={form.severity} onChange={(e) => set({ severity: e.target.value })}>
            {["low", "medium", "high", "critical"].map((s) => <option key={s} value={s}>{s}</option>)}
          </select></label>
      </div>
      <fieldset style={{ marginTop: 12 }}>
        <legend>When</legend>
        <label className="row small"><input type="radio" checked={!timed} onChange={() => setTimed(false)} /> Any time</label>
        <label className="row small"><input type="radio" checked={timed} onChange={() => { setTimed(true); set({ schedule }); }} /> Only at these times</label>
        {timed && <div style={{ marginTop: 6 }}>
          <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
            {DAYS.map((d, i) => <label key={d} className="row small" style={{ gap: 3 }}>
              <input type="checkbox" checked={schedule.days!.includes(i)} onChange={() => set({ schedule: { ...schedule, days: schedule.days!.includes(i) ? schedule.days!.filter((x) => x !== i) : [...schedule.days!, i].sort() } })} />{d}</label>)}
          </div>
          <div className="row" style={{ gap: 8, marginTop: 6 }}>
            <label className="field">From<input type="time" value={schedule.start} onChange={(e) => set({ schedule: { ...schedule, start: e.target.value } })} /></label>
            <label className="field">Until<input type="time" value={schedule.end} onChange={(e) => set({ schedule: { ...schedule, end: e.target.value } })} /></label>
          </div>
          <p className="small muted" style={{ margin: "4px 0 0" }}>In your time zone (Settings → Region). An overnight window such as 21:00–07:00 works.</p>
        </div>}
      </fieldset>
      <fieldset style={{ marginTop: 12 }}>
        <legend>Notify</legend>
        {recipients.map((p) => <label key={p.id} className="row small">
          <input type="checkbox" checked={form.notify.users.includes(p.id)} onChange={() => toggleUser(p.id)} />
          {displayValue(p.name)} <span className="muted">{p.pushDevices ? `· notifications on ${p.pushDevices} device${p.pushDevices > 1 ? "s" : ""}` : "· notifications not turned on yet"}</span></label>)}
        <p className="small muted" style={{ margin: "4px 0 8px" }}>Each person turns notifications on in Settings → Account, on the phone or computer they want them on.</p>
        <label className="field">Also email (comma-separated){!emailConfigured && <span className="small muted"> · email is not set up on this server, so these are not sent</span>}
          <input value={emails} onChange={(e) => setEmails(e.target.value)} placeholder="someone@example.com" /></label>
        <label className="row small" style={{ marginTop: 8 }}><input type="checkbox" checked={form.notify.phone} onChange={(e) => set({ notify: { ...form.notify, phone: e.target.checked } })} />
          Also tell the person on the phone when they leave or arrive</label>
      </fieldset>
    </Modal>
  );
}

export function SafeZones({ device, latest, onChanged }: { device: any; latest: any; onChanged?: () => void }) {
  const { can } = useApp();
  const { data, reload: refresh } = useData<any>(`devices/${device.id}/geofences`);
  const reload = () => { refresh(); onChanged?.(); };
  const { run, busy } = useAction();
  const [editing, setEditing] = useState<Zone | null>(null);
  const zones: Zone[] = data?.geofences || [];
  const add = () => setEditing({ name: "", latitude: latest?.lat ?? 51.5007, longitude: latest?.lon ?? -0.1246, radius: 200, alertOn: "exit",
    severity: "high", schedule: {}, notify: { users: [], emails: [], phone: false } });
  return (
    <div className="card">
      <div className="row"><h3 style={{ margin: 0, flex: 1 }}>Safe zones</h3>
        {can("respond") && !device.retired && <button className="small primary" onClick={add}>Add safe zone</button>}</div>
      <p className="small muted">Get an alert and a notification when this phone leaves or arrives somewhere, for example someone leaving home at night or a child leaving school during the day.</p>
      {!zones.length ? <p className="small muted" style={{ marginBottom: 0 }}>No safe zones yet.</p> : zones.map((z) => (
        <div key={z.id} className="row" style={{ padding: "8px 0", borderTop: "1px solid var(--line, #263042)", gap: 8, alignItems: "flex-start" }}>
          <div style={{ flex: 1 }}>
            <b>{displayValue(z.name)}</b> {!z.enabled ? <Pill value="paused" tone="muted" /> : z.state === "inside" ? <Pill value="inside" tone="good" />
              : z.state === "outside" ? <Pill value="outside" tone="warn" /> : <Pill value="waiting for a location" tone="muted" />}
            <div className="small muted">{metres(z.radius)} · alert when it {ALERT_ON[z.alertOn]} · {scheduleText(z.schedule)}
              {z.notify.users.length ? ` · notifies ${z.notify.users.length}` : ""}{z.lastAlertAt ? ` · last alert ${ago(z.lastAlertAt)}` : ""}</div>
          </div>
          {can("respond") && <>
            <button className="small" onClick={() => setEditing(z)}>Edit</button>
            <button className="small" disabled={busy} onClick={async () => { if (await run(() => api(`devices/${device.id}/geofences/${z.id}`, { method: "PATCH", body: { enabled: !z.enabled } }), z.enabled ? "Paused" : "Resumed")) reload(); }}>{z.enabled ? "Pause" : "Resume"}</button>
            <button className="small danger" disabled={busy} onClick={async () => { if (await confirmDialog(`Delete the safe zone ${z.name}?`) && await run(() => api(`devices/${device.id}/geofences/${z.id}`, { method: "DELETE" }), "Deleted")) reload(); }}>Delete</button>
          </>}
        </div>))}
      {editing && <ZoneForm device={device} zone={editing} recipients={data?.recipients || []} emailConfigured={Boolean(data?.emailConfigured)}
        onClose={(saved) => { setEditing(null); if (saved) reload(); }} />}
    </div>
  );
}
