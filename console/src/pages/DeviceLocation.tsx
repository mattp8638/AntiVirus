import { displayValue } from "../components/DisplayValue";
import { useEffect, useRef, useState } from "react";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import { ago, api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { ErrorNote, Modal, useAction, useData } from "../components/ui";

// Where a phone is and has been, plus the anti-theft controls: locate, alarm, lock, lost mode and erase.
// Loaded only for phones (Leaflet + OpenStreetMap tiles), so desktops never download the map.

const RANGES = [{ hours: 24, label: "24 hours" }, { hours: 168, label: "7 days" }, { hours: 720, label: "30 days" }];
const km = (m: number) => m >= 1000 ? `${(m / 1000).toFixed(m >= 10000 ? 0 : 1)} km` : `${Math.round(m)} m`;

function TrackMap({ points, latest }: { points: any[]; latest: any }) {
  const box = useRef<HTMLDivElement>(null);
  const map = useRef<L.Map | null>(null);
  const layer = useRef<L.LayerGroup | null>(null);
  const fitted = useRef("");
  useEffect(() => {
    if (!box.current || map.current) return;
    map.current = L.map(box.current, { zoomControl: true, attributionControl: true }).setView([51.5, -0.12], 5);
    L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {
      maxZoom: 19, attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
      // OpenStreetMap blocks tile requests without a Referer, and the console sends none by default
      // (Referrer-Policy: no-referrer). Send just this site's origin for the tiles, never the page path.
      referrerPolicy: "strict-origin-when-cross-origin",
    }).addTo(map.current);
    layer.current = L.layerGroup().addTo(map.current);
    const resize = new ResizeObserver(() => map.current?.invalidateSize());
    resize.observe(box.current);
    return () => { resize.disconnect(); map.current?.remove(); map.current = null; };
  }, []);
  useEffect(() => {
    const group = layer.current;
    if (!map.current || !group) return;
    group.clearLayers();
    const coords = points.map((p) => [p.lat, p.lon] as [number, number]);
    if (coords.length > 1) L.polyline(coords, { color: "#38bdf8", weight: 3, opacity: 0.7 }).addTo(group);
    points.slice(0, -1).forEach((p) => L.circleMarker([p.lat, p.lon], { radius: 3, color: "#38bdf8", weight: 1, fillOpacity: 0.8 })
      .bindTooltip(`${fmtTime(p.at)} · ±${Math.round(p.accuracy ?? 0)} m`).addTo(group));
    if (latest) {
      if (latest.accuracy) L.circle([latest.lat, latest.lon], { radius: latest.accuracy, color: "#a855f7", weight: 1, fillOpacity: 0.12 }).addTo(group);
      L.circleMarker([latest.lat, latest.lon], { radius: 9, color: "#fff", weight: 3, fillColor: "#a855f7", fillOpacity: 1 })
        .bindTooltip(`Last seen here ${ago(latest.at)}`, { permanent: false }).addTo(group);
    }
    // Re-frame only when the data set changes, so a refresh does not undo the technician's zoom.
    const key = `${points.length}:${latest?.at}`;
    if (key !== fitted.current) {
      fitted.current = key;
      const all = latest ? [...coords, [latest.lat, latest.lon] as [number, number]] : coords;
      if (all.length === 1) map.current.setView(all[0], 16);
      else if (all.length > 1) map.current.fitBounds(L.latLngBounds(all).pad(0.2), { maxZoom: 17 });
    }
  }, [points, latest]);
  return <div ref={box} className="track-map" role="img" aria-label="Map of the device's location history" />;
}

export function LocationTab({ device, onChanged }: { device: any; onChanged: () => void }) {
  const { can } = useApp();
  const [hours, setHours] = useState(24);
  const { data, error, reload } = useData<any>(`devices/${device.id}/locations`, { hours }, [hours]);
  const { run, busy } = useAction();
  const [lostForm, setLostForm] = useState<{ message: string; phone: string } | null>(null);
  const [erasing, setErasing] = useState(false);
  const [eraseName, setEraseName] = useState("");
  const [messageOpen, setMessageOpen] = useState(false);
  const [message, setMessage] = useState("");
  const lost = data?.lostMode;
  // Watch closely while the phone is lost; otherwise refresh every minute.
  useEffect(() => {
    const timer = setInterval(() => { if (document.visibilityState === "visible") reload(); }, lost?.enabled ? 15000 : 60000);
    return () => clearInterval(timer);
  }, [reload, lost?.enabled]);

  const send = async (type: string, label: string, payload: any = {}) => {
    if (await run(() => api(`devices/${device.id}/commands`, { body: { type, payload, reason: `${label} from the Location tab` } }), `${label} sent; it runs when the phone next checks in`)) {
      onChanged();
      setTimeout(reload, 8000);
    }
  };
  const setLost = async (enabled: boolean, form?: { message: string; phone: string }) => {
    if (await run(() => api(`devices/${device.id}/lost-mode`, { body: { enabled, ...(form || {}) } }), enabled ? "Lost mode is on" : "Lost mode is off")) {
      setLostForm(null); reload(); onChanged();
    }
  };
  const latest = data?.latest;
  const mapsLink = latest ? `https://www.google.com/maps/search/?api=1&query=${latest.lat},${latest.lon}` : "";

  return (
    <>
      {lost?.enabled && <div className="lost-banner" role="status">
        <b>Lost mode is on</b> since {lost.since ? fmtTime(lost.since) : "now"}{lost.by ? ` (by ${lost.by})` : ""}. The phone is locked, shows
        "{displayValue(lost.message)}"{lost.phone ? ` and ${lost.phone}` : ""}, and reports its location every 5 minutes.
        {can("respond") && <button className="small" disabled={busy} onClick={() => setLost(false)}>Turn off</button>}
      </div>}
      <div className="grid side">
        <div className="card" style={{ padding: 0, overflow: "hidden" }}>
          <div className="row" style={{ padding: "10px 12px" }}>
            <b style={{ flex: 1 }}>Location history</b>
            {RANGES.map((r) => <button key={r.hours} className={`small ${hours === r.hours ? "primary" : ""}`} onClick={() => setHours(r.hours)}>{r.label}</button>)}
          </div>
          <ErrorNote error={error} />
          {data && (data.points.length || latest) ? <TrackMap points={data.points} latest={latest} /> :
            <div className="empty" style={{ minHeight: 260 }}>{data ? "No location yet. Use Locate now, or check the phone allows Fenrir to use location all the time." : "Loading…"}</div>}
        </div>
        <div className="stack">
          <div className="card">
            <h3>Last known location</h3>
            {!latest ? <p className="muted small">Not reported yet.</p> : <dl className="kv compact">
              <dt>When</dt><dd>{ago(latest.at)} <span className="muted small">{fmtTime(latest.at)}</span></dd>
              <dt>Accuracy</dt><dd>{latest.accuracy ? `± ${km(latest.accuracy)}` : "—"} <span className="muted small">{displayValue(latest.source)}</span></dd>
              <dt>Coordinates</dt><dd className="mono small">{displayValue(latest.lat.toFixed(5))}, {displayValue(latest.lon.toFixed(5))}</dd>
              {typeof latest.battery === "number" && <><dt>Battery</dt><dd>{displayValue(latest.battery)}%</dd></>}
              {data.travelledMeters > 0 && <><dt>Moved</dt><dd>{km(data.travelledMeters)} in {RANGES.find((r) => r.hours === hours)?.label}</dd></>}
            </dl>}
            {latest && <a className="btn small" style={{ marginTop: 10 }} href={mapsLink} target="_blank" rel="noreferrer">Open in Maps / directions</a>}
          </div>
          {can("respond") && !device.retired && <div className="card">
            <h3>Find and protect</h3>
            <div className="action-grid">
              <button className="primary" disabled={busy} onClick={() => send("device.locate", "Locate now")}>⌖ Locate now</button>
              <button disabled={busy} onClick={() => send("device.alarm", "Play alarm", { seconds: 60 })}>🔊 Play alarm</button>
              <button disabled={busy} onClick={() => send("device.lock", "Lock")}>🔒 Lock</button>
              <button disabled={busy} onClick={() => { setMessage(""); setMessageOpen(true); }}>💬 Message</button>
              {!lost?.enabled ? <button className="warn" disabled={busy} onClick={() => setLostForm({ message: "This phone has been reported lost. Please call the number below to return it.", phone: "" })}>⚑ Lost mode…</button>
                : <button disabled={busy} onClick={() => setLost(false)}>⚑ End lost mode</button>}
              {can("configure") && <button className="danger" disabled={busy} onClick={() => { setEraseName(""); setErasing(true); }}>⌫ Erase…</button>}
            </div>
            <p className="small muted" style={{ marginBottom: 0 }}>Actions reach the phone within a minute when it is online; otherwise as soon as it reconnects.</p>
          </div>}
        </div>
      </div>

      {lostForm && <Modal title={`Lost mode · ${device.hostname}`} onClose={() => setLostForm(null)}
        footer={<><button onClick={() => setLostForm(null)}>Cancel</button><button className="primary" disabled={busy} onClick={() => setLost(true, lostForm)}>Turn on lost mode</button></>}>
        <p>The phone locks, shows this message on its lock screen and reports its location every 5 minutes. Turn it off once the phone is back.</p>
        <label className="field">Message on the screen<textarea style={{ minHeight: 80, fontFamily: "inherit" }} maxLength={300} value={lostForm.message} onChange={(e) => setLostForm({ ...lostForm, message: e.target.value })} /></label>
        <label className="field" style={{ marginTop: 10 }}>Number to call (optional)<input inputMode="tel" maxLength={40} value={lostForm.phone} onChange={(e) => setLostForm({ ...lostForm, phone: e.target.value })} placeholder="+44 7700 900123" /></label>
      </Modal>}
      {messageOpen && <Modal title={`Message ${device.hostname}`} onClose={() => setMessageOpen(false)}
        footer={<><button onClick={() => setMessageOpen(false)}>Cancel</button><button className="primary" disabled={busy || !message.trim()} onClick={async () => { await send("device.message", "Message", { message: message.trim(), title: "Message from IT" }); setMessageOpen(false); }}>Send</button></>}>
        <label className="field">Shown as a notification on the phone<textarea style={{ minHeight: 90, fontFamily: "inherit" }} maxLength={500} value={message} onChange={(e) => setMessage(e.target.value)} autoFocus /></label>
      </Modal>}
      {erasing && <Modal title={`Erase ${device.hostname}`} onClose={() => { if (!busy) setErasing(false); }}>
        <p><b>This factory-resets the phone.</b> Every app, photo and file on it is deleted, and it stops reporting to Fenrir, so you can no longer locate it. It cannot be undone.</p>
        <p className="small muted">Use it when the phone is not coming back. You'll be asked for your password again.</p>
        <label className="field">Type {displayValue(device.hostname)} to confirm<input value={eraseName} onChange={(e) => setEraseName(e.target.value)} /></label>
        <div className="foot"><button onClick={() => setErasing(false)}>Cancel</button>
          <button className="danger" disabled={busy || eraseName !== device.hostname} onClick={async () => { await send("device.wipe", "Erase"); setErasing(false); }}>Erase the phone</button></div>
      </Modal>}
    </>
  );
}

export default LocationTab;
