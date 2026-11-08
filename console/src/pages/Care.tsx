// The Care page: the people being looked after (their phones), where they are, their safe zones and care alerts
import { BrandMark } from "../brand";
// (asked for help, left a safe zone, gone quiet, low battery, location off). Family members and carers (role "carer")
// see only this; staff reach it from the menu.
import { useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import { ago, api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { displayValue } from "../components/DisplayValue";
import { PushCard } from "../components/PushCard";
import { scheduleText } from "../components/SafeZones";
import { ErrorNote, PageHead, Pill, useAction, useData, useListData } from "../components/ui";

const SEVERITY_TONE: Record<string, string> = { critical: "bad", high: "bad", medium: "warn", low: "muted" };

function PersonMap({ person, points }: { person: any; points: any[] }) {
  const box = useRef<HTMLDivElement>(null);
  const map = useRef<L.Map | null>(null);
  const layer = useRef<L.LayerGroup | null>(null);
  useEffect(() => {
    if (!box.current || map.current) return;
    map.current = L.map(box.current).setView([51.5, -0.12], 5);
    L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {
      maxZoom: 19, attribution: "&copy; OpenStreetMap contributors", referrerPolicy: "strict-origin-when-cross-origin",
    }).addTo(map.current);
    layer.current = L.layerGroup().addTo(map.current);
    return () => { map.current?.remove(); map.current = null; };
  }, []);
  useEffect(() => {
    const group = layer.current;
    if (!map.current || !group) return;
    group.clearLayers();
    const bounds: [number, number][] = [];
    (person.zones || []).filter((z: any) => z.enabled).forEach((z: any) => {
      L.circle([z.latitude, z.longitude], { radius: z.radius, color: z.state === "outside" ? "#f59e0b" : "#22c55e", weight: 2, dashArray: "6 4", fillOpacity: 0.06 })
        .bindTooltip(z.name).addTo(group);
      bounds.push([z.latitude, z.longitude]);
    });
    const coords = points.map((p) => [p.lat, p.lon] as [number, number]);
    if (coords.length > 1) L.polyline(coords, { color: "#38bdf8", weight: 3, opacity: 0.7 }).addTo(group);
    const latest = person.latest;
    if (latest) {
      if (latest.accuracy) L.circle([latest.lat, latest.lon], { radius: latest.accuracy, color: "#a855f7", weight: 1, fillOpacity: 0.12 }).addTo(group);
      L.circleMarker([latest.lat, latest.lon], { radius: 10, color: "#fff", weight: 3, fillColor: person.sos?.active ? "#dc2626" : "#a855f7", fillOpacity: 1 })
        .bindTooltip(`${person.name} · ${ago(latest.at)}`).addTo(group);
      map.current.setView([latest.lat, latest.lon], 16);
    } else if (bounds.length) map.current.setView(bounds[0], 15);
  }, [person, points]);
  return <div ref={box} className="track-map" style={{ height: 320 }} role="img" aria-label={`Map of where ${person.name} is`} />;
}

function Person({ person, onChanged }: { person: any; onChanged: () => void }) {
  const [hours, setHours] = useState(6);
  const { data: track } = useData<any>(`care/people/${person.id}/locations`, { hours }, [hours, person.latest?.at]);
  const { run, busy } = useAction();
  const latest = person.latest;
  const ack = async (alert: any, resolve = false) => {
    if (await run(() => api(`care/alerts/${alert.id}/ack`, { body: { resolve } }), resolve ? "Marked as sorted" : "You're handling it; the others have been told")) onChanged();
  };
  return (
    <div className="card" style={{ marginBottom: 16, borderColor: person.sos?.active ? "var(--bad, #dc2626)" : undefined }}>
      <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
        <h2 style={{ margin: 0, flex: 1 }}>{displayValue(person.name)}</h2>
        {person.sos?.active && <Pill value="ASKED FOR HELP" tone="bad" />}
        <Pill value={person.online ? "online" : `last seen ${person.lastSeenAt ? ago(person.lastSeenAt) : "never"}`} tone={person.online ? "good" : "warn"} />
        {typeof person.battery === "number" && <Pill value={`battery ${Math.round(person.battery)}%${person.charging ? " ⚡" : ""}`} tone={person.battery <= 15 && !person.charging ? "warn" : "muted"} />}
        {person.locationEnabled === false && <Pill value="location off" tone="bad" />}
      </div>
      {person.alerts.map((a: any) => (
        <div key={a.id} className="card" style={{ margin: "10px 0 0", padding: 10, borderColor: a.severity === "critical" ? "var(--bad, #dc2626)" : undefined }}>
          <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
            <Pill value={a.severity} tone={SEVERITY_TONE[a.severity]} />
            <b style={{ flex: 1 }}>{displayValue(a.title)}</b>
            <span className="small muted">{ago(a.createdAt)}</span>
          </div>
          <p className="small" style={{ margin: "6px 0" }}>{displayValue(a.description.replace(/https?:\/\/\S+/g, "").trim())}</p>
          <div className="row" style={{ gap: 8 }}>
            {a.acknowledgedBy ? <span className="small">Being handled by <b>{displayValue(a.acknowledgedBy)}</b> {a.acknowledgedAt ? `since ${fmtTime(a.acknowledgedAt)}` : ""}</span>
              : <button className="primary" disabled={busy} onClick={() => ack(a)}>I've got this</button>}
            <button disabled={busy} onClick={() => ack(a, true)}>All sorted</button>
            {a.mapUrl && <a className="btn small" href={a.mapUrl} target="_blank" rel="noreferrer">Map</a>}
          </div>
        </div>))}
      <div className="grid side" style={{ marginTop: 12 }}>
        <div>
          <PersonMap person={person} points={track?.points || []} />
          <div className="row small" style={{ marginTop: 6, gap: 6 }}>
            Route: {[1, 6, 24].map((h) => <button key={h} className={`small ${hours === h ? "primary" : ""}`} onClick={() => setHours(h)}>{h === 1 ? "last hour" : `${h} hours`}</button>)}
          </div>
        </div>
        <div className="stack">
          <div>
            <h3 style={{ marginTop: 0 }}>Where</h3>
            {!latest ? <p className="small muted">No location yet.</p> : <>
              <p className="small" style={{ margin: 0 }}>{ago(latest.at)} · ± {Math.round(latest.accuracy || 0)} m</p>
              <div className="row" style={{ gap: 6, marginTop: 6 }}>
                <a className="btn small" href={`https://www.google.com/maps/search/?api=1&query=${latest.lat},${latest.lon}`} target="_blank" rel="noreferrer">Directions</a>
                <button className="small" disabled={busy} onClick={async () => { if (await run(() => api(`care/people/${person.id}/locate`, { method: "POST" }), "Asked the phone where it is")) setTimeout(onChanged, 20000); }}>Update now</button>
              </div></>}
          </div>
          <div>
            <h3>Safe zones</h3>
            {!person.zones.length ? <p className="small muted">None set up.</p> : person.zones.map((z: any) => (
              <div key={z.id} className="small" style={{ marginBottom: 4 }}>
                <b>{displayValue(z.name)}</b> {z.enabled ? (z.state === "inside" ? <Pill value="inside" tone="good" /> : z.state === "outside" ? <Pill value="outside" tone="warn" /> : null) : <Pill value="paused" tone="muted" />}
                <span className="muted"> · {scheduleText(z.schedule)}</span>
              </div>))}
          </div>
        </div>
      </div>
    </div>
  );
}

export default function Care({ standalone = false }: { standalone?: boolean }) {
  const { me, logout } = useApp();
  const [params] = useSearchParams();
  const { data, error, reload } = useListData<any>("care/people");
  useEffect(() => {
    const timer = setInterval(() => { if (document.visibilityState === "visible") reload(); }, 30000);
    return () => clearInterval(timer);
  }, [reload]);
  const focus = params.get("device");
  const people = (data || []).filter((p: any) => standalone || p.cared || focus === p.id);
  const shown = focus ? [...people.filter((p: any) => p.id === focus), ...people.filter((p: any) => p.id !== focus)] : people;
  const body = <>
    <ErrorNote error={error} />
    {data && !shown.length && <div className="empty">{standalone ? "Nobody has been set up for you to look after yet. Ask the person who invited you."
      : "No phones have care set up yet. Open a phone's Location tab → Care to turn it on."}</div>}
    {shown.map((p: any) => <Person key={p.id} person={p} onChanged={reload} />)}
  </>;
  if (!standalone) return <><PageHead title="Care" subtitle="People being looked after: where they are, their safe zones, and anything that needs someone now." />{body}</>;
  return (
    <div style={{ maxWidth: 1100, margin: "0 auto", padding: 16 }}>
      <div className="row" style={{ marginBottom: 16, gap: 8 }}>
        <BrandMark />
        <div style={{ flex: 1 }}><b style={{ fontSize: 18 }}>Care</b><div className="small muted">{displayValue(me?.user.email)}</div></div>
        <button className="small" onClick={logout}>Sign out</button>
      </div>
      {body}
      <PushCard />
    </div>
  );
}
