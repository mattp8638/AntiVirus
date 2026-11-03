// "Notifications on this device": Web Push to this browser or installed console app, for the alerts this person is
// chosen for (safe zones, for a start). On iPhone and iPad it needs the console added to the home screen first.
import { useEffect, useState } from "react";
import { ago, api } from "../api";
import { useAction, useListData } from "./ui";

const supported = () => typeof window !== "undefined" && "serviceWorker" in navigator && "PushManager" in window && "Notification" in window;

function keyBytes(base64url: string): Uint8Array {
  const base64 = (base64url + "=".repeat((4 - (base64url.length % 4)) % 4)).replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
}

function deviceLabel() {
  const ua = navigator.userAgent;
  const os = /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iPhone/iPad" : /Mac/.test(ua) ? "Mac" : /Windows/.test(ua) ? "Windows" : "Linux";
  const browser = /Edg\//.test(ua) ? "Edge" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "Browser";
  return `${browser} on ${os}`;
}

export function PushCard() {
  const { data, reload } = useListData<any>("push/subscriptions");
  const { run, busy } = useAction();
  const [here, setHere] = useState<PushSubscription | null>(null);
  const [problem, setProblem] = useState("");
  useEffect(() => {
    if (!supported()) return;
    navigator.serviceWorker.getRegistration().then((reg) => reg?.pushManager.getSubscription()).then((sub) => setHere(sub ?? null)).catch(() => undefined);
  }, []);

  const turnOn = async () => {
    setProblem("");
    const permission = await Notification.requestPermission();
    if (permission !== "granted") { setProblem("Notifications are blocked for this site. Allow them in the browser's site settings, then try again."); return; }
    const reg = (await navigator.serviceWorker.getRegistration()) ?? (await navigator.serviceWorker.register("/sw.js"));
    await navigator.serviceWorker.ready;
    const { publicKey } = await api<{ publicKey: string }>("push/key");
    const sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: keyBytes(publicKey) });
    if (await run(() => api("push/subscriptions", { body: { subscription: sub.toJSON(), label: deviceLabel() } }), "Notifications are on for this device")) {
      setHere(sub); reload();
    }
  };
  const turnOff = async () => {
    if (!here) return;
    await run(() => api("push/unsubscribe", { body: { endpoint: here.endpoint } }), "Notifications are off for this device");
    await here.unsubscribe().catch(() => undefined);
    setHere(null); reload();
  };

  return (
    <div className="card" style={{ maxWidth: 520 }}>
      <h3>Notifications on this device</h3>
      <p className="small muted">Get a notification here when an alert you are chosen for happens, such as a phone leaving a safe zone. Turn it on
        on each phone or computer you want them on.</p>
      {!supported() ? <p className="small">This browser cannot receive notifications. On iPhone or iPad, add the console to the home screen
        (Share → Add to Home Screen), open it from there and turn notifications on.</p>
        : here ? <div className="row" style={{ gap: 8 }}>
            <span className="small">On for this device.</span>
            <button className="small" disabled={busy} onClick={async () => { await run(() => api("push/test", { method: "POST" }), "Test notification sent"); }}>Send a test</button>
            <button className="small" disabled={busy} onClick={turnOff}>Turn off</button></div>
        : <button className="primary" disabled={busy} onClick={() => turnOn().catch((err) => setProblem((err as Error).message))}>Turn on notifications</button>}
      {problem && <p className="small" style={{ color: "#fecaca" }}>{problem}</p>}
      {(data?.length ?? 0) > 0 && <>
        <h4 style={{ marginBottom: 4 }}>Your devices</h4>
        {data!.map((s) => <div key={s.id} className="row small" style={{ gap: 8 }}>
          <span style={{ flex: 1 }}>{s.label || "Device"} <span className="muted">· {s.lastSuccessAt ? `last delivered ${ago(s.lastSuccessAt)}` : "nothing delivered yet"}</span></span>
          <button className="small ghost" disabled={busy} onClick={async () => { if (await run(() => api("push/unsubscribe", { body: { id: s.id } }), "Removed")) reload(); }}>Remove</button>
        </div>)}
      </>}
    </div>
  );
}
