import { displayValue } from "../components/DisplayValue";
import { useEffect, useRef, useState } from "react";
import QRCode from "qrcode";
import { api } from "../api";
import { useApp } from "../app-context";
import { ErrorNote, TenantSelect, useListData } from "../components/ui";

// Enrolling a phone: the technician makes a short-lived token, the phone scans the QR code. The link is
// https://<this server>/enroll-phone#t=<token>: scanned with the camera it opens a page with the app download
// and an "Open in Fenrir" button; scanned inside the Fenrir app it enrols straight away. The token sits in the
// URL fragment, which browsers never send to a server, so it stays out of logs.

export function phoneEnrollLink(token: string) {
  return `${window.location.origin}/enroll-phone#t=${encodeURIComponent(token)}`;
}

export function AddPhone() {
  const { tenantId, can, me } = useApp();
  // "All tenants" can't own a phone: start on the first customer instead.
  const initial = tenantId || me?.tenants?.[0]?.id || "";
  const [target, setTarget] = useState(initial);
  const [groupId, setGroupId] = useState("");
  const [owner, setOwner] = useState("");
  const [token, setToken] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const canvas = useRef<HTMLCanvasElement>(null);
  const { data: groups } = useListData<any>("groups", { tenant_id: target }, [target]);
  useEffect(() => { setTarget(initial); setGroupId(""); }, [initial]);
  useEffect(() => {
    if (token && canvas.current) QRCode.toCanvas(canvas.current, phoneEnrollLink(token), { width: 440, margin: 1, errorCorrectionLevel: "M" }).catch(() => setError("Could not draw the QR code"));
  }, [token]);
  if (!can("configure")) return null;

  const create = async () => {
    setBusy(true); setError(null);
    try {
      // One phone per code, valid for a day: a photo of the screen is useless tomorrow.
      const result = await api<any>("enrollment-tokens", { body: { tenantId: target, groupId: groupId || null, label: owner ? `Phone: ${owner}` : "Phone", maxUses: 1, expiresInDays: 1 } });
      setToken(result.token);
    } catch (err) { setError((err as Error).message); } finally { setBusy(false); }
  };

  return (
    <div className="card">
      <h3>Add a phone</h3>
      <p className="small muted" style={{ marginTop: 0 }}>Android phones get location tracking, lost mode, alarm, lock and erase. Make a code, then scan it on the phone. Each code enrols one phone and expires after 24 hours.</p>
      {!token ? <>
        <div className="form-grid">
          <label className="field">Customer<TenantSelect value={target} onChange={(v) => { setTarget(v); setGroupId(""); }} allowAll={false} /></label>
          <label className="field">Group
            <select value={groupId} onChange={(e) => setGroupId(e.target.value)}>
              <option value="">None</option>
              {groups?.map((g) => <option key={g.id} value={g.id}>{displayValue(g.name)}</option>)}
            </select>
          </label>
          <label className="field">Who it's for (optional)<input value={owner} onChange={(e) => setOwner(e.target.value)} maxLength={80} placeholder="Jo Bloggs" /></label>
        </div>
        <ErrorNote error={error} />
        <button className="primary" style={{ marginTop: 12 }} disabled={busy || !target} onClick={create}>{busy ? "Creating…" : "Create phone enrolment code"}</button>
      </> : <div className="add-phone">
        <div className="qr-box"><canvas ref={canvas} aria-label="Enrolment QR code" /></div>
        <ol>
          <li>On the phone, open the camera and scan this code, or open the <b>Fenrir</b> app and tap <b>Scan enrolment code</b>.</li>
          <li>If the app isn't installed yet, the page that opens has the download.</li>
          <li>In the app, allow location <b>all the time</b>, notifications, and <b>Activate device admin</b> so lock and erase work.</li>
        </ol>
        <details className="small"><summary>Can't scan? Enter it by hand</summary>
          <p>Server: <span className="mono">{window.location.origin}</span><br />Code: <span className="mono" style={{ userSelect: "all", wordBreak: "break-all" }}>{token}</span></p>
        </details>
        <ErrorNote error={error} />
        <div className="row"><button onClick={() => setToken(null)}>Done</button><button onClick={create} disabled={busy}>Another phone</button></div>
      </div>}
    </div>
  );
}

// Public page opened by scanning the code with the phone's camera (no console sign-in needed).
export function EnrollPhonePage() {
  const token = new URLSearchParams(window.location.hash.slice(1)).get("t") || "";
  const server = window.location.origin;
  const appLink = `fenrir://enroll?server=${encodeURIComponent(server)}&token=${encodeURIComponent(token)}`;
  const android = /android/i.test(navigator.userAgent);
  const ios = /iphone|ipad|ipod/i.test(navigator.userAgent);
  return (
    <div className="login">
      <div className="card" style={{ width: "min(440px, 94vw)" }}>
        <div className="brand" style={{ padding: 0, marginBottom: 16 }}>
          <div className="brand-mark">F</div>
          <div><b>Set up Fenrir on this phone</b><small>{server.replace(/^https?:\/\//, "")}</small></div>
        </div>
        {!token ? <p>This link is missing its enrolment code. Ask IT for a new one.</p> : ios ? <>
          <p>Fenrir's phone tracking and lost mode are available for Android. On an iPhone you can add the Fenrir console to your Home Screen instead (Share → Add to Home Screen).</p>
        </> : <>
          <ol style={{ lineHeight: 1.8, paddingLeft: 20 }}>
            <li><a className="btn primary" href="/downloads/fenrir-android.apk" download>Download the Fenrir app</a> and install it. Android may ask you to allow installs from your browser.</li>
            <li>Then tap <a className="btn" href={appLink}>Open in Fenrir</a> to enrol this phone.</li>
          </ol>
          {!android && <p className="small muted">Open this page on the Android phone you're setting up.</p>}
          <p className="small muted">The code works once and expires 24 hours after it was made.</p>
        </>}
      </div>
    </div>
  );
}
