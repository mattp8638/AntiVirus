// Web protection on an iPhone, iPad or Mac that has Fenrir's DNS profile and no agent: is it working, what it blocked.
import { useState } from "react";
import { ago, fmtTime } from "../api";
import { displayValue } from "./DisplayValue";
import { ErrorNote, Pill, Table, useData } from "./ui";

export interface WebProtectionView {
  status: "active" | "quiet" | "silent" | "waiting" | "never" | "retired";
  kind: "iphone" | "ipad" | "mac";
  firstLookupAt: string | null;
  lastLookupAt: string | null;
  blocked7d: number;
  recent: { domain: string; action: string; reason: string; category: string; at: string }[];
  filtering: boolean;
  filteringNote: string | null;
  signed: boolean;
  silentAfterHours: number;
  profileUrl?: string;
}

const STATUS: Record<WebProtectionView["status"], { label: string; tone: string; say: (v: WebProtectionView) => string }> = {
  active: { label: "Working", tone: "good", say: (v) => `The device looked up a website through Fenrir ${ago(v.lastLookupAt)}.` },
  quiet: { label: "Quiet", tone: "warn", say: (v) => `No lookups for over a day (last ${ago(v.lastLookupAt)}). Fenrir alerts after ${v.silentAfterHours} hours.` },
  silent: { label: "Stopped", tone: "bad", say: (v) => `No lookups since ${fmtTime(v.lastLookupAt)}. The profile may have been removed, or a VPN is sending lookups elsewhere.` },
  waiting: { label: "Waiting for install", tone: "warn", say: () => "The profile has been downloaded but the device has not used it yet. It must be installed in Settings." },
  never: { label: "Not installed", tone: "bad", say: () => "The device has never used Fenrir's DNS: the profile was not installed, or was removed straight away." },
  retired: { label: "Decommissioned", tone: "muted", say: () => "Lookups still get plain answers so the device keeps working, but nothing is filtered. Remove the profile from the device." },
};

const WHERE: Record<WebProtectionView["kind"], string> = {
  iphone: "On the iPhone: Settings › General › VPN & Device Management",
  ipad: "On the iPad: Settings › General › VPN & Device Management",
  mac: "On the Mac: System Settings › Privacy & Security › Profiles (on macOS 15, System Settings › General › Device Management)",
};

export function WebProtectionCard({ view }: { view: WebProtectionView }) {
  const s = STATUS[view.status];
  return (
    <div className="card">
      <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
        <h3 style={{ margin: 0 }}>Web protection</h3><Pill value={s.label} tone={s.tone} />
        {!view.filtering && view.status !== "retired" && <Pill value="not blocking" tone="warn" />}
      </div>
      <p>{s.say(view)}</p>
      {view.filteringNote && view.status !== "retired" && <p className="small" role="note">{view.filteringNote}</p>}
      <p className="small muted">
        This device has no Fenrir agent. A configuration profile sends its website lookups to Fenrir over encrypted DNS, so malware and
        phishing sites are blocked here exactly as on a protected PC. Nothing else on the device is read, and there are no remote actions.
        {" "}{WHERE[view.kind]} shows the profile; the device's user can remove it, which Fenrir notices within {view.silentAfterHours} hours.
      </p>
      <div className="row small" style={{ gap: 16, flexWrap: "wrap" }}>
        <span>First used: {view.firstLookupAt ? fmtTime(view.firstLookupAt) : "not yet"}</span>
        <span>Blocked in the last 7 days: <b>{view.blocked7d}</b></span>
        <span>Profile: {view.signed ? "signed (shows as Verified)" : "unsigned (shows as Unverified, which is expected)"}</span>
      </div>
      {view.profileUrl && <details className="small" style={{ marginTop: 8 }}>
        <summary>Install the profile again</summary>
        <p>Open this link on the same device in Safari, then install it from Settings. A new profile replaces the old one.
          It holds this device's private resolver address, so send it only to the device's user.</p>
        <p className="mono" style={{ wordBreak: "break-all", userSelect: "all" }}>{view.profileUrl}</p>
      </details>}
    </div>
  );
}

export function WebProtectionBlocks({ view }: { view: WebProtectionView }) {
  return (
    <div className="card">
      <h3>Recently blocked</h3>
      <Table rows={view.recent.map((r, i) => ({ ...r, id: `${r.at}-${i}` }))} empty="Nothing blocked on this device yet."
             columns={[
               { key: "domain", label: "Website", render: (r) => <span className="mono">{displayValue(r.domain)}</span> },
               { key: "action", label: "", render: (r) => <Pill value={r.action === "observe" ? "logged only" : "blocked"} tone={r.action === "observe" ? "warn" : "bad"} /> },
               { key: "reason", label: "Why", render: (r) => <span className="small">{displayValue(r.reason || r.category)}</span> },
               { key: "at", label: "When", render: (r) => <span title={fmtTime(r.at)}>{ago(r.at)}</span> },
             ]} />
    </div>
  );
}

export function WebProtection({ deviceId }: { deviceId: string }) {
  const { data, error } = useData<WebProtectionView>(`devices/${deviceId}/web-protection`, {}, [deviceId]);
  if (error) return <ErrorNote error={error} />;
  if (!data) return <div className="empty">Loading…</div>;
  return <div className="stack"><WebProtectionCard view={data} /><WebProtectionBlocks view={data} /></div>;
}

// The public enrolment page's Apple part: name the device, then Safari downloads the profile and Settings installs it.
export type AppleKind = "iphone" | "ipad" | "mac";

export function appleKind(userAgent: string, touchPoints: number): AppleKind | null {
  if (/iphone|ipod/i.test(userAgent)) return "iphone";
  if (/ipad/i.test(userAgent)) return "ipad";
  // iPadOS 13+ asks for desktop sites and says it is a Mac; only the touch screen gives it away.
  if (/macintosh/i.test(userAgent)) return touchPoints > 1 ? "ipad" : "mac";
  return null;
}

const STEPS: Record<AppleKind, string[]> = {
  iphone: ["Tap Install web protection, then Allow when Safari asks to download a configuration profile.",
           "Open Settings. Tap Profile Downloaded near the top (or General › VPN & Device Management).",
           "Tap Install, enter your passcode and tap Install again."],
  ipad: ["Tap Install web protection, then Allow when Safari asks to download a configuration profile.",
         "Open Settings. Tap Profile Downloaded near the top (or General › VPN & Device Management).",
         "Tap Install, enter your passcode and tap Install again."],
  mac: ["Click Install web protection. The profile downloads.",
        "Open System Settings › Privacy & Security › Profiles (on macOS 15, System Settings › General › Device Management).",
        "Double-click Fenrir web protection, click Install and enter your Mac password."],
};

const DEVICE_NAME: Record<AppleKind, string> = { iphone: "iPhone", ipad: "iPad", mac: "Mac" };

export function AppleEnrol({ token, kind, onProfile = (url) => window.location.assign(url) }: {
  token: string; kind: AppleKind; onProfile?: (url: string) => void;
}) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const install = async () => {
    setBusy(true); setError(null);
    try {
      const reply = await fetch("/api/v1/enroll/apple", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enrollmentToken: token, name: name.trim() || DEVICE_NAME[kind], kind }) });
      const body = await reply.json().catch(() => ({}));
      if (!reply.ok) throw new Error(body.detail || `The server said ${reply.status}`);
      setDone(true);
      onProfile(body.profileUrl);
    } catch (err) { setError((err as Error).message); } finally { setBusy(false); }
  };
  return <>
    <p>Fenrir protects this {DEVICE_NAME[kind]} from malware and phishing websites. It adds a profile that sends website lookups to
      Fenrir over encrypted DNS. No app is installed, and nothing else on the {DEVICE_NAME[kind]} is read.</p>
    {!done ? <>
      <label className="field">Name this {DEVICE_NAME[kind]}<input value={name} onChange={(e) => setName(e.target.value)} maxLength={80}
        placeholder={`Jo's ${DEVICE_NAME[kind]}`} /></label>
      <ErrorNote error={error} />
      <button className="primary" style={{ marginTop: 12 }} disabled={busy} onClick={install}>{busy ? "Preparing…" : "Install web protection"}</button>
    </> : <p role="status"><b>Profile downloaded.</b> Now finish installing it:</p>}
    <ol style={{ lineHeight: 1.7, paddingLeft: 20 }}>{STEPS[kind].map((s) => <li key={s}>{s}</li>)}</ol>
    <p className="small muted">The profile shows as Unverified unless IT signs it; that is expected. The code works once and expires 24 hours
      after it was made. If you use a VPN app or iCloud Private Relay, some lookups can go around Fenrir.</p>
  </>;
}
