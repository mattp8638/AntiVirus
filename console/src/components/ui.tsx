import { ReactNode, useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { displayValue } from "./DisplayValue";
import { expectArray, safeArray } from "../data-shapes";
import { api, rememberReauth, setReauthPrompt } from "../api";
import { passkeyResponse, passkeysSupported } from "../passkeys";
import { useApp } from "../app-context";

/** Load data from the API and reload when deps change. */
export function useData<T>(path: string | null, query: Record<string, unknown> = {}, deps: unknown[] = [], expectList = false) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const requestVersion = useRef(0);
  const key = JSON.stringify(query);
  const reload = useCallback(async () => {
    const version = ++requestVersion.current;
    if (!path) {
      setData(null);
      setError(null);
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const result = await api<unknown>(path, { query });
      const validated = expectList ? expectArray(result, path) : result;
      if (version !== requestVersion.current) return;
      setData(validated as T);
      setError(null);
    } catch (err) {
      if (version !== requestVersion.current) return;
      setData(null);
      setError((err as Error).message);
    } finally {
      if (version === requestVersion.current) setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, key, expectList, ...deps]);
  useEffect(() => {
    reload();
  }, [reload]);
  return { data, error, loading, reload, setData };
}

/** Re-fetch every few seconds while the page is on screen, and straight away when the tab comes back. */
export function useAutoRefresh(reload: () => unknown, ms = 15000) {
  useEffect(() => {
    const tick = () => { if (document.visibilityState === "visible") reload(); };
    const timer = setInterval(tick, ms);
    document.addEventListener("visibilitychange", tick);
    return () => { clearInterval(timer); document.removeEventListener("visibilitychange", tick); };
  }, [reload, ms]);
}

// Device presence, decided by the server (presence.py): agents are online when heard from in the last 2 minutes
// (they ping every 30 seconds); phones in power saving are "asleep" for up to 30 minutes, which is not a fault.
const PRESENCE: Record<string, { label: string; dot: string; title: string }> = {
  online: { label: "Online", dot: "on", title: "Heard from in the last 2 minutes" },
  asleep: { label: "Asleep", dot: "sleep", title: "The phone is saving power. It checks in about every 10 minutes and runs actions when it wakes." },
  idle: { label: "Idle", dot: "sleep", title: "No website lookups in the last 15 minutes. Normal when the device is not being used." },
  offline: { label: "Offline", dot: "off", title: "Not heard from for over 2 minutes (30 for a phone)" },
  retired: { label: "Decommissioned", dot: "off", title: "Decommissioned" },
};

export function presenceOf(device: { presence?: string; online?: boolean }) {
  return PRESENCE[device.presence ?? (device.online ? "online" : "offline")] ?? PRESENCE.offline;
}

export function PresenceDot({ device }: { device: { presence?: string; online?: boolean } }) {
  const p = presenceOf(device);
  return <span className={`dot ${p.dot}`} title={`${p.label}: ${p.title}`} aria-label={p.label} />;
}

/** List endpoints are validated at runtime; a 200 response is not necessarily a JSON array. */
export function useListData<T>(path: string | null, query: Record<string, unknown> = {}, deps: unknown[] = []) {
  return useData<T[]>(path, query, deps, true);
}

/** Wrap an async action with toast feedback. */
export function useAction() {
  const { toast } = useApp();
  const [busy, setBusy] = useState(false);
  const run = async <T,>(fn: () => Promise<T>, success?: string): Promise<T | undefined> => {
    setBusy(true);
    try {
      const result = await fn();
      if (success) toast(success);
      return result;
    } catch (err) {
      toast((err as Error).message, true);
      return undefined;
    } finally {
      setBusy(false);
    }
  };
  return { run, busy };
}

export function PageHead({ title, subtitle, actions }: { title: string; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="page-head">
      <div>
        <h1>{displayValue(title)}</h1>
        {subtitle && <p>{displayValue(subtitle)}</p>}
      </div>
      {actions && <div className="actions">{actions}</div>}
    </div>
  );
}

export function Stat({ label, value, hint, accent, to }: { label: string; value: ReactNode; hint?: ReactNode; accent?: string; to?: string }) {
  const body = <>
    <div className="label">{label}</div>
    <div className="value">{displayValue(value)}</div>
    {hint && <div className="hint">{displayValue(hint)}</div>}
  </>;
  const className = `card stat ${accent ? `accent-${accent}` : ""}`;
  return to ? <Link to={to} className={`${className} stat-link`}>{body}</Link> : <div className={className}>{body}</div>;
}

export function Sev({ level }: { level?: string }) {
  const value = typeof level === "string" ? (level || "info").toLowerCase() : level == null ? "info" : "unknown";
  return <span className={`badge sev-${value === "informational" ? "info" : value}`}>{value}</span>;
}

const TONES: Record<string, string> = {
  new: "bad", open: "bad", pending: "warn", dispatched: "blue", completed: "good", failed: "bad", cancelled: "muted",
  triaged: "warn", resolved: "good", closed: "muted", false_positive: "muted", investigating: "warn", contained: "blue",
  allow: "good", block: "bad", observe: "warn", malicious: "bad", suspicious: "warn", unknown: "muted",
  Open: "bad", "In Progress": "warn", Waiting: "blue", Resolved: "good", Closed: "muted",
  Draft: "muted", Sent: "blue", Paid: "good", Overdue: "bad", Void: "muted",
  New: "warn", Contacted: "blue", Qualified: "blue", Proposal: "warn", Won: "good", Lost: "muted",
  patching: "blue", mitigated: "good", accepted: "muted", fixed: "good",
};

export function Pill({ value, tone }: { value: ReactNode; tone?: string }) {
  const scalar = typeof value === "string" || typeof value === "number" || typeof value === "boolean";
  const resolved = scalar ? tone ?? TONES[String(value)] ?? "muted" : "muted";
  return <span className={`badge tone-${resolved}`}>{scalar ? String(value).replace(/_/g, " ") : displayValue(value) ?? "unknown"}</span>;
}

export interface Column<T> {
  key: string;
  label: string;
  render?: (row: T) => ReactNode;
  className?: string;
}

export function Table<T extends Record<string, any>>({ rows, columns, onRow, empty = "Nothing here yet.", activeId }: {
  rows: T[] | null | undefined;
  columns: Column<T>[];
  onRow?: (row: T) => void;
  empty?: string;
  activeId?: string | null;  // the row picked with the keyboard
}) {
  if (rows == null) return <div className="empty">Loading…</div>;
  if (!Array.isArray(rows)) {
    return <div role="alert" className="empty">Unable to display records: the server returned an unexpected response format. Please check the API response.</div>;
  }
  if (rows.some((row) => !row || typeof row !== "object" || Array.isArray(row))) {
    return <div role="alert" className="empty">Unable to display records: some records could not be read. Reload this page to try again.</div>;
  }
  if (!rows.length) return <div className="empty">{empty}</div>;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>{columns.map((c) => <th key={c.key} className={c.className}>{displayValue(c.label)}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={row.id ?? i} className={`${onRow ? "clickable" : ""}${activeId != null && row.id === activeId ? " active-row" : ""}`}
                aria-selected={activeId != null ? row.id === activeId : undefined} onClick={onRow ? () => onRow(row) : undefined}>
              {columns.map((c) => <td key={c.key} className={c.className}>{displayValue(c.render ? c.render(row) : typeof row[c.key] === "boolean" ? String(row[c.key]) : row[c.key])}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function Modal({ title, onClose, children, footer, wide }: { title: string; onClose: () => void; children: ReactNode; footer?: ReactNode; wide?: boolean }) {
  return (
    <div className="modal-back" onClick={onClose}>
      <div className={`modal${wide ? " wide" : ""}`} onClick={(e) => e.stopPropagation()} role="dialog" aria-label={title}>
        <div className="row" style={{ marginBottom: 12 }}>
          <h2 style={{ margin: 0 }}>{displayValue(title)}</h2>
          <span style={{ flex: 1 }} />
          <button className="ghost" onClick={onClose} aria-label="Close">✕</button>
        </div>
        {children}
        {footer && <div className="foot">{footer}</div>}
      </div>
    </div>
  );
}

export function Tabs({ tabs, active, onChange }: { tabs: string[]; active: string; onChange: (tab: string) => void }) {
  return (
    <div className="tabs">
      {tabs.map((tab) => <button key={tab} className={tab === active ? "active" : ""} onClick={() => onChange(tab)}>{tab}</button>)}
    </div>
  );
}

export function ErrorNote({ error }: { error: string | null }) {
  return error ? <div role="alert" className="card" style={{ borderColor: "rgba(239,68,68,.5)", color: "#fecaca" }}>{displayValue(error)}</div> : null;
}

/** Simple bar chart in SVG; no chart library needed. */
export function Bars({ data, height = 140 }: { data: { label: string; value: number }[]; height?: number }) {
  const points = safeArray<{ label: string; value: number }>(data).filter(
    (d) => d !== null && typeof d === "object" && Number.isFinite(d.value)
  );
  if (!points.length) return <div className="empty">No chart data available.</div>;
  const max = Math.max(...points.map((d) => d.value), 1);
  const width = 100 / points.length;
  return (
    <svg viewBox={`0 0 100 ${height}`} preserveAspectRatio="none" style={{ width: "100%", height }} role="img">
      {points.map((d, i) => {
        const h = (d.value / max) * (height - 18);
        return (
          <g key={d.label}>
            <rect x={i * width + width * 0.15} y={height - 14 - h} width={width * 0.7} height={h} rx={0.8} fill="url(#barGrad)">
              <title>{`${d.label}: ${d.value}`}</title>
            </rect>
          </g>
        );
      })}
      <defs>
        <linearGradient id="barGrad" x1="0" x2="0" y1="0" y2="1">
          <stop offset="0" stopColor="#3b82f6" />
          <stop offset="1" stopColor="#a855f7" />
        </linearGradient>
      </defs>
    </svg>
  );
}

export function Meter({ value, max = 100 }: { value: number; max?: number }) {
  return <div className="bar"><span style={{ width: `${Math.min(100, (value / max) * 100)}%` }} /></div>;
}

export function TenantSelect({ value, onChange, allowAll = true, label }: { value: string; onChange: (id: string) => void; allowAll?: boolean; label?: string }) {
  const { me } = useApp();
  return (
    <select value={value} onChange={(e) => onChange(e.target.value)} aria-label={label ?? "Tenant"}>
      {allowAll && <option value="">All tenants</option>}
      {safeArray<{ id: string; name: string; kind: string }>(me?.tenants).map((t) => <option key={t.id} value={t.id}>{t.name}{t.kind === "msp" ? " (MSP)" : ""}</option>)}
    </select>
  );
}

// Chrome and Edge offer to install the console as an app. Installed, it runs in its own window and
// remote sessions open as app windows without browser bars. The prompt can fire before React mounts,
// so it is captured here at load.
let deferredInstall: any = null;
const installListeners = new Set<() => void>();
if (typeof window !== "undefined") {
  window.addEventListener("beforeinstallprompt", (event) => {
    event.preventDefault();
    deferredInstall = event;
    installListeners.forEach((fn) => fn());
  });
  window.addEventListener("appinstalled", () => {
    deferredInstall = null;
    installListeners.forEach((fn) => fn());
  });
}

export function InstallAppButton() {
  const [, refresh] = useState(0);
  useEffect(() => {
    const fn = () => refresh((n) => n + 1);
    installListeners.add(fn);
    return () => { installListeners.delete(fn); };
  }, []);
  const [iosHelp, setIosHelp] = useState(false);
  if (!deferredInstall) {
    // iPhone and iPad Safari have no install prompt: explain "Add to Home Screen" instead.
    const ios = /iphone|ipad|ipod/i.test(navigator.userAgent) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
    const standalone = window.matchMedia?.("(display-mode: standalone)").matches || (navigator as any).standalone;
    if (!ios || standalone) return null;
    return (
      <>
        <button className="small" onClick={() => setIosHelp(true)}>Install app</button>
        {iosHelp && <Modal title="Install Fenrir on this iPhone" onClose={() => setIosHelp(false)}>
          <ol style={{ lineHeight: 1.9, paddingLeft: 20 }}>
            <li>Tap the <b>Share</b> button <span aria-hidden>⎋</span> in Safari's toolbar.</li>
            <li>Scroll down and tap <b>Add to Home Screen</b>.</li>
            <li>Tap <b>Add</b>. Fenrir opens from its icon like an app, without Safari's bars.</li>
          </ol>
          <p className="small muted">Open this page in Safari to do this; other iPhone browsers can't add apps to the Home Screen.</p>
        </Modal>}
      </>
    );
  }
  return (
    <button className="small" title="Install the console as an app: it opens in its own window, and remote sessions open without browser bars"
            onClick={async () => { const prompt = deferredInstall; deferredInstall = null; refresh((n) => n + 1); await prompt.prompt(); }}>
      Install app
    </button>
  );
}

/** Asks for the password (and MFA code), or a passkey, when the server needs a recent re-authentication. */
export function ReauthDialog() {
  const { me } = useApp();
  const [pending, setPending] = useState<((ok: string | null) => void) | null>(null);
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [needCode, setNeedCode] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    setReauthPrompt(() => new Promise<string | null>((resolve) => { setError(null); setPassword(""); setCode(""); setPending(() => resolve); }));
    return () => setReauthPrompt(null);
  }, []);
  if (!pending) return null;
  const finish = (token: string | null) => { pending(token); setPending(null); };
  const submit = async (withPasskey = false) => {
    setBusy(true);
    try {
      const body = withPasskey ? { passkey: await passkeyResponse() } : { password, ...(code ? { code } : {}) };
      const result = await api<{ reauthToken: string; expiresInSeconds: number }>("auth/reauth", { body });
      rememberReauth(result.reauthToken, result.expiresInSeconds);
      finish(result.reauthToken);
    } catch (err) {
      const message = (err as Error).message;
      if (message === "MFA code required") { setNeedCode(true); setError(null); } else setError(message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal title="Confirm it's you" onClose={() => finish(null)}
           footer={<>
             {passkeysSupported() && !!me?.passkeys && <button disabled={busy} onClick={() => submit(true)}>Use a passkey</button>}
             <button className="primary" disabled={busy || !password || (needCode && code.length !== 6)} onClick={() => submit()}>Confirm</button>
           </>}>
      <p className="muted">This action is sensitive. Enter your password{needCode ? " and authenticator code" : ""} to continue. It stays confirmed for 5 minutes.</p>
      <form onSubmit={(e) => { e.preventDefault(); submit(); }}>
        <label className="field">Password<input type="password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} /></label>
        {needCode && <label className="field" style={{ marginTop: 10 }}>Authenticator code<input inputMode="numeric" maxLength={6} value={code} onChange={(e) => setCode(e.target.value)} /></label>}
        <button type="submit" hidden />
      </form>
      <ErrorNote error={error} />
    </Modal>
  );
}
