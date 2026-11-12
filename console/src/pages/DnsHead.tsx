import { useEffect, useState } from "react";
import { api } from "../api";
import { useApp } from "../app-context";
import { ErrorNote, Pill, Table, useAction, useData } from "../components/ui";

export interface QueryRow { id: number; at: string; tenantId: string; deviceId: string | null; hostname: string; qname: string; qtype: string;
  action: string; reason: string; category: string; source: string; ruleId: string; score: number | null }
export interface Explain { domain: string; action: string; reason: string; category: string; source: string; ruleId: string; score: number | null;
  trail: string[]; audits: { id: string; name: string; action: string; mode: string }[]; observe: boolean; dgaLike: boolean;
  ruleset: { sources: { source: string; category: string; matched: string; weight: number }[]; liveScore: number; protected: boolean;
    active: { version: number; score: number; category: string; sources: string[] } | null; blockThreshold: number; monitorThreshold: number } }
export interface Rule { id: string; tenantId: string; kind: string; name: string; action: string; match: string; patterns: string[]; scopeType: string;
  scopeIds: string[]; scopeNames: string[]; qtypes: string[]; schedule: { days?: number[]; start?: string; end?: string; timezone?: string };
  mode: string; priority: number; enabled: boolean; comment: string; expiresAt: string | null; expired: boolean; hits: number;
  lastHitAt: string | null; version: number; createdBy: string; createdAt: string; mspWide?: boolean; editable?: boolean }

export const SOURCE_TEXT: Record<string, string> = { rule: "Rule", entry: "Allow/block list", policy: "Policy list", intel: "Threat intel",
  ruleset: "Fenrir ruleset", blocklist: "External list", category: "Category", heuristic: "Heuristic", safesearch: "SafeSearch", other: "Other" };
export const ACTION_TONE: Record<string, string> = { block: "bad", allow: "good", monitor: "warn", observe: "warn" };
export const CATEGORIES = ["malware", "phishing", "command-and-control", "cryptomining", "newly-registered", "parked", "dga", "adult", "gambling",
  "piracy", "ads-trackers", "social-media", "streaming", "games", "dating", "proxies-vpn", "doh-bypass"];
export const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

/** Re-read every 30 seconds while the view is open. */
export function useAutoRefresh(reload: () => unknown, seconds = 30) {
  useEffect(() => {
    const timer = window.setInterval(() => { if (!document.hidden) reload(); }, seconds * 1000);
    return () => window.clearInterval(timer);
  }, [reload, seconds]);
}

/** Lookups and blocks per day as paired bars. */
export function Trend({ daily }: { daily: { day: string; queries: number; blocked: number }[] }) {
  if (!daily.length) return <p className="muted small">No lookups counted in this period yet.</p>;
  const max = Math.max(...daily.map((d) => d.queries), 1);
  const w = 100 / daily.length;
  return (
    <svg viewBox="0 0 100 120" preserveAspectRatio="none" style={{ width: "100%", height: 140 }} role="img" aria-label="Lookups and blocks per day">
      {daily.map((d, i) => {
        const h = (d.queries / max) * 100, hb = (d.blocked / max) * 100;
        return <g key={d.day}>
          <rect x={i * w + w * 0.12} y={104 - h} width={w * 0.38} height={h} rx={0.6} fill="#3b82f6"><title>{`${d.day}: ${d.queries} lookups`}</title></rect>
          <rect x={i * w + w * 0.52} y={104 - hb} width={w * 0.38} height={Math.max(hb, d.blocked ? 0.8 : 0)} rx={0.6} fill="#ef4444"><title>{`${d.day}: ${d.blocked} blocked`}</title></rect>
        </g>;
      })}
    </svg>
  );
}

export function ActionPill({ action }: { action: string }) {
  return <Pill value={action} tone={ACTION_TONE[action] ?? "muted"} />;
}

export function describeRule(r: Rule): string {
  const what = r.match === "category" ? `category ${r.patterns.join(", ")}` : `${r.match === "domain" ? "" : r.match + " "}${r.patterns.slice(0, 3).join(", ")}${r.patterns.length > 3 ? ` +${r.patterns.length - 3}` : ""}`;
  const who = r.scopeType === "tenant" ? (r.mspWide ? "every customer" : "the whole customer") : `${r.scopeType === "group" ? "groups" : "devices"} ${r.scopeNames.join(", ")}`;
  const when = r.schedule?.days?.length ? `, ${r.schedule.days.map((d) => DAYS[d]).join("/")} ${r.schedule.start}-${r.schedule.end}` : "";
  const types = r.qtypes?.length ? `, ${r.qtypes.join("/")} only` : "";
  return `${what} · ${who}${when}${types}`;
}

/** "Why was this allowed or blocked?" Every step the resolver took, the ruleset's opinion and one-click fixes. */
export function ExplainView({ domain, deviceId, tenantId, onChanged }: { domain: string; deviceId?: string | null; tenantId?: string; onChanged?: () => void }) {
  const { can } = useApp();
  const { data, error, reload } = useData<Explain>("dns/explain", { domain, device_id: deviceId || undefined, tenant_id: deviceId ? undefined : tenantId || undefined }, [domain, deviceId]);
  const { run, busy } = useAction();
  const [expiry, setExpiry] = useState("");
  const quick = async (action: string, scope: string) => {
    await run(() => api("dns/quick", { method: "POST", body: { domain, action, scope, deviceId, tenantId, expiresAt: expiry ? new Date(expiry).toISOString() : null } }),
              `${action === "allow" ? "Allowed" : "Blocked"} ${domain}${scope === "device" ? " on this device" : " for the customer"}.`);
    reload();
    onChanged?.();
  };
  if (error) return <ErrorNote error={error} />;
  if (!data) return <p className="muted small">Working it out…</p>;
  return (
    <>
      <p><ActionPill action={data.action} /> <b className="mono">{data.domain}</b> {data.category && <span className="small muted">· {data.category}</span>}
        {data.source && <span className="small muted"> · decided by {SOURCE_TEXT[data.source] ?? data.source}</span>}
        {data.observe && <span className="small" style={{ color: "#fbbf24" }}> · policy is observe-only</span>}</p>
      <h3>Every step</h3>
      <ol className="small">{(data.trail.length ? data.trail : [data.reason]).map((t, i) => <li key={i}>{t}</li>)}</ol>
      {data.audits.length > 0 && <p className="small" style={{ color: "#fbbf24" }}>Audit and monitor rules that matched: {data.audits.map((a) => a.name).join(", ")}</p>}
      <h3>Fenrir ruleset</h3>
      {data.ruleset.protected ? <p className="small">Protected domain: never in the Fenrir ruleset.</p> : data.ruleset.sources.length ? <>
        <p className="small">Score now <b>{data.ruleset.liveScore}</b> (blocks at {data.ruleset.blockThreshold}, monitored from {data.ruleset.monitorThreshold})
          {data.ruleset.active ? <>; active build v{data.ruleset.active.version}: <b>{data.ruleset.active.score}</b> ({data.ruleset.active.category})</> : "; not in the active build"}.</p>
        <Table rows={data.ruleset.sources.map((s, i) => ({ ...s, id: String(i) }))} columns={[
          { key: "source", label: "Source", render: (s) => <span className="mono small">{s.source}</span> }, { key: "category", label: "Category" },
          { key: "matched", label: "Listed as", render: (s) => <span className="mono small">{s.matched}</span> }, { key: "weight", label: "Weight", className: "right" }]} />
      </> : <p className="small muted">No feed or threat intel source lists this domain.</p>}
      {data.dgaLike && <p className="small" style={{ color: "#fbbf24" }}>The name looks machine-generated (DGA heuristic).</p>}
      {can("configure") && <div className="row" style={{ gap: 6, flexWrap: "wrap", marginTop: 10 }}>
        {deviceId && <><button disabled={busy} onClick={() => quick("allow", "device")}>Allow on this device</button>
          <button disabled={busy} onClick={() => quick("block", "device")}>Block on this device</button></>}
        <button disabled={busy} onClick={() => quick("allow", "tenant")}>Allow for the customer</button>
        <button className="danger" disabled={busy} onClick={() => quick("block", "tenant")}>Block for the customer</button>
        <label className="small">until <input type="date" value={expiry} onChange={(e) => setExpiry(e.target.value)} /></label>
        <span className="small muted">(no date = permanent; becomes an allow/block list entry)</span>
      </div>}
    </>
  );
}

export function Check({ tenantId, deviceId }: { tenantId?: string; deviceId?: string }) {
  const [domain, setDomain] = useState("");
  const [shown, setShown] = useState("");
  return (
    <div className="card">
      <h3>Check a domain</h3>
      <p className="small muted">What would happen to this domain{deviceId ? " on this device" : ""}, step by step, and why.</p>
      <div className="row" style={{ gap: 6 }}>
        <input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="example.com" onKeyDown={(e) => e.key === "Enter" && domain && setShown(domain.trim())} style={{ flex: 1 }} />
        <button className="primary" disabled={!domain} onClick={() => setShown(domain.trim())}>Check</button>
      </div>
      {shown && <div style={{ marginTop: 12 }}><ExplainView key={shown} domain={shown} deviceId={deviceId} tenantId={tenantId} /></div>}
    </div>
  );
}
