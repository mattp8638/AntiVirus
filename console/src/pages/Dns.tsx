import { useState } from "react";
import { ago, api, downloadFile, fmtTime } from "../api";
import { useApp } from "../app-context";
import { confirmDialog } from "../components/dialogs";
import { displayValue } from "../components/DisplayValue";
import { ErrorNote, Modal, PageHead, Pill, Stat, Table, useAction, useData, useListData } from "../components/ui";
import { ActionPill, CATEGORIES, Check, DAYS, ExplainView, SOURCE_TEXT, Trend, describeRule, useAutoRefresh, type QueryRow, type Rule } from "./DnsHead";

const NAV: { section: string; items: string[] }[] = [
  { section: "Investigate", items: ["Overview", "Query explorer", "Devices"] },
  { section: "Policies & rules", items: ["Rules", "Allow / block lists", "DNS policies"] },
  { section: "Threat intelligence", items: ["Fenrir ruleset", "External feeds"] },
];

export default function Dns() {
  const [page, setPage] = useState(() => { try { return localStorage.getItem("fenrir.dns.page") || "Overview"; } catch { return "Overview"; } });
  const [explorerDevice, setExplorerDevice] = useState<string>("");
  const go = (p: string) => { setPage(p); try { localStorage.setItem("fenrir.dns.page", p); } catch { /* not kept */ } };
  return (
    <>
      <PageHead title="DNS protection"
                subtitle="Encrypted DNS filtering that follows every device on and off the network: your rules and lists, policy categories, threat intel and the Fenrir ruleset, with the reason for every decision." />
      <div className="dns-layout" style={{ display: "grid", gridTemplateColumns: "minmax(170px, 210px) minmax(0, 1fr)", gap: 16, alignItems: "start" }}>
        <nav className="card" aria-label="DNS protection" style={{ padding: 8, position: "sticky", top: 8 }}>
          {NAV.map((g) => (
            <div key={g.section} style={{ marginBottom: 10 }}>
              <div className="small muted" style={{ textTransform: "uppercase", letterSpacing: ".05em", padding: "4px 8px" }}>{g.section}</div>
              {g.items.map((item) => <button key={item} className={item === page ? "primary" : "ghost"} aria-current={item === page ? "page" : undefined}
                                             onClick={() => go(item)} style={{ display: "block", width: "100%", textAlign: "left", marginBottom: 2 }}>{item}</button>)}
            </div>
          ))}
        </nav>
        <div style={{ minWidth: 0 }}>
          {page === "Overview" && <Overview openDevice={(id) => { setExplorerDevice(id); go("Devices"); }} />}
          {page === "Query explorer" && <Explorer initialDevice={explorerDevice} />}
          {page === "Devices" && <Devices openId={explorerDevice} onOpened={() => setExplorerDevice("")} />}
          {page === "Rules" && <Rules kind="rule" />}
          {page === "Allow / block lists" && <Rules kind="entry" />}
          {page === "DNS policies" && <Policies />}
          {page === "Fenrir ruleset" && <Ruleset />}
          {page === "External feeds" && <BlocklistsCard />}
        </div>
      </div>
      <style>{"@media (max-width: 760px) { .dns-layout { grid-template-columns: minmax(0, 1fr) !important; } .dns-layout > nav { position: static !important; } }"}</style>
    </>
  );
}

// --------------------------------------------------------------------------- overview

interface Overview {
  days: number; queries: number; blocked: number; blockRate: number; monitored: number; daily: { day: string; queries: number; blocked: number }[];
  topDomains: [string, number][]; topCategories: [string, number][]; bySource: [string, number][];
  topDevices: { id: string; hostname: string; blocked: number }[]; devices: { total: number; activeToday: number }; rules: number; entries: number;
  expiringSoon: number; ruleset: { version: number; domainCount: number; createdAt: string; stats: { blocking: number } } | null;
}

function Overview({ openDevice }: { openDevice: (id: string) => void }) {
  const { tenantId } = useApp();
  const [days, setDays] = useState(7);
  const { data: d, error, reload } = useData<Overview>("dns/overview", { tenant_id: tenantId, days }, [days]);
  useAutoRefresh(reload);
  return (
    <>
      <ErrorNote error={error} />
      <div className="card" style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <span className="small muted">Period</span>
        {[1, 7, 30, 90].map((n) => <button key={n} className={n === days ? "primary" : ""} onClick={() => setDays(n)}>{n === 1 ? "Today" : `${n} days`}</button>)}
      </div>
      <div className="grid k4">
        <Stat label="Lookups" value={d ? d.queries.toLocaleString() : "—"} hint="every query from every device" />
        <Stat label="Blocked" value={d ? d.blocked.toLocaleString() : "—"} hint={d ? `${d.blockRate}% of lookups` : undefined} accent={d?.blocked ? "red" : undefined} />
        <Stat label="Devices resolving today" value={d ? `${d.devices.activeToday} / ${d.devices.total}` : "—"} hint="devices whose DNS reached Fenrir" />
        <Stat label="Monitored" value={d?.monitored ?? "—"} hint="audit rules and ruleset matches, not blocked" accent={d?.monitored ? "amber" : undefined} />
      </div>
      <div className="grid k2">
        <div className="card"><h3>Lookups (blue) and blocks (red) per day</h3>{d && <Trend daily={d.daily} />}</div>
        <div className="card">
          <h3>Protection in place</h3>
          <table className="small"><tbody>
            <tr><td className="muted">Rules</td><td><b>{d?.rules ?? "—"}</b> active</td></tr>
            <tr><td className="muted">Allow / block entries</td><td><b>{d?.entries ?? "—"}</b>{d?.expiringSoon ? <span style={{ color: "#fbbf24" }}> · {d.expiringSoon} expire within a week</span> : null}</td></tr>
            <tr><td className="muted">Fenrir ruleset</td><td>{d?.ruleset ? <>v{d.ruleset.version}: <b>{d.ruleset.domainCount.toLocaleString()}</b> domains ({d.ruleset.stats.blocking.toLocaleString()} blocking), built {ago(d.ruleset.createdAt)}</> : "not built yet"}</td></tr>
          </tbody></table>
          <h3>What blocked</h3>
          <Table rows={(d?.bySource ?? []).map(([s, n]) => ({ id: s, s, n }))} empty="Nothing blocked in this period."
                 columns={[{ key: "s", label: "Decided by", render: (r) => SOURCE_TEXT[r.s] ?? r.s }, { key: "n", label: "Blocks", className: "right" }]} />
        </div>
      </div>
      <div className="grid k3">
        <div className="card"><h3>Top blocked domains</h3>
          <Table rows={(d?.topDomains ?? []).map(([x, n]) => ({ id: x, x, n }))} empty="—"
                 columns={[{ key: "x", label: "Domain", render: (r) => <span className="mono small">{r.x}</span> }, { key: "n", label: "Blocks", className: "right" }]} /></div>
        <div className="card"><h3>Top categories</h3>
          <Table rows={(d?.topCategories ?? []).map(([x, n]) => ({ id: x, x, n }))} empty="—"
                 columns={[{ key: "x", label: "Category" }, { key: "n", label: "Blocks", className: "right" }]} /></div>
        <div className="card"><h3>Devices with most blocks</h3>
          <Table rows={d?.topDevices ?? []} empty="—" onRow={(r) => openDevice(r.id)}
                 columns={[{ key: "hostname", label: "Device" }, { key: "blocked", label: "Blocks", className: "right" }]} /></div>
      </div>
      <Check tenantId={tenantId ?? undefined} />
    </>
  );
}

// --------------------------------------------------------------------------- query explorer

function Explorer({ initialDevice = "" }: { initialDevice?: string }) {
  const { tenantId } = useApp();
  const empty = { q: "", device_id: initialDevice, action: "", category: "", source: "", hours: 24 };
  const [filters, setFilters] = useState(empty);
  const [applied, setApplied] = useState(empty);
  const [open, setOpen] = useState<QueryRow | null>(null);
  const params = { tenant_id: tenantId, ...applied };
  const { data, error, reload } = useListData<QueryRow>("dns/queries", params, [JSON.stringify(params)]);
  const { data: scope } = useData<{ devices: { id: string; name: string }[] }>("dns/scope-options", { tenant_id: tenantId });
  useAutoRefresh(reload);
  const { run, busy } = useAction();
  const set = (k: keyof typeof empty) => (e: { target: { value: string } }) => setFilters({ ...filters, [k]: k === "hours" ? Number(e.target.value) : e.target.value });
  const csv = () => {
    const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v !== "" && v != null).map(([k, v]) => [k, String(v)]));
    return run(() => downloadFile(`dns/queries.csv?${q}`, "fenrir-dns.csv"), "Exported.");
  };
  return (
    <>
      <ErrorNote error={error} />
      <div className="card" style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        <input placeholder="Domain contains…" value={filters.q} onChange={set("q")} onKeyDown={(e) => e.key === "Enter" && setApplied(filters)} style={{ flex: 1, minWidth: 180 }} />
        <select value={filters.device_id} onChange={set("device_id")} aria-label="Device"><option value="">Every device</option>
          {(scope?.devices ?? []).map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}</select>
        <select value={filters.action} onChange={set("action")} aria-label="Action"><option value="">Any action</option>
          {["block", "allow", "monitor", "observe"].map((a) => <option key={a} value={a}>{a}</option>)}</select>
        <select value={filters.category} onChange={set("category")} aria-label="Category"><option value="">Any category</option>
          {CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}</select>
        <select value={filters.source} onChange={set("source")} aria-label="Decided by"><option value="">Decided by anything</option>
          {Object.entries(SOURCE_TEXT).filter(([k]) => k !== "other").map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select>
        <select value={filters.hours} onChange={set("hours")} aria-label="Window">
          {[[1, "1 hour"], [24, "24 hours"], [168, "7 days"], [720, "30 days"]].map(([h, l]) => <option key={h} value={h}>{l}</option>)}</select>
        <button className="primary" onClick={() => setApplied(filters)}>Search</button>
        <button onClick={() => { setFilters(empty); setApplied(empty); }}>Reset</button>
        <button disabled={busy} onClick={csv}>Export CSV</button>
      </div>
      <p className="small muted">The log keeps what each policy's <b>Query logging</b> setting asks for (blocked lookups by default, plus anything an audit or monitor rule matched). Set it to <i>all</i> on a policy to see every lookup.</p>
      <div className="card">
        <Table rows={data ?? undefined} onRow={setOpen} empty="No logged lookups match."
               columns={[
                 { key: "at", label: "Time", render: (r) => <span title={fmtTime(r.at)}>{ago(r.at)}</span> },
                 { key: "hostname", label: "Device", render: (r) => r.hostname || <span className="muted">—</span> },
                 { key: "qname", label: "Domain", render: (r) => <><span className="mono small">{r.qname}</span> <span className="small muted">{r.qtype}</span></> },
                 { key: "action", label: "Action", render: (r) => <ActionPill action={r.action} /> },
                 { key: "category", label: "Category" },
                 { key: "source", label: "Decided by", render: (r) => <>{SOURCE_TEXT[r.source] ?? (r.source || "—")}{r.score != null && <span className="small muted"> · score {r.score}</span>}
                   <div className="small muted">{r.reason}</div></> },
               ]} />
      </div>
      {open && <Modal title={open.qname} onClose={() => setOpen(null)} wide>
        <p className="small muted">{fmtTime(open.at)} · {open.hostname || "unknown device"} · {open.qtype} · logged as <b>{open.action}</b>: {open.reason}</p>
        <h3>Decided now</h3>
        <ExplainView domain={open.qname} deviceId={open.deviceId} tenantId={open.tenantId} onChanged={reload} />
      </Modal>}
    </>
  );
}

// --------------------------------------------------------------------------- devices

interface DeviceRow { id: string; tenantId: string; hostname: string; platform: string; queriesToday: number; blockedToday: number; queries7d: number;
  blocked7d: number; lastBlockAt: string | null; proxy: { state: string; detail: string; at: string | null }; resolving: boolean }
const PROXY_TONE: Record<string, string> = { on: "good", problem: "bad", skipped: "warn", off: "muted", "not reported": "muted" };

function Devices({ openId, onOpened }: { openId?: string; onOpened?: () => void }) {
  const { tenantId, tenantName } = useApp();
  const [q, setQ] = useState("");
  const [open, setOpen] = useState<string | null>(openId || null);
  const { data, error, reload } = useListData<DeviceRow>("dns/devices", { tenant_id: tenantId, q }, [q]);
  useAutoRefresh(reload, 60);
  const rows = data ?? [];
  const notResolving = rows.filter((d) => !d.resolving).length;
  const problems = rows.filter((d) => d.proxy.state === "problem").length;
  return (
    <>
      <ErrorNote error={error} />
      <div className="grid k3">
        <Stat label="Devices" value={rows.length} />
        <Stat label="Not resolving through Fenrir (7 days)" value={notResolving} hint="no lookups counted: DNS is not reaching Fenrir" accent={notResolving ? "amber" : undefined} />
        <Stat label="Local DNS proxy problems" value={problems} accent={problems ? "red" : undefined} />
      </div>
      <div className="card"><input placeholder="Search devices" value={q} onChange={(e) => setQ(e.target.value)} style={{ width: "100%" }} /></div>
      <div className="card">
        <Table rows={data ?? undefined} onRow={(r) => setOpen(r.id)} empty="No devices."
               columns={[
                 { key: "hostname", label: "Device", render: (r) => <><b>{r.hostname}</b><div className="small muted">{r.platform} · {tenantName(r.tenantId)}</div></> },
                 { key: "proxy", label: "Local proxy", render: (r) => <span title={r.proxy.detail}><Pill value={r.proxy.state} tone={PROXY_TONE[r.proxy.state]} /></span> },
                 { key: "queriesToday", label: "Today", render: (r) => <>{r.queriesToday.toLocaleString()} <span className="small muted">lookups</span><div className="small" style={{ color: r.blockedToday ? "#fca5a5" : undefined }}>{r.blockedToday} blocked</div></> },
                 { key: "queries7d", label: "7 days", render: (r) => r.resolving ? <>{r.queries7d.toLocaleString()}<div className="small muted">{r.blocked7d} blocked</div></> : <Pill value="not resolving" tone="warn" /> },
                 { key: "lastBlockAt", label: "Last block", render: (r) => r.lastBlockAt ? ago(r.lastBlockAt) : <span className="muted">—</span> },
               ]} />
      </div>
      {open && <DeviceModal id={open} onClose={() => { setOpen(null); onOpened?.(); }} />}
    </>
  );
}

interface DeviceDetail {
  device: { id: string; hostname: string; platform: string; tenantId: string; groupName: string };
  policy: { origins: string[]; enabled: boolean; mode: string; blockedCategories: string[]; fenrirRuleset: string; externalLists: string; logQueries: string;
    localProxy: boolean; localProxyFailMode: string; safeSearch: boolean; allowDomains: number; blockDomains: number };
  proxy: { state: string; detail: string; at: string | null }; events: { type: string; summary: string; at: string }[];
  daily: { day: string; queries: number; blocked: number }[]; topBlocked: [string, number][]; categories: [string, number][];
  recent: QueryRow[]; rules: { id: string; name: string; kind: string; action: string; mode: string; scopeType: string; mspWide: boolean }[];
}

function DeviceModal({ id, onClose }: { id: string; onClose: () => void }) {
  const { data, error } = useData<DeviceDetail>(`dns/devices/${id}`, {}, [id]);
  const [explain, setExplain] = useState<QueryRow | null>(null);
  const p = data?.policy;
  return (
    <Modal title={data ? `${data.device.hostname}: DNS protection` : "Device"} onClose={onClose} wide>
      <ErrorNote error={error} />
      {data && p && <>
        <div className="grid k2">
          <div>
            <h3>Policy in force</h3>
            <table className="small"><tbody>
              <tr><td className="muted">DNS filtering</td><td>{p.enabled ? (p.mode === "observe" ? <Pill value="observe only" tone="warn" /> : <Pill value="on" tone="good" />) : <Pill value="off" tone="bad" />}</td></tr>
              <tr><td className="muted">Blocked categories</td><td>{p.blockedCategories.join(", ") || "none"}</td></tr>
              <tr><td className="muted">Fenrir ruleset</td><td>{p.fenrirRuleset}</td></tr>
              <tr><td className="muted">External lists</td><td>{p.externalLists === "ruleset" ? "only through the ruleset" : "block on their own"}</td></tr>
              <tr><td className="muted">Policy lists</td><td>{p.allowDomains} allowed · {p.blockDomains} blocked</td></tr>
              <tr><td className="muted">SafeSearch</td><td>{p.safeSearch ? "enforced" : "off"}</td></tr>
              <tr><td className="muted">Query logging</td><td>{p.logQueries}</td></tr>
              <tr><td className="muted">Set by</td><td>{p.origins.join(", ") || "defaults"}</td></tr>
            </tbody></table>
          </div>
          <div>
            <h3>On the device</h3>
            <table className="small"><tbody>
              <tr><td className="muted">Local DNS proxy</td><td>{p.localProxy ? <>on (when Fenrir is unreachable: {p.localProxyFailMode === "closed" ? "refuse" : "use the network's DNS"})</> : "off (DNS-over-HTTPS address only)"}</td></tr>
              <tr><td className="muted">Proxy status</td><td><Pill value={data.proxy.state} tone={PROXY_TONE[data.proxy.state]} /> {data.proxy.detail}{data.proxy.at && <span className="muted"> · {ago(data.proxy.at)}</span>}</td></tr>
              <tr><td className="muted">Group</td><td>{data.device.groupName || "none"}</td></tr>
            </tbody></table>
            <h3>Last 14 days</h3>
            <Trend daily={data.daily} />
          </div>
        </div>
        <div className="grid k2">
          <div><h3>Most blocked</h3>
            <Table rows={data.topBlocked.map(([x, n]) => ({ id: x, x, n }))} empty="Nothing blocked recently."
                   columns={[{ key: "x", label: "Domain", render: (r) => <span className="mono small">{r.x}</span> }, { key: "n", label: "Blocks", className: "right" }]} /></div>
          <div><h3>Rules and lists that apply</h3>
            <Table rows={data.rules} empty="None (policy, intel, ruleset and lists only)."
                   columns={[{ key: "name", label: "Rule", render: (r) => <>{r.name} {r.mspWide && <Pill value="MSP-wide" tone="muted" />}</> },
                             { key: "action", label: "", render: (r) => <>{<ActionPill action={r.action} />} {r.mode === "audit" && <Pill value="audit" tone="warn" />}</> },
                             { key: "scopeType", label: "Scope" }]} /></div>
        </div>
        <h3>Recent logged lookups</h3>
        <Table rows={data.recent} onRow={setExplain} empty="None logged."
               columns={[{ key: "at", label: "Time", render: (r) => ago(r.at) }, { key: "qname", label: "Domain", render: (r) => <span className="mono small">{r.qname}</span> },
                         { key: "action", label: "", render: (r) => <ActionPill action={r.action} /> }, { key: "reason", label: "Why", render: (r) => <span className="small">{r.reason}</span> }]} />
        {explain && <div className="card" style={{ marginTop: 10 }}><div className="row"><h3 style={{ flex: 1, margin: 0 }}>{explain.qname}</h3><button className="ghost" onClick={() => setExplain(null)}>Close</button></div>
          <ExplainView domain={explain.qname} deviceId={id} /></div>}
        <h3>DNS events from the agent</h3>
        <Table rows={data.events.map((e, i) => ({ ...e, id: String(i) }))} empty="The agent has not reported DNS events."
               columns={[{ key: "at", label: "When", render: (e) => ago(e.at) }, { key: "type", label: "Event", render: (e) => <span className="mono small">{e.type}</span> }, { key: "summary", label: "" }]} />
        <Check deviceId={id} />
      </>}
    </Modal>
  );
}

// --------------------------------------------------------------------------- rules and lists

function Rules({ kind }: { kind: "rule" | "entry" }) {
  const { tenantId, can } = useApp();
  const { data, error, reload } = useListData<Rule>("dns/rules", { tenant_id: tenantId, kind }, [kind]);
  useAutoRefresh(reload, 60);
  const { run, busy } = useAction();
  const [editing, setEditing] = useState<Partial<Rule> | null>(null);
  const [history, setHistory] = useState<Rule | null>(null);
  const [importing, setImporting] = useState(false);
  const [filter, setFilter] = useState({ q: "", action: "" });
  const rows = (data ?? []).filter((r) => (!filter.action || r.action === filter.action) &&
    (!filter.q || `${r.name} ${r.patterns.join(" ")} ${r.comment}`.toLowerCase().includes(filter.q.toLowerCase())));
  const toggle = async (r: Rule) => { await run(() => api(`dns/rules/${r.id}`, { method: "PUT", body: { enabled: !r.enabled } }), r.enabled ? "Turned off." : "Turned on."); reload(); };
  const remove = async (r: Rule) => {
    if (!(await confirmDialog(`Delete "${r.name}"? It can be restored from its history.`, { confirmLabel: "Delete" }))) return;
    await run(() => api(`dns/rules/${r.id}`, { method: "DELETE" }), "Deleted."); reload();
  };
  const isRule = kind === "rule";
  return (
    <>
      <ErrorNote error={error} />
      <div className="card small muted">
        {isRule ? <>Rules run <b>first</b>, before policy lists, threat intel, the Fenrir ruleset and categories. The closest scope wins (device, then group, then customer, then MSP-wide),
          then priority (lower first), then allow before block. <b>Audit</b> rules and <b>monitor</b> rules only record what they match, so a rule can be tried on real traffic first.
          Every change is versioned and can be restored.</>
          : <>Simple allow and block lines, checked with the rules (before everything else). A domain covers its subdomains. Give temporary entries an expiry date.
          Entries added from the query explorer land here. On your MSP tenant they apply to every customer.</>}
      </div>
      <div className="card" style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        <input placeholder="Search" value={filter.q} onChange={(e) => setFilter({ ...filter, q: e.target.value })} style={{ flex: 1, minWidth: 180 }} />
        <select value={filter.action} onChange={(e) => setFilter({ ...filter, action: e.target.value })} aria-label="Action"><option value="">Allow, block and monitor</option>
          <option value="allow">Allow</option><option value="block">Block</option>{isRule && <option value="monitor">Monitor</option>}</select>
        {can("configure") && <>
          <button className="primary" onClick={() => setEditing({ kind, action: "block", match: "domain", patterns: [], scopeType: "tenant", scopeIds: [], qtypes: [], schedule: {}, mode: "enforce", priority: 100, enabled: true, tenantId: tenantId || "" })}>
            {isRule ? "Add a rule" : "Add an entry"}</button>
          {!isRule && <button onClick={() => setImporting(true)}>Import many</button>}
        </>}
      </div>
      <div className="card">
        <Table rows={data ? rows : undefined} empty={isRule ? "No DNS rules yet." : "No allow or block entries yet."}
               columns={[
                 { key: "priority", label: isRule ? "Priority" : "", render: (r) => isRule ? r.priority : <ActionPill action={r.action} /> },
                 { key: "name", label: isRule ? "Rule" : "Domain", render: (r) => <><b>{isRule ? r.name : r.patterns.join(", ")}</b> {r.mspWide && <Pill value="MSP-wide" tone="muted" />}
                   {!r.enabled && <Pill value="off" tone="muted" />} {r.expired && <Pill value="expired" tone="muted" />}
                   <div className="small muted">{isRule ? describeRule(r) : describeRule(r).split(" · ")[1]}</div>{r.comment && <div className="small">{r.comment}</div>}</> },
                 ...(isRule ? [{ key: "action", label: "Action", render: (r: Rule) => <>{<ActionPill action={r.action} />} {r.mode === "audit" && <Pill value="audit only" tone="warn" />}</> }] : []),
                 { key: "hits", label: "Hits", render: (r) => <>{r.hits.toLocaleString()}<div className="small muted">{r.lastHitAt ? `last ${ago(r.lastHitAt)}` : "never"}</div></> },
                 { key: "expiresAt", label: "Expires", render: (r) => r.expiresAt ? r.expiresAt.slice(0, 10) : <span className="muted small">never</span> },
                 { key: "actions", label: "", className: "right", render: (r) => <span style={{ display: "inline-flex", gap: 4 }}>
                   <button className="ghost" onClick={() => setHistory(r)}>History (v{r.version})</button>
                   {r.editable !== false && can("configure") && <>
                     <button className="ghost" onClick={() => setEditing(r)}>Edit</button>
                     <button className="ghost" disabled={busy} onClick={() => toggle(r)}>{r.enabled ? "Turn off" : "Turn on"}</button>
                     <button className="ghost danger" disabled={busy} onClick={() => remove(r)}>Delete</button></>}</span> },
               ]} />
      </div>
      {editing && <RuleEditor rule={editing} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); reload(); }} />}
      {history && <RuleHistory rule={history} onClose={() => setHistory(null)} onRestored={() => { setHistory(null); reload(); }} />}
      {importing && <ImportEntries onClose={() => setImporting(false)} onDone={() => { setImporting(false); reload(); }} />}
    </>
  );
}

function RuleEditor({ rule, onClose, onSaved }: { rule: Partial<Rule>; onClose: () => void; onSaved: () => void }) {
  const { me, tenantId } = useApp();
  const tenants = me?.tenants ?? [];
  const [r, setR] = useState<Partial<Rule> & { patternsText?: string; changeComment?: string }>({ ...rule, patternsText: (rule.patterns ?? []).join("\n"),
    tenantId: rule.tenantId || tenantId || tenants[0]?.id || "" });
  const { data: scope } = useData<{ groups: { id: string; name: string; tenantId: string }[]; devices: { id: string; name: string; tenantId: string }[] }>(
    "dns/scope-options", { tenant_id: r.tenantId }, [r.tenantId]);
  const { run, busy } = useAction();
  const isRule = r.kind === "rule";
  const schedule = r.schedule ?? {};
  const scheduled = !!schedule.days?.length;
  const save = async () => {
    const body = { ...r, patterns: (r.patternsText ?? "").split(/[\n,]+/).map((x) => x.trim()).filter(Boolean),
                   expiresAt: r.expiresAt ? new Date(r.expiresAt).toISOString() : null, schedule: scheduled ? schedule : {} };
    delete (body as { patternsText?: string }).patternsText;
    const ok = await run(() => rule.id ? api(`dns/rules/${rule.id}`, { method: "PUT", body }) : api("dns/rules", { method: "POST", body }),
                         rule.id ? "Saved as a new version." : "Created.");
    if (ok) onSaved();
  };
  const options = (r.scopeType === "group" ? scope?.groups : scope?.devices) ?? [];
  return (
    <Modal title={rule.id ? `Edit ${isRule ? "rule" : "entry"}` : isRule ? "New DNS rule" : "New allow / block entry"} onClose={onClose} wide
           footer={<><button onClick={onClose}>Cancel</button><button className="primary" disabled={busy} onClick={save}>{rule.id ? "Save new version" : "Create"}</button></>}>
      <div className="form-grid">
        {!rule.id && <label className="field">Customer<select value={r.tenantId} onChange={(e) => setR({ ...r, tenantId: e.target.value, scopeIds: [] })}>
          {tenants.map((t) => <option key={t.id} value={t.id}>{t.parentId ? t.name : `${t.name} (MSP-wide: every customer)`}</option>)}</select></label>}
        {isRule && <label className="field">Name<input value={r.name ?? ""} onChange={(e) => setR({ ...r, name: e.target.value })} placeholder="e.g. Block social media in school hours" /></label>}
        <label className="field">Action<select value={r.action} onChange={(e) => setR({ ...r, action: e.target.value })}>
          <option value="block">Block</option><option value="allow">Allow (skip everything after this)</option>{isRule && <option value="monitor">Monitor (log only)</option>}</select></label>
        <label className="field">Match<select value={r.match} onChange={(e) => setR({ ...r, match: e.target.value })}>
          <option value="domain">Domain and its subdomains</option><option value="exact">Exact name only</option><option value="wildcard">Wildcard (*.ads.*.example)</option>
          {isRule && <><option value="regex">Pattern (regular expression)</option><option value="category">Category</option></>}</select></label>
        {r.match === "category"
          ? <label className="field">Categories<select multiple value={(r.patternsText ?? "").split("\n").filter(Boolean)} style={{ minHeight: 140 }}
                    onChange={(e) => setR({ ...r, patternsText: Array.from(e.target.selectedOptions).map((o) => o.value).join("\n") })}>
              {CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}</select></label>
          : <label className="field">{r.match === "regex" ? "Patterns (one per line)" : "Domains (one per line)"}<textarea rows={5} value={r.patternsText}
                    onChange={(e) => setR({ ...r, patternsText: e.target.value })} placeholder={r.match === "regex" ? "^[a-z0-9]{30,}\\.example$" : "contoso.com\ncdn.contoso.net"} /></label>}
        <label className="field">Applies to<select value={r.scopeType} onChange={(e) => setR({ ...r, scopeType: e.target.value, scopeIds: [] })}>
          <option value="tenant">The whole customer</option><option value="group">Device groups (and their subgroups)</option><option value="device">Specific devices</option></select></label>
        {r.scopeType !== "tenant" && <label className="field">{r.scopeType === "group" ? "Groups" : "Devices"}<select multiple value={r.scopeIds ?? []} style={{ minHeight: 120 }}
                    onChange={(e) => setR({ ...r, scopeIds: Array.from(e.target.selectedOptions).map((o) => o.value) })}>
          {options.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}</select></label>}
        {isRule && <>
          <label className="field">Query types<select multiple value={r.qtypes ?? []} style={{ minHeight: 100 }} onChange={(e) => setR({ ...r, qtypes: Array.from(e.target.selectedOptions).map((o) => o.value) })}>
            {["A", "AAAA", "CNAME", "MX", "TXT", "HTTPS", "SVCB", "SRV", "PTR", "NS", "SOA", "ANY"].map((q) => <option key={q} value={q}>{q}</option>)}</select>
            <span className="small muted">None selected = every type</span></label>
          <label className="field">Priority<input type="number" min={0} max={10000} value={r.priority ?? 100} onChange={(e) => setR({ ...r, priority: Number(e.target.value) })} />
            <span className="small muted">Lower runs first within the same scope</span></label>
          <div className="field"><label><input type="checkbox" checked={scheduled} onChange={(e) => setR({ ...r, schedule: e.target.checked ? { days: [0, 1, 2, 3, 4], start: "09:00", end: "17:00" } : {} })} /> Only at certain times</label>
            {scheduled && <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 6 }}>
              {DAYS.map((d, i) => <label key={d} className="small"><input type="checkbox" checked={schedule.days?.includes(i) ?? false}
                onChange={(e) => setR({ ...r, schedule: { ...schedule, days: e.target.checked ? [...(schedule.days ?? []), i] : (schedule.days ?? []).filter((x) => x !== i) } })} /> {d}</label>)}
              <input type="time" value={schedule.start} onChange={(e) => setR({ ...r, schedule: { ...schedule, start: e.target.value } })} />
              to <input type="time" value={schedule.end} onChange={(e) => setR({ ...r, schedule: { ...schedule, end: e.target.value } })} />
              <span className="small muted">customer's time zone</span></div>}</div>
          <label className="field"><span><input type="checkbox" checked={r.mode === "audit"} onChange={(e) => setR({ ...r, mode: e.target.checked ? "audit" : "enforce" })} /> Audit only</span>
            <span className="small muted">Record what it would do in the query log, change nothing</span></label>
        </>}
        <label className="field">Expires<input type="date" value={r.expiresAt ? r.expiresAt.slice(0, 10) : ""} onChange={(e) => setR({ ...r, expiresAt: e.target.value || null })} /></label>
        <label className="field">Note (why)<input value={r.comment ?? ""} onChange={(e) => setR({ ...r, comment: e.target.value })} /></label>
        {rule.id && <label className="field">What changed (kept in the history)<input value={r.changeComment ?? ""} onChange={(e) => setR({ ...r, changeComment: e.target.value })} /></label>}
      </div>
    </Modal>
  );
}

function RuleHistory({ rule, onClose, onRestored }: { rule: Rule; onClose: () => void; onRestored: () => void }) {
  const { can } = useApp();
  const { data, error } = useListData<{ version: number; change: string; actor: string; comment: string; at: string; changes: { field: string; from: unknown; to: unknown }[] }>(
    `dns/rules/${rule.id}/history`);
  const { run, busy } = useAction();
  const show = (v: unknown) => v === null || v === undefined || v === "" ? "—" : typeof v === "object" ? JSON.stringify(v) : String(v);
  return (
    <Modal title={`History: ${rule.name}`} onClose={onClose} wide>
      <ErrorNote error={error} />
      <Table rows={(data ?? []).map((h) => ({ ...h, id: String(h.version) }))} empty="No history."
             columns={[
               { key: "version", label: "Version", render: (h) => <><b>v{h.version}</b> <Pill value={h.change} tone={h.change === "delete" ? "bad" : "muted"} /></> },
               { key: "at", label: "When", render: (h) => <>{ago(h.at)}<div className="small muted">{h.actor}</div></> },
               { key: "changes", label: "What changed", render: (h) => <>{h.comment && <div className="small"><i>{h.comment}</i></div>}
                 {h.changes.map((c, i) => <div key={i} className="small"><span className="mono">{c.field}</span>: <span style={{ color: "#fca5a5" }}>{show(c.from)}</span> → <span style={{ color: "#86efac" }}>{show(c.to)}</span></div>)}</> },
               { key: "actions", label: "", render: (h) => can("configure") && rule.editable !== false && h.change !== "delete" && h.version !== rule.version
                 ? <button className="ghost" disabled={busy} onClick={async () => { if (await run(() => api(`dns/rules/${rule.id}/restore/${h.version}`, { method: "POST" }), `Version ${h.version} restored.`)) onRestored(); }}>Restore</button> : null },
             ]} />
    </Modal>
  );
}

function ImportEntries({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const { me, tenantId } = useApp();
  const tenants = me?.tenants ?? [];
  const [body, setBody] = useState({ tenantId: tenantId || tenants[0]?.id || "", action: "block", text: "", expiresAt: "", comment: "" });
  const [result, setResult] = useState<{ created: number; skipped: number; errors: string[] } | null>(null);
  const { run, busy } = useAction();
  return (
    <Modal title="Import allow / block entries" onClose={onClose} wide
           footer={<><button onClick={onClose}>{result ? "Close" : "Cancel"}</button>{!result && <button className="primary" disabled={busy || !body.text.trim()} onClick={async () => {
             const r = await run(() => api<{ created: number; skipped: number; errors: string[] }>("dns/rules/import", { method: "POST",
               body: { ...body, expiresAt: body.expiresAt ? new Date(body.expiresAt).toISOString() : null } }));
             if (r) { setResult(r); if (!r.errors.length) onDone(); }
           }}>Import</button>}</>}>
      {result ? <p>{result.created} added, {result.skipped} already listed{result.errors.length ? `, ${result.errors.length} not understood:` : "."}
        {result.errors.map((e, i) => <span key={i} className="small mono" style={{ display: "block" }}>{e}</span>)}</p> : <div className="form-grid">
        <label className="field">Customer<select value={body.tenantId} onChange={(e) => setBody({ ...body, tenantId: e.target.value })}>
          {tenants.map((t) => <option key={t.id} value={t.id}>{t.parentId ? t.name : `${t.name} (MSP-wide)`}</option>)}</select></label>
        <label className="field">Action<select value={body.action} onChange={(e) => setBody({ ...body, action: e.target.value })}><option value="block">Block</option><option value="allow">Allow</option></select></label>
        <label className="field">Domains<textarea rows={10} value={body.text} onChange={(e) => setBody({ ...body, text: e.target.value })}
                  placeholder={"one per line; hosts-file lines and # comments are fine\n0.0.0.0 bad.example\ncontoso.com"} /></label>
        <label className="field">Expires<input type="date" value={body.expiresAt} onChange={(e) => setBody({ ...body, expiresAt: e.target.value })} /></label>
        <label className="field">Note<input value={body.comment} onChange={(e) => setBody({ ...body, comment: e.target.value })} /></label>
      </div>}
    </Modal>
  );
}

// --------------------------------------------------------------------------- policies (read here, edit in Protection policies)

interface PolicyRow { id: string; name: string; tenantId: string | null; settings: { dns?: Record<string, unknown> }; devices: number; groups: number; tenants: number }

function Policies() {
  const { tenantId } = useApp();
  const { data, error } = useListData<PolicyRow>("policies", { tenant_id: tenantId });
  const v = (p: PolicyRow, key: string, fallback: string) => { const x = p.settings?.dns?.[key]; return x === undefined ? <span className="muted">{fallback}</span> : Array.isArray(x) ? x.join(", ") || "none" : String(x); };
  return (
    <>
      <ErrorNote error={error} />
      <div className="card small muted">Each protection policy's DNS section sets the filtering mode, blocked categories, policy allow/block lists, SafeSearch, logging, how the Fenrir ruleset and external lists are used,
        and the local DNS proxy on Windows, Linux and macOS. Grey values are inherited from the layer above. Open a policy to change it.</div>
      <div className="card">
        <Table rows={data ?? undefined} empty="No policies." onRow={(p) => { window.location.href = `/policies/${p.id}`; }}
               columns={[
                 { key: "name", label: "Policy", render: (p) => <><b>{p.name}</b><div className="small muted">{p.devices} devices · {p.groups} groups · {p.tenants} customers</div></> },
                 { key: "enabled", label: "Filtering", render: (p) => v(p, "enabled", "inherited") },
                 { key: "blockedCategories", label: "Blocked categories", render: (p) => <span className="small">{v(p, "blockedCategories", "inherited")}</span> },
                 { key: "fenrirRuleset", label: "Ruleset", render: (p) => v(p, "fenrirRuleset", "inherited") },
                 { key: "localProxy", label: "Local proxy", render: (p) => v(p, "localProxy", "inherited") },
                 { key: "logQueries", label: "Logging", render: (p) => v(p, "logQueries", "inherited") },
               ]} />
      </div>
    </>
  );
}

// --------------------------------------------------------------------------- Fenrir ruleset

interface Build { id: string; version: number; active: boolean; createdBy: string; createdAt: string; domainCount: number;
  settings: { blockThreshold: number; monitorThreshold: number; sources: { id: string; name: string; weight: number; domains: number; category: string }[] };
  stats: { domains: number; blocking: number; monitorOnly: number; byCategory: Record<string, number>; scored: number; protectedSkipped: number; seconds: number };
  diff: { added: number; removed: number; addedSample: string[]; removedSample: string[]; previousVersion: number | null } }
interface RulesetState { config: { blockThreshold: number; monitorThreshold: number; intelWeight: number; protected: string[]; autoBuild: boolean };
  builtinProtected: string[]; sources: { id: string; name: string; category: string; enabled: boolean; domains: number; weight: number; inRuleset: boolean }[];
  builds: Build[]; building: boolean; buildError: string; canManage: boolean }

function Ruleset() {
  const { data, error, reload } = useData<RulesetState>("dns/ruleset");
  useAutoRefresh(reload, data?.building ? 3 : 60);
  const { run, busy } = useAction();
  const [cfg, setCfg] = useState<RulesetState["config"] | null>(null);
  const [weights, setWeights] = useState<Record<string, number>>({});
  const [protectedText, setProtectedText] = useState<string | null>(null);
  const [test, setTest] = useState("");
  const [shown, setShown] = useState("");
  const [diffOf, setDiffOf] = useState<Build | null>(null);
  if (!data) return <ErrorNote error={error} />;
  const c = cfg ?? data.config;
  const active = data.builds.find((b) => b.active);
  const save = async () => {
    await run(() => api("dns/ruleset/config", { method: "PUT", body: { ...c, weights: { ...Object.fromEntries(data.sources.map((s) => [s.id, s.weight])), ...weights },
      protected: (protectedText ?? data.config.protected.join("\n")).split(/[\n,]+/).map((x) => x.trim()).filter(Boolean) } }), "Saved. Build to apply.");
    setCfg(null); setWeights({}); setProtectedText(null); reload();
  };
  const build = async () => { await run(() => api("dns/ruleset/build", { method: "POST" }), "Building…"); reload(); };
  const canManage = data.canManage;
  return (
    <>
      <div className="card small muted">
        Your own ruleset, built from every feed below and Fenrir's threat intel. Each source that lists a domain adds its <b>weight</b>; the total (capped at 100) is the domain's score.
        At or above the <b>block threshold</b> it blocks (threat categories always; other categories where the policy blocks them). Between the thresholds it is <b>monitored</b>:
        logged, never blocked. Protected domains are never included. It rebuilds automatically after the feeds refresh, and every build can be compared and rolled back.
        Policies choose to use it (<i>Fenrir DNS ruleset: block / monitor / off</i>) and whether external lists still block on their own (<i>External blocklists: direct / ruleset</i>).
      </div>
      <div className="grid k4">
        <Stat label="Active build" value={active ? `v${active.version}` : "none"} hint={active ? `built ${ago(active.createdAt)} by ${active.createdBy}` : "build it below"} accent={active ? "green" : undefined} />
        <Stat label="Domains" value={active ? active.domainCount.toLocaleString() : "—"} hint={active ? `${active.stats.blocking.toLocaleString()} block · ${active.stats.monitorOnly.toLocaleString()} monitor` : undefined} />
        <Stat label="Domains scored" value={active ? active.stats.scored.toLocaleString() : "—"} hint={active ? `${active.stats.protectedSkipped} protected skipped` : undefined} />
        <Stat label="Last change" value={active ? `+${active.diff.added.toLocaleString()} / −${active.diff.removed.toLocaleString()}` : "—"} hint={active?.diff.previousVersion ? `against v${active.diff.previousVersion}` : "first build"} />
      </div>
      {data.buildError && <div className="card" style={{ borderColor: "rgba(239,68,68,.5)" }}>The last build failed: {data.buildError}</div>}
      <div className="grid k2">
        <div className="card">
          <h3>Scoring</h3>
          <div className="form-grid">
            <label className="field">Block from score<input type="number" min={1} max={100} value={c.blockThreshold} disabled={!canManage} onChange={(e) => setCfg({ ...c, blockThreshold: Number(e.target.value) })} /></label>
            <label className="field">Monitor from score<input type="number" min={1} max={100} value={c.monitorThreshold} disabled={!canManage} onChange={(e) => setCfg({ ...c, monitorThreshold: Number(e.target.value) })} /></label>
            <label className="field">Threat intel weight<input type="number" min={0} max={100} value={c.intelWeight} disabled={!canManage} onChange={(e) => setCfg({ ...c, intelWeight: Number(e.target.value) })} /></label>
            <label className="field"><span><input type="checkbox" checked={c.autoBuild} disabled={!canManage} onChange={(e) => setCfg({ ...c, autoBuild: e.target.checked })} /> Rebuild after the feeds change</span></label>
          </div>
          <h3>Sources and weights</h3>
          <Table rows={data.sources} columns={[
            { key: "name", label: "Feed", render: (s) => <><b>{s.name}</b><div className="small muted">{s.category} · {s.domains.toLocaleString()} domains{!s.enabled && " · disabled"}</div></> },
            { key: "weight", label: "Weight", render: (s) => <input type="number" min={0} max={100} style={{ width: 70 }} disabled={!canManage} value={weights[s.id] ?? s.weight}
                                                                   onChange={(e) => setWeights({ ...weights, [s.id]: Number(e.target.value) })} /> },
            { key: "inRuleset", label: "", render: (s) => s.inRuleset ? <Pill value="counts" tone="good" /> : <span className="small muted">{s.weight ? "enable or set a weight" : "weight 0"}</span> },
          ]} />
          <p className="small muted">A disabled feed counts towards agreement once you give it a weight here, without blocking on its own.</p>
          <h3>Protected domains</h3>
          <textarea rows={4} style={{ width: "100%" }} disabled={!canManage} value={protectedText ?? data.config.protected.join("\n")} onChange={(e) => setProtectedText(e.target.value)} placeholder="your-company.co.uk" />
          <p className="small muted">Always protected: {data.builtinProtected.slice(0, 12).join(", ")} and {data.builtinProtected.length - 12} more, plus this server.</p>
          {canManage && <div className="row" style={{ gap: 6 }}><button className="primary" disabled={busy} onClick={save}>Save settings</button>
            <button disabled={busy || data.building} onClick={build}>{data.building ? "Building…" : "Build now"}</button></div>}
        </div>
        <div className="card">
          <h3>Active build by category</h3>
          {active ? <Table rows={Object.entries(active.stats.byCategory).sort((a, b) => b[1] - a[1]).map(([k, n]) => ({ id: k, k, n }))}
                           columns={[{ key: "k", label: "Category" }, { key: "n", label: "Domains", className: "right", render: (r) => r.n.toLocaleString() }]} /> : <p className="muted">Not built yet.</p>}
          <h3>Test a domain</h3>
          <div className="row" style={{ gap: 6 }}><input value={test} onChange={(e) => setTest(e.target.value)} onKeyDown={(e) => e.key === "Enter" && setShown(test)} placeholder="suspicious.example" style={{ flex: 1 }} />
            <button onClick={() => setShown(test)} disabled={!test}>Score it</button></div>
          {shown && <RulesetExplain key={shown} domain={shown} />}
        </div>
      </div>
      <div className="card">
        <h3>Builds</h3>
        <Table rows={data.builds} empty="No builds yet."
               columns={[
                 { key: "version", label: "Build", render: (b) => <><b>v{b.version}</b> {b.active && <Pill value="active" tone="good" />}</> },
                 { key: "createdAt", label: "Built", render: (b) => <>{ago(b.createdAt)}<div className="small muted">{b.createdBy} · {b.stats.seconds}s</div></> },
                 { key: "domainCount", label: "Domains", render: (b) => <>{b.domainCount.toLocaleString()}<div className="small muted">block ≥{b.settings.blockThreshold} · monitor ≥{b.settings.monitorThreshold}</div></> },
                 { key: "diff", label: "Change", render: (b) => b.diff.previousVersion ? <button className="ghost" onClick={() => setDiffOf(b)}>+{b.diff.added.toLocaleString()} / −{b.diff.removed.toLocaleString()}</button> : <span className="muted small">first build</span> },
                 { key: "actions", label: "", render: (b) => canManage && !b.active ? <button className="ghost" disabled={busy} onClick={async () => {
                   if (await run(() => api(`dns/ruleset/${b.version}/activate`, { method: "POST" }), `Build v${b.version} is active.`)) reload(); }}>Make active</button> : null },
               ]} />
      </div>
      {diffOf && <Modal title={`Build v${diffOf.version} against v${diffOf.diff.previousVersion}`} onClose={() => setDiffOf(null)} wide>
        <div className="grid k2">
          <div><h3 style={{ color: "#fca5a5" }}>Added ({diffOf.diff.added.toLocaleString()})</h3>{diffOf.diff.addedSample.map((d) => <div key={d} className="mono small">{d}</div>)}
            {diffOf.diff.added > diffOf.diff.addedSample.length && <p className="small muted">and {(diffOf.diff.added - diffOf.diff.addedSample.length).toLocaleString()} more</p>}</div>
          <div><h3 style={{ color: "#86efac" }}>Removed ({diffOf.diff.removed.toLocaleString()})</h3>{diffOf.diff.removedSample.map((d) => <div key={d} className="mono small">{d}</div>)}
            {diffOf.diff.removed > diffOf.diff.removedSample.length && <p className="small muted">and {(diffOf.diff.removed - diffOf.diff.removedSample.length).toLocaleString()} more</p>}</div>
        </div>
        <h3>Sources in this build</h3>
        <Table rows={diffOf.settings.sources.map((s) => ({ ...s }))} columns={[{ key: "name", label: "Source" }, { key: "weight", label: "Weight", className: "right" },
          { key: "domains", label: "Domains", className: "right", render: (s) => (s.domains ?? 0).toLocaleString() }]} />
      </Modal>}
    </>
  );
}

function RulesetExplain({ domain }: { domain: string }) {
  const { data, error } = useData<{ sources: { source: string; category: string; matched: string; weight: number }[]; liveScore: number; protected: boolean;
    active: { version: number; score: number; category: string } | null; blockThreshold: number; monitorThreshold: number }>("dns/ruleset/explain", { domain }, [domain]);
  if (error) return <ErrorNote error={error} />;
  if (!data) return null;
  const verdict = data.protected ? "protected" : data.liveScore >= data.blockThreshold ? "would block" : data.liveScore >= data.monitorThreshold ? "would monitor" : "not included";
  return (
    <div style={{ marginTop: 10 }}>
      <p><Pill value={verdict} tone={verdict === "would block" ? "bad" : verdict === "would monitor" ? "warn" : "muted"} /> score <b>{data.liveScore}</b> from the feeds as they are now
        {data.active ? <>; active build v{data.active.version}: <b>{data.active.score}</b> ({data.active.category})</> : "; not in the active build"}</p>
      <Table rows={data.sources.map((s, i) => ({ ...s, id: String(i) }))} empty="No source lists it."
             columns={[{ key: "source", label: "Source", render: (s) => <span className="mono small">{s.source}</span> }, { key: "category", label: "Category" },
                       { key: "matched", label: "Listed as", render: (s) => <span className="mono small">{s.matched}</span> }, { key: "weight", label: "+", className: "right" }]} />
    </div>
  );
}

function BlocklistsCard() {
  const { can } = useApp();
  const canManage = can("platform");
  const { data, reload } = useListData<any>("dns/blocklists");
  const { run, busy } = useAction();
  const [adding, setAdding] = useState<any>(null);
  const toggle = async (row: any) => {
    if (await run(() => api(`dns/blocklists/${row.id}`, { method: "PATCH", body: { enabled: !row.enabled } }), row.enabled ? "List disabled" : "List enabled")) reload();
  };
  const sync = async (row: any) => {
    const result = await run(() => api<any>(`dns/blocklists/${row.id}/sync`, { method: "POST" }));
    if (result) reload();
  };
  return (
    <div className="card">
      <h3>External blocklists</h3>
      <p className="small muted">Refreshed on a schedule by the server. Malware lists block wherever DNS protection is on; other lists block only where a policy blocks their category. Policy allow lists and allow indicators always win.</p>
      <Table rows={data ?? undefined} empty="No lists configured."
             columns={[{ key: "name", label: "List", render: (r) => <><b>{displayValue(r.name)}</b><div className="small muted">{displayValue(r.description)}</div></> },
                       { key: "category", label: "Category" },
                       { key: "enabled", label: "State", render: (r) => <Pill value={r.enabled ? "enabled" : "disabled"} /> },
                       { key: "domainCount", label: "Domains", className: "right", render: (r) => Number(r.domainCount || 0).toLocaleString() },
                       { key: "lastSuccessAt", label: "Last refresh", render: (r) => r.lastSuccessAt ? fmtTime(r.lastSuccessAt) : "never" },
                       { key: "lastError", label: "Problem", render: (r) => r.lastError ? <span className="small" style={{ color: "var(--red)" }}>{displayValue(r.lastError)}</span> : "" },
                       ...(canManage ? [{ key: "actions", label: "", render: (r: any) => <div className="row">
                         <button className="ghost" disabled={busy} onClick={() => toggle(r)}>{r.enabled ? "Disable" : "Enable"}</button>
                         <button className="ghost" disabled={busy || !r.enabled} onClick={() => sync(r)}>Refresh now</button>
                         {!r.builtin && <button className="ghost danger" disabled={busy} onClick={async () => {
                           if (await confirmDialog(`Remove the list "${r.name}"? Its domains stop being blocked.`, { confirmLabel: "Remove list" }) && await run(() => api(`dns/blocklists/${r.id}`, { method: "DELETE" }), "List removed")) reload();
                         }}>Remove</button>}</div> }] : [])]} />
      {canManage && (adding ? (
        <div className="form-grid" style={{ marginTop: 12 }}>
          <label className="field">Short id<input value={adding.id} onChange={(e) => setAdding({ ...adding, id: e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, "") })} placeholder="e.g. our-phishing-list" maxLength={40} /></label>
          <label className="field">Name<input value={adding.name} onChange={(e) => setAdding({ ...adding, name: e.target.value })} /></label>
          <label className="field">List address (https)<input value={adding.url} onChange={(e) => setAdding({ ...adding, url: e.target.value })} placeholder="https://example.org/blocklist.txt" /></label>
          <label className="field">Category<select value={adding.category} onChange={(e) => setAdding({ ...adding, category: e.target.value })}>
            {["malware", "phishing", "command-and-control", "cryptomining", "newly-registered", "parked", "dga", "adult", "gambling", "piracy", "ads-trackers", "social-media", "streaming", "games", "dating", "proxies-vpn", "doh-bypass"].map((c) => <option key={c}>{c}</option>)}</select></label>
          <div className="row"><button className="primary" disabled={busy || !adding.id || !adding.url.startsWith("https://")} onClick={async () => {
            if (await run(() => api("dns/blocklists", { body: { ...adding, name: adding.name || adding.id } }), "List added: it downloads on the next refresh")) { setAdding(null); reload(); }
          }}>Add list</button><button onClick={() => setAdding(null)}>Cancel</button></div>
        </div>) : <button style={{ marginTop: 12 }} onClick={() => setAdding({ id: "", name: "", url: "https://", category: "malware" })}>Add a list</button>)}
      <p className="small muted">Lists can be hosts files, AdBlock-style lists or one domain per line. Malware lists block wherever DNS protection is on; other categories only where a policy blocks them.</p>
    </div>
  );
}
