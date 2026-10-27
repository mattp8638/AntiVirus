import { Fragment } from "react";
import { ago, fmtTime } from "../api";
import { useApp } from "../app-context";
import { Pill, Sev, useData } from "../components/ui";
import { TimeChart } from "../components/TimeChart";
import { RiskBreakdown } from "../components/Vuln";

// The device landing page: what needs attention first, then the last 24 hours, recent activity and the
// facts a technician asks for on the phone (who is signed in, model, serial, Windows build, storage).

const OPEN_ALERT = (a: any) => !["resolved", "closed", "false_positive"].includes(a.status);
const days = (seconds?: number) => seconds ? `${(seconds / 86400).toFixed(seconds < 864000 ? 1 : 0)} days` : "—";

// "HP" + "HP EliteBook 840" reads as "HP EliteBook 840", not "HP HP EliteBook 840".
export const makeModel = (make?: string, model?: string) =>
  !model ? (make || "—") : make && !model.toLowerCase().startsWith(make.toLowerCase().split(" ")[0]) ? `${make} ${model}` : model;

// Friendly names for command types ("process.tree.terminate" -> "Kill process tree").
export function useCommandLabels() {
  const { data } = useData<any[]>("commands/catalog");
  return (type: string) => data?.find((c) => c.type === type)?.label ?? type;
}

export interface GoTo { (section: string, sub?: string): void }

export function DeviceOverview({ data, profile, patches, go, management, whereabouts }: { data: any; profile: any; patches: any; go: GoTo; management: React.ReactNode; whereabouts?: any }) {
  const d = data.device;
  const isPhone = d.platform === "android";
  const { can } = useApp();
  const { data: metrics } = useData<any>(isPhone ? null : `rmm/devices/${d.id}/metrics`, { hours: 24 });
  const commandLabel = useCommandLabels();
  const p = profile?.profile || {};
  const hw = p.hardware || {}, os = p.os || {};
  const m = d.metrics || {};
  const openAlerts = (data.alerts || []).filter(OPEN_ALERT);
  const pendingPatches = (patches?.patches || []).filter((x: any) => x.status !== "installed");
  const series = metrics?.series || [];

  // Everything worth a technician's attention, worst first.
  const attention: { severity: string; title: string; detail?: string; action?: () => void; actionLabel?: string }[] = [];
  if (!d.approved) attention.push({ severity: "high", title: "Waiting for approval", detail: "Approve the device to manage it." });
  if (d.isolated) attention.push({ severity: "high", title: "Isolated from the network", detail: "Only Fenrir can reach it until released." });
  if (!d.online && d.lastSeenAt) attention.push({ severity: "medium", title: `Offline since ${fmtTime(d.lastSeenAt)}`, detail: "Commands queue until it checks in." });
  if (openAlerts.length) {
    const worst = ["critical", "high", "medium", "low"].find((s) => openAlerts.some((a: any) => a.severity === s)) || "low";
    attention.push({ severity: worst === "low" ? "medium" : worst, title: `${openAlerts.length} open alert${openAlerts.length === 1 ? "" : "s"}`,
                     detail: openAlerts.slice(0, 2).map((a: any) => a.title).join(" · "), action: () => go("security", "Alerts"), actionLabel: "Review" });
  }
  const openVulns = (data.vulnerabilities || []).filter((v: any) => ["open", "patching"].includes(v.status));
  if (openVulns.length) {
    const kev = openVulns.filter((v: any) => v.knownExploited);
    const worst = openVulns[0];
    attention.push({ severity: kev.length ? "critical" : worst.riskScore >= 7 ? "high" : "medium",
                     title: kev.length ? `${kev.length} vulnerabilit${kev.length === 1 ? "y" : "ies"} exploited in the wild` : `${openVulns.length} open vulnerabilit${openVulns.length === 1 ? "y" : "ies"}`,
                     detail: `Worst: ${worst.vulnId} in ${worst.package}${worst.fix?.ref ? `, fixed by ${worst.fix.ref}` : ""}`,
                     action: () => go("security", "Vulnerabilities"), actionLabel: "Fix" });
  }
  if (!data.policy.applied) attention.push({ severity: "low", title: "Policy change not applied yet", detail: "The agent picks it up at its next check-in." });
  if (pendingPatches.length) attention.push({ severity: pendingPatches.some((x: any) => ["critical", "security"].includes(x.classification)) ? "medium" : "low",
                                              title: `${pendingPatches.length} patch${pendingPatches.length === 1 ? "" : "es"} not installed`, action: () => go("software", "Patches"), actionLabel: "Patches" });
  if (m.rebootPending && !(profile?.findings || []).some((f: any) => /restart is pending/i.test(f.title))) attention.push({ severity: "low", title: "A restart is pending" });
  const findingTitles = (profile?.findings || []).map((f: any) => f.title).join(" ");
  const lowDisk = (m.disks || []).filter((x: any) => typeof x.freePercent === "number" && x.freePercent < 15);
  for (const x of lowDisk) if (!findingTitles.includes(`${x.mount} is`)) attention.push({ severity: x.freePercent < 5 ? "high" : "medium",
    title: `${x.mount} is ${x.freePercent < 5 ? "nearly full" : "running low on space"}`, detail: `${Number(x.freeGb).toFixed(1)} GB free (${Math.round(x.freePercent)}%)`, action: () => go("system"), actionLabel: "Details" });
  if (m.uptimeSeconds > 30 * 86400 && !/Not restarted/.test(findingTitles)) attention.push({ severity: "medium", title: `Not restarted for ${Math.floor(m.uptimeSeconds / 86400)} days`, detail: "Updates may be waiting on a restart." });
  if (isPhone) {
    const lost = whereabouts?.lostMode;
    if (lost?.enabled) attention.push({ severity: "high", title: "Lost mode is on", detail: lost.message, action: () => go("location"), actionLabel: "Map" });
    if (m.screenLockSecure === false) attention.push({ severity: "high", title: "No screen lock", detail: "Anyone who picks the phone up can use it. Set a PIN, pattern or password." });
    if (m.rooted) attention.push({ severity: "high", title: "The phone is rooted", detail: "Apps can bypass Android's protections." });
    if (m.encrypted === false) attention.push({ severity: "high", title: "Storage is not encrypted" });
    if (m.deviceAdmin === false) attention.push({ severity: "medium", title: "Fenrir is not a device administrator", detail: "Lock and erase won't work until it is turned back on in the Fenrir app." });
    if (m.locationEnabled === false) attention.push({ severity: "medium", title: "Location is turned off on the phone", detail: "It can't be found on the map." });
    if (typeof m.batteryPercent === "number" && m.batteryPercent < 15 && !m.charging) attention.push({ severity: "low", title: `Battery at ${m.batteryPercent}%` });
    if (m.developerMode) attention.push({ severity: "low", title: "Developer options are on" });
    if (m.securityPatch && Date.now() - new Date(m.securityPatch).getTime() > 120 * 86400e3) attention.push({ severity: "medium", title: `Security patch from ${m.securityPatch}`, detail: "More than four months old; check for a system update." });
    if (!whereabouts?.latest && whereabouts) attention.push({ severity: "low", title: "No location reported yet", action: () => go("location"), actionLabel: "Locate" });
  }
  for (const f of profile?.findings || []) attention.push({ severity: f.severity, title: f.title, detail: f.detail, action: () => go("system"), actionLabel: "Details" });
  const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  attention.sort((a, b) => (order[a.severity] ?? 4) - (order[b.severity] ?? 4));

  // Recent activity: alerts and remote actions on one timeline.
  const activity = [
    ...(data.alerts || []).map((a: any) => ({ at: a.createdAt, kind: "alert", text: a.title, tone: a.severity, status: a.status })),
    ...(data.commands || []).map((c: any) => ({ at: c.createdAt, kind: "action", text: `${commandLabel(c.type)}${c.issuedBy ? ` by ${c.issuedBy}` : ""}`, tone: "", status: c.status })),
  ].sort((a, b) => String(b.at).localeCompare(String(a.at))).slice(0, 10);

  const volumes: any[] = (p.volumes && p.volumes.length ? p.volumes : (m.disks || []).map((x: any) => ({ mount: x.mount, sizeGb: x.totalGb, freeGb: x.freeGb })));

  return (
    <div className="grid side">
      <div className="stack">
        <div className="card">
          <div className="row" style={{ marginBottom: 8 }}>
            <h3 style={{ margin: 0 }}>Needs attention</h3>
            <span style={{ flex: 1 }} />
            {profile?.collectedAt && <span className="small muted">System checks from {ago(profile.collectedAt)}</span>}
          </div>
          {attention.length === 0 ? <div className="all-good"><span className="dot on" /> Nothing needs attention on this device.</div> :
            <div className="attention">
              {attention.slice(0, 8).map((item, i) => (
                <div key={i} className={`attention-item sev-edge-${item.severity}`}>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div><b>{item.title}</b></div>
                    {item.detail && <div className="small muted ellipsis">{item.detail}</div>}
                  </div>
                  {item.action && <button className="small" onClick={item.action}>{item.actionLabel}</button>}
                </div>))}
              {attention.length > 8 && <button className="ghost small" onClick={() => go("system")}>+{attention.length - 8} more on the System tab</button>}
            </div>}
        </div>

        {isPhone && <div className="card">
          <div className="row" style={{ marginBottom: 6 }}>
            <h3 style={{ margin: 0 }}>Where it is</h3>
            <span style={{ flex: 1 }} />
            <button className="ghost small" onClick={() => go("location")}>Open map →</button>
          </div>
          {!whereabouts?.latest ? <p className="muted small">No location yet. Use Locate to ask the phone where it is.</p> : <p style={{ margin: 0 }}>
            Last located <b>{ago(whereabouts.latest.at)}</b>{whereabouts.latest.accuracy ? ` to within ${Math.round(whereabouts.latest.accuracy)} m` : ""}
            <span className="muted small"> · {whereabouts.latest.lat.toFixed(4)}, {whereabouts.latest.lon.toFixed(4)}</span>
            {whereabouts.travelledMeters > 0 && <span className="muted small"> · moved {(whereabouts.travelledMeters / 1000).toFixed(1)} km today</span>}
          </p>}
        </div>}

        {!isPhone && <div className="card">
          <div className="row" style={{ marginBottom: 6 }}>
            <h3 style={{ margin: 0 }}>Last 24 hours</h3>
            <span style={{ flex: 1 }} />
            <button className="ghost small" onClick={() => go("health")}>Open Health →</button>
          </div>
          {!metrics ? <div className="muted small">Loading…</div> :
            <TimeChart height={130} times={series.map((x: any) => x.at)} series={[
              { label: "CPU", color: "#38bdf8", values: series.map((x: any) => x.cpu) },
              { label: "Memory", color: "#a855f7", values: series.map((x: any) => x.memory) },
            ]} />}
        </div>}

        <div className="card">
          <div className="row" style={{ marginBottom: 6 }}>
            <h3 style={{ margin: 0 }}>Recent activity</h3>
            <span style={{ flex: 1 }} />
            <button className="ghost small" onClick={() => go("activity", "Remote actions")}>All actions →</button>
          </div>
          {activity.length === 0 ? <p className="muted small">No alerts or remote actions yet.</p> :
            <div className="activity">
              {activity.map((a, i) => (
                <div key={i} className="activity-item">
                  <span className={`activity-dot ${a.kind === "alert" ? `sev-dot-${a.tone}` : ""}`} />
                  <span className="small muted activity-when" title={fmtTime(a.at)}>{ago(a.at)}</span>
                  <span className="ellipsis" style={{ flex: 1 }}>{a.kind === "alert" ? <Sev level={a.tone} /> : <span className="chip">action</span>} {a.text}</span>
                  <Pill value={a.status} />
                </div>))}
            </div>}
        </div>
      </div>

      <div className="stack">
        {data.risk && <div className="card">
          <h3>Risk score</h3>
          <RiskBreakdown risk={data.risk} onOpenVulns={() => go("security", "Vulnerabilities")} />
        </div>}
        <div className="card">
          <h3>At a glance</h3>
          <dl className="kv compact">
            {!isPhone && <><dt>Signed in</dt><dd>{m.loggedOnUser || d.inventory?.loggedOnUser || "nobody"}</dd></>}
            {isPhone && m.phoneNumber && <><dt>Number</dt><dd>{m.phoneNumber}</dd></>}
            {isPhone && <><dt>Battery</dt><dd>{typeof m.batteryPercent === "number" ? `${m.batteryPercent}%${m.charging ? " · charging" : ""}` : "—"}</dd></>}
            {isPhone && m.network && <><dt>Network</dt><dd>{m.network}{m.wifiSsid ? ` · ${m.wifiSsid}` : ""}{m.carrier ? ` · ${m.carrier}` : ""}</dd></>}
            {isPhone && m.securityPatch && <><dt>Security patch</dt><dd>{m.securityPatch}</dd></>}
            <dt>Model</dt><dd>{makeModel(hw.manufacturer || m.manufacturer, hw.model || m.model)}{hw.chassis ? <span className="muted"> · {hw.chassis}</span> : null}</dd>
            <dt>Serial</dt><dd className="mono">{hw.serial || d.serialNumber || "—"}</dd>
            <dt>OS</dt><dd>{os.name ? <>{os.name}{os.displayVersion ? ` ${os.displayVersion}` : ""} <span className="muted small">build {os.build || os.version}</span></> : d.osVersion}</dd>
            {hw.cpu?.name && <><dt>Processor</dt><dd className="small">{hw.cpu.name}</dd></>}
            {(hw.memory?.totalGb || m.memoryTotalGb) && <><dt>Memory</dt><dd>{Math.round(hw.memory?.totalGb || m.memoryTotalGb)} GB</dd></>}
            <dt>IP address</dt><dd className="mono">{d.ipAddress || "—"}</dd>
            {os.joinType && <><dt>Joined to</dt><dd>{[os.joinType, os.domain].filter(Boolean).join(" · ")}</dd></>}
            <dt>Up for</dt><dd>{days(m.uptimeSeconds)}{m.lastBootAt ? <span className="muted small"> since {fmtTime(m.lastBootAt)}</span> : null}</dd>
            <dt>Agent</dt><dd>{d.agentVersion || "—"}</dd>
          </dl>
          {!isPhone && <button className="small" style={{ marginTop: 10 }} onClick={() => go("system")}>Full system profile →</button>}
        </div>

        <div className="card">
          <h3>Storage</h3>
          {volumes.length === 0 ? <p className="muted small">No disk information yet.</p> : volumes.map((v) => {
            const free = Number(v.freeGb) || 0, size = Number(v.sizeGb) || 0;
            const usedPct = size ? Math.round(100 * (size - free) / size) : 0;
            const freePct = 100 - usedPct;
            const enc = v.encryption;
            const encrypted = enc && /on|encrypted/i.test(`${enc.protection} ${enc.status}`) && !/^off$/i.test(String(enc.protection ?? ""));
            return (
              <div key={v.mount} style={{ marginBottom: 10 }}>
                <div className="row small" style={{ gap: 6 }}>
                  <b>{v.mount}</b>{v.label && <span className="muted">{v.label}</span>}
                  {enc && <Pill value={encrypted ? "BitLocker on" : "not encrypted"} tone={encrypted ? "good" : "warn"} />}
                  <span style={{ flex: 1 }} />
                  <span className="muted">{free.toFixed(free < 10 ? 1 : 0)} GB free of {Math.round(size)} GB</span>
                </div>
                <div className="bar" style={{ marginTop: 4 }}><span style={{ width: `${usedPct}%`, background: freePct < 5 ? "var(--red)" : freePct < 15 ? "var(--amber)" : undefined }} /></div>
              </div>);
          })}
        </div>

        <div className="card">
          <h3>Management</h3>
          {management}
          {can("read") && <p className="small muted" style={{ marginTop: 10, marginBottom: 0 }}>
            Policy revision <span className="mono">{String(data.policy.revision).slice(0, 10)}</span> · {data.policy.applied ? <Pill value="applied" tone="good" /> : <Pill value="waiting for agent" tone="warn" />}
            {" "}<button className="ghost small" onClick={() => go("settings", "Effective policy")}>Effective policy →</button>
          </p>}
          {data.policy.overridesBlocked.length > 0 && <p className="small">{data.policy.overridesBlocked.length} override(s) blocked by locks.</p>}
        </div>
      </div>
    </div>
  );
}

export function DeviceDetails({ data }: { data: any }) {
  const d = data.device;
  const copy = (text: string) => navigator.clipboard?.writeText(text);
  return (
    <dl className="kv">
      <dt>Device ID</dt><dd className="mono">{d.id} <button className="ghost small" onClick={() => copy(d.id)}>Copy</button></dd>
      <dt>Platform</dt><dd>{d.platform}</dd>
      <dt>Agent</dt><dd>{d.agentVersion || "—"} (platform {d.platformVersion || "—"})</dd>
      <dt>Health</dt><dd><Pill value={d.healthState} tone={d.healthState === "healthy" ? "good" : "warn"} /></dd>
      <dt>Risk score</dt><dd>{d.riskScore} <span className="small muted">— from open alerts in the last 7 days and open critical/high vulnerabilities</span></dd>
      <dt>Approved</dt><dd>{d.approved ? "Yes" : <Pill value="waiting" tone="warn" />}</dd>
      <dt>Enrolled</dt><dd>{fmtTime(d.enrolledAt)}</dd>
      <dt>Last check-in</dt><dd>{fmtTime(d.lastSeenAt)} ({ago(d.lastSeenAt)})</dd>
      <dt>Events stored</dt><dd>{data.eventCount}</dd>
      <dt>Encrypted DNS</dt><dd className="mono small">{data.dnsOverHttpsUrl} <button className="ghost small" onClick={() => copy(data.dnsOverHttpsUrl)}>Copy</button></dd>
      {Object.entries(d.inventory || {}).filter(([, v]) => v !== null && v !== "" && typeof v !== "object").map(([k, v]) =>
        <Fragment key={k}><dt>{k.replace(/([A-Z])/g, " $1").replace(/^./, (s) => s.toUpperCase())}</dt><dd>{String(v)}</dd></Fragment>)}
    </dl>
  );
}
