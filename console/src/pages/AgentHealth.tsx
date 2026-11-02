import { displayValue } from "../components/DisplayValue";
import { Fragment, useState } from "react";
import { Link } from "react-router-dom";
import { ago } from "../api";
import { useApp } from "../app-context";
import { ErrorNote, PageHead, Pill, Stat, useData } from "../components/ui";

// What each reporting component is, in words a technician recognises.
const COMPONENTS: Record<string, string> = {
  "inventory.profile": "System profile (inventory, Active Directory snapshot)",
  "agent.update": "Agent self-update",
  "agent.repair": "Agent self-repair",
  "agent.cycle": "Agent main loop",
  "command.poll": "Fetching commands",
  "command": "Running a command",
  "device.heartbeat": "Check-in",
  "device.identity": "Device identity",
  "ad.monitor": "Active Directory event monitor",
  "ad.ntlm": "NTLM audit",
  "ransomware.shield": "Ransomware shield",
  "ransomware.snapshot": "Ransomware snapshots",
  "ransomware.restore": "Ransomware restore",
  "realtime.broker": "Real-time scanning",
  "process.etw": "Process monitoring (ETW)",
  "network.wfp": "Network filter (WFP)",
  "tamper.protection": "Tamper protection",
  "tamper.policy": "Tamper policy",
  "signatures.delta": "Signature updates",
  "update.sync": "Windows Update scan",
  "update.apply": "Windows Update install",
  "patch": "Patching",
  "scan.scheduled": "Scheduled scan",
  "vulnerability.assessment": "Vulnerability assessment",
  "laps.rotation": "Local admin password rotation",
  "localadmin.reduce": "Local admin removal",
  "auth.bruteforce": "Brute-force protection",
  "credential.hardening": "Credential hardening",
};

export default function AgentHealth() {
  const { tenantId, tenantName, can } = useApp();
  const { data, error } = useData<any>("agent-health", { tenant_id: tenantId });
  const [filter, setFilter] = useState<"problems" | "outdated" | "all">("problems");
  const [open, setOpen] = useState<string | null>(null);
  const t = data?.totals;
  const rows = (data?.devices || []).filter((d: any) =>
    filter === "all" ? true : filter === "outdated" ? d.onCurrentBuild === false : d.openProblems > 0 || d.failedCommands.length > 0 || d.onCurrentBuild === false);
  return (
    <>
      <PageHead title="Agent health" subtitle="Whether each agent is on the current build (and why not), and what it reported failing in the last 7 days: profile collection, updates, commands, protection components and monitors. A problem clears when the same component reports success." />
      <ErrorNote error={error} />
      {(data?.stalledRollouts || []).map((r: any) => (
        <div key={r.id} className="card warn-card" style={{ marginBottom: 14 }}>
          <b>Agent updates for {displayValue(r.platform)} are {displayValue(r.state)}: no device gets build {displayValue(r.version || r.build)} until it is resumed.</b>
          <div className="small" style={{ marginTop: 4 }}>{displayValue(r.reason)}</div>
          {can("platform") && <div className="small" style={{ marginTop: 6 }}><Link to="/settings">Review and resume it in Settings › Agent releases</Link></div>}
        </div>
      ))}
      <div className="grid k4" style={{ marginBottom: 14 }}>
        <Stat label="Agents" value={t ? `${t.online}/${t.devices} online` : "—"} />
        <Stat label="On the current build" value={t ? `${t.current}/${t.devices}` : "—"} accent={t && t.outdated ? "#fcd34d" : "green"} hint={t?.outdated ? `${t.outdated} out of date` : undefined} />
        <Stat label="Reporting a problem" value={t?.withProblems ?? "—"} accent={t?.withProblems ? "#f87171" : "green"} />
        <Stat label="Server builds" value={data ? Object.entries(data.builds).filter(([, b]) => b).map(([p, b]) => `${p} ${String(b).slice(0, 8)}`).join(" · ") || "none" : "—"} />
      </div>
      <div className="row" style={{ gap: 6, marginBottom: 10 }}>
        {(["problems", "outdated", "all"] as const).map((f) => (
          <button key={f} className={filter === f ? "primary small" : "small"} onClick={() => setFilter(f)}>
            {f === "problems" ? "Needs attention" : f === "outdated" ? "Out of date" : "All agents"}
          </button>
        ))}
      </div>
      <div className="card">
        {data && rows.length === 0 && <p className="muted">{filter === "problems" ? "Every agent is on the current build and reported nothing failing in the last 7 days." : "No agents match."}</p>}
        {!data && !error && <p className="muted">Loading…</p>}
        {rows.length > 0 && (
          <div className="table-wrap"><table>
            <thead><tr><th>Device</th><th>Agent</th><th>Update</th><th>Problems (7 days)</th><th>Last seen</th></tr></thead>
            <tbody>
              {rows.map((d: any) => (
                <Fragment key={d.deviceId}>
                  <tr onClick={() => setOpen(open === d.deviceId ? null : d.deviceId)} style={{ cursor: "pointer" }}>
                    <td><Link to={`/devices/${d.deviceId}`} onClick={(e) => e.stopPropagation()}><b>{displayValue(d.hostname)}</b></Link>
                      <div className="small muted">{tenantName(d.tenantId)} · {displayValue(d.platform)} · {d.online ? "online" : "offline"}</div></td>
                    <td>{displayValue(d.agentVersion || "—")}<div className="small muted mono">{d.agentBuild ? String(d.agentBuild).slice(0, 8) : "no build reported"}</div></td>
                    <td>{d.onCurrentBuild === true ? <Pill value="current" tone="good" /> : d.onCurrentBuild === false
                      ? <><Pill value="out of date" tone="warn" /><div className="small">{displayValue(d.update)}</div></> : <span className="muted small">server ships no build to compare</span>}</td>
                    <td>{d.openProblems > 0 ? <Pill value={`${d.openProblems} open`} tone="bad" /> : <span className="muted small">none open</span>}
                      {d.failedCommands.length > 0 && <div className="small">{d.failedCommands.length} failed command(s)</div>}</td>
                    <td>{ago(d.lastSeenAt)}</td>
                  </tr>
                  {open === d.deviceId && (
                    <tr><td colSpan={5}>
                      {d.problems.length === 0 && d.failedCommands.length === 0 && <p className="muted small">Nothing reported failing in the last 7 days.</p>}
                      {d.problems.map((p: any) => (
                        <div key={p.component} className="small" style={{ padding: "4px 0", opacity: p.resolved ? 0.6 : 1 }}>
                          <Pill value={p.resolved ? "recovered" : "open"} tone={p.resolved ? "good" : "bad"} />{" "}
                          <b>{COMPONENTS[p.component] || displayValue(p.component)}</b>: {displayValue(p.error || p.summary)}
                          <span className="muted"> · {p.count}× · last {ago(p.at)} · {displayValue(p.type)}</span>
                        </div>
                      ))}
                      {d.failedCommands.map((c: any) => (
                        <div key={c.id} className="small" style={{ padding: "4px 0" }}>
                          <Pill value="command failed" tone="warn" /> <b className="mono">{displayValue(c.type)}</b>: {displayValue(c.error || "no reason given")}
                          <span className="muted"> · {ago(c.at)}</span>
                        </div>
                      ))}
                    </td></tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table></div>
        )}
      </div>
    </>
  );
}
