import { displayValue } from "../components/DisplayValue";
import { useNavigate } from "react-router-dom";
import { ago } from "../api";
import { useApp } from "../app-context";
import { ErrorNote, PageHead, Pill, Stat, Table, useData } from "../components/ui";
import { DefenderFleet } from "../components/Defender";

const TONE: Record<string, string> = { protected: "good", outdated: "warn", stale: "warn", unprotected: "bad" };
// What blocks a program before it runs on Windows (Fenrir ships no kernel driver; Microsoft Defender does this).
const PRE: Record<string, [string, string, string]> = {
  defender: ["Defender", "good", "Microsoft Defender's real-time protection is on and blocks malicious programs before they run."],
  none: ["None", "bad", "Microsoft Defender is off, passive or has real-time protection off. Fenrir still stops threats just after they start."],
  unknown: ["Checking", "muted", "Fenrir has not read Microsoft Defender's state on this device yet (it checks every six hours)."],
};

export default function ProtectionHealth() {
  const { tenantId, tenantName } = useApp();
  const navigate = useNavigate();
  const { data, error } = useData<any>("protection/health", { tenant_id: tenantId });
  const t = data?.totals;
  return (
    <>
      <PageHead title="Protection health" subtitle="Whether every endpoint is protected, on the current agent, scanning and reporting in. Devices that report degraded protection raise an alert automatically. To test detection safely, run the built-in “Validate real-time protection (EICAR test)” script." />
      <ErrorNote error={error} />
      <div className="grid k4">
        <Stat label="Protected" value={t ? `${t.protected}/${t.devices}` : "—"} accent="green" />
        <Stat label="Unprotected (agent reports a problem)" value={t?.unprotected ?? "—"} accent={t?.unprotected ? "red" : "green"} />
        <Stat label="Not reporting for 7+ days" value={t?.stale ?? "—"} accent={t?.stale ? "red" : undefined} />
        <Stat label="Agent out of date" value={t?.outdated ?? "—"} hint={t ? `${t.noRecentScan} with no scan in 7 days` : undefined} />
      </div>
      {(t?.preExecution?.none ?? 0) > 0 && <div className="card warn-card" style={{ marginTop: 14 }}>
        <b>{t.preExecution.none} Windows {t.preExecution.none === 1 ? "device has" : "devices have"} nothing blocking programs before they run.</b>
        <p className="small" style={{ marginBottom: 0 }}>Fenrir's Windows agent stops threats just after they start. Blocking beforehand comes from Microsoft Defender's
          real-time protection, which is off on {t.preExecution.none === 1 ? "this device" : "these devices"}. Turn on <b>Manage Microsoft Defender</b> in
          Policies to keep it on, or check what is holding it off (another antivirus, Group Policy or tamper protection).</p>
      </div>}
      <div className="card" style={{ marginTop: 14 }}>
        <Table rows={data?.devices.map((d: any) => ({ ...d, id: d.deviceId }))} onRow={(d) => navigate(`/devices/${d.deviceId}`)} empty="No approved devices in scope."
               columns={[{ key: "status", label: "Status", render: (d) => <Pill value={d.status} tone={TONE[d.status]} /> },
                         { key: "hostname", label: "Device", render: (d) => <><b>{displayValue(d.hostname)}</b><div className="small muted">{tenantName(d.tenantId)} · {displayValue(d.platform)}</div></> },
                         { key: "healthState", label: "Agent health", render: (d) => <>{displayValue(d.healthState)}{d.isolated && <> <Pill value="isolated" tone="blue" /></>}</> },
                         { key: "preExecution", label: "Blocks before it runs", render: (d) => d.preExecution ? <span title={PRE[d.preExecution]?.[2]}><Pill value={PRE[d.preExecution]?.[0] ?? d.preExecution} tone={PRE[d.preExecution]?.[1]} /></span> : <span className="muted">—</span> },
                         { key: "agentVersion", label: "Agent", render: (d) => <>{displayValue(d.agentVersion || "—")}{d.outdated && <div className="small muted">latest {displayValue(d.latestAgentVersion)}</div>}</> },
                         { key: "lastSeenAt", label: "Last seen", render: (d) => <span style={{ color: d.stale ? "#fca5a5" : undefined }}>{ago(d.lastSeenAt)}</span> },
                         { key: "lastScanAt", label: "Last scan", render: (d) => <span style={{ color: d.noRecentScan ? "#fcd34d" : undefined }}>{ago(d.lastScanAt)}</span> },
                         { key: "detections30d", label: "Detections (30d)", className: "right" },
                         { key: "quarantined30d", label: "Quarantined (30d)", className: "right" }]} />
      </div>
      <DefenderFleet />
    </>
  );
}
