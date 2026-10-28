import { displayValue } from "../components/DisplayValue";
import { useNavigate } from "react-router-dom";
import { ago } from "../api";
import { useApp } from "../app-context";
import { ErrorNote, PageHead, Pill, Stat, Table, useData } from "../components/ui";

const TONE: Record<string, string> = { protected: "good", outdated: "warn", stale: "warn", unprotected: "bad" };

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
      <div className="card" style={{ marginTop: 14 }}>
        <Table rows={data?.devices.map((d: any) => ({ ...d, id: d.deviceId }))} onRow={(d) => navigate(`/devices/${d.deviceId}`)} empty="No approved devices in scope."
               columns={[{ key: "status", label: "Status", render: (d) => <Pill value={d.status} tone={TONE[d.status]} /> },
                         { key: "hostname", label: "Device", render: (d) => <><b>{displayValue(d.hostname)}</b><div className="small muted">{tenantName(d.tenantId)} · {displayValue(d.platform)}</div></> },
                         { key: "healthState", label: "Agent health", render: (d) => <>{displayValue(d.healthState)}{d.isolated && <> <Pill value="isolated" tone="blue" /></>}</> },
                         { key: "agentVersion", label: "Agent", render: (d) => <>{displayValue(d.agentVersion || "—")}{d.outdated && <div className="small muted">latest {displayValue(d.latestAgentVersion)}</div>}</> },
                         { key: "lastSeenAt", label: "Last seen", render: (d) => <span style={{ color: d.stale ? "#fca5a5" : undefined }}>{ago(d.lastSeenAt)}</span> },
                         { key: "lastScanAt", label: "Last scan", render: (d) => <span style={{ color: d.noRecentScan ? "#fcd34d" : undefined }}>{ago(d.lastScanAt)}</span> },
                         { key: "detections30d", label: "Detections (30d)", className: "right" },
                         { key: "quarantined30d", label: "Quarantined (30d)", className: "right" }]} />
      </div>
    </>
  );
}
