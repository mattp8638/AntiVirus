// Predictive analytics from device heartbeats: when each drive will fill up, and CPU or memory use far above a device's
// own normal. Shown on the device's Health tab and, across the fleet, under Monitoring.
import { Link } from "react-router-dom";
import { ago, fmtTime } from "../api";
import { displayValue } from "./DisplayValue";
import { ErrorNote, Pill, Sev, Table, useData, useListData } from "./ui";

const DISK_TONE: Record<string, string> = { exhausted: "bad", critical: "bad", warning: "warn", ok: "good", stable: "good" };
const DISK_LABEL: Record<string, string> = { exhausted: "full", critical: "full within a week", warning: "full within a month", ok: "more than a month", stable: "not growing" };

export function daysLeft(row: any): string {
  if (row.status === "exhausted") return "full now";
  if (row.daysRemaining === null || row.daysRemaining === undefined) return "not filling up";
  const days = Number(row.daysRemaining);
  return days < 1 ? "under a day" : days < 60 ? `${Math.round(days)} days` : `${Math.round(days / 30)} months`;
}

const gb = (value: number) => `${Number(value || 0).toFixed(1)} GB`;

export function anomalyText(row: any): string {
  const what = row.metric === "memory" ? "Memory" : row.metric === "cpu" ? "CPU" : String(row.metric);
  const normal = Number(row.baselineMean || 0).toFixed(0);
  return `${what} at ${Number(row.currentValue || 0).toFixed(0)}% against a normal of ${normal}%${row.isSustained ? `, for ${row.consecutiveSpikes} checks in a row` : ""}`;
}

function processes(row: any): string {
  const list = (row.topProcesses || []).slice(0, 3).map((p: any) => p.name || p.process || p.exe || "").filter(Boolean);
  return list.length ? list.join(", ") : "";
}

export function DeviceAnalytics({ deviceId }: { deviceId: string }) {
  const { data: disks, error: diskError } = useListData<any>(`rmm/devices/${deviceId}/analytics/disk-predictions`, {}, [deviceId]);
  const { data: anomalies, error: anomalyError } = useListData<any>(`rmm/devices/${deviceId}/analytics/anomalies`, {}, [deviceId]);
  return (
    <div className="grid k2" style={{ marginTop: 14 }}>
      <div className="card">
        <h3>Disk forecast</h3>
        <ErrorNote error={diskError} />
        <Table rows={disks} empty="Not enough history yet: forecasts start after a few days of heartbeats."
               columns={[{ key: "mount", label: "Drive", render: (r) => <span className="mono">{displayValue(r.mount)}</span> },
                         { key: "status", label: "Full in", render: (r) => <><b>{daysLeft(r)}</b> <Pill value={DISK_LABEL[r.status] ?? r.status} tone={DISK_TONE[r.status]} /></> },
                         { key: "used", label: "Used", render: (r) => `${gb(r.currentUsedGb)} of ${gb(r.totalGb)}` },
                         { key: "growth", label: "Growth", render: (r) => r.dailyGrowthGb > 0 ? `${gb(r.dailyGrowthGb)} a day` : "flat" },
                         { key: "confidence", label: "Confidence", render: (r) => `${Math.round(Number(r.confidenceScore || 0) * 100)}%` }]} />
        <p className="small muted">A trend line through the drive's used space; "full" means past the safety margin, not the last byte.</p>
      </div>
      <div className="card">
        <h3>Unusual resource use</h3>
        <ErrorNote error={anomalyError} />
        <Table rows={(anomalies || []).slice(0, 15)} empty="Nothing unusual: CPU and memory have stayed close to this device's normal."
               columns={[{ key: "at", label: "When", render: (r) => <span title={fmtTime(r.at)}>{ago(r.at)}</span> },
                         { key: "metric", label: "What", render: (r) => <>{anomalyText(r)}{r.isSustained && <> <Pill value="sustained" tone="warn" /></>}</> },
                         ...((anomalies || []).some((r) => processes(r)) ? [{ key: "processes", label: "Busiest", render: (r: any) => <span className="small">{displayValue(processes(r) || "—")}</span> }] : [])]} />
        <p className="small muted">Flagged when use is several standard deviations above this device's own baseline.</p>
      </div>
    </div>
  );
}

export function FleetDiskForecasts({ tenantId }: { tenantId: string }) {
  const { data, error } = useListData<any>("rmm/analytics/storage-exhaustion", { tenant_id: tenantId, status: "attention" }, [tenantId]);
  return (
    <div className="card">
      <ErrorNote error={error} />
      <Table rows={data} empty="No drive is forecast to fill up within a month."
             columns={[{ key: "hostname", label: "Device", render: (r) => <Link to={`/devices/${r.deviceId}?tab=health`}>{displayValue(r.hostname)}</Link> },
                       { key: "mount", label: "Drive", render: (r) => <span className="mono">{displayValue(r.mount)}</span> },
                       { key: "status", label: "Full in", render: (r) => <><b>{daysLeft(r)}</b> <Pill value={DISK_LABEL[r.status] ?? r.status} tone={DISK_TONE[r.status]} /></> },
                       { key: "used", label: "Used", render: (r) => `${gb(r.currentUsedGb)} of ${gb(r.totalGb)}` },
                       { key: "growth", label: "Growth", render: (r) => r.dailyGrowthGb > 0 ? `${gb(r.dailyGrowthGb)} a day` : "flat" },
                       { key: "predictedAt", label: "Forecast", render: (r) => ago(r.predictedAt) }]} />
    </div>
  );
}

export function FleetAnomalies({ tenantId }: { tenantId: string }) {
  const { data, error } = useListData<any>("rmm/analytics/resource-anomalies", { tenant_id: tenantId }, [tenantId]);
  return (
    <div className="card">
      <ErrorNote error={error} />
      <Table rows={data} empty="Nothing unusual across the fleet."
             columns={[{ key: "at", label: "When", render: (r) => <span title={fmtTime(r.at)}>{ago(r.at)}</span> },
                       { key: "hostname", label: "Device", render: (r) => <Link to={`/devices/${r.deviceId}?tab=health`}>{displayValue(r.hostname)}</Link> },
                       { key: "metric", label: "What", render: (r) => <>{anomalyText(r)}{r.isSustained && <> <Pill value="sustained" tone="warn" /></>}</> },
                       ...((data || []).some((r) => processes(r)) ? [{ key: "processes", label: "Busiest", render: (r: any) => <span className="small">{displayValue(processes(r) || "—")}</span> }] : [])]} />
    </div>
  );
}

export function MonitorHistory({ tenantId }: { tenantId: string }) {
  const { data, error } = useData<any[]>("rmm/alerts", { tenant_id: tenantId }, [tenantId]);
  return (
    <div className="card">
      <ErrorNote error={error} />
      <Table rows={data} empty="No monitoring alerts yet."
             columns={[{ key: "severity", label: "Sev", render: (r) => <Sev level={r.severity} /> },
                       { key: "title", label: "Alert", render: (r) => <Link to={`/alerts?id=${r.id}`}>{displayValue(r.title)}</Link> },
                       { key: "hostname", label: "Device", render: (r) => r.deviceId ? <Link to={`/devices/${r.deviceId}`}>{displayValue(r.hostname || r.deviceId)}</Link> : "—" },
                       { key: "status", label: "Status", render: (r) => <Pill value={r.status} /> },
                       { key: "createdAt", label: "Raised", render: (r) => <span title={fmtTime(r.createdAt)}>{ago(r.createdAt)}</span> }]} />
    </div>
  );
}
