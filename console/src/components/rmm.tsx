import { displayValue } from "./DisplayValue";
// Shared RMM widgets: device/group/customer target picker, remote "Connect" buttons, job output and a sparkline.
import { useEffect, useMemo, useState } from "react";
import { api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { Modal, Pill, useAction, useData, useListData } from "./ui";

export interface Targets {
  deviceIds: string[];
  groupIds: string[];
  tenantIds: string[];
  platforms: string[];
}

export const emptyTargets = (): Targets => ({ deviceIds: [], groupIds: [], tenantIds: [], platforms: [] });

export function describeTargets(t: Targets | undefined, tenantName: (id?: string | null) => string): string {
  if (!t) return "—";
  const parts: string[] = [];
  if (t.tenantIds?.length) parts.push(t.tenantIds.map((id) => tenantName(id)).join(", "));
  if (t.groupIds?.length) parts.push(`${t.groupIds.length} group(s)`);
  if (t.deviceIds?.length) parts.push(`${t.deviceIds.length} device(s)`);
  if (t.platforms?.length) parts.push(`(${t.platforms.join("/")} only)`);
  return parts.join(" + ") || "—";
}

/** Pick devices, groups or whole customers. Used by scripts, deployments, patching and schedules. */
export function TargetPicker({ value, onChange, platforms }: { value: Targets; onChange: (t: Targets) => void; platforms?: string[] }) {
  const { me, tenantId } = useApp();
  const [mode, setMode] = useState<"devices" | "groups" | "tenants">(value.tenantIds.length ? "tenants" : value.groupIds.length ? "groups" : "devices");
  const [q, setQ] = useState("");
  const { data: devices } = useListData<any>("devices", { tenant_id: tenantId, q });
  const { data: groups } = useListData<any>("groups", { tenant_id: tenantId });
  const toggle = (key: keyof Targets, id: string) => {
    const set = new Set(value[key]);
    if (set.has(id)) set.delete(id); else set.add(id);
    onChange({ ...value, [key]: [...set] });
  };
  const visible = (devices || []).filter((d) => d.approved && (!platforms?.length || platforms.includes(d.platform)));
  return (
    <div className="card" style={{ padding: 12 }}>
      <div className="row" style={{ marginBottom: 8 }}>
        {(["devices", "groups", "tenants"] as const).map((m) => (
          <button key={m} className={mode === m ? "primary small" : "small"} onClick={() => setMode(m)}>
            {m === "tenants" ? "Customers" : m[0].toUpperCase() + m.slice(1)}
            {value[m === "devices" ? "deviceIds" : m === "groups" ? "groupIds" : "tenantIds"].length > 0 &&
              ` (${value[m === "devices" ? "deviceIds" : m === "groups" ? "groupIds" : "tenantIds"].length})`}
          </button>
        ))}
        <span style={{ flex: 1 }} />
        {(["windows", "linux", "macos"]).map((p) => (
          <label key={p} className="small"><input type="checkbox" checked={value.platforms.includes(p)} onChange={() => toggle("platforms", p)} /> {p}</label>
        ))}
      </div>
      {mode === "devices" && <>
        <input placeholder="Search devices" value={q} onChange={(e) => setQ(e.target.value)} style={{ width: "100%", marginBottom: 6 }} />
        <div style={{ maxHeight: 220, overflow: "auto" }}>
          {visible.map((d) => (
            <label key={d.id} className="row small" style={{ padding: "3px 0" }}>
              <input type="checkbox" checked={value.deviceIds.includes(d.id)} onChange={() => toggle("deviceIds", d.id)} />
              <span className={`dot ${d.online ? "on" : "off"}`} /> {displayValue(d.hostname)} <span className="muted">{displayValue(d.platform)}</span>
            </label>
          ))}
          {!visible.length && <div className="muted small">No matching devices.</div>}
        </div>
      </>}
      {mode === "groups" && (
        <div style={{ maxHeight: 220, overflow: "auto" }}>
          {(groups || []).map((g) => (
            <label key={g.id} className="row small" style={{ padding: "3px 0" }}>
              <input type="checkbox" checked={value.groupIds.includes(g.id)} onChange={() => toggle("groupIds", g.id)} /> {displayValue(g.name)}
            </label>
          ))}
          {!groups?.length && <div className="muted small">No device groups yet.</div>}
        </div>
      )}
      {mode === "tenants" && (
        <div style={{ maxHeight: 220, overflow: "auto" }}>
          {me?.tenants.filter((t) => t.kind !== "unassigned").map((t) => (
            <label key={t.id} className="row small" style={{ padding: "3px 0" }}>
              <input type="checkbox" checked={value.tenantIds.includes(t.id)} onChange={() => toggle("tenantIds", t.id)} /> {t.name}
            </label>
          ))}
        </div>
      )}
    </div>
  );
}

/** Start a remote session and open the pop-out viewer. */
export function useConnect() {
  const { run, busy } = useAction();
  const connect = async (deviceId: string, mode: "desktop" | "terminal" | "files" = "desktop", ticketId?: string) => {
    // Open the window first so pop-up blockers treat it as a direct click. It starts on an in-app page
    // (not about:blank) so an installed console opens it as an app window without browser bars.
    const width = Math.min(window.screen.availWidth, 1440);
    const height = Math.min(window.screen.availHeight, 900);
    const placeholder = window.open("/remote/starting", "_blank", `popup,width=${width},height=${height}`);
    const session = await run(() => api<any>("remote/sessions", { body: { deviceId, mode, ticketId } }));
    if (!session) { placeholder?.close(); return; }
    if (placeholder) placeholder.location.href = `/remote/${session.id}`;
    else openRemoteWindow(session.id);
  };
  return { connect, busy };
}

export function ConnectButtons({ device, ticketId, compact }: { device: any; ticketId?: string; compact?: boolean }) {
  const { can } = useApp();
  const { connect, busy } = useConnect();
  if (!can("respond") || !device?.approved) return null;
  return (
    <span className="row" style={{ gap: 6 }} onClick={(e) => e.stopPropagation()}>
      <button className={compact ? "small primary" : "primary"} disabled={busy} title="Remote desktop in a new window" onClick={() => connect(device.id, "desktop", ticketId)}>
        ⧉ Connect
      </button>
      {!compact && <>
        <button disabled={busy} onClick={() => connect(device.id, "terminal", ticketId)}>{device.platform === "windows" ? "PowerShell" : "Terminal"}</button>
        <button disabled={busy} onClick={() => connect(device.id, "files", ticketId)}>Files</button>
      </>}
    </span>
  );
}

export function JobStatus({ job }: { job: any }) {
  const s = job.summary || {};
  return (
    <span className="row" style={{ gap: 4 }}>
      <Pill value={job.status} tone={job.status === "completed" ? "good" : job.status === "running" ? "blue" : job.status === "partial" ? "warn" : job.status === "cancelled" ? "muted" : "bad"} />
      <span className="small muted">{displayValue(s.completed || 0)}✓ {displayValue(s.failed || 0)}✗ {displayValue((s.pending || 0) + (s.dispatched || 0))} waiting{s.skipped ? ` · ${s.skipped} skipped` : ""}</span>
    </span>
  );
}

export function JobDetail({ jobId, onClose }: { jobId: string; onClose: () => void }) {
  const { data, reload } = useData<any>(`rmm/jobs/${jobId}`);
  const running = data?.status === "running";
  useEffect(() => {
    if (!running) return;
    const timer = window.setInterval(reload, 2000);
    return () => window.clearInterval(timer);
  }, [running, reload]);
  const [open, setOpen] = useState<string | null>(null);
  const { run } = useAction();
  if (!data) return null;
  return (
    <Modal title={data.name} onClose={onClose}
           footer={<>{data.status === "running" && <button onClick={async () => { await run(() => api(`rmm/jobs/${jobId}/cancel`, { method: "POST" }), "Pending actions cancelled"); reload(); }}>Cancel pending</button>}
                     {["failed", "partial"].includes(data.status) && <button title="Run again on the devices where it failed" onClick={async () => { await run(() => api(`rmm/jobs/${jobId}/retry`, { method: "POST" }), "Retry queued"); reload(); }}>Retry failed devices</button>}
                   <button onClick={reload}>Refresh</button><button className="primary" onClick={onClose}>Close</button></>}>
      <p className="small muted">{displayValue(data.createdBy)} · {fmtTime(data.createdAt)} · {displayValue(data.commandType)}{data.script ? ` · ${data.script.language}` : ""}</p>
      <JobStatus job={data} />
      <div style={{ marginTop: 12 }}>
        {data.results.map((r: any) => (
          <div key={r.deviceId} className="card" style={{ padding: 10, marginTop: 8 }}>
            <div className="row" style={{ cursor: "pointer" }} onClick={() => setOpen(open === r.deviceId ? null : r.deviceId)}>
              <b>{displayValue(r.hostname)}</b><Pill value={r.status} />{r.exitCode !== undefined && r.exitCode !== null && <span className="small muted">exit {displayValue(r.exitCode)}</span>}
              {r.durationMs && <span className="small muted">{(r.durationMs / 1000).toFixed(1)}s</span>}
              <span style={{ flex: 1 }} /><span className="small muted">{open === r.deviceId ? "▲" : "▼"}</span>
            </div>
            {open === r.deviceId && <div style={{ marginTop: 8 }}>
              {r.error && <p style={{ color: "#fecaca" }}>{displayValue(r.error)}</p>}
              {r.stdout && <><h3>Output</h3><pre style={{ whiteSpace: "pre-wrap" }}>{displayValue(r.stdout)}</pre></>}
              {r.stderr && <><h3 style={{ marginTop: 8 }}>Errors</h3><pre style={{ whiteSpace: "pre-wrap", color: "#fecaca" }}>{displayValue(r.stderr)}</pre></>}
              {!r.stdout && !r.stderr && Object.keys(r.result || {}).length > 0 && <pre>{JSON.stringify(r.result, null, 2)}</pre>}
            </div>}
          </div>
        ))}
        {Object.entries(data.payload?.skipped || {}).map(([device, why]) => (
          <div key={device} className="small muted" style={{ marginTop: 4 }}>Skipped {device}: {String(why)}</div>
        ))}
      </div>
    </Modal>
  );
}

/** Tiny line chart for device health history. */
export function Sparkline({ points, max = 100, color = "#3b82f6", height = 60 }: { points: number[]; max?: number; color?: string; height?: number }) {
  const path = useMemo(() => {
    if (points.length < 2) return "";
    return points.map((v, i) => `${i === 0 ? "M" : "L"}${(i / (points.length - 1)) * 100},${height - (Math.min(v, max) / max) * (height - 4) - 2}`).join(" ");
  }, [points, max, height]);
  if (!path) return <div className="muted small">Not enough data yet.</div>;
  return (
    <svg viewBox={`0 0 100 ${height}`} preserveAspectRatio="none" style={{ width: "100%", height }} role="img">
      <path d={path} fill="none" stroke={color} strokeWidth={1.2} vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

export function pct(value?: number) {
  return value === undefined || value === null ? "—" : `${Math.round(value)}%`;
}

/** Open a session in its own window, like ScreenConnect's host client. */
export function openRemoteWindow(sessionId: string) {
  const width = Math.min(window.screen.availWidth, 1440);
  const height = Math.min(window.screen.availHeight, 900);
  window.open(`/remote/${sessionId}`, `fenrir-remote-${sessionId}`, `popup,width=${width},height=${height}`);
}
