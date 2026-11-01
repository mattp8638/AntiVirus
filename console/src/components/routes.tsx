import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { useApp } from "../app-context";
import { displayValue } from "./DisplayValue";
import { ErrorNote, Modal, Pill, useAction, useData } from "./ui";
import { useConnect } from "./rmm";

interface Route {
  kind: "agent" | "tunnel" | "amt"; available: boolean; detail: string; deviceId?: string; modes?: string[]; via?: string;
  targetHost?: string; targetNodeId?: string; ports?: { port: number; protocol: string; allowed: boolean }[];
  amtEndpointId?: string; powerState?: string; suggestHost?: string; suggestPort?: number;
}

const MODE_LABEL: Record<string, string> = { desktop: "Desktop", terminal: "Terminal", files: "Files", backstage: "Backstage" };

/** Every way to reach a device or an agentless network node: its own agent, a tunnel through a peer, or Intel AMT. */
export function RoutesPanel({ deviceId, nodeId }: { deviceId?: string; nodeId?: string }) {
  const { can } = useApp();
  const { data, error } = useData<Route[]>("remote/routes", deviceId ? { device_id: deviceId } : { node_id: nodeId });
  const { connect, busy } = useConnect();
  const [tunnel, setTunnel] = useState<{ route: Route; port: number } | null>(null);
  if (error) return <ErrorNote error={error} />;
  if (!data) return <div className="small muted">Finding routes…</div>;
  if (!data.length) return <div className="small muted">No route: no agent, no peer agent that has seen it, and no Intel AMT.</div>;
  return (
    <div className="routes">
      {data.map((r, i) => (
        <div key={i} className="card" style={{ padding: 10, marginBottom: 8, opacity: r.available ? 1 : 0.7 }}>
          <div className="row" style={{ justifyContent: "space-between" }}>
            <b>{r.kind === "agent" ? "Fenrir agent" : r.kind === "tunnel" ? `Tunnel via ${r.via}` : "Intel AMT (out-of-band)"}</b>
            <Pill value={r.available ? "available" : "unavailable"} tone={r.available ? "good" : "muted"} />
          </div>
          <div className="small muted">{displayValue(r.detail)}</div>
          {r.kind === "agent" && r.available && can("remote") && <div className="row" style={{ gap: 6, marginTop: 6 }}>
            {r.modes?.map((m) => <button key={m} className="small" disabled={busy} onClick={() => connect(r.deviceId!, m as any)}>{MODE_LABEL[m] ?? m}</button>)}
          </div>}
          {r.kind === "tunnel" && <div className="row" style={{ gap: 6, marginTop: 6, flexWrap: "wrap" }}>
            {r.ports?.map((p) => <button key={p.port} className="small" disabled={!p.allowed || !can("remote")} title={p.allowed ? "" : "Not in this device's allowed tunnel ports"}
                                        onClick={() => setTunnel({ route: r, port: p.port })}>{p.protocol} ({p.port})</button>)}
          </div>}
          {r.kind === "amt" && <div className="small" style={{ marginTop: 6 }}>
            {r.amtEndpointId ? <>Power: <b>{displayValue(r.powerState || "unknown")}</b> · <Link to="/out-of-band">Manage power</Link></>
              : <Link to="/out-of-band">Add {r.suggestHost}:{r.suggestPort} under Out-of-band management</Link>}
          </div>}
        </div>
      ))}
      {tunnel && <TunnelModal route={tunnel.route} port={tunnel.port} onClose={() => setTunnel(null)} />}
    </div>
  );
}

function TunnelModal({ route, port, onClose }: { route: Route; port: number; onClose: () => void }) {
  const { run, busy } = useAction();
  const [reason, setReason] = useState("");
  const [command, setCommand] = useState<string | null>(null);
  const localPort = port === 3389 ? 13389 : port === 22 ? 2222 : 10000 + port;
  const open = async () => {
    const session = await run(() => api<any>("remote/sessions", { body: { deviceId: route.deviceId, mode: "tunnel", targetNodeId: route.targetNodeId,
                                                                           targetHost: route.targetHost, targetPort: port, reason } }));
    if (!session) return;
    const viewer = await run(() => api<any>(`remote/sessions/${session.id}/viewer-token`, { method: "POST" }));
    if (!viewer) return;
    const base = `${window.location.protocol === "https:" ? "wss" : "ws"}://${window.location.host}`;
    setCommand(`fenrir-tunnel -listen 127.0.0.1:${localPort} -url "${base}${viewer.path}?token=${viewer.token}"`);
  };
  const client = port === 3389 ? `mstsc /v:127.0.0.1:${localPort}` : port === 22 ? `ssh -p ${localPort} <user>@127.0.0.1`
    : port === 5900 ? `your VNC viewer at 127.0.0.1:${localPort}` : `https://127.0.0.1:${localPort} (or http://)`;
  return (
    <Modal title={`Tunnel to ${route.targetHost}:${port}`} onClose={onClose}
           footer={!command && <button className="primary" disabled={busy || reason.trim().length < 8} onClick={open}>Open tunnel</button>}>
      {!command ? <>
        <p className="small muted">The agent on {route.via} connects to {route.targetHost}:{port} on its own network and relays the connection. Nothing is opened to the internet; the tunnel needs a fresh sign-in check and is audited.</p>
        <label className="field">Reason (audited)<input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. Patch the file server's RAID firmware" /></label>
      </> : <>
        <p className="small">1. Run this on your computer within 15 minutes (fenrir-tunnel is built from <code>agent/linux/cmd/fenrir-tunnel</code> for Windows, macOS and Linux):</p>
        <pre className="mono small" style={{ whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{command}</pre>
        <button className="small" onClick={() => navigator.clipboard?.writeText(command)}>Copy</button>
        <p className="small">2. Connect: <code>{client}</code></p>
        <p className="small muted">End the session from Remote sessions or by stopping fenrir-tunnel.</p>
      </>}
    </Modal>
  );
}
