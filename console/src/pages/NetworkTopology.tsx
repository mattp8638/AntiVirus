import { useState } from "react";
import { ago, api } from "../api";
import { useApp } from "../app-context";
import { displayValue } from "../components/DisplayValue";
import { RoutesPanel } from "../components/routes";
import { ErrorNote, Modal, PageHead, Pill, Stat, Table, useAction, useData, useListData } from "../components/ui";

interface TopologyNode {
  id: string; type: "subnet" | "node"; label: string; ip?: string; mac?: string; vendor?: string; kind?: string; openPorts?: number[];
  subnet?: string; managed?: boolean; deviceId?: string | null; ignored?: boolean; gateway?: string; lastSeen: string;
}
interface Topology {
  nodes: TopologyNode[]; edges: { from: string; to: string; kind: string }[];
  summary: { subnets: number; nodes: number; managed: number; unmanaged: number; deployable: number };
  settings: { probeDeviceIds?: string[]; intervalHours?: number; sweep?: boolean };
}

const KIND_ICON: Record<string, string> = { gateway: "⇄", network: "⌁", server: "▤", workstation: "▣", printer: "⎙", camera: "◉", virtual: "◫", iot: "◌", unknown: "?" };

export default function NetworkTopology() {
  const { tenantId, can } = useApp();
  const { data, error, reload } = useData<Topology>(tenantId ? "network/topology" : null, { tenant_id: tenantId });
  const { data: devices } = useListData<any>(tenantId ? "devices" : null, { tenant_id: tenantId });
  const { run, busy } = useAction();
  const [selected, setSelected] = useState<TopologyNode | null>(null);
  const [schedule, setSchedule] = useState(false);
  const [showIgnored, setShowIgnored] = useState(false);

  const discover = async () => { if (await run(() => api<any>("network/discover", { body: { tenantId, sweep: true } }), "Discovery queued on the customer's devices. Results arrive as they check in.")) reload(); };
  const subnets = data?.nodes.filter((n) => n.type === "subnet") ?? [];
  const members = (cidr: string) => (data?.nodes ?? []).filter((n) => n.type === "node" && n.subnet === cidr && (showIgnored || !n.ignored))
    .sort((a, b) => Number(b.kind === "gateway") - Number(a.kind === "gateway") || Number(a.managed) - Number(b.managed));

  if (!tenantId) return <><PageHead title="Network topology" subtitle="Choose a customer to see their network map." /></>;
  return (
    <>
      <PageHead title="Network topology"
                subtitle="Built from ARP tables, routes and a light TCP sweep run by the customer's own agents. Managed devices are matched by MAC and IP; everything else is classified by vendor and open ports so you can see unmanaged machines, printers and network gear."
                actions={can("respond") && <>
                  <button className="primary" disabled={busy} onClick={discover}>Discover now</button>
                  {can("configure") && <button className="ghost" onClick={() => setSchedule(true)}>Schedule</button>}</>} />
      <ErrorNote error={error} />
      {data && <div className="grid k4">
        <Stat label="Subnets" value={data.summary.subnets} />
        <Stat label="Devices seen" value={data.summary.nodes} />
        <Stat label="Unmanaged" value={data.summary.unmanaged} accent={data.summary.unmanaged ? "amber" : undefined} />
        <Stat label="Could take an agent" value={data.summary.deployable} hint="unmanaged workstations and servers" />
      </div>}
      <label className="small" style={{ display: "block", margin: "10px 0" }}><input type="checkbox" checked={showIgnored} onChange={(e) => setShowIgnored(e.target.checked)} /> Show ignored</label>
      {data && !subnets.length && <div className="card empty">Nothing discovered yet. Run discovery to map this customer's network.</div>}
      {subnets.map((s) => (
        <div className="card" key={s.id}>
          <h3>{displayValue(s.label)} <span className="small muted">gateway {displayValue(s.gateway || "unknown")} · seen {ago(s.lastSeen)}</span></h3>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
            {members(s.label).map((n) => (
              <button key={n.id} className={n.managed ? "" : "ghost"} onClick={() => setSelected(n)} title={`${n.ip} · ${n.vendor || "unknown vendor"}`}
                      style={{ display: "flex", flexDirection: "column", alignItems: "flex-start", minWidth: 150, opacity: n.ignored ? 0.5 : 1,
                               borderColor: n.managed ? "var(--good, #2e7d32)" : n.kind === "gateway" ? "var(--blue, #1565c0)" : undefined }}>
                <span>{KIND_ICON[n.kind || "unknown"] ?? "?"} <b>{displayValue(n.label)}</b></span>
                <span className="small muted">{displayValue(n.ip)} · {displayValue(n.kind)}{n.managed ? " · managed" : ""}</span>
              </button>
            ))}
          </div>
        </div>
      ))}
      {selected && <NodeModal node={selected} onClose={() => setSelected(null)} onChanged={() => { setSelected(null); reload(); }} />}
      {schedule && data && <ScheduleModal current={data.settings} devices={devices ?? []} onClose={() => setSchedule(false)} onSaved={() => { setSchedule(false); reload(); }} />}
    </>
  );
}

function NodeModal({ node, onClose, onChanged }: { node: TopologyNode; onClose: () => void; onChanged: () => void }) {
  const { can } = useApp();
  const { run, busy } = useAction();
  const patch = async (body: any) => { if (await run(() => api(`network/nodes/${node.id}`, { method: "PATCH", body }), "Updated")) onChanged(); };
  const monitor = async () => { if (await run(() => api(`network/nodes/${node.id}/monitor`, { body: {} }), "Monitor created on Network monitoring")) onChanged(); };
  return (
    <Modal title={node.label} onClose={onClose}
           footer={can("configure") && <>
             {!node.managed && !!node.openPorts?.length && <button disabled={busy} onClick={monitor}>Monitor port {node.openPorts[0]}</button>}
             <button className="ghost" disabled={busy} onClick={() => patch({ ignored: !node.ignored })}>{node.ignored ? "Stop ignoring" : "Ignore"}</button></>}>
      <Table rows={[
        { k: "IP address", v: node.ip }, { k: "MAC", v: node.mac }, { k: "Vendor", v: node.vendor }, { k: "Open ports", v: (node.openPorts || []).join(", ") },
        { k: "Managed", v: node.managed ? <a href={`/devices/${node.deviceId}`}>yes, open device</a> : <Pill value="unmanaged" tone="warn" /> },
        { k: "Last seen", v: ago(node.lastSeen) },
      ]} columns={[{ key: "k", label: "" }, { key: "v", label: "", render: (r) => r.v || "-" }]} />
      {can("configure") && <label className="field">Kind<select value={node.kind} disabled={busy} onChange={(e) => patch({ kind: e.target.value })}>
        {Object.keys(KIND_ICON).map((k) => <option key={k}>{k}</option>)}</select></label>}
      <h4 style={{ marginTop: 12 }}>Connect</h4>
      {node.managed && node.deviceId ? <RoutesPanel deviceId={node.deviceId} /> : <RoutesPanel nodeId={node.id} />}
    </Modal>
  );
}

function ScheduleModal({ current, devices, onClose, onSaved }: { current: Topology["settings"]; devices: any[]; onClose: () => void; onSaved: () => void }) {
  const { tenantId } = useApp();
  const { run, busy } = useAction();
  const [probes, setProbes] = useState<string[]>(current.probeDeviceIds || []);
  const [hours, setHours] = useState(current.intervalHours || 24);
  const save = async () => {
    if (await run(() => api("network/topology/settings", { method: "PUT", body: { tenantId, probeDeviceIds: probes, intervalHours: hours, sweep: true } }), "Schedule saved")) onSaved();
  };
  return (
    <Modal title="Scheduled discovery" onClose={onClose} footer={<button className="primary" disabled={busy} onClick={save}>Save</button>}>
      <p className="small muted">Pick one or two always-on devices per site (a server is ideal). They re-map the network on this schedule.</p>
      <label className="field">Every (hours)<input type="number" min={1} max={168} value={hours} onChange={(e) => setHours(Number(e.target.value))} /></label>
      <div style={{ maxHeight: 260, overflow: "auto" }}>{devices.map((d) => <label key={d.id} className="small" style={{ display: "block" }}>
        <input type="checkbox" checked={probes.includes(d.id)} onChange={(e) => setProbes(e.target.checked ? [...probes, d.id] : probes.filter((p) => p !== d.id))} /> {displayValue(d.hostname)}</label>)}</div>
    </Modal>
  );
}
