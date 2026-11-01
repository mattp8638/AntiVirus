import { useState } from "react";
import { ago, api } from "../api";
import { useApp } from "../app-context";
import { displayValue } from "../components/DisplayValue";
import { RoutesPanel } from "../components/routes";
import { ErrorNote, Modal, PageHead, Pill, Stat, Table, useAction, useData, useListData } from "../components/ui";
import { NETWORK_SECTION, SectionTabs } from "../components/sections";

interface Connection { switchId: string; switch: string; port: string; kind: "access" | "shared"; vlan?: number | null }
interface TopologyNode {
  id: string; type: "subnet" | "node"; label: string; ip?: string; mac?: string; vendor?: string; kind?: string; openPorts?: number[];
  subnet?: string; managed?: boolean; deviceId?: string | null; ignored?: boolean; gateway?: string; lastSeen: string; connection?: Connection;
}
interface SwitchView { id: string; label: string; ip: string; ports: string[]; uplinks: { port: string; to: string; toLabel: string; peerPort: string }[] }
interface Topology {
  nodes: TopologyNode[]; edges: { from: string; to: string; kind: string; port?: string; peerPort?: string; vlan?: number | null }[];
  switches?: SwitchView[];
  summary: { subnets: number; nodes: number; managed: number; unmanaged: number; deployable: number; switches?: number; connected?: number };
  settings: { probeDeviceIds?: string[]; intervalHours?: number; sweep?: boolean };
}

// Switches in the order a person reads a network: the one the gateway is plugged into first, then outwards by uplink.
function orderSwitches(data: Topology): { sw: SwitchView; depth: number; via?: string }[] {
  const switches = data.switches ?? [];
  if (!switches.length) return [];
  const byId = new Map(switches.map((s) => [s.id, s]));
  const gateway = data.nodes.find((n) => n.kind === "gateway" && n.connection);
  const roots = [gateway?.connection?.switchId, ...switches.filter((s) => !switches.some((o) => o.uplinks.some((u) => u.to === s.id))).map((s) => s.id),
                 ...switches.map((s) => s.id)].filter((id): id is string => !!id && byId.has(id));
  const out: { sw: SwitchView; depth: number; via?: string }[] = [];
  const seen = new Set<string>();
  const visit = (id: string, depth: number, via?: string) => {
    if (seen.has(id)) return;
    seen.add(id);
    const sw = byId.get(id)!;
    out.push({ sw, depth, via });
    for (const u of sw.uplinks) if (byId.has(u.to)) visit(u.to, depth + 1, `${sw.label} ${u.port}`);
    for (const other of switches) for (const u of other.uplinks) if (u.to === id && !seen.has(other.id)) visit(other.id, depth + 1, `${sw.label}${u.peerPort ? " " + u.peerPort : ""}`);
  };
  for (const id of roots) visit(id, 0);
  return out;
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
  const [switchAccess, setSwitchAccess] = useState(false);

  const discover = async () => { if (await run(() => api<any>("network/discover", { body: { tenantId, sweep: true } }), "Discovery queued on the customer's devices. Results arrive as they check in.")) reload(); };
  const subnets = data?.nodes.filter((n) => n.type === "subnet") ?? [];
  const members = (cidr: string) => (data?.nodes ?? []).filter((n) => n.type === "node" && n.subnet === cidr && (showIgnored || !n.ignored))
    .sort((a, b) => Number(b.kind === "gateway") - Number(a.kind === "gateway") || Number(a.managed) - Number(b.managed));

  if (!tenantId) return <><SectionTabs items={NETWORK_SECTION} /><PageHead title="Network topology" subtitle="Choose a customer to see their network map." /></>;
  return (
    <>
      <SectionTabs items={NETWORK_SECTION} />
      <PageHead title="Network topology"
                subtitle="Which device is plugged into which switch port, and how the switches connect: read over SNMP from the customer's switches by a probe device, plus ARP tables and a light TCP sweep from their agents. Managed devices are matched by MAC and IP; everything else is classified by vendor and open ports."
                actions={can("respond") && <>
                  <button className="primary" disabled={busy} onClick={discover}>Discover now</button>
                  {can("configure") && <button className="ghost" onClick={() => setSchedule(true)}>Schedule</button>}
                  {can("configure") && <button className="ghost" onClick={() => setSwitchAccess(true)}>Switch access</button>}</>} />
      <ErrorNote error={error} />
      {data && <div className="grid k4">
        <Stat label="Subnets" value={data.summary.subnets} />
        <Stat label="Devices seen" value={data.summary.nodes} />
        <Stat label="Unmanaged" value={data.summary.unmanaged} accent={data.summary.unmanaged ? "amber" : undefined} />
        <Stat label="Could take an agent" value={data.summary.deployable} hint="unmanaged workstations and servers" />
      </div>}
      {data && <PhysicalMap data={data} showIgnored={showIgnored} onSelect={setSelected} onSetUp={() => setSwitchAccess(true)} canSetUp={can("configure")} />}
      {data && !!subnets.length && <h3 style={{ marginTop: 16 }}>Subnets</h3>}
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
      {switchAccess && <SwitchAccessModal onClose={() => { setSwitchAccess(false); reload(); }} />}
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
        { k: "Connected to", v: node.connection ? `${node.connection.switch} · ${node.connection.port}${node.connection.vlan ? ` · VLAN ${node.connection.vlan}` : ""}${node.connection.kind === "shared" ? " (shared port: an unmanaged switch or access point is in between)" : ""}` : "" },
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
      <p className="small muted">Pick one or two always-on devices per site (a server is ideal). They re-map the network on this schedule.
        Switch ports are read only from Linux or macOS probes (a small VM or Raspberry Pi is enough); Windows probes map subnets.</p>
      <label className="field">Every (hours)<input type="number" min={1} max={168} value={hours} onChange={(e) => setHours(Number(e.target.value))} /></label>
      <div style={{ maxHeight: 260, overflow: "auto" }}>{devices.map((d) => <label key={d.id} className="small" style={{ display: "block" }}>
        <input type="checkbox" checked={probes.includes(d.id)} onChange={(e) => setProbes(e.target.checked ? [...probes, d.id] : probes.filter((p) => p !== d.id))} /> {displayValue(d.hostname)}</label>)}</div>
    </Modal>
  );
}


function PhysicalMap({ data, showIgnored, onSelect, onSetUp, canSetUp }: { data: Topology; showIgnored: boolean; onSelect: (n: TopologyNode) => void; onSetUp: () => void; canSetUp: boolean }) {
  const ordered = orderSwitches(data);
  if (!ordered.length) {
    return <div className="card small muted" style={{ marginTop: 10 }}>
      No switch ports mapped yet. To see which device is plugged into which switch port, add read-only SNMP access to the customer's switches
      and pick a Linux or macOS probe under Schedule, then run discovery.{canSetUp && <> <button className="ghost small" onClick={onSetUp}>Set up switch access</button></>}
    </div>;
  }
  const attached = (switchId: string, port: string) => data.nodes.filter((n) => n.type === "node" && n.connection?.switchId === switchId && n.connection.port === port
                                                                          && (showIgnored || !n.ignored));
  return (
    <div style={{ marginTop: 10 }}>
      <h3>Physical connections</h3>
      {ordered.map(({ sw, depth, via }) => (
        <div className="card" key={sw.id} style={{ marginLeft: Math.min(depth, 4) * 24, borderLeft: depth ? "3px solid var(--blue, #1565c0)" : undefined }}>
          <h4 style={{ margin: "0 0 6px" }}>{KIND_ICON.network} {displayValue(sw.label)} <span className="small muted">{displayValue(sw.ip)}{via ? ` · connected to ${via}` : ""}</span></h4>
          {!!sw.uplinks.length && <div className="small muted" style={{ marginBottom: 6 }}>Uplinks: {sw.uplinks.map((u) => `${u.port} → ${u.toLabel}${u.peerPort ? ` ${u.peerPort}` : ""}`).join(" · ")}</div>}
          <Table rows={sw.ports.map((port) => ({ port, nodes: attached(sw.id, port) })).filter((r) => r.nodes.length)} empty="No devices learned on this switch's ports."
                 columns={[{ key: "port", label: "Port", render: (r: any) => <span className="mono">{r.port}</span> },
                           { key: "nodes", label: "Connected", render: (r: any) => <span style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                             {r.nodes.length > 1 && <Pill value={`${r.nodes.length} devices via an unmanaged switch or access point`} tone="muted" />}
                             {r.nodes.map((n: TopologyNode) => <button key={n.id} className={n.managed ? "small" : "small ghost"} onClick={() => onSelect(n)}
                               title={`${n.ip || ""} ${n.mac || ""}`}>{KIND_ICON[n.kind || "unknown"] ?? "?"} {displayValue(n.label)}{n.connection?.vlan ? ` · VLAN ${n.connection.vlan}` : ""}{n.managed ? " · managed" : ""}</button>)}
                           </span> }]} />
        </div>
      ))}
    </div>
  );
}

function SwitchAccessModal({ onClose }: { onClose: () => void }) {
  const { tenantId } = useApp();
  const { data, reload } = useData<any[]>(tenantId ? "network/snmp-credentials" : null, { tenant_id: tenantId });
  const { run, busy } = useAction();
  const blank = { name: "", version: "2c", hosts: "", community: "", username: "", authProtocol: "SHA256", authPassword: "", privProtocol: "AES", privPassword: "" };
  const [form, setForm] = useState<any>(null);
  const save = async () => {
    const body: any = { tenantId, name: form.name, version: form.version, hosts: String(form.hosts).split(/[\s,]+/).filter(Boolean) };
    if (form.version === "2c") { if (form.community) body.community = form.community; }
    else Object.assign(body, { username: form.username, authProtocol: form.authProtocol, privProtocol: form.privProtocol,
                               ...(form.authPassword ? { authPassword: form.authPassword } : {}), ...(form.privPassword ? { privPassword: form.privPassword } : {}) });
    const path = form.id ? `network/snmp-credentials/${form.id}` : "network/snmp-credentials";
    if (await run(() => api(path, { method: form.id ? "PUT" : "POST", body }), "Switch access saved")) { setForm(null); reload(); }
  };
  return (
    <Modal title="Switch access (SNMP, read-only)" onClose={onClose} wide footer={form ? <button className="primary" disabled={busy} onClick={save}>Save</button> : undefined}>
      <p className="small muted">Fenrir reads switch names, port names, MAC address tables, LLDP neighbours and ARP tables with read-only SNMP. Secrets are stored
        encrypted and released only to the customer's probe device, for one discovery at a time. Use a read-only community or a v3 user; SNMPv3 with AES is recommended.</p>
      {!form && <>
        <Table rows={data} empty="No switch access yet." columns={[{ key: "name", label: "Name" }, { key: "version", label: "SNMP", render: (r: any) => `v${r.version}` },
          { key: "hosts", label: "Switches", render: (r: any) => <span className="mono small">{r.hosts.join(", ")}</span> },
          { key: "lastResult", label: "Last result", render: (r: any) => <span className="small">{Object.entries(r.lastResult || {}).map(([h, v]: any) =>
              <div key={h}>{h}: {v.ok ? <Pill value={v.sysName || "answered"} tone="good" /> : <Pill value={v.error || "no answer"} tone="bad" />}</div>)}</span> },
          { key: "act", label: "", render: (r: any) => <span className="row" style={{ gap: 6 }}><button className="small" onClick={() => setForm({ ...blank, ...r, hosts: r.hosts.join(", ") })}>Edit</button>
            <button className="small danger" disabled={busy} onClick={async () => { if (confirm("Remove this switch access?") && await run(() => api(`network/snmp-credentials/${r.id}`, { method: "DELETE" }), "Removed")) reload(); }}>Remove</button></span> }]} />
        <button className="primary" style={{ marginTop: 8 }} onClick={() => setForm(blank)}>Add switch access</button>
      </>}
      {form && <div className="form-grid">
        <label className="field">Name<input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="e.g. Head office switches" /></label>
        <label className="field">Switch and router addresses<input value={form.hosts} onChange={(e) => setForm({ ...form, hosts: e.target.value })} placeholder="192.168.1.2, 192.168.1.3" /></label>
        <label className="field">SNMP version<select value={form.version} onChange={(e) => setForm({ ...form, version: e.target.value })}><option value="2c">v2c</option><option value="3">v3</option></select></label>
        {form.version === "2c" ? <label className="field">Read-only community{form.id && " (leave empty to keep)"}<input type="password" value={form.community} onChange={(e) => setForm({ ...form, community: e.target.value })} /></label> : <>
          <label className="field">Username<input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} /></label>
          <label className="field">Authentication<select value={form.authProtocol} onChange={(e) => setForm({ ...form, authProtocol: e.target.value })}>{["SHA256", "SHA512", "SHA", "MD5", ""].map((p) => <option key={p} value={p}>{p || "none"}</option>)}</select></label>
          <label className="field">Auth passphrase{form.id && " (leave empty to keep)"}<input type="password" value={form.authPassword} onChange={(e) => setForm({ ...form, authPassword: e.target.value })} /></label>
          <label className="field">Privacy<select value={form.privProtocol} onChange={(e) => setForm({ ...form, privProtocol: e.target.value })}>{["AES", "AES256", "DES", ""].map((p) => <option key={p} value={p}>{p || "none"}</option>)}</select></label>
          <label className="field">Privacy passphrase{form.id && " (leave empty to keep)"}<input type="password" value={form.privPassword} onChange={(e) => setForm({ ...form, privPassword: e.target.value })} /></label>
        </>}
      </div>}
    </Modal>
  );
}
