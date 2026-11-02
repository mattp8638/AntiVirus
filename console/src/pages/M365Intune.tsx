import { displayValue } from "../components/DisplayValue";
import { useState } from "react";
import { api, ago } from "../api";
import { confirmDialog } from "../components/dialogs";
import { ErrorNote, Modal, Pill, Table, Tabs, useAction, useData } from "../components/ui";

const ACTION_LABEL: Record<string, string> = { sync: "Sync", restart: "Restart", defender_scan: "Defender scan", defender_update: "Update Defender",
  lock: "Lock", locate: "Locate", retire: "Retire", wipe: "Wipe" };
const DANGER = new Set(["retire", "wipe", "lock"]);

// Intune for one Microsoft 365 connection: devices and their actions, BitLocker and LAPS, policies, apps, Autopilot.
export default function M365Intune({ connection }: { connection: any }) {
  const base = `m365/connections/${connection.id}/intune`;
  const [tab, setTab] = useState("Devices");
  return (
    <>
      <Tabs tabs={["Devices", "Policies", "Apps", "Autopilot"]} active={tab} onChange={setTab} />
      {tab === "Devices" && <Devices base={base} />}
      {tab === "Policies" && <Policies base={base} />}
      {tab === "Apps" && <Apps base={base} />}
      {tab === "Autopilot" && <Autopilot base={base} />}
    </>
  );
}

function Devices({ base }: { base: string }) {
  const { data, error } = useData<any[]>(base + "/devices", {}, [], true);
  const { run, busy } = useAction();
  const [filter, setFilter] = useState("");
  const [secret, setSecret] = useState<{ title: string; lines: string[] } | null>(null);
  const act = async (d: any, action: string) => {
    if (DANGER.has(action) && !(await confirmDialog(`${ACTION_LABEL[action]} ${d.name}? ${action === "wipe" ? "This factory-resets the device and erases everything on it." : action === "retire" ? "Company data and management are removed from it." : ""}`))) return;
    await run(() => api(`${base}/devices/${d.id}/action`, { body: { action } }), `${ACTION_LABEL[action]} sent to ${d.name}`);
  };
  const reveal = async (d: any, kind: "bitlocker" | "laps") => {
    const out = await run(() => api<any>(`${base}/devices/${d.id}/${kind}`, { method: "POST" }));
    if (!out) return;
    setSecret(kind === "bitlocker"
      ? { title: `BitLocker recovery keys: ${d.name}`, lines: out.keys.map((k: any) => `${k.volume || "volume"}: ${k.key}`) }
      : { title: `LAPS password: ${d.name}`, lines: [`Account: ${out.account}`, `Password: ${out.password}`, `Backed up ${ago(out.backedUp)}`] });
  };
  const rows = (data || []).filter((d) => !filter || `${d.name} ${d.user} ${d.serial}`.toLowerCase().includes(filter.toLowerCase()));
  return (
    <div className="card">
      <ErrorNote error={error} />
      <input placeholder="Find a device, user or serial" value={filter} onChange={(e) => setFilter(e.target.value)} style={{ marginBottom: 8 }} />
      <Table rows={rows} empty={data ? "No devices are enrolled in Intune." : "Loading…"} columns={[
        { key: "name", label: "Device", render: (d) => <><b>{displayValue(d.name)}</b><div className="small muted">{displayValue(d.user)} · {displayValue(d.os)} {displayValue(d.osVersion)}</div></> },
        { key: "compliance", label: "Compliance", render: (d) => <Pill value={d.compliance} tone={d.compliance === "compliant" ? "good" : d.compliance === "noncompliant" ? "bad" : "warn"} /> },
        { key: "lastSync", label: "Last sync", render: (d) => ago(d.lastSync) },
        { key: "encrypted", label: "Encrypted", render: (d) => d.encrypted == null ? "—" : d.encrypted ? "yes" : <span style={{ color: "#fca5a5" }}>no</span> },
        { key: "actions", label: "", render: (d) => <div className="row" style={{ gap: 4, flexWrap: "wrap" }}>
          {d.actions.map((a: string) => <button key={a} className={`small${DANGER.has(a) ? " danger" : ""}`} disabled={busy} onClick={() => act(d, a)}>{ACTION_LABEL[a]}</button>)}
          {String(d.os).toLowerCase() === "windows" && <>
            <button className="small" disabled={busy} onClick={() => reveal(d, "bitlocker")}>BitLocker key</button>
            <button className="small" disabled={busy} onClick={() => reveal(d, "laps")}>LAPS password</button></>}
        </div> },
      ]} />
      {secret && <Modal title={secret.title} onClose={() => setSecret(null)}>
        <p className="small muted">Shown once; Fenrir does not keep it. The reveal is recorded in the audit log.</p>
        {secret.lines.map((l) => <div key={l} className="mono">{l}</div>)}
      </Modal>}
    </div>
  );
}

function Policies({ base }: { base: string }) {
  const { data, error } = useData<any>(base + "/policies");
  const list = (rows: any[]) => <Table rows={rows} empty="None." columns={[
    { key: "name", label: "Name", render: (p) => <b>{displayValue(p.name)}</b> }, { key: "type", label: "Type" },
    { key: "assignments", label: "Assigned to", render: (p) => p.assignments ? `${p.assignments} target(s)` : <span style={{ color: "#fcd34d" }}>not assigned</span> },
    { key: "modified", label: "Changed", render: (p) => ago(p.modified) }]} />;
  return (
    <div className="card">
      <ErrorNote error={error} />
      <h3 style={{ marginTop: 0 }}>Compliance policies</h3>{data && list(data.compliance)}
      <h3>Configuration profiles</h3>{data && list(data.configuration)}
    </div>
  );
}

function Apps({ base }: { base: string }) {
  const { data, error, reload } = useData<any[]>(base + "/apps", {}, [], true);
  const { run, busy } = useAction();
  const [assigning, setAssigning] = useState<any>(null);
  const [intent, setIntent] = useState("required");
  const [groupId, setGroupId] = useState("");
  const save = async () => {
    if (await run(() => api(`${base}/apps/${assigning.id}/assign`, { body: { intent, groupId: groupId.trim() || null } }), "Assignment added")) { setAssigning(null); reload(); }
  };
  return (
    <div className="card">
      <ErrorNote error={error} />
      <Table rows={data} empty="No apps in Intune." columns={[
        { key: "name", label: "App", render: (a) => <><b>{displayValue(a.name)}</b><div className="small muted">{displayValue(a.publisher)} · {displayValue(a.type)}</div></> },
        { key: "assignments", label: "Assigned", render: (a) => a.assignments.length ? a.assignments.map((x: any, i: number) => <div key={i} className="small">{x.intent}: {x.target}</div>) : <span className="muted">not assigned</span> },
        { key: "assign", label: "", render: (a) => <button className="small" onClick={() => setAssigning(a)}>Assign</button> }]} />
      {assigning && <Modal title={`Assign ${assigning.name}`} onClose={() => setAssigning(null)}
        footer={<button className="primary" disabled={busy} onClick={save}>Add assignment</button>}>
        <label className="field">Intent<select value={intent} onChange={(e) => setIntent(e.target.value)}>
          <option value="required">Required (installed automatically)</option><option value="available">Available (in Company Portal)</option>
          <option value="uninstall">Uninstall</option></select></label>
        <label className="field">Group ID (blank: all devices)<input placeholder="Entra group object ID" value={groupId} onChange={(e) => setGroupId(e.target.value)} /></label>
        <p className="small muted">Existing assignments are kept.</p>
      </Modal>}
    </div>
  );
}

function Autopilot({ base }: { base: string }) {
  const { data, error, reload } = useData<any[]>(base + "/autopilot", {}, [], true);
  const { run, busy } = useAction();
  const [csv, setCsv] = useState("");
  const [tag, setTag] = useState("");
  const send = async () => {
    const out = await run(() => api<any>(`${base}/autopilot/import`, { body: { csv, groupTag: tag } }));
    if (out) { setCsv(""); reload(); }
  };
  return (
    <div className="grid k2" style={{ gap: 14, alignItems: "start" }}>
      <div className="card">
        <ErrorNote error={error} />
        <h3 style={{ marginTop: 0 }}>Autopilot devices</h3>
        <Table rows={data} empty="No Autopilot devices." columns={[
          { key: "serial", label: "Serial", render: (r) => <b className="mono">{displayValue(r.serial)}</b> },
          { key: "model", label: "Model", render: (r) => `${r.manufacturer || ""} ${r.model || ""}` },
          { key: "groupTag", label: "Group tag" }, { key: "profileStatus", label: "Profile", render: (r) => <Pill value={r.profileStatus || "unknown"} /> }]} />
      </div>
      <div className="card">
        <h3 style={{ marginTop: 0 }}>Import hardware hashes</h3>
        <p className="small muted">Paste the CSV from <span className="mono">Get-WindowsAutopilotInfo -OutputFile</span> (header row included).</p>
        <textarea rows={8} value={csv} onChange={(e) => setCsv(e.target.value)} placeholder="Device Serial Number,Windows Product ID,Hardware Hash" />
        <label className="field">Group tag (optional)<input value={tag} onChange={(e) => setTag(e.target.value)} /></label>
        <button className="primary" disabled={busy || !csv.trim()} onClick={send}>Import</button>
      </div>
    </div>
  );
}
