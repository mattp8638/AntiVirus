import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ago, api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { ErrorNote, Modal, PageHead, Pill, Sev, Table, Tabs, useAction, useData } from "../components/ui";

export default function DeviceDetail() {
  const { id } = useParams();
  const { tenantName, can } = useApp();
  const { data, error, reload } = useData<any>(`devices/${id}`);
  const { data: policies } = useData<any[]>("policies", { tenant_id: data?.device.tenantId }, [data?.device.tenantId]);
  const { data: groups } = useData<any[]>("groups", { tenant_id: data?.device.tenantId }, [data?.device.tenantId]);
  const [tab, setTab] = useState("Overview");
  const [action, setAction] = useState<string | null>(null);
  const { run } = useAction();

  if (error) return <ErrorNote error={error} />;
  if (!data) return <div className="empty">Loading…</div>;
  const d = data.device;

  const patch = async (body: any, message: string) => {
    await run(() => api(`devices/${d.id}`, { method: "PATCH", body }), message);
    reload();
  };

  return (
    <>
      <PageHead title={d.hostname}
                subtitle={<>{d.osVersion} · {tenantName(d.tenantId)} · <span className={`dot ${d.online ? "on" : "off"}`} /> {d.online ? "online" : `last seen ${ago(d.lastSeenAt)}`}</>}
                actions={can("respond") && <>
                  {!d.approved && can("configure") && <button className="primary" onClick={() => patch({ approved: true }, "Device approved")}>Approve</button>}
                  <button onClick={() => setAction("scan.quick")}>Scan</button>
                  {d.isolated ? <button onClick={() => setAction("device.release")}>Release isolation</button>
                              : <button className="danger" onClick={() => setAction("device.isolate")}>Isolate</button>}
                  <button onClick={() => setAction("")}>More actions…</button>
                </>} />
      <Tabs tabs={["Overview", "Effective policy", "Alerts", "Actions", "Software", "Vulnerabilities"]} active={tab} onChange={setTab} />

      {tab === "Overview" && (
        <div className="grid k2">
          <div className="card">
            <h3>Device</h3>
            <dl className="kv">
              <dt>Device ID</dt><dd className="mono">{d.id}</dd>
              <dt>Platform</dt><dd>{d.platform}</dd>
              <dt>Agent</dt><dd>{d.agentVersion || "—"} (platform {d.platformVersion || "—"})</dd>
              <dt>Health</dt><dd><Pill value={d.healthState} tone={d.healthState === "healthy" ? "good" : "warn"} /></dd>
              <dt>Isolated</dt><dd>{d.isolated ? <Pill value="isolated" tone="bad" /> : "No"}</dd>
              <dt>Risk score</dt><dd>{d.riskScore}</dd>
              <dt>IP address</dt><dd>{d.ipAddress || "—"}</dd>
              <dt>Serial</dt><dd>{d.serialNumber || "—"}</dd>
              <dt>Enrolled</dt><dd>{fmtTime(d.enrolledAt)}</dd>
              <dt>Events stored</dt><dd>{data.eventCount}</dd>
              <dt>Encrypted DNS</dt><dd className="mono small">{data.dnsOverHttpsUrl}</dd>
            </dl>
          </div>
          <div className="card">
            <h3>Management</h3>
            <div className="form-grid">
              <label className="field">Group
                <select value={d.groupId ?? ""} disabled={!can("configure")} onChange={(e) => patch({ groupId: e.target.value || null }, "Group updated")}>
                  <option value="">No group</option>
                  {groups?.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
                </select>
              </label>
              <label className="field">Device policy override
                <select value={d.policyId ?? ""} disabled={!can("configure")} onChange={(e) => patch({ policyId: e.target.value || null }, "Policy override updated")}>
                  <option value="">Inherit from group/tenant</option>
                  {policies?.filter((p) => p.tenantId).map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
                </select>
              </label>
            </div>
            <p className="small muted" style={{ marginTop: 12 }}>
              Policy revision {data.policy.revision} · {data.policy.applied ? <Pill value="applied" tone="good" /> : <Pill value="waiting for agent" tone="warn" />}
            </p>
            {data.policy.overridesBlocked.length > 0 && (
              <p className="small">{data.policy.overridesBlocked.length} override(s) blocked by locks — see Effective policy.</p>
            )}
            {Object.keys(d.inventory || {}).length > 0 && (
              <><h3 style={{ marginTop: 16 }}>Inventory</h3><pre>{JSON.stringify(d.inventory, null, 2)}</pre></>
            )}
          </div>
        </div>
      )}

      {tab === "Effective policy" && <EffectivePolicy policy={data.policy} />}

      {tab === "Alerts" && (
        <div className="card">
          <Table rows={data.alerts} empty="No alerts for this device."
                 columns={[{ key: "severity", label: "Sev", render: (r) => <Sev level={r.severity} /> }, { key: "title", label: "Alert" },
                           { key: "status", label: "Status", render: (r) => <Pill value={r.status} /> },
                           { key: "mitre", label: "MITRE", render: (r) => r.mitre.filter((m: string) => m.startsWith("T")).join(", ") },
                           { key: "incidentId", label: "Incident", render: (r) => r.incidentId ? <Link to={`/incidents/${r.incidentId}`}>open</Link> : "—" },
                           { key: "createdAt", label: "When", render: (r) => ago(r.createdAt) }]} />
        </div>
      )}

      {tab === "Actions" && (
        <div className="card">
          <Table rows={data.commands} empty="No remote actions yet."
                 columns={[{ key: "type", label: "Action" }, { key: "status", label: "Status", render: (r) => <Pill value={r.status} /> },
                           { key: "issuedBy", label: "By" }, { key: "targetPath", label: "Target", render: (r) => <span className="mono small">{r.targetPath || r.recordId || "—"}</span> },
                           { key: "reason", label: "Reason" }, { key: "createdAt", label: "Queued", render: (r) => ago(r.createdAt) },
                           { key: "result", label: "Result", render: (r) => Object.keys(r.result || {}).length ? <span className="mono small">{JSON.stringify(r.result).slice(0, 80)}</span> : "—" }]} />
        </div>
      )}

      {tab === "Software" && (
        <div className="card">
          <Table rows={data.software} empty="No inventory yet. The agent reports software on its inventory cycle."
                 columns={[{ key: "name", label: "Name" }, { key: "version", label: "Version" }, { key: "vendor", label: "Vendor" }, { key: "ecosystem", label: "Source" }]} />
        </div>
      )}

      {tab === "Vulnerabilities" && (
        <div className="card">
          <div className="row" style={{ marginBottom: 10 }}>
            <button onClick={() => run(() => api("vulnerabilities/scan", { body: { deviceId: d.id } }), "Vulnerability scan queued")}>Scan now</button>
          </div>
          <Table rows={data.vulnerabilities} empty="No open vulnerabilities."
                 columns={[{ key: "vulnId", label: "ID", render: (r) => <a href={`https://osv.dev/vulnerability/${r.vulnId}`} target="_blank" rel="noreferrer">{r.vulnId}</a> },
                           { key: "severity", label: "Sev", render: (r) => <><Sev level={r.severity} /> {r.knownExploited && <Pill value="exploited" tone="bad" />}</> },
                           { key: "package", label: "Package" }, { key: "installedVersion", label: "Installed" }, { key: "fixedVersion", label: "Fixed in" },
                           { key: "status", label: "Status", render: (r) => <Pill value={r.status} /> }]} />
        </div>
      )}

      {action !== null && <CommandModal device={d} initial={action} onClose={() => { setAction(null); reload(); }} />}
    </>
  );
}

function EffectivePolicy({ policy }: { policy: any }) {
  const { data: schema } = useData<any>("policy-schema");
  const [filter, setFilter] = useState("");
  const blocked = useMemo(() => new Set(policy.overridesBlocked.map((b: any) => b.setting)), [policy]);
  if (!schema) return <div className="empty">Loading…</div>;
  return (
    <div className="card">
      <div className="row" style={{ marginBottom: 12 }}>
        <input placeholder="Filter settings" value={filter} onChange={(e) => setFilter(e.target.value)} />
        <span className="muted small">Each value shows the layer that set it. Locked settings cannot be overridden lower down.</span>
      </div>
      {schema.sections.map((section: any) => {
        const fields = section.fields.filter((f: any) => !filter || f.label.toLowerCase().includes(filter.toLowerCase()) || f.path.includes(filter));
        if (!fields.length) return null;
        return (
          <div key={section.key} style={{ marginBottom: 18 }}>
            <h3>{section.title}</h3>
            <Table rows={fields.map((f: any) => ({ ...f, id: f.path }))}
                   columns={[{ key: "label", label: "Setting" },
                             { key: "value", label: "Value", render: (f) => <span className="mono small">{JSON.stringify(policy.settings[section.key][f.key])}</span> },
                             { key: "origin", label: "Set by", render: (f) => <span className="small">{policy.origin[f.path]}</span> },
                             { key: "lock", label: "", render: (f) => <>
                                 {(policy.locked[f.path] || policy.locked[section.key]) && <Pill value={`locked by ${policy.locked[f.path] || policy.locked[section.key]}`} tone="blue" />}
                                 {blocked.has(f.path) && <Pill value="override blocked" tone="warn" />}
                               </> }]} />
          </div>
        );
      })}
    </div>
  );
}

export function CommandModal({ device, initial, onClose, incidentId }: { device: any; initial: string; onClose: () => void; incidentId?: string }) {
  const { data: catalog } = useData<any[]>("commands/catalog");
  const [type, setType] = useState(initial || "scan.quick");
  const [targetPath, setTargetPath] = useState("");
  const [recordId, setRecordId] = useState("");
  const [pid, setPid] = useState("");
  const [reason, setReason] = useState("");
  const { run, busy } = useAction();
  const isKill = type === "process.terminate" || type === "process.tree.terminate";
  const available = catalog?.filter((c) => c.platforms.includes(device.platform)) ?? [];
  const spec = available.find((c) => c.type === type);
  const submit = async () => {
    const ok = await run(() => api(`devices/${device.id}/commands`, { body: { type, targetPath, recordId, reason, incidentId, payload: isKill && pid ? { pid: Number(pid) } : {} } }), `${spec?.label ?? type} queued`);
    if (ok) onClose();
  };
  return (
    <Modal title={`Remote action · ${device.hostname}`} onClose={onClose}
           footer={<><button onClick={onClose}>Cancel</button><button className={spec?.destructive ? "danger" : "primary"} disabled={busy || !spec} onClick={submit}>Queue action</button></>}>
      <div className="form-grid">
        <label className="field">Action
          <select value={type} onChange={(e) => setType(e.target.value)}>
            {available.map((c) => <option key={c.type} value={c.type}>{c.group}: {c.label}</option>)}
          </select>
        </label>
        {spec?.needs.includes("targetPath") && <label className="field">Target path<input value={targetPath} onChange={(e) => setTargetPath(e.target.value)} placeholder="C:\\path\\file.exe" /></label>}
        {isKill && <label className="field">Process ID<input value={pid} onChange={(e) => setPid(e.target.value.replace(/\D/g, ""))} placeholder="from the alert" /></label>}
        {spec?.needs.includes("recordId") && <label className="field">Record ID<input value={recordId} onChange={(e) => setRecordId(e.target.value)} /></label>}
        <label className="field">Reason<input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Recorded in the audit log" /></label>
      </div>
      {spec?.description && <p className="muted">{spec.description}</p>}
      {isKill && !pid && <p style={{ color: "#fde68a" }}>No process ID: every running copy of this program on the device will be killed.</p>}
      {spec?.destructive && <p style={{ color: "#fecaca" }}>This action changes the device and cannot be undone automatically.</p>}
    </Modal>
  );
}
