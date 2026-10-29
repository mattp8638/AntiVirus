import { displayValue } from "../components/DisplayValue";
import { useState } from "react";
import { api } from "../api";
import { useApp } from "../app-context";
import { Modal, PageHead, Pill, Table, TenantSelect, useAction, useListData } from "../components/ui";

export default function Automations() {
  const { can, tenantName } = useApp();
  const { data, reload } = useListData<any>("automations");
  const { data: books } = useListData<any>("playbooks");
  const [creating, setCreating] = useState(false);
  const { run } = useAction();
  return (
    <>
      <PageHead title="Response rules" subtitle="SOAR rules: when an alert matches, queue response actions, open tickets or call webhooks."
                actions={can("configure") && <button className="primary" onClick={() => setCreating(true)}>New automation</button>} />
      <div className="card">
        <Table rows={data} empty="No automations yet. Policy-level auto-response (kill, isolate, rollback, ticket) still applies."
               columns={[{ key: "name", label: "Automation" }, { key: "tenantId", label: "Scope", render: (r) => r.tenantId ? tenantName(r.tenantId) : "Global" },
                         { key: "conditions", label: "When", render: (r) => <span className="mono small">{JSON.stringify(r.conditions)}</span> },
                         { key: "actions", label: "Then", render: (r) => r.actions.map((a: any, i: number) => <span key={i} className="chip">{displayValue(a.type)}{a.command ? `: ${a.command}` : ""}</span>) },
                         { key: "runs", label: "Runs", className: "right" },
                         { key: "enabled", label: "On", render: (r) => <input type="checkbox" checked={r.enabled} disabled={!can("configure")}
                             onChange={async () => { await run(() => api(`automations/${r.id}`, { method: "PATCH", body: { enabled: !r.enabled } })); reload(); }} /> }]} />
      </div>
      <div className="card">
        <h3>Guided response playbooks</h3>
        <Table rows={books?.map((b) => ({ ...b, id: b.id }))}
               columns={[{ key: "name", label: "Playbook" }, { key: "incident_type", label: "Incident type" },
                         { key: "default_severity", label: "Default severity", render: (b) => <Pill value={b.default_severity} /> },
                         { key: "stages", label: "Stages", render: (b) => Object.keys(b.stages || {}).length },
                         { key: "gates", label: "Closure gates", render: (b) => (b.critical_closure_gates || []).length }]} />
      </div>
      {creating && <NewAutomation onClose={() => { setCreating(false); reload(); }} />}
    </>
  );
}

function NewAutomation({ onClose }: { onClose: () => void }) {
  const { tenantId } = useApp();
  const { data: catalog } = useListData<any>("commands/catalog");
  const [tenant, setTenant] = useState(tenantId);
  const [name, setName] = useState("Isolate on ransomware");
  const [minSeverity, setMinSeverity] = useState("critical");
  const [mitre, setMitre] = useState("T1486");
  const [titleContains, setTitleContains] = useState("");
  const [command, setCommand] = useState("device.isolate");
  const [ticket, setTicket] = useState(true);
  const [webhook, setWebhook] = useState(false);
  const { run, busy } = useAction();
  const submit = async () => {
    const actions: any[] = [];
    if (command) actions.push({ type: "command", command, useProcessPath: ["process.terminate", "process.tree.terminate", "remediate.path"].includes(command) });
    if (ticket) actions.push({ type: "ticket" });
    if (webhook) actions.push({ type: "webhook" });
    const conditions: any = { minSeverity };
    if (mitre) conditions.mitre = mitre.split(",").map((s) => s.trim()).filter(Boolean);
    if (titleContains) conditions.titleContains = titleContains;
    const ok = await run(() => api("automations", { body: { tenantId: tenant || null, name, conditions, actions } }), "Automation created");
    if (ok) onClose();
  };
  return (
    <Modal title="New automation" onClose={onClose} footer={<><button onClick={onClose}>Cancel</button><button className="primary" disabled={busy} onClick={submit}>Create</button></>}>
      <div className="form-grid">
        <label className="field">Scope<TenantSelect value={tenant} onChange={setTenant} label="Scope" /></label>
        <label className="field">Name<input value={name} onChange={(e) => setName(e.target.value)} /></label>
        <label className="field">Minimum severity<select value={minSeverity} onChange={(e) => setMinSeverity(e.target.value)}>{["low", "medium", "high", "critical"].map((s) => <option key={s}>{s}</option>)}</select></label>
        <label className="field">MITRE techniques (any)<input value={mitre} onChange={(e) => setMitre(e.target.value)} placeholder="T1486, T1490" /></label>
        <label className="field">Title contains<input value={titleContains} onChange={(e) => setTitleContains(e.target.value)} /></label>
        <label className="field">Run action
          <select value={command} onChange={(e) => setCommand(e.target.value)}>
            <option value="">None</option>{catalog?.map((c) => <option key={c.type} value={c.type}>{displayValue(c.label)}</option>)}
          </select>
        </label>
      </div>
      <div className="row" style={{ marginTop: 12 }}>
        <label><input type="checkbox" checked={ticket} onChange={(e) => setTicket(e.target.checked)} /> Open a PSA ticket</label>
        <label><input type="checkbox" checked={webhook} onChange={(e) => setWebhook(e.target.checked)} /> Notify webhooks</label>
      </div>
    </Modal>
  );
}
