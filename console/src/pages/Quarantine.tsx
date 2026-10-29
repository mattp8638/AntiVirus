import { useState } from "react";
import { Link } from "react-router-dom";
import { ago, api } from "../api";
import { useApp } from "../app-context";
import { ErrorNote, PageHead, Pill, Table, useAction, useListData } from "../components/ui";
import { confirmDialog, promptDialog } from "../components/dialogs";

const TONE: Record<string, string> = { quarantined: "warn", restoring: "blue", deleting: "blue", restored: "muted", deleted: "muted" };

interface Item {
  deviceId: string; hostname: string; tenantId: string; recordId: string; path: string; threat: string; sha256: string;
  source: string; quarantinedAt: string; status: string; commandId: string | null; lastError: string;
}

export default function Quarantine() {
  const { tenantId, tenantName } = useApp();
  const [showReleased, setShowReleased] = useState(false);
  const { data, error, reload } = useListData<Item>("protection/quarantine", { tenant_id: tenantId, include_released: showReleased }, [showReleased]);
  const { run, busy } = useAction();

  const act = async (item: Item, kind: "quarantine.restore" | "quarantine.delete") => {
    const verb = kind === "quarantine.restore" ? "Restore" : "Permanently delete";
    if (!await confirmDialog(`${verb} ${item.path || item.recordId} on ${item.hostname}?`)) return;
    const reason = await promptDialog("Reason (recorded in the audit log)", kind === "quarantine.restore" ? "False positive" : "Confirmed malicious") ?? "";
    await run(() => api(`devices/${item.deviceId}/commands`, { method: "POST", body: { type: kind, recordId: item.recordId, reason } }),
              `${verb} queued; the device acts on it at its next check-in.`);
    reload();
  };

  return (
    <>
      <PageHead title="Quarantine" subtitle="Files agents have isolated after a scan or real-time detection. Restore a false positive or delete a confirmed threat; the device carries out the action when it next checks in."
                actions={<label className="small" style={{ display: "flex", gap: 6, alignItems: "center" }}>
                  <input type="checkbox" checked={showReleased} onChange={(e) => setShowReleased(e.target.checked)} /> Show restored and deleted</label>} />
      <ErrorNote error={error} />
      <div className="card">
        <Table rows={data?.map((i) => ({ ...i, id: `${i.deviceId}:${i.recordId}` }))} empty="Nothing is in quarantine."
               columns={[
                 { key: "status", label: "Status", render: (i) => <><Pill value={i.status} tone={TONE[i.status]} />{i.lastError && <div className="small" style={{ color: "#fca5a5" }}>Last action failed: {i.lastError}</div>}</> },
                 { key: "threat", label: "Threat", render: (i) => <><b>{i.threat || "Unknown"}</b><div className="small muted mono" title={i.sha256}>{i.path}</div></> },
                 { key: "hostname", label: "Device", render: (i) => <><Link to={`/devices/${i.deviceId}`}>{i.hostname}</Link><div className="small muted">{tenantName(i.tenantId)}</div></> },
                 { key: "quarantinedAt", label: "Quarantined", render: (i) => ago(i.quarantinedAt) },
                 { key: "actions", label: "", className: "right", render: (i) => i.status === "quarantined" ? (
                   <span style={{ display: "inline-flex", gap: 6 }}>
                     <button disabled={busy} onClick={() => act(i, "quarantine.restore")}>Restore</button>
                     <button className="danger" disabled={busy} onClick={() => act(i, "quarantine.delete")}>Delete</button>
                   </span>) : null },
               ]} />
      </div>
    </>
  );
}
