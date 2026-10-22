import { useState } from "react";
import { api } from "../api";
import { useApp } from "../app-context";
import { Modal, PageHead, Pill, Sev, Stat, Table, useAction, useData } from "../components/ui";

export default function Vulnerabilities() {
  const { tenantId, can } = useApp();
  const [status, setStatus] = useState("open");
  const [severity, setSeverity] = useState("");
  const { data, reload } = useData<any[]>("vulnerabilities", { tenant_id: tenantId, status, severity });
  const [open, setOpen] = useState<any>(null);
  const { run, busy } = useAction();
  const kev = data?.filter((v) => v.knownExploited).length ?? 0;
  const exposures = data?.reduce((n, v) => n + v.devices.length, 0) ?? 0;
  return (
    <>
      <PageHead title="Vulnerabilities" subtitle="Software inventory matched against OSV.dev, prioritised by CISA's Known Exploited Vulnerabilities catalogue."
                actions={can("respond") && <button className="primary" disabled={busy} onClick={() => run(() => api<any>("vulnerabilities/scan", { body: { tenantId: tenantId || undefined } }), "Scan queued for all devices in scope")}>Scan now</button>} />
      <div className="grid k3">
        <Stat label="Unique vulnerabilities" value={data?.length ?? "—"} />
        <Stat label="Known exploited (fix first)" value={kev} accent={kev ? "red" : "green"} />
        <Stat label="Device exposures" value={exposures} />
      </div>
      <div className="row" style={{ margin: "16px 0 12px" }}>
        <select value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status">{["open", "patching", "mitigated", "accepted", "fixed"].map((s) => <option key={s}>{s}</option>)}</select>
        <select value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Severity"><option value="">Any severity</option>{["critical", "high", "medium", "low"].map((s) => <option key={s}>{s}</option>)}</select>
      </div>
      <div className="card">
        <Table rows={data?.map((v) => ({ ...v, id: v.vulnId }))} onRow={setOpen} empty="No vulnerabilities in this view."
               columns={[{ key: "priority", label: "Priority", render: (v) => <Pill value={v.priority} tone={v.priority === "P1" ? "bad" : v.priority === "P2" ? "warn" : "muted"} /> },
                         { key: "vulnId", label: "Vulnerability", render: (v) => <><b>{v.vulnId}</b> {v.knownExploited && <Pill value="actively exploited" tone="bad" />}<div className="small muted">{v.summary.slice(0, 110)}</div></> },
                         { key: "severity", label: "Severity", render: (v) => <Sev level={v.severity} /> },
                         { key: "packages", label: "Package", render: (v) => v.packages.join(", ") },
                         { key: "fixedVersion", label: "Fix", render: (v) => v.fixedVersion || "—" },
                         { key: "devices", label: "Devices", render: (v) => v.devices.length, className: "right" }]} />
      </div>
      {open && (
        <Modal title={open.vulnId} onClose={() => setOpen(null)}>
          <p>{open.summary}</p>
          <p><a href={`https://osv.dev/vulnerability/${open.vulnId}`} target="_blank" rel="noreferrer">OSV record</a> · <a href={`https://nvd.nist.gov/vuln/detail/${open.vulnId}`} target="_blank" rel="noreferrer">NVD</a></p>
          <Table rows={open.devices} columns={[{ key: "hostname", label: "Device" }, { key: "installed", label: "Installed" }, { key: "status", label: "Status", render: (d) => <Pill value={d.status} /> },
            { key: "act", label: "", render: (d) => can("respond") && <select value={d.status} aria-label="Set status" onChange={async (e) => {
                await run(() => api(`vulnerabilities/${d.id}`, { method: "PATCH", body: { status: e.target.value } }), "Status updated"); reload(); setOpen(null); }}>
                {["open", "patching", "mitigated", "accepted", "fixed"].map((s) => <option key={s}>{s}</option>)}</select> }]} />
        </Modal>
      )}
    </>
  );
}
