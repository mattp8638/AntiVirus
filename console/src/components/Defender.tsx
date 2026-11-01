// Managed Microsoft Defender: what Defender has on a device, against what policy asks; and the fleet at a glance.
import { useNavigate } from "react-router-dom";
import { ago, api } from "../api";
import { useApp } from "../app-context";
import { displayValue } from "./DisplayValue";
import { ErrorNote, Pill, Stat, Table, useAction, useData } from "./ui";

const RULE_LABEL: Record<string, string> = {
  blockOfficeChildProcesses: "Office apps creating child processes", blockOfficeExecutableContent: "Office apps writing executables",
  blockOfficeCodeInjection: "Office apps injecting code", blockObfuscatedScripts: "Obfuscated scripts",
  blockScriptDownloadedPayloads: "Scripts launching downloads", blockEmailExecutables: "Executables from email",
  blockCredentialStealingLsass: "Credential stealing from LSASS", blockPsexecWmiProcessCreation: "PsExec and WMI process creation",
  blockUntrustedUsbProcesses: "Untrusted programs from USB", blockWmiPersistence: "WMI persistence",
  blockVulnerableSignedDrivers: "Vulnerable signed drivers", blockAdobeReaderChildProcesses: "Adobe Reader child processes",
  blockWebshellCreation: "Webshells on servers", advancedRansomwareProtection: "Advanced ransomware protection",
};
const MODE_TONE: Record<string, string> = { block: "good", warn: "warn", audit: "blue", off: "muted" };

export function DeviceDefender({ deviceId }: { deviceId: string }) {
  const { can } = useApp();
  const { data, error, reload } = useData<any>(`devices/${deviceId}/defender`, {}, [deviceId]);
  const { run, busy } = useAction();
  if (error) return <ErrorNote error={error} />;
  if (!data) return <div className="empty">Loading…</div>;
  const s = data.status;
  const check = async () => { if (await run(() => api(`devices/${deviceId}/defender/check`, { method: "POST" }), "Check sent to the device")) reload(); };
  return (
    <>
      <div className="row" style={{ gap: 8, flexWrap: "wrap", marginBottom: 10 }}>
        <Pill value={data.managed ? "managed by Fenrir" : "not managed (read only)"} tone={data.managed ? "good" : "muted"} />
        {data.managed && <Pill value={data.inSync ? "policy applied" : "policy waiting to apply"} tone={data.inSync ? "good" : "warn"} />}
        <span className="small muted">{data.checkedAt ? `checked ${ago(data.checkedAt)}` : "not checked yet"}{data.checking ? " · checking now" : ""}</span>
        <span className="spacer" />
        {can("respond") && <button disabled={busy || data.checking} onClick={check}>{data.managed ? "Apply and check now" : "Check now"}</button>}
      </div>
      {!data.managed && <p className="small muted">Turn on <b>Manage Microsoft Defender</b> in this device's policy to set Defender's protection
        and attack surface rules from Fenrir, and to see its detections as alerts.</p>}
      {data.problems.length > 0 && <div className="card" style={{ borderColor: "rgba(239,68,68,.5)" }}>{data.problems.map((p: string) => <div key={p}>⚠ {p}</div>)}</div>}
      {data.advice.map((tip: string) => <p key={tip} className="small">ℹ {tip}</p>)}
      {data.error && <p className="small" style={{ color: "#fca5a5" }}>Last check: {displayValue(data.error)}</p>}
      {s && s.available !== false && <div className="grid k4" style={{ margin: "10px 0" }}>
        <Stat label="Mode" value={s.mode || "—"} accent={["Normal", "EDR Block Mode"].includes(s.mode) ? "green" : "red"} />
        <Stat label="Real-time protection" value={s.realTime ? "on" : "off"} accent={s.realTime ? "green" : "red"} />
        <Stat label="Tamper protection" value={s.tamper ? "on" : "off"} accent={s.tamper ? "green" : "amber"} />
        <Stat label="Signatures" value={`${s.signatureAgeDays ?? "—"} days old`} hint={s.signatureVersion} accent={(s.signatureAgeDays ?? 0) > 3 ? "amber" : undefined} />
      </div>}
      {data.managed && <>
        <h3>Attack surface reduction in Defender</h3>
        <Table rows={data.rules.map((r: any) => ({ ...r, id: r.guid }))} columns={[
          { key: "key", label: "Rule", render: (r) => RULE_LABEL[r.key] ?? r.key },
          { key: "wanted", label: "Policy", render: (r) => <Pill value={r.wanted} tone={MODE_TONE[r.wanted]} /> },
          { key: "actual", label: "On the device", render: (r) => r.actual ? <Pill value={r.actual} tone={r.actual === r.wanted || r.wanted === "off" ? MODE_TONE[r.actual] : "bad"} /> : <span className="small muted">not set</span> },
        ]} />
      </>}
      {s?.detections?.length > 0 && <>
        <h3>Defender detections (30 days)</h3>
        <Table rows={s.detections} columns={[
          { key: "name", label: "Threat", render: (x) => <b>{displayValue(x.name || x.threatId)}</b> },
          { key: "resources", label: "Where", render: (x) => <span className="small mono">{displayValue((x.resources || [])[0] || "")}</span> },
          { key: "actionSuccess", label: "Dealt with", render: (x) => <Pill value={x.actionSuccess ? "yes" : "no"} tone={x.actionSuccess ? "good" : "bad"} /> },
          { key: "at", label: "When", render: (x) => ago(x.at) },
        ]} />
      </>}
    </>
  );
}

export function DefenderFleet() {
  const { tenantId } = useApp();
  const navigate = useNavigate();
  const { data, error } = useData<any>("defender/fleet", { tenant_id: tenantId });
  if (error) return <ErrorNote error={error} />;
  if (!data || !data.devices.length) return null;
  const s = data.summary;
  return (
    <div className="card" style={{ marginTop: 14 }}>
      <h3 style={{ marginTop: 0 }}>Microsoft Defender <span className="small muted">{s.managed} of {s.devices} Windows devices managed · {s.withProblems} with problems · {s.tamperOff} without tamper protection</span></h3>
      <Table rows={data.devices.map((d: any) => ({ ...d, id: d.deviceId }))} onRow={(d) => navigate(`/devices/${d.deviceId}?tab=security&sub=Microsoft%20Defender`)}
             columns={[{ key: "hostname", label: "Device", render: (d) => <><b>{displayValue(d.hostname)}</b><div className="small muted">{displayValue(d.customer)}</div></> },
                       { key: "managed", label: "Managed", render: (d) => <Pill value={d.managed ? (d.inSync ? "yes" : "applying") : "no"} tone={d.managed ? (d.inSync ? "good" : "warn") : "muted"} /> },
                       { key: "mode", label: "Mode", render: (d) => displayValue(d.mode || "—") },
                       { key: "realTime", label: "Real-time", render: (d) => d.realTime == null ? "—" : <Pill value={d.realTime ? "on" : "off"} tone={d.realTime ? "good" : "bad"} /> },
                       { key: "tamper", label: "Tamper", render: (d) => d.tamper == null ? "—" : <Pill value={d.tamper ? "on" : "off"} tone={d.tamper ? "good" : "warn"} /> },
                       { key: "problems", label: "Problems", render: (d) => <span className="small">{d.problems.join("; ") || "—"}</span> },
                       { key: "checkedAt", label: "Checked", render: (d) => (d.checkedAt ? ago(d.checkedAt) : "not yet") }]} />
    </div>
  );
}
