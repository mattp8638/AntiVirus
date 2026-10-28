import { displayValue } from "../components/DisplayValue";
import { Fragment, useEffect, useState } from "react";
import { ago, api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { ErrorNote, Pill, Sev, Table, useAction, useData } from "../components/ui";
import { makeModel } from "./DeviceOverview";

// Everything a technician usually asks the user for: hardware, Windows build, disk health, BitLocker,
// who uses the machine, network, battery, security posture and recent problems. The agent collects it
// every 6 hours; "Refresh" asks for a new copy on the next check-in.

const yesNo = (v: unknown) => v === true ? "Yes" : v === false ? "No" : "—";
const gb = (v: unknown) => typeof v === "number" ? `${v >= 100 ? Math.round(v) : v.toFixed(1)} GB` : "—";
const list = (v: unknown) => Array.isArray(v) && v.length ? v.join(", ") : "—";
const healthTone = (h: string) => /healthy|ok|verified/i.test(h) ? "good" : /warn|degraded/i.test(h) ? "warn" : h ? "bad" : "muted";

function Kv({ rows }: { rows: [string, React.ReactNode][] }) {
  return <dl className="kv">{rows.filter(([, v]) => v !== undefined && v !== null && v !== "").map(([k, v]) => <Fragment key={k}><dt>{k}</dt><dd>{displayValue(v)}</dd></Fragment>)}</dl>;
}

function Meter({ percent, tone }: { percent: number; tone: string }) {
  const colour = tone === "bad" ? "#ef4444" : tone === "warn" ? "#f59e0b" : "#22c55e";
  return <div style={{ background: "rgba(148,163,184,0.2)", borderRadius: 4, height: 6, width: 120, display: "inline-block", verticalAlign: "middle" }}>
    <div style={{ background: colour, width: `${Math.min(Math.max(percent, 0), 100)}%`, height: "100%", borderRadius: 4 }} /></div>;
}

export function SystemTab({ deviceId }: { deviceId: string }) {
  const { can } = useApp();
  const { data, error, reload } = useData<any>(`devices/${deviceId}/profile`);
  const { run, busy } = useAction();
  const [shown, setShown] = useState<{ volume: string; keyId: string; recoveryPassword: string } | null>(null);
  useEffect(() => { if (!shown) return; const timer = setTimeout(() => setShown(null), 60000); return () => clearTimeout(timer); }, [shown]);
  if (!data) return <div className="card"><ErrorNote error={error} /><div className="empty">Loading…</div></div>;

  const p = data.profile || {};
  const hw = p.hardware || {}, os = p.os || {}, users = p.users || {}, sec = p.security || {}, ev = p.events || {}, bat = p.battery || {};
  const refresh = async () => { await run(() => api(`devices/${deviceId}/profile/refresh`, { method: "POST" }), "Requested; the new profile arrives a minute or two after the device next checks in"); };
  const reveal = async (row: any) => {
    const result = await run(() => api<any>(`devices/${deviceId}/recovery-keys/${row.id}/reveal`, { method: "POST" }));
    if (result) setShown(result);
  };

  return (
    <>
      <div className="card" style={{ marginBottom: 14 }}>
        <ErrorNote error={error} />
        <div className="row">
          <span className="small muted" style={{ flex: 1 }}>
            {data.collectedAt ? <>Collected {ago(data.collectedAt)} ({fmtTime(data.collectedAt)}). The agent refreshes this every 6 hours.</>
              : "This device has not sent a system profile yet. It needs an agent from this release or later, and arrives a few minutes after the agent starts."}
          </span>
          <button onClick={reload} disabled={busy}>Reload</button>
          {can("respond") && <button className="primary" disabled={busy} onClick={refresh}>Refresh from device</button>}
        </div>
        {(data.findings || []).length > 0 && <>
          <h3 style={{ marginTop: 12 }}>Things to look at</h3>
          {data.findings.map((f: any, i: number) => (
            <div key={i} className="row small" style={{ padding: "4px 0", borderTop: i ? "1px solid rgba(148,163,184,0.12)" : undefined }}>
              <Sev level={f.severity} /> <span className="muted" style={{ minWidth: 80 }}>{displayValue(f.area)}</span> <b>{displayValue(f.title)}</b> <span className="muted">{displayValue(f.detail)}</span>
            </div>))}
        </>}
        {data.collectedAt && (data.findings || []).length === 0 && <p className="small" style={{ marginTop: 10 }}><Pill value="no problems found" tone="good" /></p>}
      </div>

      {data.collectedAt && <div className="grid k2">
        <div className="card">
          <h3>Hardware</h3>
          <Kv rows={[
            ["Make and model", makeModel(hw.manufacturer, hw.model)],
            ["Serial", hw.serial && <span className="mono">{displayValue(hw.serial)}</span>],
            ["Type", hw.chassis],
            ["Processor", hw.cpu?.name && `${hw.cpu.name} (${hw.cpu.cores ?? "?"} cores, ${hw.cpu.threads ?? "?"} threads)`],
            ["Memory", hw.memory?.totalGb !== undefined && `${gb(hw.memory.totalGb)}${hw.memory.slotsUsed ? ` in ${hw.memory.slotsUsed} module(s)` : ""}`],
            ["Memory modules", (hw.memory?.modules || []).length > 0 && <span className="small">{displayValue(hw.memory.modules.map((m: any) => [m.slot, gb(m.sizeGb), m.speedMhz && `${m.speedMhz} MHz`, m.manufacturer].filter(Boolean).join(" ")).join(" · "))}</span>],
            ["Graphics", (hw.gpus || []).map((g: any) => g.name).filter(Boolean).join(", ")],
            ["BIOS / firmware", [hw.biosVersion, hw.biosDate && fmtTime(hw.biosDate).split(",")[0]].filter(Boolean).join(" · ")],
            ["TPM", hw.tpm?.present == null ? undefined : hw.tpm.present ? `${hw.tpm.version || "present"}${hw.tpm.ready === false ? " (not ready)" : ""}${hw.tpm.manufacturer ? ` · ${hw.tpm.manufacturer}` : ""}` : <Pill value="none" tone="warn" />],
            ["Secure Boot", hw.secureBoot === undefined || hw.secureBoot === null ? undefined : hw.secureBoot ? <Pill value="on" tone="good" /> : <Pill value="off" tone="warn" />],
          ]} />
        </div>
        <div className="card">
          <h3>Operating system</h3>
          <Kv rows={[
            ["Name", os.name],
            ["Version", [os.displayVersion, os.build || os.version].filter(Boolean).join(" · build ")],
            ["Architecture", os.architecture],
            ["Joined to", [os.joinType, os.domain].filter(Boolean).join(" · ")],
            ["Activation", os.activation && <Pill value={os.activation} tone={os.activation === "Licensed" ? "good" : "warn"} />],
            ["Installed", os.installDate && fmtTime(os.installDate)],
            ["Last restart", os.lastBoot && <>{fmtTime(os.lastBoot)} ({ago(os.lastBoot)})</>],
            ["Restart pending", os.rebootPending ? <><Pill value="yes" tone="warn" /> <span className="small muted">{list(os.rebootReasons)}</span></> : os.rebootPending === false ? "No" : undefined],
            ["Last update installed", os.lastUpdateInstalled && <>{fmtTime(os.lastUpdateInstalled)} ({ago(os.lastUpdateInstalled)})</>],
            ["Time zone", os.timezone],
          ]} />
        </div>
      </div>}

      {data.collectedAt && <>
        <div className="card" style={{ marginTop: 14 }}>
          <h3>Disks</h3>
          <Table rows={p.disks || []} empty="No physical disks reported."
                 columns={[{ key: "name", label: "Disk", render: (d) => <><b>{displayValue(d.name || d.model)}</b><div className="small muted mono">{[d.serial, d.busType, d.mediaType].filter((x: string) => x && x !== "Unspecified").join(" · ")}</div></> },
                           { key: "sizeGb", label: "Size", render: (d) => gb(d.sizeGb) },
                           { key: "health", label: "Health", render: (d) => <Pill value={d.health || "unknown"} tone={healthTone(d.health)} /> },
                           { key: "wearPercent", label: "Wear", render: (d) => typeof d.wearPercent === "number" ? <><Meter percent={d.wearPercent} tone={d.wearPercent >= 80 ? "bad" : d.wearPercent >= 50 ? "warn" : "good"} /> {d.wearPercent}%</> : "—" },
                           { key: "temperatureC", label: "Temp", render: (d) => typeof d.temperatureC === "number" && d.temperatureC > 0 ? `${d.temperatureC} °C` : "—" },
                           { key: "powerOnHours", label: "Powered on", render: (d) => typeof d.powerOnHours === "number" ? `${Math.round(d.powerOnHours / 24)} days` : "—" },
                           { key: "errors", label: "Errors", render: (d) => { const n = (d.readErrors || 0) + (d.writeErrors || 0); return n ? <Pill value={`${n}`} tone="bad" /> : "0"; } }]} />
        </div>

        <div className="card" style={{ marginTop: 14 }}>
          <h3>Volumes and encryption</h3>
          <Table rows={p.volumes || []} empty="No volumes reported."
                 columns={[{ key: "mount", label: "Volume", render: (v) => <><b>{displayValue(v.mount)}</b> {v.system && <Pill value="system" tone="blue" />}<div className="small muted">{[v.label, v.fileSystem].filter(Boolean).join(" · ")}</div></> },
                           { key: "free", label: "Free space", render: (v) => { const pc = v.sizeGb ? (100 * (v.freeGb || 0)) / v.sizeGb : 0; return <><Meter percent={100 - pc} tone={pc < 5 ? "bad" : pc < 15 ? "warn" : "good"} /> {gb(v.freeGb)} free of {gb(v.sizeGb)} ({Math.round(pc)}%)</>; } },
                           { key: "encryption", label: "Encryption", render: (v) => { const e = v.encryption; if (!e) return <Pill value="not reported" tone="muted" />;
                               const on = /FullyEncrypted|on|encrypted/i.test(`${e.status} ${e.protection}`) && !/Off|FullyDecrypted/i.test(String(e.protection ?? ""));
                               return <><Pill value={e.status || "unknown"} tone={on ? "good" : "warn"} />{e.protection && <span className="small muted"> protection {String(e.protection).toLowerCase()}</span>}
                                 <div className="small muted">{[e.method, list(e.protectors)].filter((x: string) => x && x !== "—").join(" · ")}{typeof e.percent === "number" && e.percent < 100 ? ` · ${e.percent}%` : ""}</div></>; } }]} />
          <h3 style={{ marginTop: 14 }}>Recovery keys</h3>
          <p className="small muted">BitLocker (or FileVault) recovery keys the agent read from the device. They are encrypted here; revealing one asks for your password again and is audited. Keys the device no longer has are kept, marked removed.</p>
          {shown && <div className="card" style={{ marginBottom: 10 }}>
            <div className="small muted">{shown.volume} · key ID <span className="mono">{shown.keyId}</span></div>
            <pre className="mono" style={{ fontSize: 16, userSelect: "all", whiteSpace: "pre-wrap" }}>{shown.recoveryPassword}</pre>
            <button onClick={() => navigator.clipboard?.writeText(shown.recoveryPassword)}>Copy</button>{" "}<button onClick={() => setShown(null)}>Hide now</button>
            <span className="muted small"> Hidden automatically after 60 seconds.</span>
          </div>}
          <Table rows={data.recoveryKeys || []} empty="No recovery keys stored for this device."
                 columns={[{ key: "volume", label: "Volume" }, { key: "keyId", label: "Key ID", render: (k) => <span className="mono small">{displayValue(k.keyId)}</span> },
                           { key: "kind", label: "Type" }, { key: "status", label: "Status", render: (k) => <Pill value={k.status} tone={k.status === "active" ? "good" : "muted"} /> },
                           { key: "lastSeen", label: "Last seen", render: (k) => ago(k.lastSeen) },
                           { key: "reveal", label: "", className: "right", render: (k) => can("respond") && <button className="small" disabled={busy} onClick={() => reveal(k)}>Reveal</button> }]} />
        </div>

        <div className="card" style={{ marginTop: 14 }}>
          <h3>Users</h3>
          {(users.sessions || []).length > 0 && <p className="small">Signed in now: {users.sessions.map((s: any) => <span key={`${s.user}${s.session}`} style={{ marginRight: 10 }}><b>{displayValue(s.user)}</b> <span className="muted">({displayValue(s.state)}{s.idle && s.idle !== "none" && s.idle !== "." ? `, idle ${s.idle}` : ""}{s.logonTime ? `, since ${s.logonTime}` : ""})</span></span>)}</p>}
          {(users.administratorsGroup || []).length > 0 && <p className="small">Administrators group: {displayValue(users.administratorsGroup.join(", "))}</p>}
          <Table rows={users.local || []} empty="No local accounts reported."
                 columns={[{ key: "name", label: "Local account", render: (u) => <><b>{displayValue(u.name)}</b> {u.admin && <Pill value="admin" tone="warn" />}<div className="small muted">{displayValue(u.fullName || u.description)}</div></> },
                           { key: "enabled", label: "Enabled", render: (u) => yesNo(u.enabled) },
                           { key: "lastLogon", label: "Last sign-in", render: (u) => u.lastLogon ? ago(u.lastLogon) : "never" },
                           { key: "passwordLastSet", label: "Password set", render: (u) => <>{u.passwordLastSet ? ago(u.passwordLastSet) : "—"}{u.passwordRequired === false && u.enabled && <> <Pill value="no password required" tone="bad" /></>}</> }]} />
          {(users.profiles || []).length > 0 && <>
            <h3 style={{ marginTop: 14 }}>User profiles on disk</h3>
            <Table rows={users.profiles} columns={[{ key: "name", label: "User" }, { key: "path", label: "Folder", render: (u) => <span className="mono small">{displayValue(u.path)}</span> },
                                                   { key: "lastUse", label: "Last used", render: (u) => u.lastUse ? ago(u.lastUse) : "—" },
                                                   { key: "loaded", label: "Loaded", render: (u) => yesNo(u.loaded) }]} />
          </>}
        </div>

        <div className="grid k2" style={{ marginTop: 14 }}>
          <div className="card">
            <h3>Security</h3>
            <Kv rows={[
              ["Antivirus", (sec.antivirus || []).length ? sec.antivirus.map((a: any) => <div key={a.name}>{displayValue(a.name)} <Pill value={a.enabled ? "on" : "off"} tone={a.enabled ? "good" : "bad"} /> {a.upToDate === false && <Pill value="out of date" tone="warn" />}</div>) : undefined],
              ["Defender", sec.defender && <span className="small">{sec.defender.passive ? "passive mode" : sec.defender.realtime ? "real-time on" : "real-time off"}{typeof sec.defender.signatureAgeDays === "number" ? ` · signatures ${sec.defender.signatureAgeDays} day(s) old` : ""}{sec.defender.tamperProtection ? " · tamper protection on" : ""}</span>],
              ["Firewall", (sec.firewall || []).length ? sec.firewall.map((f: any) => <span key={f.profile} style={{ marginRight: 8 }}>{displayValue(f.profile)} <Pill value={f.enabled ? "on" : "off"} tone={f.enabled ? "good" : "bad"} /></span>) : undefined],
              ["UAC", sec.uac == null ? undefined : sec.uac ? "On" : <Pill value="off" tone="bad" />],
              ["Remote Desktop", sec.rdpEnabled == null ? undefined : sec.rdpEnabled ? <Pill value="enabled" tone="warn" /> : "Disabled"],
              ["SMBv1", sec.smb1 == null ? undefined : sec.smb1 ? <Pill value="enabled" tone="bad" /> : "Disabled"],
              ["LSA protection", sec.lsaProtection == null ? undefined : yesNo(sec.lsaProtection)],
              ["SSH", sec.sshRootLogin !== undefined ? `root login ${sec.sshRootLogin}` : undefined],
              ["SELinux", sec.selinux || undefined],
              ["AppArmor", sec.apparmor == null ? undefined : yesNo(sec.apparmor)],
              ["Gatekeeper", sec.gatekeeper == null ? undefined : sec.gatekeeper ? "On" : <Pill value="off" tone="warn" />],
              ["System Integrity Protection", sec.sip == null ? undefined : sec.sip ? "On" : <Pill value="off" tone="bad" />],
            ]} />
          </div>
          <div className="card">
            <h3>Battery</h3>
            {!bat.present ? <p className="muted small">No battery (desktop or not reported).</p> : <Kv rows={[
              ["Charge", typeof bat.chargePercent === "number" ? `${bat.chargePercent}%` : "—"],
              ["Status", bat.status],
              ["Health", typeof bat.healthPercent === "number" ? <><Meter percent={bat.healthPercent} tone={bat.healthPercent < 60 ? "bad" : bat.healthPercent < 80 ? "warn" : "good"} /> {displayValue(bat.healthPercent)}% of design capacity</> : undefined],
              ["Charge cycles", bat.cycleCount || undefined],
            ]} />}
            <h3 style={{ marginTop: 14 }}>Problems in the event log</h3>
            <Kv rows={[
              ["Errors (24 h)", ev.errorsLast24h ?? undefined],
              ["Critical (24 h)", ev.criticalLast24h ? <Pill value={`${ev.criticalLast24h}`} tone="bad" /> : ev.criticalLast24h],
              ["Unexpected shutdowns (7 days)", ev.unexpectedShutdowns7d ? <Pill value={`${ev.unexpectedShutdowns7d}`} tone="warn" /> : ev.unexpectedShutdowns7d],
              ["Blue screens (7 days)", ev.bluescreens7d ? <Pill value={`${ev.bluescreens7d}`} tone="bad" /> : ev.bluescreens7d],
              ["Disk errors (7 days)", ev.diskErrors7d ? <Pill value={`${ev.diskErrors7d}`} tone="bad" /> : ev.diskErrors7d],
              ["Failed services", (p.services?.autoStopped || []).length ? <span className="small">{displayValue(p.services.autoStopped.join(", "))}</span> : undefined],
            ]} />
          </div>
        </div>

        {(ev.recent || []).length > 0 && <div className="card" style={{ marginTop: 14 }}>
          <h3>Recent errors</h3>
          <Table rows={ev.recent} columns={[{ key: "time", label: "When", render: (e) => e.time ? ago(e.time) : "—" },
                                            { key: "level", label: "Level", render: (e) => <Pill value={e.level || "error"} tone={/critical/i.test(e.level) ? "bad" : /warn/i.test(e.level) ? "warn" : "muted"} /> },
                                            { key: "source", label: "Source", render: (e) => <span className="small">{displayValue(e.source)}{e.id ? ` (${e.id})` : ""}</span> },
                                            { key: "message", label: "Message", render: (e) => <span className="small">{displayValue(e.message)}</span> }]} />
        </div>}

        <div className="card" style={{ marginTop: 14 }}>
          <h3>Network</h3>
          <Table rows={p.network?.adapters || []} empty="No network adapters reported."
                 columns={[{ key: "name", label: "Adapter", render: (a) => <><b>{displayValue(a.name)}</b><div className="small muted">{displayValue(a.description)}</div></> },
                           { key: "status", label: "Status", render: (a) => <Pill value={a.status || "unknown"} tone={/up/i.test(a.status) ? "good" : "muted"} /> },
                           { key: "ipv4", label: "Address", render: (a) => <span className="mono small">{list(a.ipv4)}{a.wifiSsid ? <div>Wi-Fi: {displayValue(a.wifiSsid)}</div> : null}</span> },
                           { key: "gateway", label: "Gateway / DNS", render: (a) => <span className="mono small">{list(a.gateway)}<div className="muted">{list(a.dns)}</div></span> },
                           { key: "mac", label: "MAC", render: (a) => <span className="mono small">{displayValue(a.mac)}</span> },
                           { key: "speed", label: "Speed", render: (a) => <span className="small">{displayValue(a.speed)}{a.dhcp ? ` · DHCP ${String(a.dhcp).toLowerCase()}` : ""}</span> }]} />
        </div>

        <div className="grid k2" style={{ marginTop: 14 }}>
          <div className="card">
            <h3>Starts with the computer</h3>
            <Table rows={p.startup || []} empty="Nothing reported."
                   columns={[{ key: "name", label: "Name", render: (s) => <><b>{displayValue(s.name)}</b><div className="mono small muted" style={{ wordBreak: "break-all" }}>{displayValue(s.command)}</div></> },
                             { key: "location", label: "Where", render: (s) => <span className="small">{displayValue(s.location)}{s.user ? ` · ${s.user}` : ""}</span> }]} />
          </div>
          <div className="card">
            <h3>Printers</h3>
            <Table rows={p.printers || []} empty="No printers."
                   columns={[{ key: "name", label: "Printer", render: (r) => <><b>{displayValue(r.name)}</b>{r.shared && <> <Pill value="shared" tone="blue" /></>}<div className="small muted">{displayValue(r.driver)}</div></> },
                             { key: "port", label: "Port", render: (r) => <span className="small mono">{displayValue(r.port)}</span> }]} />
            <h3 style={{ marginTop: 14 }}>Monitors</h3>
            {(p.monitors || []).length === 0 ? <p className="muted small">None reported.</p> :
              p.monitors.map((m: any, i: number) => <div key={i} className="small">{[m.manufacturer, m.model].filter(Boolean).join(" ") || "Monitor"} <span className="muted mono">{displayValue(m.serial)}{m.year ? ` · ${m.year}` : ""}</span></div>)}
            <h3 style={{ marginTop: 14 }}>Shared folders</h3>
            {(p.shares || []).length === 0 ? <p className="muted small">None.</p> :
              p.shares.map((s: any) => <div key={s.name} className="small"><b>{displayValue(s.name)}</b> <span className="mono muted">{displayValue(s.path)}</span></div>)}
          </div>
        </div>
      </>}
    </>
  );
}
