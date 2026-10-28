import { displayValue } from "../components/DisplayValue";
import { Fragment, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ago, fmtTime } from "../api";
import { useApp } from "../app-context";
import { PageHead, Pill, Sev, Stat, Table, Tabs, useData, useListData } from "../components/ui";

// Active Directory, per customer domain. Built from what the Fenrir agent on each domain controller reports:
// a directory snapshot every 6 hours (system profile) and live Security-log events.

const TYPE_LABEL: Record<string, string> = {
  "ad.group.member_added": "Added to group", "ad.group.member_removed": "Removed from group", "ad.user.created": "User created",
  "ad.user.deleted": "User deleted", "ad.user.enabled": "User enabled", "ad.user.disabled": "User disabled", "ad.user.changed": "User changed",
  "ad.user.password_reset": "Password reset", "ad.user.locked_out": "Locked out", "ad.user.unlocked": "Unlocked",
  "ad.computer.created": "Computer joined", "ad.computer.deleted": "Computer removed", "ad.computer.changed": "Computer delegation",
  "ad.kerberos.rc4_service_ticket": "RC4 ticket", "ad.kerberos.asrep": "No pre-auth ticket", "ad.kerberos.preauth_failed": "Kerberos failure",
  "ad.kerberos.tgt_failed": "Kerberos failure", "ad.ntlm.failed": "NTLM failure", "ad.replication.requested": "Replication (DCSync)",
  "ad.adminsdholder.modified": "AdminSDHolder", "ad.object.sensitive_change": "Sensitive attribute", "ad.gpo.changed": "GPO change",
  "ad.trust.created": "Trust created", "ad.trust.removed": "Trust removed", "ad.dsrm.password_set": "DSRM password", "ad.log.cleared": "Log cleared",
  "ad.sidhistory.added": "SID history", "ad.policy.domain_changed": "Domain policy", "ad.policy.kerberos_changed": "Kerberos policy",
};
const RISKY_LABEL: Record<string, string> = {
  kerberoastable: "Kerberoastable (user accounts with SPNs)", asrepRoastable: "No Kerberos pre-authentication", passwordNotRequired: "Password not required",
  reversibleEncryption: "Reversible password encryption", privilegedPasswordNeverExpires: "Privileged, password never expires",
  privilegedStale: "Privileged, unused for 90 days", privilegedOldPassword: "Privileged, password over a year old", sidHistory: "SID history",
  adminCountOrphans: "adminCount=1 but no longer privileged", unconstrainedDelegation: "Unconstrained delegation",
  resourceBasedDelegation: "Resource-based delegation", unsupportedOs: "Unsupported Windows",
};

export default function ActiveDirectory() {
  const { tenantId, tenantName } = useApp();
  const { data } = useListData<any>("ad/domains", { tenant_id: tenantId });
  const [selected, setSelected] = useState<{ tenantId: string; domain: string } | null>(null);
  useEffect(() => {
    if (!selected && data?.length) setSelected({ tenantId: data[0].tenantId, domain: data[0].domain });
  }, [data, selected]);
  return (
    <>
      <PageHead title="Active Directory" subtitle="Domains, privileged access and attacks, from the Fenrir agent on each domain controller. Servers are detected as domain controllers automatically." />
      {data && data.length === 0 && (
        <div className="card">
          <h3 style={{ marginTop: 0 }}>No domain controllers yet</h3>
          <p className="muted">Install the Fenrir agent on your domain controllers. Each one detects that it is a DC within the hour (or when it is
            promoted), starts reading its Security log for directory changes and attacks, and sends a full directory health check every 6 hours.</p>
          <Link to="/deploy">Deploy the agent →</Link>
        </div>
      )}
      {data && data.length > 0 && (
        <div className="grid k3" style={{ marginBottom: 14 }}>
          {data.map((d) => {
            const active = selected?.tenantId === d.tenantId && selected?.domain === d.domain;
            return (
              <button key={d.tenantId + d.domain} className={`card domain-card ${active ? "active" : ""}`} style={{ textAlign: "left", cursor: "pointer" }}
                      onClick={() => setSelected({ tenantId: d.tenantId, domain: d.domain })}>
                <div className="row" style={{ alignItems: "baseline" }}>
                  <b style={{ fontSize: 16, flex: 1 }}>{displayValue(d.domain)}</b>
                  {d.score !== null && <span className={`badge tone-${d.score >= 80 ? "good" : d.score >= 50 ? "warn" : "bad"}`}>{displayValue(d.score)}/100</span>}
                </div>
                <div className="small muted">{tenantName(d.tenantId)}{d.netbios ? ` · ${d.netbios}` : ""}{d.mode ? ` · ${d.mode}` : ""}</div>
                <div className="row small" style={{ marginTop: 8 }}>
                  {(["critical", "high", "medium"] as const).map((s) => d.findings[s] > 0 && <span key={s}><Sev level={s} /> {displayValue(d.findings[s])}</span>)}
                  <span className="muted">{displayValue(d.agents.filter((a: any) => a.online).length)}/{displayValue(d.agents.length)} DC agents online</span>
                </div>
              </button>
            );
          })}
        </div>
      )}
      {selected && <DomainDetail key={selected.tenantId + selected.domain} tenantId={selected.tenantId} domain={selected.domain} />}
    </>
  );
}

function Names({ rows, keyName = "sam" }: { rows: any[]; keyName?: string }) {
  const [all, setAll] = useState(false);
  const list = (rows || []).map((r) => (typeof r === "string" ? r : r[keyName] || r.name)).filter(Boolean);
  if (!list.length) return null;
  const shown = all ? list : list.slice(0, 12);
  return (
    <div className="row small" style={{ flexWrap: "wrap", gap: 4, marginTop: 6 }}>
      {shown.map((n: string, i: number) => <span key={n + i} className="chip mono">{n}</span>)}
      {list.length > shown.length && <button className="small" onClick={() => setAll(true)}>+{list.length - shown.length} more</button>}
    </div>
  );
}

function DomainDetail({ tenantId, domain }: { tenantId: string; domain: string }) {
  const { data } = useData<any>(`ad/domains/${tenantId}/${encodeURIComponent(domain)}`);
  const [tab, setTab] = useState("Findings");
  if (!data) return null;
  const counts = data.counts || {};
  const openAlerts = (data.alerts || []).filter((a: any) => !["resolved", "closed", "false_positive"].includes(a.status));
  return (
    <>
      <div className="grid k4" style={{ marginBottom: 14 }}>
        <Stat label="Health score" value={data.score ?? "—"} hint={data.snapshotAt ? `checked ${ago(data.snapshotAt)}` : "waiting for the first directory snapshot"} />
        <Stat label="Users" value={counts.enabledUsers ?? "—"} hint={counts.users !== undefined ? `${counts.users} in total` : undefined} />
        <Stat label="Computers" value={counts.enabledComputers ?? counts.computers ?? "—"} hint={counts.gpos !== undefined ? `${counts.gpos} group policies` : undefined} />
        <Stat label="Open AD alerts" value={openAlerts.length} accent={openAlerts.length ? "#f87171" : undefined} hint={`${(data.activity || []).length} directory events in 7 days`} />
      </div>
      {openAlerts.length > 0 && (
        <div className="card" style={{ marginBottom: 14 }}>
          <h3 style={{ marginTop: 0 }}>Active Directory alerts</h3>
          {openAlerts.slice(0, 8).map((a: any) => (
            <div key={a.id} className="row small" style={{ padding: "4px 0" }}>
              <Sev level={a.severity} /><Link to={`/alerts?focus=${a.id}`} style={{ flex: 1 }}>{displayValue(a.title)}</Link><span className="muted">{ago(a.createdAt)}</span>
            </div>
          ))}
        </div>
      )}
      <Tabs tabs={["Findings", "Privileged groups", "Accounts at risk", "Activity", "Domain controllers", "Policies"]} active={tab} onChange={setTab} />
      {tab === "Findings" && (
        <div className="card">
          {!data.snapshotAt && <p className="muted">The domain controller has not sent its directory snapshot yet (it does within a few minutes of starting, then every 6 hours).</p>}
          {data.findingsList.length === 0 && data.snapshotAt && <p className="muted">No findings. Nice work.</p>}
          {data.findingsList.map((f: any) => (
            <div key={f.id} className="finding" style={{ padding: "10px 0", borderBottom: "1px solid var(--line)" }}>
              <div className="row"><Sev level={f.severity} /><b style={{ flex: 1 }}>{displayValue(f.title)}</b>{f.mitre?.map((m: string) => <span key={m} className="chip">{m}</span>)}</div>
              <div className="small" style={{ marginTop: 4 }}>{displayValue(f.detail)}</div>
              <div className="small" style={{ marginTop: 4 }}><b>Fix:</b> {displayValue(f.fix)}</div>
              <Names rows={f.affected} />
            </div>
          ))}
        </div>
      )}
      {tab === "Privileged groups" && (
        <div className="card">
          <Table rows={data.privilegedGroups} empty="No privileged group data yet."
                 columns={[{ key: "label", label: "Group", render: (g) => <><b>{displayValue(g.name)}</b>{g.name !== g.label && <div className="small muted">{displayValue(g.label)}</div>}</> },
                           { key: "memberCount", label: "Members", className: "right" },
                           { key: "members", label: "Who", render: (g) => <Names rows={g.members} /> }]} />
          <p className="small muted">Members are listed recursively (nested groups expanded). Changes to these groups alert immediately.</p>
        </div>
      )}
      {tab === "Accounts at risk" && (
        <div className="card">
          {Object.entries(RISKY_LABEL).map(([key, label]) => {
            const value = data.risky?.[key];
            if (!Array.isArray(value) || !value.length) return null;
            return <div key={key} style={{ marginBottom: 12 }}><b>{label}</b> <span className="muted">({value.length})</span><Names rows={value} /></div>;
          })}
          <p className="small muted">Stale accounts: {displayValue(data.risky?.staleUsers ?? "—")} users and {displayValue(data.risky?.staleComputers ?? "—")} computers not used in 90 days.</p>
        </div>
      )}
      {tab === "Activity" && (
        <div className="card">
          <Table rows={data.activity} empty="No directory changes or attacks recorded in the last 7 days."
                 columns={[{ key: "at", label: "When", render: (e) => <span className="small">{fmtTime(e.at)}</span> },
                           { key: "type", label: "What", render: (e) => <Pill value={TYPE_LABEL[e.type] || e.type} tone={e.fields.privilegedGroup || e.type === "ad.replication.requested" ? "bad" : "muted"} /> },
                           { key: "summary", label: "Detail", render: (e) => <>{displayValue(e.summary)}{e.fields.privilegedGroup && <> <Pill value={e.fields.privilegedGroup} tone="warn" /></>}</> },
                           { key: "dc", label: "Domain controller", render: (e) => <span className="small muted">{displayValue(e.fields.domainController)}</span> }]} />
        </div>
      )}
      {tab === "Domain controllers" && (
        <div className="card">
          <Table rows={data.controllers} empty="No domain controllers listed yet."
                 columns={[{ key: "name", label: "Domain controller", render: (dc) => <b>{displayValue(dc.name)}</b> },
                           { key: "site", label: "Site" }, { key: "os", label: "OS", render: (dc) => <span className="small">{displayValue(dc.os)}</span> },
                           { key: "roles", label: "FSMO roles", render: (dc) => (dc.roles || []).map((r: string) => <span key={r} className="chip">{r}</span>) },
                           { key: "gc", label: "GC", render: (dc) => dc.globalCatalog ? "Yes" : "—" },
                           { key: "agent", label: "Fenrir", render: (dc) => dc.agent ? <Link to={`/devices/${dc.agent.deviceId}`}><span className={`dot ${dc.agent.online ? "on" : "off"}`} /> {dc.agent.online ? "online" : `seen ${ago(dc.agent.lastSeen)}`}</Link> : <Pill value="not installed" tone="bad" /> }]} />
        </div>
      )}
      {tab === "Policies" && (
        <div className="grid k2">
          <div className="card">
            <h3 style={{ marginTop: 0 }}>Password and lockout</h3>
            <dl className="kv compact">
              {[["Minimum length", data.passwordPolicy.minLength], ["Complexity", yes(data.passwordPolicy.complexity)], ["Maximum age (days)", data.passwordPolicy.maxAgeDays || "never"],
                ["History", data.passwordPolicy.historyCount], ["Lockout after", data.passwordPolicy.lockoutThreshold === 0 ? "never" : `${data.passwordPolicy.lockoutThreshold} failures`],
                ["krbtgt password age", data.krbtgt.passwordAgeDays !== undefined ? `${data.krbtgt.passwordAgeDays} days` : undefined],
                ["LAPS", data.laps.windowsSchema ? "Windows LAPS" : data.laps.legacySchema ? "Legacy LAPS" : "not deployed"],
                ["LAPS coverage", data.laps.eligibleComputers ? `${data.laps.coveredComputers}/${data.laps.eligibleComputers} computers` : undefined],
                ["AD Recycle Bin", yes(data.recycleBin)], ["Forest", data.domainInfo.forest], ["PDC emulator", data.domainInfo.pdcEmulator]]
                .filter(([, v]) => v !== undefined && v !== null && v !== "")
                .map(([k, v]) => <Fragment key={k as string}><dt>{displayValue(k)}</dt><dd>{String(v)}</dd></Fragment>)}
            </dl>
          </div>
          <div className="card">
            <h3 style={{ marginTop: 0 }}>Audit policy on the DCs</h3>
            {(data.auditPolicy || []).length === 0 ? <p className="muted small">Not reported yet.</p> :
              <Table rows={data.auditPolicy} columns={[{ key: "name", label: "Subcategory" },
                { key: "success", label: "Success", render: (a) => a.success ? "✓" : <span style={{ color: "#f87171" }}>off</span> },
                { key: "failure", label: "Failure", render: (a) => a.failure ? "✓" : <span className="muted">off</span> }]} />}
          </div>
          <div className="card">
            <h3 style={{ marginTop: 0 }}>Recently changed group policies</h3>
            <Table rows={(data.gpos || []).slice(0, 15)} empty="No group policy data."
                   columns={[{ key: "name", label: "GPO" }, { key: "modified", label: "Modified", render: (g) => <span className="small">{g.modified ? ago(g.modified) : "—"}</span> },
                             { key: "status", label: "Status", render: (g) => <span className="small muted">{displayValue(g.status)}</span> }]} />
          </div>
          <div className="card">
            <h3 style={{ marginTop: 0 }}>Trusts</h3>
            <Table rows={data.trusts} empty="No trusts."
                   columns={[{ key: "name", label: "Domain" }, { key: "direction", label: "Direction" }, { key: "type", label: "Type" },
                             { key: "sid", label: "SID filtering", render: (t) => t.sidFilteringQuarantined ? "on" : "off" }]} />
          </div>
        </div>
      )}
    </>
  );
}

const yes = (v: any) => v === true ? "on" : v === false ? "off" : undefined;
