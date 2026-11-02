import { displayValue } from "../components/DisplayValue";
import { useState } from "react";
import { ErrorNote, Pill, Table, Tabs, useData } from "../components/ui";

// Teams, SharePoint and OneDrive for one Microsoft 365 connection. Sharing settings are enforced through the
// "Security standards" (no Anyone links, no guest resharing); leavers' OneDrive is handed over in offboarding.
export default function M365Collaboration({ connection }: { connection: any }) {
  const base = `m365/connections/${connection.id}/collaboration`;
  const [tab, setTab] = useState("Teams");
  return (
    <>
      <Tabs tabs={["Teams", "SharePoint sites", "Sharing"]} active={tab} onChange={setTab} />
      {tab === "Teams" && <Teams base={base} />}
      {tab === "SharePoint sites" && <Sites base={base} />}
      {tab === "Sharing" && <Sharing base={base} />}
    </>
  );
}

function Teams({ base }: { base: string }) {
  const { data, error } = useData<any[]>(base + "/teams", {}, [], true);
  return <div className="card"><ErrorNote error={error} />
    <Table rows={data} empty={data ? "No teams." : "Loading…"} columns={[
      { key: "name", label: "Team", render: (t) => <><b>{displayValue(t.name)}</b><div className="small muted">{displayValue(t.visibility)}</div></> },
      { key: "owners", label: "Owners", render: (t) => <>{t.owners.join(", ") || "—"}{t.issue && <div><Pill value={t.issue} tone={t.owners.length ? "warn" : "bad"} /></div>}</> },
      { key: "members", label: "Members", className: "right" },
      { key: "guests", label: "Guests", className: "right", render: (t) => t.guests ? <span style={{ color: "#fcd34d" }}>{t.guests}</span> : 0 }]} /></div>;
}

function Sites({ base }: { base: string }) {
  const { data, error } = useData<any[]>(base + "/sites", {}, [], true);
  return <div className="card"><ErrorNote error={error} />
    <Table rows={(data || []).map((s, i) => ({ ...s, id: String(i) }))} empty={data ? "No sites." : "Loading…"} columns={[
      { key: "url", label: "Site", render: (s) => <><b className="small">{displayValue(s.url)}</b><div className="small muted">{displayValue(s.template)} · {displayValue(s.owner)}</div></> },
      { key: "storageGB", label: "Storage (GB)", className: "right" },
      { key: "files", label: "Files", className: "right" },
      { key: "lastActivity", label: "Last activity" }]} /></div>;
}

function Sharing({ base }: { base: string }) {
  const { data, error } = useData<any>(base + "/sharing");
  return <div className="card"><ErrorNote error={error} />
    {data && <>
      <p><b>External sharing:</b> <Pill value={data.label} tone={data.sharingCapability === "externalUserAndGuestSharing" ? "bad" : "good"} /></p>
      <p><b>Guests can reshare:</b> {data.isResharingByExternalUsersEnabled ? <Pill value="yes" tone="warn" /> : <Pill value="no" tone="good" />}</p>
      {data.sharingAllowedDomainList.length > 0 && <p className="small">Only these domains: {data.sharingAllowedDomainList.join(", ")}</p>}
      {data.sharingBlockedDomainList.length > 0 && <p className="small">Blocked domains: {data.sharingBlockedDomainList.join(", ")}</p>}
      <p className="small muted">To enforce these across customers, assign the "no 'Anyone' links" and "Guests cannot reshare" standards in Partner and standards › Security standards.</p>
    </>}</div>;
}
