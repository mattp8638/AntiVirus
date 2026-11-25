// Microsoft 365 diagnostics (M365-32): public domain and email checks, and a read-only Graph explorer limited to
// approved directory, policy, device, report and security resources. Every explorer call is audited.
import { useState } from "react";
import { api } from "../api";
import { Pill, Table, useAction } from "../components/ui";

const TONE: Record<string, string> = { pass: "good", warn: "warn", fail: "bad", info: "neutral", error: "bad" };

export function DomainDiagnostics() {
  const { run, busy } = useAction();
  const [domain, setDomain] = useState("");
  const [out, setOut] = useState<any>(null);
  return (
    <div className="card" style={{ marginTop: 12 }}>
      <h3>Domain and email diagnostics</h3>
      <p className="small muted">Reads public DNS (MX, SPF, DMARC, DKIM, autodiscover, MTA-STS) and Microsoft's public sign-in information. Nothing is changed.</p>
      <div className="row" style={{ gap: 8 }}><input value={domain} placeholder="contoso.com" onChange={(e) => setDomain(e.target.value)} />
        <button disabled={busy || !domain} onClick={async () => setOut(await run(() => api<any>("m365/tools/domain", { body: { domain } })))}>Check</button></div>
      {out && <Table rows={out.checks} columns={[
        { key: "check", label: "Check" }, { key: "status", label: "", render: (c: any) => <Pill value={c.status} tone={TONE[c.status]} /> },
        { key: "detail", label: "Result", render: (c: any) => <span className="small">{c.detail}{c.records.length > 0 && <div className="muted">{c.records.join(" | ")}</div>}</span> },
      ]} />}
    </div>
  );
}

export function GraphExplorer({ connection }: { connection: any }) {
  const { run, busy } = useAction();
  const [path, setPath] = useState("/users?$select=displayName,userPrincipalName&$top=10");
  const [out, setOut] = useState<any>(null);
  return (
    <div className="card" style={{ marginTop: 12 }}>
      <h3>Graph explorer (read only)</h3>
      <p className="small muted">One GET request to Microsoft Graph with this connection. Only directory, policy, device, report and security resources; never mail, files, chats or calendars. Changes go through the reviewed actions. Every request is audited.</p>
      <div className="row" style={{ gap: 8 }}><input style={{ flex: 1 }} value={path} onChange={(e) => setPath(e.target.value)} />
        <button disabled={busy} onClick={async () => setOut(await run(() => api<any>("m365/tools/graph", { body: { connectionId: connection.id, path } })))}>Send GET</button></div>
      {out && <>
        <p className="small">HTTP {out.status} · {out.bytes} bytes{out.truncated && " (cut at 1 MB)"}{out.nextPage && " · more pages exist (narrow with $filter or $top)"}</p>
        <pre className="small" style={{ maxHeight: 400, overflow: "auto" }}>{out.json ? JSON.stringify(out.json, null, 2) : out.text}</pre>
      </>}
    </div>
  );
}
