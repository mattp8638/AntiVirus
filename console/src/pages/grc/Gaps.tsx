// Control gaps and governance exceptions (FLOW-06): from a failing control, a policy exception or a risk, to an
// owned ticket, treatment and evidence, and a review that closes it only when it is really fixed.
import { useState } from "react";
import { api, fmtTime } from "../../api";
import { useApp } from "../../app-context";
import { Modal, PageHead, Pill, Table, useAction, useListData } from "../../components/ui";
import { COMPLIANCE_SECTION, SectionTabs } from "../../components/sections";

const TONE: Record<string, string> = { open: "bad", treating: "warn", in_review: "blue", closed: "good" };

export default function Gaps() {
  const { tenantId, can } = useApp();
  const { run, busy } = useAction();
  const { data, reload } = useListData<any>("grc/gaps", { tenantId: tenantId || undefined }, [tenantId]);
  const [open, setOpen] = useState<any>(null);
  return (
    <>
      <SectionTabs items={COMPLIANCE_SECTION} />
      <PageHead title="Gaps" subtitle="Failing controls, policy exceptions and risks being treated: affected devices, an owner and a ticket for the work, the treatment and its evidence, and a review that closes the gap only when the control passes again." />
      {tenantId && can("grc") && <button className="primary" style={{ marginBottom: 10 }} disabled={busy} onClick={() => run(() => api("grc/gaps/scan", { body: { tenantId } })).then((r: any) => { if (r) reload(); })}>Check controls now</button>}
      <Table rows={data} onRow={(g) => setOpen(g)} empty="No gaps." columns={[
        { key: "title", label: "Gap", render: (g) => <><b>{g.title}</b><div className="small muted">{g.source}{g.reopened ? ` · reopened ${g.reopened}×` : ""}</div></> },
        { key: "status", label: "Status", render: (g) => <><Pill value={g.status.replace("_", " ")} tone={TONE[g.status]} />{g.overdue && <Pill value="overdue" tone="bad" />}</> },
        { key: "owner", label: "Owner" },
        { key: "devices", label: "Devices", render: (g) => g.devices.length || "—" },
        { key: "treatment", label: "Treatment" }]} />
      {open && <GapDetail gap={open} onClose={() => { setOpen(null); reload(); }} />}
    </>
  );
}

function GapDetail({ gap, onClose }: { gap: any; onClose: () => void }) {
  const { can } = useApp();
  const { run, busy } = useAction();
  const [g, setG] = useState(gap);
  const { data: evidence } = useListData<any>("grc/evidence", { tenant_id: g.tenantId }, [g.tenantId]);
  const [f, setF] = useState({ owner: g.owner, due: g.due ?? "", treatment: g.treatment, justification: g.justification, evidenceIds: g.evidenceIds as string[] });
  const call = (path: string, body: any, msg: string, method = "POST") => run(() => api(`grc/gaps/${g.id}${path}`, { method, body }), msg).then((r: any) => r && setG(r));
  return (
    <Modal wide title={g.title} onClose={onClose} footer={can("grc") && g.status !== "closed" && <>
      <button disabled={busy} onClick={() => call("", f, "Saved", "PATCH")}>Save</button>
      {!g.ticketId && <button disabled={busy} onClick={() => call("/ticket", {}, "Ticket opened")}>Open a ticket</button>}
      {(g.status === "open" || g.status === "treating") && <button className="primary" disabled={busy} onClick={async () => { await run(() => api(`grc/gaps/${g.id}`, { method: "PATCH", body: f })); call("/submit", {}, "Submitted for review"); }}>Submit for review</button>}
      {g.status === "in_review" && <>
        <button onClick={() => { const note = window.prompt("What still needs doing?") ?? ""; call("/review", { outcome: "return", note }, "Sent back"); }}>Send back</button>
        <button className="primary" onClick={() => call("/review", { outcome: "close", note: window.prompt("Review note (optional)") ?? "" }, "Closed")}>Close after review</button>
      </>}
    </>}>
      <p className="small"><Pill value={g.status.replace("_", " ")} tone={TONE[g.status]} /> {g.source}{g.ticketId && " · has a ticket"}{g.review && ` · last review: ${g.review.outcome} by ${g.review.by}`}</p>
      <pre className="small" style={{ whiteSpace: "pre-wrap" }}>{g.description}</pre>
      <div className="form-grid">
        <label className="field">Owner<input value={f.owner} onChange={(e) => setF({ ...f, owner: e.target.value })} /></label>
        <label className="field">Due<input type="date" value={f.due} onChange={(e) => setF({ ...f, due: e.target.value })} /></label>
        <label className="field">Treatment<select value={f.treatment} onChange={(e) => setF({ ...f, treatment: e.target.value })}><option value="remediate">Remediate</option><option value="compensate">Compensating control</option><option value="accept">Accept the risk</option></select></label>
      </div>
      {f.treatment !== "remediate" && <label className="field">Justification<textarea rows={2} value={f.justification} onChange={(e) => setF({ ...f, justification: e.target.value })} /></label>}
      <h4>Evidence</h4>
      <div className="row small" style={{ gap: 10, flexWrap: "wrap" }}>{(evidence ?? []).map((e: any) => <label key={e.id} className="row" style={{ gap: 4 }}><input type="checkbox" checked={f.evidenceIds.includes(e.id)} onChange={(x) => setF({ ...f, evidenceIds: x.target.checked ? [...f.evidenceIds, e.id] : f.evidenceIds.filter((y) => y !== e.id) })} /> {e.title}</label>)}</div>
      <h4>Timeline</h4>
      {g.timeline.map((t: any, i: number) => <div key={i} className="small">{fmtTime(t.at)} · {t.by}: {t.text}</div>)}
    </Modal>
  );
}
