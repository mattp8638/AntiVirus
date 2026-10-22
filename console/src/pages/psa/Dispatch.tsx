import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../../api";
import { PageHead, Pill, useAction, useData } from "../../components/ui";
import { PRIORITY_TONE } from "./ServiceBoard";

const START_HOUR = 7;
const END_HOUR = 19;
const SLOT_MINUTES = 30;

/** Dispatch board: members down the side, the working day across the top. Drag tickets onto a slot to book them. */
export default function Dispatch() {
  const navigate = useNavigate();
  const [day, setDay] = useState(() => { const d = new Date(); d.setHours(0, 0, 0, 0); return d; });
  const dayEnd = useMemo(() => new Date(day.getTime() + 86400000), [day]);
  const { data: meta } = useData<any>("psa/meta");
  const { data: entries, reload } = useData<any[]>("psa/schedule", { start: day.toISOString(), end: dayEnd.toISOString() });
  const { data: queue, reload: reloadQueue } = useData<any[]>("tickets", { status: "active", assignee: "unassigned" });
  const { run } = useAction();
  const slots = useMemo(() => Array.from({ length: ((END_HOUR - START_HOUR) * 60) / SLOT_MINUTES }, (_, i) => START_HOUR * 60 + i * SLOT_MINUTES), []);
  const members: any[] = meta?.members || [];
  const width = 100 / slots.length;
  const book = async (ticketId: string, member: string, minute: number) => {
    const start = new Date(day.getTime() + minute * 60000);
    const result = await run(() => api<any>("psa/schedule", { body: { ticketId, member, startAt: start.toISOString(), endAt: new Date(start.getTime() + 3600000).toISOString() } }), "Booked");
    if (result?.conflict) window.alert(`${member} already has something booked then.`);
    reload();
    reloadQueue();
  };
  const moveEntry = async (entryId: string, member: string, minute: number) => {
    const entry = entries?.find((e) => e.id === entryId);
    if (!entry) return;
    const length = new Date(entry.endAt).getTime() - new Date(entry.startAt).getTime();
    const start = new Date(day.getTime() + minute * 60000);
    await run(() => api(`psa/schedule/${entryId}`, { method: "PATCH", body: { member, startAt: start.toISOString(), endAt: new Date(start.getTime() + length).toISOString() } }), "Moved");
    reload();
  };
  const position = (e: any) => {
    const start = new Date(e.startAt), end = new Date(e.endAt);
    const startMin = Math.max(START_HOUR * 60, start.getHours() * 60 + start.getMinutes() + (start < day ? -1440 : 0));
    const endMin = Math.min(END_HOUR * 60, end.getHours() * 60 + end.getMinutes() + (end >= dayEnd ? 1440 : 0));
    return { left: `${((startMin - START_HOUR * 60) / ((END_HOUR - START_HOUR) * 60)) * 100}%`, width: `${Math.max(2, ((endMin - startMin) / ((END_HOUR - START_HOUR) * 60)) * 100)}%` };
  };
  return (
    <>
      <PageHead title="Dispatch" subtitle="Drag unassigned tickets onto an engineer's timeline. Drag bookings to move them."
                actions={<>
                  <button onClick={() => setDay(new Date(day.getTime() - 86400000))}>‹</button>
                  <b>{day.toLocaleDateString(undefined, { weekday: "long", day: "numeric", month: "short" })}</b>
                  <button onClick={() => setDay(new Date(day.getTime() + 86400000))}>›</button>
                  <button onClick={() => { const d = new Date(); d.setHours(0, 0, 0, 0); setDay(d); }}>Today</button>
                </>} />
      <div className="grid" style={{ gridTemplateColumns: "260px minmax(0, 1fr)" }}>
        <div className="card" style={{ maxHeight: "75vh", overflow: "auto" }}>
          <h3>Unassigned ({queue?.length ?? 0})</h3>
          {(queue || []).map((t) => (
            <div key={t.id} className="lead" draggable onDragStart={(e) => e.dataTransfer.setData("text/plain", `ticket:${t.id}`)} style={{ cursor: "grab" }}>
              <div className="row"><Pill value={t.priority} tone={PRIORITY_TONE[t.priority]} /><span className="small muted">#{t.number}</span></div>
              <div className="small"><b>{t.subject}</b></div><div className="small muted">{t.account}</div>
            </div>
          ))}
          {!queue?.length && <p className="muted small">Nothing waiting.</p>}
        </div>
        <div className="card" style={{ overflowX: "auto" }}>
          <div style={{ display: "grid", gridTemplateColumns: "180px 1fr", minWidth: 900 }}>
            <div />
            <div style={{ position: "relative", height: 22 }}>
              {slots.filter((m) => m % 60 === 0).map((m) => (
                <span key={m} className="small muted" style={{ position: "absolute", left: `${((m - START_HOUR * 60) / ((END_HOUR - START_HOUR) * 60)) * 100}%` }}>{String(m / 60).padStart(2, "0")}:00</span>
              ))}
            </div>
            {members.map((member) => (
              <div key={member.email} style={{ display: "contents" }}>
                <div style={{ padding: "10px 8px", borderTop: "1px solid var(--line)" }}><b className="small">{member.name}</b><div className="small muted">{member.role.replace(/_/g, " ")}</div></div>
                <div style={{ position: "relative", height: 54, borderTop: "1px solid var(--line)" }}>
                  {slots.map((minute, i) => (
                    <div key={minute} title={`${Math.floor(minute / 60)}:${String(minute % 60).padStart(2, "0")}`}
                         onDragOver={(e) => e.preventDefault()}
                         onDrop={(e) => { const data = e.dataTransfer.getData("text/plain"); if (data.startsWith("ticket:")) book(data.slice(7), member.email, minute); else if (data.startsWith("entry:")) moveEntry(data.slice(6), member.email, minute); }}
                         style={{ position: "absolute", top: 0, bottom: 0, left: `${i * width}%`, width: `${width}%`, borderLeft: minute % 60 === 0 ? "1px solid #1a2540" : "1px dashed #121a2e" }} />
                  ))}
                  {(entries || []).filter((e) => e.member === member.email).map((e) => (
                    <div key={e.id} draggable onDragStart={(ev) => ev.dataTransfer.setData("text/plain", `entry:${e.id}`)}
                         onClick={() => e.ticketId && navigate(`/tickets/${e.ticketId}`)}
                         title={e.title}
                         style={{ position: "absolute", top: 6, bottom: 6, ...position(e), background: e.kind === "Onsite" ? "rgba(168,85,247,.35)" : e.kind === "Meeting" ? "rgba(100,116,139,.4)" : "rgba(59,130,246,.35)",
                                  border: "1px solid rgba(255,255,255,.15)", borderRadius: 6, padding: "2px 6px", overflow: "hidden", cursor: "pointer", fontSize: 12 }}>
                      <b>{e.ticketNumber ? `#${e.ticketNumber}` : e.kind}</b> {e.title.replace(/^#\d+ /, "")}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
          {!members.length && <p className="muted">Add staff users to see their timelines.</p>}
        </div>
      </div>
    </>
  );
}
