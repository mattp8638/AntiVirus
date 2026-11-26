import { useState } from "react";
import { Link } from "react-router-dom";
import { api, fmtTime } from "../../api";
import { useApp } from "../../app-context";
import { displayValue } from "../../components/DisplayValue";
import { ErrorNote, Modal, useAction, useData } from "../../components/ui";
import { safeArray } from "../../data-shapes";

/** Each person's ISMS dashboard for the chosen customer, and their email digest of the same tiles. */

const STATUS_WORD: Record<string, string> = { good: "OK", warning: "Needs attention", problem: "Action needed", neutral: "For information" };
const STATUS_TONE: Record<string, string> = { good: "ok", warning: "warn", problem: "bad", neutral: "muted" };

export function IsmsDashboardTab({ onOpenTab }: { onOpenTab?: (tab: string) => void }) {
  const { tenantId } = useApp();
  const { data, error, reload } = useData<any>(tenantId ? "isms/dashboard" : null, { tenant_id: tenantId }, [tenantId]);
  const [editing, setEditing] = useState(false);
  if (!tenantId) return <p className="muted">Choose a customer in the tenant picker to see its ISMS dashboard.</p>;
  if (error) return <div className="card"><ErrorNote error={error} /></div>;
  const tiles = safeArray<any>(data?.tiles);
  const digest = data?.digest;
  return <div className="card">
    <div className="row" style={{ marginBottom: 8, gap: 8 }}>
      <p className="small muted" style={{ flex: 1, margin: 0 }}>{digest?.enabled ? `You get these figures by email ${digest.frequency === "weekly" ? "every Monday" : "on the 1st of each month"}; next ${fmtTime(digest.nextSendAt)}.` : "Your chosen figures for this customer, from live records."}</p>
      <button onClick={() => setEditing(true)}>Choose tiles and email</button>
    </div>
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))", gap: 12 }}>
      {tiles.map((t) => <section key={t.id} className="card" aria-label={t.title} style={{ margin: 0 }}>
        <div className="small muted">{t.title}</div>
        <div style={{ fontSize: 22, fontWeight: 600 }}>{displayValue(t.value)}</div>
        <div className="small">{displayValue(t.detail)}</div>
        <div className="row" style={{ marginTop: 6, gap: 6 }}>
          <span className={`badge tone-${STATUS_TONE[t.status]}`}>{STATUS_WORD[t.status]}</span>
          <span style={{ flex: 1 }} />
          {t.href ? <Link className="small" to={t.href}>Open {t.title}</Link>
            : onOpenTab && t.tab && <button className="small" onClick={() => onOpenTab(t.tab)}>Open {t.tab}</button>}
        </div>
      </section>)}
    </div>
    {editing && <Customize tenantId={tenantId} available={safeArray<any>(data?.available)} layout={safeArray<string>(data?.layout)} digest={digest} onClose={() => { setEditing(false); reload(); }} />}
  </div>;
}

function Customize({ tenantId, available, layout, digest, onClose }: { tenantId: string; available: any[]; layout: string[]; digest: any; onClose: () => void }) {
  const [tiles, setTiles] = useState<string[]>(layout);
  const [freq, setFreq] = useState<string>(digest?.enabled ? digest.frequency : "off");
  const { run, busy } = useAction();
  const move = (i: number, d: number) => { const n = [...tiles]; [n[i], n[i + d]] = [n[i + d], n[i]]; setTiles(n); };
  const name = (id: string) => available.find((a) => a.id === id)?.title ?? id;
  const save = async () => {
    const ok = await run(async () => {
      await api("isms/dashboard/layout", { method: "PUT", body: { tenantId, tiles } });
      if (freq !== "off" || digest) await api("isms/dashboard/digest", { method: "PUT", body: { tenantId, frequency: freq === "off" ? (digest?.frequency ?? "weekly") : freq, enabled: freq !== "off" } });
      return true;
    }, "Dashboard saved");
    if (ok) onClose();
  };
  return <Modal title="Choose tiles and email" onClose={onClose} footer={<button className="primary" disabled={busy || !tiles.length} onClick={save}>Save</button>}>
    <fieldset><legend className="small">Tiles (only those your ISMS role allows)</legend>
      {available.map((a) => <label key={a.id} className="small" style={{ display: "block" }}>
        <input type="checkbox" checked={tiles.includes(a.id)} onChange={() => setTiles(tiles.includes(a.id) ? tiles.filter((x) => x !== a.id) : [...tiles, a.id])} /> {a.title}: {a.description}</label>)}
    </fieldset>
    {tiles.length > 1 && <><p className="small">Order</p><ol className="small">{tiles.map((t, i) => <li key={t}>{name(t)}{" "}
      <button className="small" disabled={i === 0} aria-label={`Move ${name(t)} up`} onClick={() => move(i, -1)}>Up</button>{" "}
      <button className="small" disabled={i === tiles.length - 1} aria-label={`Move ${name(t)} down`} onClick={() => move(i, 1)}>Down</button></li>)}</ol></>}
    <label className="field">Email me these figures<select value={freq} onChange={(e) => setFreq(e.target.value)}>
      <option value="off">Never</option><option value="weekly">Weekly (Mondays)</option><option value="monthly">Monthly (the 1st)</option></select></label>
  </Modal>;
}
