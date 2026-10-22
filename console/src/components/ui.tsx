import { ReactNode, useCallback, useEffect, useState } from "react";
import { api } from "../api";
import { useApp } from "../app-context";

/** Load data from the API and reload when deps change. */
export function useData<T>(path: string | null, query: Record<string, unknown> = {}, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const key = JSON.stringify(query);
  const reload = useCallback(async () => {
    if (!path) return;
    setLoading(true);
    try {
      setData(await api<T>(path, { query }));
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, key, ...deps]);
  useEffect(() => {
    reload();
  }, [reload]);
  return { data, error, loading, reload, setData };
}

/** Wrap an async action with toast feedback. */
export function useAction() {
  const { toast } = useApp();
  const [busy, setBusy] = useState(false);
  const run = async <T,>(fn: () => Promise<T>, success?: string): Promise<T | undefined> => {
    setBusy(true);
    try {
      const result = await fn();
      if (success) toast(success);
      return result;
    } catch (err) {
      toast((err as Error).message, true);
      return undefined;
    } finally {
      setBusy(false);
    }
  };
  return { run, busy };
}

export function PageHead({ title, subtitle, actions }: { title: string; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="page-head">
      <div>
        <h1>{title}</h1>
        {subtitle && <p>{subtitle}</p>}
      </div>
      {actions && <div className="actions">{actions}</div>}
    </div>
  );
}

export function Stat({ label, value, hint, accent }: { label: string; value: ReactNode; hint?: ReactNode; accent?: string }) {
  return (
    <div className={`card stat ${accent ? `accent-${accent}` : ""}`}>
      <div className="label">{label}</div>
      <div className="value">{value}</div>
      {hint && <div className="hint">{hint}</div>}
    </div>
  );
}

export function Sev({ level }: { level?: string }) {
  const value = (level || "info").toLowerCase();
  return <span className={`badge sev-${value === "informational" ? "info" : value}`}>{value}</span>;
}

const TONES: Record<string, string> = {
  new: "bad", open: "bad", pending: "warn", dispatched: "blue", completed: "good", failed: "bad", cancelled: "muted",
  triaged: "warn", resolved: "good", closed: "muted", false_positive: "muted", investigating: "warn", contained: "blue",
  allow: "good", block: "bad", observe: "warn", malicious: "bad", suspicious: "warn", unknown: "muted",
  Open: "bad", "In Progress": "warn", Waiting: "blue", Resolved: "good", Closed: "muted",
  Draft: "muted", Sent: "blue", Paid: "good", Overdue: "bad", Void: "muted",
  New: "warn", Contacted: "blue", Qualified: "blue", Proposal: "warn", Won: "good", Lost: "muted",
  patching: "blue", mitigated: "good", accepted: "muted", fixed: "good",
};

export function Pill({ value, tone }: { value: ReactNode; tone?: string }) {
  const resolved = tone ?? TONES[String(value)] ?? "muted";
  return <span className={`badge tone-${resolved}`}>{String(value).replace(/_/g, " ")}</span>;
}

export interface Column<T> {
  key: string;
  label: string;
  render?: (row: T) => ReactNode;
  className?: string;
}

export function Table<T extends Record<string, any>>({ rows, columns, onRow, empty = "Nothing here yet." }: {
  rows: T[] | null | undefined;
  columns: Column<T>[];
  onRow?: (row: T) => void;
  empty?: string;
}) {
  if (!rows) return <div className="empty">Loading…</div>;
  if (!rows.length) return <div className="empty">{empty}</div>;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>{columns.map((c) => <th key={c.key} className={c.className}>{c.label}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={row.id ?? i} className={onRow ? "clickable" : ""} onClick={onRow ? () => onRow(row) : undefined}>
              {columns.map((c) => <td key={c.key} className={c.className}>{c.render ? c.render(row) : String(row[c.key] ?? "")}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function Modal({ title, onClose, children, footer }: { title: string; onClose: () => void; children: ReactNode; footer?: ReactNode }) {
  return (
    <div className="modal-back" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()} role="dialog" aria-label={title}>
        <div className="row" style={{ marginBottom: 12 }}>
          <h2 style={{ margin: 0 }}>{title}</h2>
          <span style={{ flex: 1 }} />
          <button className="ghost" onClick={onClose} aria-label="Close">✕</button>
        </div>
        {children}
        {footer && <div className="foot">{footer}</div>}
      </div>
    </div>
  );
}

export function Tabs({ tabs, active, onChange }: { tabs: string[]; active: string; onChange: (tab: string) => void }) {
  return (
    <div className="tabs">
      {tabs.map((tab) => <button key={tab} className={tab === active ? "active" : ""} onClick={() => onChange(tab)}>{tab}</button>)}
    </div>
  );
}

export function ErrorNote({ error }: { error: string | null }) {
  return error ? <div className="card" style={{ borderColor: "rgba(239,68,68,.5)", color: "#fecaca" }}>{error}</div> : null;
}

/** Simple bar chart in SVG; no chart library needed. */
export function Bars({ data, height = 140 }: { data: { label: string; value: number }[]; height?: number }) {
  if (!data.length) return <div className="empty">No data in this period.</div>;
  const max = Math.max(...data.map((d) => d.value), 1);
  const width = 100 / data.length;
  return (
    <svg viewBox={`0 0 100 ${height}`} preserveAspectRatio="none" style={{ width: "100%", height }} role="img">
      {data.map((d, i) => {
        const h = (d.value / max) * (height - 18);
        return (
          <g key={d.label}>
            <rect x={i * width + width * 0.15} y={height - 14 - h} width={width * 0.7} height={h} rx={0.8} fill="url(#barGrad)">
              <title>{`${d.label}: ${d.value}`}</title>
            </rect>
          </g>
        );
      })}
      <defs>
        <linearGradient id="barGrad" x1="0" x2="0" y1="0" y2="1">
          <stop offset="0" stopColor="#3b82f6" />
          <stop offset="1" stopColor="#a855f7" />
        </linearGradient>
      </defs>
    </svg>
  );
}

export function Meter({ value, max = 100 }: { value: number; max?: number }) {
  return <div className="bar"><span style={{ width: `${Math.min(100, (value / max) * 100)}%` }} /></div>;
}

export function TenantSelect({ value, onChange, allowAll = true, label }: { value: string; onChange: (id: string) => void; allowAll?: boolean; label?: string }) {
  const { me } = useApp();
  return (
    <select value={value} onChange={(e) => onChange(e.target.value)} aria-label={label ?? "Tenant"}>
      {allowAll && <option value="">All tenants</option>}
      {me?.tenants.map((t) => <option key={t.id} value={t.id}>{t.name}{t.kind === "msp" ? " (MSP)" : ""}</option>)}
    </select>
  );
}
