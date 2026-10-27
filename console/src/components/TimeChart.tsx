import { useMemo, useRef, useState } from "react";

export interface TimeSeries {
  label: string;
  color: string;
  values: (number | null | undefined)[];
  unit?: string;
}

// A light line chart over time: hour/day gridlines, a 0–max scale and a hover readout for every series.
export function TimeChart({ times, series, max = 100, height = 150 }: { times: string[]; series: TimeSeries[]; max?: number; height?: number }) {
  const ref = useRef<SVGSVGElement>(null);
  const [hover, setHover] = useState<number | null>(null);
  const width = 600;
  const pad = { left: 30, right: 8, top: 8, bottom: 20 };
  const stamps = useMemo(() => times.map((t) => new Date(t).getTime()), [times]);
  const start = stamps[0] ?? 0, end = stamps[stamps.length - 1] ?? 1;
  const span = Math.max(end - start, 1);
  const x = (t: number) => pad.left + ((t - start) / span) * (width - pad.left - pad.right);
  const y = (v: number) => pad.top + (1 - Math.min(Math.max(v, 0), max) / max) * (height - pad.top - pad.bottom);

  const paths = useMemo(() => series.map((s) => {
    let d = "";
    s.values.forEach((v, i) => {
      if (v === null || v === undefined || Number.isNaN(v)) return;
      d += `${d ? "L" : "M"}${x(stamps[i]).toFixed(1)},${y(v).toFixed(1)} `;
    });
    return d;
  }), [series, stamps]); // eslint-disable-line react-hooks/exhaustive-deps

  const ticks = useMemo(() => {
    const out: { t: number; label: string }[] = [];
    if (stamps.length < 2) return out;
    const multiDay = span > 36 * 3600e3;
    const step = multiDay ? 24 * 3600e3 : (span > 12 * 3600e3 ? 4 : 1) * 3600e3;
    const first = new Date(start);
    if (multiDay) first.setHours(24, 0, 0, 0); else first.setMinutes(60, 0, 0);
    for (let t = first.getTime(); t < end; t += step) {
      const d = new Date(t);
      out.push({ t, label: multiDay ? d.toLocaleDateString([], { weekday: "short", day: "numeric" }) : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) });
    }
    return out;
  }, [stamps, start, end, span]);

  if (stamps.length < 2) return <div className="muted small">Not enough data yet; the agent reports every minute.</div>;

  const onMove = (event: React.MouseEvent) => {
    const box = ref.current?.getBoundingClientRect();
    if (!box) return;
    const t = start + ((event.clientX - box.left) / box.width * width - pad.left) / (width - pad.left - pad.right) * span;
    let best = 0;
    for (let i = 1; i < stamps.length; i++) if (Math.abs(stamps[i] - t) < Math.abs(stamps[best] - t)) best = i;
    setHover(best);
  };

  return (
    <div style={{ position: "relative" }}>
      <svg ref={ref} viewBox={`0 0 ${width} ${height}`} style={{ width: "100%", height }} onMouseMove={onMove} onMouseLeave={() => setHover(null)} role="img">
        {[0, 25, 50, 75, 100].map((p) => (
          <g key={p}>
            <line x1={pad.left} x2={width - pad.right} y1={y((p / 100) * max)} y2={y((p / 100) * max)} stroke="currentColor" strokeOpacity={0.08} />
            <text x={pad.left - 4} y={y((p / 100) * max) + 3} fontSize={9} textAnchor="end" fill="currentColor" opacity={0.5}>{Math.round((p / 100) * max)}</text>
          </g>
        ))}
        {ticks.map((tick) => (
          <g key={tick.t}>
            <line x1={x(tick.t)} x2={x(tick.t)} y1={pad.top} y2={height - pad.bottom} stroke="currentColor" strokeOpacity={0.06} />
            <text x={x(tick.t)} y={height - 6} fontSize={9} textAnchor="middle" fill="currentColor" opacity={0.5}>{tick.label}</text>
          </g>
        ))}
        {paths.map((d, i) => d && <path key={series[i].label} d={d} fill="none" stroke={series[i].color} strokeWidth={1.6} strokeLinejoin="round" />)}
        {hover !== null && <line x1={x(stamps[hover])} x2={x(stamps[hover])} y1={pad.top} y2={height - pad.bottom} stroke="currentColor" strokeOpacity={0.3} />}
      </svg>
      <div className="row small" style={{ gap: 14, flexWrap: "wrap" }}>
        {series.map((s) => {
          const v = hover !== null ? s.values[hover] : s.values[s.values.length - 1];
          return <span key={s.label}><span style={{ display: "inline-block", width: 10, height: 3, background: s.color, verticalAlign: "middle", marginRight: 5 }} />
            {s.label}: <b>{v === null || v === undefined ? "—" : `${Math.round(v)}${s.unit ?? "%"}`}</b></span>;
        })}
        <span className="muted">{hover !== null ? new Date(stamps[hover]).toLocaleString() : "latest"}</span>
      </div>
    </div>
  );
}
