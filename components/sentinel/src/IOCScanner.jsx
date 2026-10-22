import { useState } from 'react'

const API = 'http://localhost:8000'
const arr = value => Array.isArray(value) ? value : []
const toneFor = value => {
  const raw = String(value || '').toLowerCase()
  if (['critical', 'high'].some(v => raw.includes(v))) return 'red'
  if (['medium', 'warning', 'review'].some(v => raw.includes(v))) return 'orange'
  if (['low', 'complete', 'none', 'no ioc'].some(v => raw.includes(v))) return 'green'
  return 'blue'
}

async function api(path, options = {}) {
  const res = await fetch(`${API}${path}`, options)
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

function Badge({ children, tone = 'blue' }) { return <span className={`badge ${tone}`}>{children}</span> }
function Button({ children, ...props }) { return <button className="primary-btn" {...props}>{children}</button> }
function Panel({ title, subtitle, children }) { return <section className="panel"><div className="panel-header"><div><h2>{title}</h2>{subtitle && <p>{subtitle}</p>}</div></div>{children}</section> }
function StatCard({ title, value, subtitle, tone = 'blue' }) { return <section className={`stat-card ${tone}`}><p>{title}</p><h2>{value}</h2><span>{subtitle}</span></section> }
function Verdict({ title, message, tone = 'blue', eyebrow = 'Result' }) { return <section className={`verdict-card ${tone}`}><Badge tone={tone}>{eyebrow}</Badge><h2>{title}</h2><p>{message}</p></section> }
function Empty({ children = 'Nothing to show yet.' }) { return <div className="empty-state">{children}</div> }

function Toggle({ id, label, description, enabled, onChange }) {
  return <label className={`investigation-scope-card ${enabled ? 'selected' : ''}`}>
    <input type="checkbox" checked={enabled} onChange={event => onChange(id, event.target.checked)} />
    <div><strong>{label}</strong><p>{description}</p></div>
  </label>
}

function FindingCards({ findings }) {
  if (!findings.length) return <Empty>No IOC matches were found.</Empty>
  return <div className="record-grid evidence-record-grid">{findings.map((item, index) => {
    const tone = toneFor(item.severity)
    return <article className={`record-card evidence ${tone}`} key={item.finding_id || index}>
      <div className="record-card-top"><Badge tone={tone}>{item.severity || 'review'}</Badge><span>{item.source || 'source'}</span></div>
      <h3>{item.indicator}</h3>
      <p className="record-summary">{item.reason}</p>
      <div className="record-evidence-grid">
        <article className="record-evidence-field"><span>Indicator type</span><strong>{item.indicator_type}</strong></article>
        <article className="record-evidence-field"><span>Source</span><strong>{item.source}</strong></article>
        <article className="record-evidence-field"><span>Timestamp</span><strong>{item.timestamp}</strong></article>
        <article className="record-evidence-field wide"><span>Recommended action</span><strong>{item.recommended_action}</strong></article>
        <article className="record-evidence-field wide"><span>Evidence</span><strong>{JSON.stringify(item.evidence)}</strong></article>
      </div>
    </article>
  })}</div>
}

function IndicatorCards({ indicators }) {
  if (!indicators.length) return <Empty>No valid indicators were extracted.</Empty>
  return <div className="inline-chip-row">{indicators.map((item, index) => <span className="inline-chip" key={`${item.value}-${index}`}>{item.type}: {item.value}</span>)}</div>
}

export function IOCScanner() {
  const [indicators, setIndicators] = useState('')
  const [scanPaths, setScanPaths] = useState('')
  const [scope, setScope] = useState({ include_files: true, include_processes: true, include_network: true, include_registry_autoruns: true, include_dns_cache: true, include_recent_logs: true })
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const setScopeValue = (key, value) => setScope(current => ({ ...current, [key]: value }))

  const runScan = async () => {
    setLoading(true); setError(''); setResult(null)
    try {
      const paths = scanPaths.split(/[\n,;]/).map(x => x.trim()).filter(Boolean)
      setResult(await api('/api/ioc-scanner/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ indicators, scan_paths: paths.length ? paths : undefined, ...scope, max_files: 1500 }),
      }))
    } catch (e) { setError(e.message) } finally { setLoading(false) }
  }

  const summary = result?.summary || {}
  const findings = arr(result?.findings)
  const extracted = arr(result?.indicators)

  return <div className="page-stack">
    <div className="page-title"><Badge tone="purple">Compromise Check</Badge><h1>IOC Scanner</h1><p>Search local endpoint evidence for known indicators across files, processes, network connections, autoruns, DNS cache and logs.</p></div>

    <Panel title="Indicators and Scope" subtitle="Paste IPs, domains, URLs, hashes, CVEs or email indicators. No blocking or deletion is performed.">
      <textarea className="input-area" rows="7" value={indicators} onChange={e => setIndicators(e.target.value)} placeholder="Paste IOCs here, one per line or as raw text..." />
      <textarea className="input-area" rows="3" value={scanPaths} onChange={e => setScanPaths(e.target.value)} placeholder="Optional scan paths, separated by new lines. Defaults to Downloads, Desktop and Documents." />
      <div className="scope-grid">
        <Toggle id="include_files" label="Files and text content" description="Scans file names, hashes and safe text-like file content." enabled={scope.include_files} onChange={setScopeValue} />
        <Toggle id="include_processes" label="Processes" description="Scans process names, paths and command lines." enabled={scope.include_processes} onChange={setScopeValue} />
        <Toggle id="include_network" label="Network" description="Scans active network connection evidence." enabled={scope.include_network} onChange={setScopeValue} />
        <Toggle id="include_registry_autoruns" label="Autoruns/startup" description="Scans registry Run keys and startup folder artefacts where available." enabled={scope.include_registry_autoruns} onChange={setScopeValue} />
        <Toggle id="include_dns_cache" label="DNS cache" description="Scans Windows DNS cache output where available." enabled={scope.include_dns_cache} onChange={setScopeValue} />
        <Toggle id="include_recent_logs" label="Recent logs/text" description="Scans selected paths for log/text IOC evidence." enabled={scope.include_recent_logs} onChange={setScopeValue} />
      </div>
      <Button onClick={runScan} disabled={!indicators.trim() || loading}>{loading ? 'Scanning…' : 'Run IOC Scan'}</Button>
      {error && <div className="error-box">{error}</div>}
    </Panel>

    {result && <>
      <Verdict tone={toneFor(result.severity)} eyebrow="IOC verdict" title={summary.verdict || result.status} message="Matches are evidence only. Validate indicator quality and preserve artefacts before containment." />
      <div className="stats-grid three">
        <StatCard title="Risk Score" value={result.risk_score ?? '—'} subtitle="Higher is better" tone={(result.risk_score ?? 0) > 80 ? 'green' : (result.risk_score ?? 0) > 60 ? 'orange' : 'red'} />
        <StatCard title="Indicators" value={summary.indicator_count ?? extracted.length} subtitle="Valid extracted IOCs" tone={extracted.length ? 'blue' : 'orange'} />
        <StatCard title="Matches" value={summary.match_count ?? findings.length} subtitle={`${summary.high || 0} high / ${summary.medium || 0} medium`} tone={findings.length ? 'red' : 'green'} />
      </div>
      <Panel title="Extracted Indicators"><IndicatorCards indicators={extracted} /></Panel>
      <Panel title="IOC Matches"><FindingCards findings={findings} /></Panel>
      <Panel title="Recommended Actions"><div className="action-card-grid">{arr(result.recommended_actions).map((item, index) => <article className="action-card blue" key={index}><Badge>Action</Badge><h3>Step {index + 1}</h3><p>{item}</p></article>)}</div></Panel>
    </>}
  </div>
}
