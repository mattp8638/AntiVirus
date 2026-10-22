import { useState } from 'react'

const API = 'http://localhost:8000'
const arr = value => Array.isArray(value) ? value : []
const toneFor = value => {
  const raw = String(value || '').toLowerCase()
  if (['critical', 'high', 'failed'].some(v => raw.includes(v))) return 'red'
  if (['medium', 'warning', 'review'].some(v => raw.includes(v))) return 'orange'
  if (['low', 'complete', 'ok', 'safe'].some(v => raw.includes(v))) return 'green'
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
  if (!findings.length) return <Empty>No persistence findings returned.</Empty>
  return <div className="record-grid evidence-record-grid">{findings.map((item, index) => {
    const tone = toneFor(item.risk_rating)
    return <article className={`record-card evidence ${tone}`} key={`${item.type}-${item.name}-${index}`}>
      <div className="record-card-top"><Badge tone={tone}>{item.risk_rating || 'review'}</Badge><span>{item.type || 'persistence'}</span></div>
      <h3>{item.name || `Persistence item ${index + 1}`}</h3>
      <p className="record-summary">{item.reason_flagged || 'Persistence item observed and requires validation.'}</p>
      <div className="record-evidence-grid">
        <article className="record-evidence-field"><span>Location</span><strong>{item.location || 'Not available'}</strong></article>
        <article className="record-evidence-field"><span>Path</span><strong>{item.path || 'Not available'}</strong></article>
        <article className="record-evidence-field wide"><span>Command</span><strong>{item.command || 'Not available'}</strong></article>
        <article className="record-evidence-field"><span>Publisher</span><strong>{item.publisher || 'Unknown'}</strong></article>
        <article className="record-evidence-field"><span>Signature</span><strong>{item.signature || 'Not checked'}</strong></article>
        <article className="record-evidence-field"><span>SHA256</span><strong>{item.sha256 || 'Not file-backed'}</strong></article>
        <article className="record-evidence-field"><span>Created</span><strong>{item.created_at || 'Unknown'}</strong></article>
        <article className="record-evidence-field"><span>Modified</span><strong>{item.modified_at || 'Unknown'}</strong></article>
        <article className="record-evidence-field wide"><span>Recommended action</span><strong>{item.recommended_action || 'Validate and preserve evidence before removal.'}</strong></article>
      </div>
    </article>
  })}</div>
}

function TimelineTable({ timeline }) {
  if (!timeline.length) return <Empty>No timestamped persistence events were available.</Empty>
  return <div className="table-wrap"><table className="data-table"><thead><tr><th>Time</th><th>Source</th><th>Event</th><th>Severity</th></tr></thead><tbody>{timeline.map((item, index) => <tr key={index}><td>{item.timestamp || 'Unknown'}</td><td>{item.source || 'Unknown'}</td><td>{item.event || 'Persistence item'}</td><td><Badge tone={toneFor(item.severity)}>{item.severity || 'info'}</Badge></td></tr>)}</tbody></table></div>
}

export function PersistenceScanner() {
  const [scope, setScope] = useState({ include_services: true, include_startup: true, include_scheduled_tasks: true, include_powershell_profiles: true, include_browser_extensions: true })
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const setScopeValue = (key, value) => setScope(current => ({ ...current, [key]: value }))

  const runScan = async () => {
    setLoading(true); setError(''); setResult(null)
    try {
      setResult(await api('/api/persistence/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(scope),
      }))
    } catch (e) { setError(e.message) } finally { setLoading(false) }
  }

  const summary = result?.summary || {}
  const findings = arr(result?.findings)
  const timeline = arr(result?.timeline)

  return <div className="page-stack">
    <div className="page-title"><Badge tone="purple">Persistence</Badge><h1>Persistence Scanner</h1><p>Review startup items, services, scheduled tasks, PowerShell profiles and browser extension locations for reboot-surviving footholds.</p></div>

    <Panel title="Persistence Scan Scope" subtitle="Choose which local persistence areas should be checked.">
      <div className="scope-grid">
        <Toggle id="include_startup" label="Startup folders and registry autoruns" description="Checks startup folders and Run/RunOnce-style registry locations where available." enabled={scope.include_startup} onChange={setScopeValue} />
        <Toggle id="include_services" label="Services" description="Checks Windows service binary paths and start configuration where available." enabled={scope.include_services} onChange={setScopeValue} />
        <Toggle id="include_scheduled_tasks" label="Scheduled tasks" description="Checks scheduled task commands for suspicious persistence behaviour." enabled={scope.include_scheduled_tasks} onChange={setScopeValue} />
        <Toggle id="include_powershell_profiles" label="PowerShell profiles" description="Checks profile scripts that can run whenever PowerShell starts." enabled={scope.include_powershell_profiles} onChange={setScopeValue} />
        <Toggle id="include_browser_extensions" label="Browser extension locations" description="Lists extension directories for Chrome, Edge and Firefox profiles where available." enabled={scope.include_browser_extensions} onChange={setScopeValue} />
      </div>
      <Button onClick={runScan} disabled={loading}>{loading ? 'Scanning…' : 'Run Persistence Scan'}</Button>
      {error && <div className="error-box">{error}</div>}
    </Panel>

    {result && <>
      <Verdict tone={toneFor(result.severity)} eyebrow="Persistence verdict" title={summary.verdict || result.status} message="Persistence output is normalised into reviewable findings with evidence and remediation." />
      <div className="stats-grid three">
        <StatCard title="Risk Score" value={result.risk_score ?? '—'} subtitle="Higher is better" tone={result.risk_score > 80 ? 'green' : result.risk_score > 60 ? 'orange' : 'red'} />
        <StatCard title="Findings" value={summary.total ?? findings.length} subtitle="Persistence items reviewed" tone={findings.length ? 'orange' : 'green'} />
        <StatCard title="High / Medium" value={`${summary.high || 0}/${summary.medium || 0}`} subtitle="Prioritise these first" tone={(summary.high || summary.medium) ? 'red' : 'green'} />
      </div>
      <Panel title="Persistence Findings" subtitle="Prioritised persistence artefacts and recommended actions."><FindingCards findings={findings} /></Panel>
      <Panel title="Persistence Timeline" subtitle="Timestamped persistence artefacts where file metadata was available."><TimelineTable timeline={timeline} /></Panel>
      <Panel title="Recommended Actions"><div className="action-card-grid">{arr(result.recommended_actions).map((item, index) => <article className="action-card blue" key={index}><Badge>Action</Badge><h3>Step {index + 1}</h3><p>{item}</p></article>)}</div></Panel>
    </>}
  </div>
}
