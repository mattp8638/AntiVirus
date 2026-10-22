import { useState } from 'react'

const API = 'http://localhost:8000'
const arr = value => Array.isArray(value) ? value : []
const toneFor = value => {
  const raw = String(value || '').toLowerCase()
  if (['critical', 'high'].some(v => raw.includes(v))) return 'red'
  if (['medium', 'external', 'warning', 'review'].some(v => raw.includes(v))) return 'orange'
  if (['low', 'complete', 'private', 'loopback'].some(v => raw.includes(v))) return 'green'
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

function ConnectionCards({ items }) {
  if (!items.length) return <Empty>No connections matched this snapshot scope.</Empty>
  return <div className="record-grid evidence-record-grid">{items.slice(0, 200).map((item, index) => {
    const tone = toneFor(item.risk_rating || item.destination_classification)
    return <article className={`record-card evidence ${tone}`} key={`${item.pid}-${item.local_address}-${item.remote_address}-${index}`}>
      <div className="record-card-top"><Badge tone={tone}>{item.risk_rating || 'low'}</Badge><span>{item.status || 'connection'}</span></div>
      <h3>{item.process_name || 'Unknown process'}</h3>
      <p className="record-summary">{item.reason_flagged || 'Network connection observed.'}</p>
      <div className="record-evidence-grid">
        <article className="record-evidence-field"><span>PID</span><strong>{item.pid ?? 'Unknown'}</strong></article>
        <article className="record-evidence-field"><span>Local</span><strong>{item.local_address || 'None'}</strong></article>
        <article className="record-evidence-field"><span>Remote</span><strong>{item.remote_address || 'None'}</strong></article>
        <article className="record-evidence-field"><span>Remote Port</span><strong>{item.remote_port || '—'}</strong></article>
        <article className="record-evidence-field"><span>Destination</span><strong>{item.destination_classification || 'unknown'}</strong></article>
        <article className="record-evidence-field"><span>Reputation</span><strong>{item.reputation || 'not enriched'}</strong></article>
        <article className="record-evidence-field"><span>ASN</span><strong>{item.asn || 'not enriched'}</strong></article>
        <article className="record-evidence-field"><span>Country</span><strong>{item.country || 'not enriched'}</strong></article>
        <article className="record-evidence-field wide"><span>Path</span><strong>{item.process_path || 'Not available'}</strong></article>
        <article className="record-evidence-field wide"><span>Recommended action</span><strong>{item.recommended_action || 'Validate process and destination.'}</strong></article>
      </div>
    </article>
  })}</div>
}

function FindingCards({ findings }) {
  if (!findings.length) return <Empty>No suspicious network findings were generated.</Empty>
  return <ConnectionCards items={findings} />
}

export function NetworkConnectionMonitor() {
  const [scope, setScope] = useState({ include_listening: true, include_loopback: false, include_private_remote: true })
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const setScopeValue = (key, value) => setScope(current => ({ ...current, [key]: value }))

  const runSnapshot = async () => {
    setLoading(true); setError(''); setResult(null)
    try {
      setResult(await api('/api/network/snapshot', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(scope),
      }))
    } catch (e) { setError(e.message) } finally { setLoading(false) }
  }

  const summary = result?.summary || {}
  const findings = arr(result?.findings)
  const connections = arr(result?.connections)

  return <div className="page-stack">
    <div className="page-title"><Badge tone="blue">Network Evidence</Badge><h1>Network Connection Monitor</h1><p>Capture a safe point-in-time snapshot of outbound connections, listening ports and suspicious process/destination pairs.</p></div>

    <Panel title="Snapshot Scope" subtitle="This is a snapshot monitor first; live monitoring hooks can be added later.">
      <div className="scope-grid">
        <Toggle id="include_listening" label="Include listening ports" description="Shows local ports waiting for inbound connections." enabled={scope.include_listening} onChange={setScopeValue} />
        <Toggle id="include_loopback" label="Include loopback" description="Includes localhost connections that are usually lower priority." enabled={scope.include_loopback} onChange={setScopeValue} />
        <Toggle id="include_private_remote" label="Include private remote addresses" description="Includes RFC1918/private network destinations as well as public internet destinations." enabled={scope.include_private_remote} onChange={setScopeValue} />
      </div>
      <Button onClick={runSnapshot} disabled={loading}>{loading ? 'Collecting…' : 'Run Network Snapshot'}</Button>
      {error && <div className="error-box">{error}</div>}
    </Panel>

    {result && <>
      <Verdict tone={toneFor(result.severity)} eyebrow="Network verdict" title={summary.verdict || result.status} message="Network connections are grouped into readable evidence with process context and enrichment placeholders." />
      <div className="stats-grid three">
        <StatCard title="Risk Score" value={result.risk_score ?? '—'} subtitle="Higher is better" tone={(result.risk_score ?? 0) > 80 ? 'green' : (result.risk_score ?? 0) > 60 ? 'orange' : 'red'} />
        <StatCard title="Connections" value={summary.total ?? connections.length} subtitle="Snapshot entries" tone={connections.length ? 'blue' : 'green'} />
        <StatCard title="External / Listening" value={`${summary.external || 0}/${summary.listening || 0}`} subtitle="Destinations and exposed ports" tone={(summary.external || summary.listening) ? 'orange' : 'green'} />
      </div>
      <Panel title="Suspicious Network Findings" subtitle="Prioritised process and destination pairs."><FindingCards findings={findings} /></Panel>
      <Panel title="All Network Connections" subtitle="Snapshot evidence. Limited to the first 200 entries for readability."><ConnectionCards items={connections} /></Panel>
      <Panel title="Recommended Actions"><div className="action-card-grid">{arr(result.recommended_actions).map((item, index) => <article className="action-card blue" key={index}><Badge>Action</Badge><h3>Step {index + 1}</h3><p>{item}</p></article>)}</div></Panel>
    </>}
  </div>
}
