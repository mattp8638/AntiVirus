import { useEffect, useMemo, useState } from 'react'

const API = 'http://localhost:8000'
const arr = value => Array.isArray(value) ? value : []
const pick = (obj, keys, fallback = 'Not available') => keys.map(key => obj?.[key]).find(value => value !== undefined && value !== null && value !== '') ?? fallback
const toneFor = value => {
  const raw = String(value || '').toLowerCase()
  if (['critical', 'high', 'failed', 'error'].some(v => raw.includes(v))) return 'red'
  if (['medium', 'warning', 'review', 'pending', 'in-progress'].some(v => raw.includes(v))) return 'orange'
  if (['low', 'complete', 'success', 'ok'].some(v => raw.includes(v))) return 'green'
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

function InvestigationList({ items, selectedId, onSelect }) {
  if (!items.length) return <Empty>No investigations found yet. Queue an agent investigation or run the local investigator first.</Empty>
  return <div className="device-queue">{items.map((item, index) => {
    const id = item.investigation_id || item.request_id || item.id || `inv-${index}`
    const severity = item.highest_severity || item.severity || item.status
    return <button className={`device-row ${selectedId === id ? 'selected' : ''}`} key={id} onClick={() => onSelect(id)}>
      <div className="device-rank">#{index + 1}</div>
      <div className="device-main"><div><Badge tone={toneFor(severity)}>{severity || 'investigation'}</Badge><h3>{id}</h3><p>{item.hostname || item.agent_id || 'Unknown endpoint'}</p></div></div>
      <div className="device-metrics"><span><b>{item.finding_count ?? '—'}</b> findings</span><span><b>{item.evidence_count ?? '—'}</b> evidence</span><span><b>{item.status || 'unknown'}</b> status</span></div>
    </button>
  })}</div>
}

function KeyGrid({ data }) {
  const entries = Object.entries(data || {}).filter(([, value]) => value !== undefined && value !== null && value !== '' && !Array.isArray(value) && typeof value !== 'object')
  if (!entries.length) return <Empty>No summary details available.</Empty>
  return <div className="kv-grid">{entries.map(([key, value]) => <article className="kv-card" key={key}><span>{key.replace(/_/g, ' ')}</span><strong>{String(value)}</strong></article>)}</div>
}

function FindingCards({ items }) {
  if (!items.length) return <Empty>No findings were stored for this investigation.</Empty>
  return <div className="action-card-grid">{items.map((finding, index) => {
    const severity = pick(finding, ['severity', 'status'], 'review')
    return <article className={`action-card ${toneFor(severity)}`} key={finding.finding_id || index}>
      <div className="action-card-top"><Badge tone={toneFor(severity)}>{severity}</Badge><span>{finding.module || `#${index + 1}`}</span></div>
      <h3>{pick(finding, ['title', 'control', 'event'], `Finding ${index + 1}`)}</h3>
      <p>{pick(finding, ['recommended_action', 'remediation', 'description', 'summary'], 'Review this finding and determine the next action.')}</p>
      {finding.evidence && <div className="nested-object-card"><div className="nested-object-title">Evidence</div><p style={{ margin: 0, wordBreak: 'break-word' }}>{JSON.stringify(finding.evidence)}</p></div>}
    </article>
  })}</div>
}

function TimelineTable({ items }) {
  if (!items.length) return <Empty>No timeline entries were stored for this investigation.</Empty>
  return <div className="table-wrap"><table className="data-table"><thead><tr><th>Time</th><th>Source</th><th>Event</th><th>Severity</th><th>Evidence</th></tr></thead><tbody>{items.map((item, index) => <tr key={index}><td>{item.time || item.timestamp || 'Unknown'}</td><td>{item.source || 'Unknown'}</td><td>{item.event || item.title || 'Event'}</td><td><Badge tone={toneFor(item.severity)}>{item.severity || 'info'}</Badge></td><td>{item.evidence_ref || '—'}</td></tr>)}</tbody></table></div>
}

export function InvestigationDetails() {
  const [history, setHistory] = useState([])
  const [selectedId, setSelectedId] = useState('')
  const [details, setDetails] = useState(null)
  const [caseOutcome, setCaseOutcome] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const selectedSummary = useMemo(() => history.find(item => (item.investigation_id || item.request_id || item.id) === selectedId) || history[0], [history, selectedId])
  const summary = details?.summary || selectedSummary || {}
  const investigationId = summary.investigation_id || summary.request_id || selectedId
  const findings = arr(details?.findings)
  const timeline = arr(details?.timeline)

  const loadHistory = async () => {
    setError('')
    try {
      const data = await api('/api/investigator/history')
      const loaded = arr(data.investigations)
      setHistory(loaded)
      if (!selectedId && loaded.length) setSelectedId(loaded[0].investigation_id || loaded[0].request_id || loaded[0].id)
    } catch (e) { setError(e.message) }
  }

  const loadDetails = async (id = selectedId) => {
    if (!id) return
    setLoading(true); setError('')
    try { setDetails(await api(`/api/investigator/${id}`)) } catch (e) { setError(e.message) } finally { setLoading(false) }
  }

  useEffect(() => { loadHistory() }, [])
  useEffect(() => { if (selectedId) loadDetails(selectedId) }, [selectedId])

  const createCase = async () => {
    if (!investigationId) return
    setError(''); setCaseOutcome(null)
    try { setCaseOutcome(await api(`/api/cases/from-investigation/${investigationId}`, { method: 'POST' })) } catch (e) { setError(e.message) }
  }

  const severity = summary.highest_severity || summary.severity || summary.status

  return <div className="page-stack">
    <div className="page-title"><Badge tone="purple">Investigation Review</Badge><h1>Investigation Details</h1><p>Review completed investigation summaries, findings, timelines and evidence before creating a case or exporting a report.</p></div>
    <div className="stats-grid three"><StatCard title="Investigations" value={history.length} subtitle="Stored results" /><StatCard title="Selected Findings" value={findings.length} subtitle="Normalised findings" tone={findings.length ? 'orange' : 'green'} /><StatCard title="Timeline Entries" value={timeline.length} subtitle="Chronological evidence" tone={timeline.length ? 'blue' : 'orange'} /></div>

    <section className="device-triage-layout">
      <Panel title="Investigation History" subtitle="Select a completed investigation to inspect."><InvestigationList items={history} selectedId={selectedId} onSelect={setSelectedId} /><Button onClick={loadHistory}>Refresh History</Button></Panel>
      <Panel title="Selected Investigation" subtitle={investigationId || 'No investigation selected'}>
        {summary ? <>
          <Verdict tone={toneFor(severity)} eyebrow={summary.status || 'Investigation'} title={summary.exit_decision || summary.status || 'Investigation result'} message={`Host: ${summary.hostname || summary.agent_id || 'unknown'}. Highest severity: ${summary.highest_severity || 'unknown'}.`} />
          <KeyGrid data={summary} />
          <Button onClick={createCase} disabled={!investigationId}>Create Case From This Investigation</Button>
          {summary.investigation_id && <a className="download-link" href={`${API}/api/investigator/${summary.investigation_id}/report`} target="_blank" rel="noreferrer">Open HTML Report</a>}
          {summary.investigation_id && <a className="download-link" href={`${API}/api/investigator/${summary.investigation_id}/bundle`} target="_blank" rel="noreferrer">Download Evidence Bundle</a>}
          {loading && <Empty>Loading investigation details…</Empty>}
          {caseOutcome && <Verdict tone="green" eyebrow="Case created" title={caseOutcome.status || 'created'} message={caseOutcome.case?.case_id || 'Case created from investigation.'} />}
        </> : <Empty>Select an investigation.</Empty>}
        {error && <div className="error-box">{error}</div>}
      </Panel>
    </section>

    <Panel title="Findings" subtitle="Matched suspicious behaviour, hardening issues or evidence-derived risks."><FindingCards items={findings} /></Panel>
    <Panel title="Timeline" subtitle="Chronological investigation evidence."><TimelineTable items={timeline} /></Panel>
  </div>
}
