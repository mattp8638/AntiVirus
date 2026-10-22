import { useEffect, useMemo, useState } from 'react'

const API = 'http://localhost:8000'
const arr = value => Array.isArray(value) ? value : []
const isObj = value => value && typeof value === 'object' && !Array.isArray(value)
const pick = (obj, keys, fallback = 'Not available') => keys.map(key => obj?.[key]).find(value => value !== undefined && value !== null && value !== '') ?? fallback
const toneFor = value => {
  const raw = String(value || '').toLowerCase()
  if (['critical', 'high', 'open', 'investigating'].some(v => raw.includes(v))) return raw.includes('open') || raw.includes('investigating') ? 'orange' : 'red'
  if (['medium', 'contained', 'review'].some(v => raw.includes(v))) return 'orange'
  if (['low', 'closed', 'remediated', 'ok', 'created'].some(v => raw.includes(v))) return 'green'
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

function CaseCards({ cases, selectedId, onSelect }) {
  if (!cases.length) return <Empty>No cases exist yet. Create a case manually or from a completed investigation.</Empty>
  return <div className="record-grid evidence-record-grid">{cases.map((item, index) => {
    const selected = item.case_id === selectedId
    return <button className={`record-card evidence ${toneFor(item.severity)} ${selected ? 'selected' : ''}`} key={item.case_id} onClick={() => onSelect(item.case_id)} style={{ textAlign: 'left' }}>
      <div className="record-card-top"><Badge tone={toneFor(item.severity)}>{item.severity}</Badge><span>{item.status}</span></div>
      <h3>{item.title}</h3>
      <p className="record-summary">{item.summary || 'No summary recorded yet.'}</p>
      <div className="record-evidence-grid">
        <article className="record-evidence-field"><span>Case ID</span><strong>{item.case_id}</strong></article>
        <article className="record-evidence-field"><span>Endpoint</span><strong>{item.affected_agent_id || 'Not linked'}</strong></article>
        <article className="record-evidence-field"><span>Investigation</span><strong>{item.investigation_id || 'Not linked'}</strong></article>
        <article className="record-evidence-field"><span>Updated</span><strong>{item.updated_at || 'Unknown'}</strong></article>
      </div>
    </button>
  })}</div>
}

function FindingCards({ findings }) {
  if (!findings.length) return <Empty>No findings are linked to this case yet.</Empty>
  return <div className="action-card-grid">{findings.map((finding, index) => {
    const severity = pick(finding, ['severity', 'status'], 'review')
    return <article className={`action-card ${toneFor(severity)}`} key={index}>
      <div className="action-card-top"><Badge tone={toneFor(severity)}>{severity}</Badge><span>#{index + 1}</span></div>
      <h3>{pick(finding, ['title', 'control', 'event'], `Finding ${index + 1}`)}</h3>
      <p>{pick(finding, ['recommended_action', 'remediation', 'summary'], 'Review this finding and decide the next action.')}</p>
    </article>
  })}</div>
}

function TimelineTable({ timeline }) {
  if (!timeline.length) return <Empty>No timeline entries are linked to this case yet.</Empty>
  return <div className="table-wrap"><table className="data-table"><thead><tr><th>Time</th><th>Source</th><th>Event</th><th>Severity</th></tr></thead><tbody>{timeline.map((item, index) => <tr key={index}><td>{item.time || item.timestamp || 'Unknown'}</td><td>{item.source || 'Unknown'}</td><td>{item.event || item.title || 'Event'}</td><td><Badge tone={toneFor(item.severity)}>{item.severity || 'info'}</Badge></td></tr>)}</tbody></table></div>
}

function EvidenceCards({ evidence }) {
  if (!evidence.length) return <Empty>No evidence metadata is attached to this case.</Empty>
  return <div className="record-grid evidence-record-grid">{evidence.map((item, index) => <article className="record-card evidence blue" key={index}>
    <div className="record-card-top"><Badge tone="blue">{item.type || 'Evidence'}</Badge><span>#{index + 1}</span></div>
    <h3>{item.hostname || item.investigation_id || item.agent_id || `Evidence ${index + 1}`}</h3>
    <div className="record-evidence-grid">{Object.entries(item).map(([key, value]) => <article className="record-evidence-field" key={key}><span>{key.replace(/_/g, ' ')}</span><strong>{isObj(value) || Array.isArray(value) ? JSON.stringify(value) : String(value ?? 'Not provided')}</strong></article>)}</div>
  </article>)}</div>
}

export function CaseManagement() {
  const [cases, setCases] = useState([])
  const [selectedId, setSelectedId] = useState('')
  const [selected, setSelected] = useState(null)
  const [investigations, setInvestigations] = useState([])
  const [title, setTitle] = useState('')
  const [severity, setSeverity] = useState('medium')
  const [summary, setSummary] = useState('')
  const [investigationId, setInvestigationId] = useState('')
  const [note, setNote] = useState('')
  const [action, setAction] = useState('')
  const [error, setError] = useState('')
  const [outcome, setOutcome] = useState(null)

  const selectedCase = selected?.case
  const linkedInvestigation = selected?.investigation
  const openCount = cases.filter(c => ['open', 'investigating'].includes(String(c.status).toLowerCase())).length
  const criticalCount = cases.filter(c => String(c.severity).toLowerCase() === 'critical').length
  const linkedCount = cases.filter(c => c.investigation_id).length

  const loadCases = async () => {
    setError('')
    try {
      const data = await api('/api/cases/')
      const loaded = arr(data.cases)
      setCases(loaded)
      if (!selectedId && loaded.length) setSelectedId(loaded[0].case_id)
    } catch (e) { setError(e.message) }
  }

  const loadInvestigations = async () => {
    try {
      const data = await api('/api/investigator/history')
      setInvestigations(arr(data.investigations))
    } catch (_) {}
  }

  const loadSelected = async (caseId = selectedId) => {
    if (!caseId) return
    setError('')
    try { setSelected(await api(`/api/cases/${caseId}`)) } catch (e) { setError(e.message) }
  }

  useEffect(() => { loadCases(); loadInvestigations() }, [])
  useEffect(() => { if (selectedId) loadSelected(selectedId) }, [selectedId])

  const createCase = async () => {
    setError(''); setOutcome(null)
    try {
      const payload = { title: title || 'New Sentinel case', severity, status: 'open', summary, investigation_id: investigationId || null }
      const data = await api('/api/cases/', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })
      setOutcome(data)
      await loadCases()
      if (data?.case?.case_id) setSelectedId(data.case.case_id)
    } catch (e) { setError(e.message) }
  }

  const createFromInvestigation = async () => {
    if (!investigationId) { setError('Select an investigation first.'); return }
    setError(''); setOutcome(null)
    try {
      const data = await api(`/api/cases/from-investigation/${investigationId}`, { method: 'POST' })
      setOutcome(data)
      await loadCases()
      if (data?.case?.case_id) setSelectedId(data.case.case_id)
    } catch (e) { setError(e.message) }
  }

  const updateSelected = async (patch) => {
    if (!selectedCase) return
    setError(''); setOutcome(null)
    try {
      const data = await api(`/api/cases/${selectedCase.case_id}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(patch) })
      setOutcome(data)
      await loadCases()
      await loadSelected(selectedCase.case_id)
      setNote(''); setAction('')
    } catch (e) { setError(e.message) }
  }

  const generateReport = async () => {
    if (!selectedCase) return
    setError(''); setOutcome(null)
    try {
      const data = await api(`/api/cases/${selectedCase.case_id}/report`, { method: 'POST' })
      setOutcome(data)
      await loadSelected(selectedCase.case_id)
    } catch (e) { setError(e.message) }
  }

  const investigationOptions = useMemo(() => investigations.map((item, index) => {
    const id = item.investigation_id || item.request_id || item.id || ''
    const label = `${id || `Investigation ${index + 1}`} — ${item.hostname || item.agent_id || 'unknown host'}`
    return { id, label }
  }).filter(item => item.id), [investigations])

  return <div className="page-stack">
    <div className="page-title"><Badge tone="purple">Reportable Workflow</Badge><h1>Case Management</h1><p>Create cases from investigations, track actions and export readable incident reports.</p></div>
    <div className="stats-grid three"><StatCard title="Cases" value={cases.length} subtitle="Stored in SQLite" /><StatCard title="Open / Investigating" value={openCount} subtitle="Needs attention" tone={openCount ? 'orange' : 'green'} /><StatCard title="Linked Investigations" value={linkedCount} subtitle="Evidence-backed cases" tone={linkedCount ? 'green' : 'blue'} /></div>

    <Panel title="Create Case" subtitle="Create manually, or select an investigation and create a case from its findings.">
      <input className="text-input" value={title} onChange={e => setTitle(e.target.value)} placeholder="Case title" />
      <select className="text-input" value={severity} onChange={e => setSeverity(e.target.value)}><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option></select>
      <textarea className="input-area" rows="3" value={summary} onChange={e => setSummary(e.target.value)} placeholder="Executive summary or reason for opening this case" />
      <select className="text-input" value={investigationId} onChange={e => setInvestigationId(e.target.value)}><option value="">No linked investigation</option>{investigationOptions.map(item => <option key={item.id} value={item.id}>{item.label}</option>)}</select>
      <Button onClick={createCase}>Create Case</Button>
      <Button onClick={createFromInvestigation} disabled={!investigationId}>Create From Investigation</Button>
      <Button onClick={() => { loadCases(); loadInvestigations() }}>Refresh</Button>
      {error && <div className="error-box">{error}</div>}
    </Panel>

    {outcome && <Verdict tone={toneFor(outcome.status)} eyebrow="Case action" title={outcome.status || 'Complete'} message="The case workflow has been updated." />}

    <section className="device-triage-layout">
      <Panel title="Case Queue" subtitle="Select a case to inspect evidence, notes and actions."><CaseCards cases={cases} selectedId={selectedId} onSelect={setSelectedId} /></Panel>
      <Panel title="Selected Case" subtitle={selectedCase ? selectedCase.case_id : 'No case selected'}>
        {selectedCase ? <>
          <Verdict tone={toneFor(selectedCase.severity)} eyebrow={selectedCase.status} title={selectedCase.title} message={selectedCase.summary || 'No summary recorded yet.'} />
          <div className="investigation-form-row">
            <select className="text-input" value={selectedCase.status} onChange={e => updateSelected({ status: e.target.value })}><option value="open">Open</option><option value="investigating">Investigating</option><option value="contained">Contained</option><option value="remediated">Remediated</option><option value="closed">Closed</option></select>
            <select className="text-input" value={selectedCase.severity} onChange={e => updateSelected({ severity: e.target.value })}><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option></select>
          </div>
          <textarea className="input-area" rows="2" value={note} onChange={e => setNote(e.target.value)} placeholder="Add case note" />
          <Button onClick={() => updateSelected({ note })} disabled={!note.trim()}>Add Note</Button>
          <input className="text-input" value={action} onChange={e => setAction(e.target.value)} placeholder="Add containment, eradication or recovery action" />
          <Button onClick={() => updateSelected({ action: { action } })} disabled={!action.trim()}>Add Action</Button>
          <Button onClick={generateReport}>Generate Incident Report</Button>
          <a className="download-link" href={`${API}/api/cases/${selectedCase.case_id}/report`} target="_blank" rel="noreferrer">Open Incident Report</a>
        </> : <Empty>Select or create a case.</Empty>}
      </Panel>
    </section>

    {selectedCase && <>
      <Panel title="Linked Evidence"><EvidenceCards evidence={arr(selectedCase.evidence)} /></Panel>
      <Panel title="Investigation Findings"><FindingCards findings={arr(linkedInvestigation?.findings)} /></Panel>
      <Panel title="Investigation Timeline"><TimelineTable timeline={arr(linkedInvestigation?.timeline)} /></Panel>
      <Panel title="Notes and Actions"><div className="action-card-grid">
        {arr(selectedCase.notes).map((n, i) => <article className="action-card blue" key={`n-${i}`}><Badge>Note</Badge><h3>{n.created_at || `Note ${i + 1}`}</h3><p>{n.note}</p></article>)}
        {arr(selectedCase.actions).map((a, i) => <article className={`action-card ${toneFor(a.status)}`} key={`a-${i}`}><Badge tone={toneFor(a.status)}>{a.status || 'open'}</Badge><h3>{a.action || `Action ${i + 1}`}</h3><p>{a.created_at || 'No timestamp'}</p></article>)}
      </div></Panel>
    </>}
  </div>
}
