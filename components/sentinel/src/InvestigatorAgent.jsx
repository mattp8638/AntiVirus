import { useEffect, useMemo, useState } from 'react'
import './investigator.css'

const API = 'http://localhost:8000'

const arr = value => Array.isArray(value) ? value : []
const isObj = value => value && typeof value === 'object' && !Array.isArray(value)
const pick = (obj, keys, fallback = 'Not available') => keys.map(key => obj?.[key]).find(value => value !== undefined && value !== null && value !== '') ?? fallback
const nice = key => String(key || '').replace(/_/g, ' ').replace(/([a-z])([A-Z])/g, '$1 $2').replace(/\b\w/g, c => c.toUpperCase())
const toneFor = value => {
  const raw = String(value || '').toLowerCase()
  if (['critical', 'high', 'failed', 'danger', 'error', 'pending'].some(v => raw.includes(v))) return raw.includes('pending') ? 'orange' : 'red'
  if (['medium', 'warning', 'review', 'queued', 'requested'].some(v => raw.includes(v))) return 'orange'
  if (['low', 'safe', 'active', 'complete', 'success', 'healthy', 'idle'].some(v => raw.includes(v))) return 'green'
  return 'blue'
}
const bandRank = band => ({ critical: 4, high: 3, medium: 2, low: 1 }[String(band || '').toLowerCase()] || 0)
const getAssessment = device => isObj(device?.latest_assessment) ? device.latest_assessment : null
const getRiskBand = device => getAssessment(device)?.risk_band || device?.risk_band || 'unknown'
const getRiskScore = device => Number(getAssessment(device)?.risk_score ?? device?.risk_score ?? 0)
const getFindings = device => arr(getAssessment(device)?.findings)
const priorityScore = device => (bandRank(getRiskBand(device)) * 100) + getFindings(device).filter(f => ['critical', 'high'].includes(String(f.severity || '').toLowerCase())).length * 20 + Math.max(0, 100 - getRiskScore(device))

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

function ScopeToggle({ id, label, description, checked, onChange }) {
  return <label className={`investigation-scope-card ${checked ? 'selected' : ''}`}>
    <input type="checkbox" checked={checked} onChange={event => onChange(id, event.target.checked)} />
    <div><strong>{label}</strong><p>{description}</p></div>
  </label>
}

function DevicePicker({ devices, selectedId, onSelect }) {
  if (!devices.length) return <Empty>No registered agents found. Register an endpoint first, then return to Investigator.</Empty>
  return <div className="device-queue">{devices.map((device, index) => {
    const id = pick(device, ['agent_id', 'id', 'hostname'], `device-${index}`)
    const host = pick(device, ['hostname', 'name', 'agent_id'], `Device ${index + 1}`)
    const band = getRiskBand(device)
    const score = getRiskScore(device)
    const investigation = device.investigation || 'idle'
    return <button className={`device-row ${selectedId === id ? 'selected' : ''}`} key={id} onClick={() => onSelect(id)}>
      <div className="device-rank">#{index + 1}</div>
      <div className="device-main"><div><Badge tone={toneFor(investigation)}>{investigation}</Badge><h3>{host}</h3><p>{device.operating_system || 'No operating system reported'}</p></div></div>
      <div className="device-metrics">
        <span><b>{score || '—'}</b> score</span>
        <span><b>{band}</b> band</span>
        <span><b>{getFindings(device).length}</b> findings</span>
        <span><b>{priorityScore(device)}</b> priority</span>
      </div>
    </button>
  })}</div>
}

function KeyGrid({ data }) {
  const entries = Object.entries(data || {}).filter(([, value]) => value !== undefined && value !== null && value !== '' && !Array.isArray(value) && !isObj(value))
  if (!entries.length) return <Empty>No details returned.</Empty>
  return <div className="kv-grid">{entries.map(([key, value]) => <article className="kv-card" key={key}><span>{nice(key)}</span><strong>{String(value)}</strong></article>)}</div>
}

function ActionCards({ items, empty = 'No findings available.' }) {
  if (!items?.length) return <Empty>{empty}</Empty>
  return <div className="action-card-grid">{items.map((item, index) => {
    const title = pick(item, ['control', 'title', 'issue', 'event'], `Finding ${index + 1}`)
    const detail = pick(item, ['remediation', 'recommended_action', 'description', 'summary'], 'Review this finding and determine the next action.')
    const severity = pick(item, ['severity', 'status'], 'Review')
    return <article className={`action-card ${toneFor(severity)}`} key={index}>
      <div className="action-card-top"><Badge tone={toneFor(severity)}>{severity}</Badge><span>#{index + 1}</span></div>
      <h3>{title}</h3>
      <p>{detail}</p>
    </article>
  })}</div>
}

export function Investigator() {
  const [agents, setAgents] = useState(null)
  const [selectedId, setSelectedId] = useState('')
  const [priority, setPriority] = useState('normal')
  const [reason, setReason] = useState('Analyst requested endpoint investigation')
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [scope, setScope] = useState({
    processes: true,
    network: true,
    services: true,
    startup: true,
    scheduled_tasks: true,
    eventlogs: true,
    software: true,
    users: true,
    files: true,
  })

  const devices = useMemo(() => arr(agents?.agents || agents?.results || agents?.items).slice().sort((a, b) => priorityScore(b) - priorityScore(a)), [agents])
  const selected = devices.find(device => pick(device, ['agent_id', 'id', 'hostname'], '') === selectedId) || devices[0]
  const selectedAssessment = getAssessment(selected)
  const pendingCount = devices.filter(device => String(device.investigation || '').toLowerCase() === 'pending').length
  const completeCount = devices.filter(device => String(device.investigation || '').toLowerCase() === 'complete').length

  const loadAgents = async () => {
    setError('')
    try {
      const data = await api('/api/endpoint/agents')
      const loaded = arr(data.agents || data.results || data.items).slice().sort((a, b) => priorityScore(b) - priorityScore(a))
      setAgents(data)
      if (!selectedId && loaded.length) setSelectedId(pick(loaded[0], ['agent_id', 'id', 'hostname'], ''))
    } catch (e) { setError(e.message) }
  }

  useEffect(() => { loadAgents() }, [])

  const setScopeValue = (key, value) => setScope(current => ({ ...current, [key]: value }))

  const queueInvestigation = async () => {
    if (!selected) return
    setLoading(true); setError(''); setResult(null)
    const agentId = pick(selected, ['agent_id', 'id'], '')
    const collectors = Object.entries(scope).filter(([, enabled]) => enabled).map(([key]) => key)
    try {
      const response = await api(`/api/endpoint/agent/${agentId}/investigate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ priority, reason, scope: { collectors } }),
      })
      setResult(response)
      await loadAgents()
    } catch (e) { setError(e.message) } finally { setLoading(false) }
  }

  return <div className="page-stack">
    <div className="page-title"><Badge tone="purple">Agent Investigation</Badge><h1>Investigator</h1><p>Select a registered device, choose the investigation scope, then queue evidence collection for that endpoint.</p></div>
    <div className="stats-grid three"><StatCard title="Registered Devices" value={devices.length} subtitle="Available investigation targets" /><StatCard title="Pending Investigations" value={pendingCount} subtitle="Queued for agents" tone={pendingCount ? 'orange' : 'green'} /><StatCard title="Completed Evidence" value={completeCount} subtitle="Evidence uploaded by agents" tone={completeCount ? 'green' : 'blue'} /></div>

    <section className="device-triage-layout">
      <Panel title="Investigation Target" subtitle="Choose which device should collect evidence."><DevicePicker devices={devices} selectedId={selectedId} onSelect={setSelectedId} /><Button onClick={loadAgents}>Refresh Devices</Button></Panel>
      <Panel title="Selected Device" subtitle={selected ? pick(selected, ['hostname', 'agent_id'], 'Selected endpoint') : 'No device selected'}>
        {selected ? <><Verdict tone={toneFor(selected.investigation || getRiskBand(selected))} eyebrow="Target state" title={selected.investigation || 'idle'} message={`Risk band: ${getRiskBand(selected)}. Risk score: ${getRiskScore(selected) || 'not assessed'}.`} /><KeyGrid data={selected} />{selected.evidence_file && <a className="download-link" href={`${API}/api/endpoint/agent/${selected.agent_id}/evidence/download`}>Download uploaded evidence</a>}</> : <Empty>Select a device to view target details.</Empty>}
      </Panel>
    </section>

    <Panel title="Investigation Scope" subtitle="Choose what the agent should collect. This becomes the investigation instruction for the selected endpoint.">
      <div className="scope-grid">
        <ScopeToggle id="processes" label="Processes and process tree" description="Running processes, command lines and suspicious parent/child chains." checked={scope.processes} onChange={setScopeValue} />
        <ScopeToggle id="network" label="Network connections" description="Active connections, risky processes with external sessions and remote endpoints." checked={scope.network} onChange={setScopeValue} />
        <ScopeToggle id="services" label="Services" description="Installed/running services, binary paths, account context and start type." checked={scope.services} onChange={setScopeValue} />
        <ScopeToggle id="startup" label="Startup folders and autoruns" description="Startup folders, registry autoruns and other persistence entries." checked={scope.startup} onChange={setScopeValue} />
        <ScopeToggle id="scheduled_tasks" label="Scheduled tasks" description="Task scheduler entries that may persist or re-launch tooling." checked={scope.scheduled_tasks} onChange={setScopeValue} />
        <ScopeToggle id="eventlogs" label="Windows event logs" description="Security, PowerShell and Defender operational event summaries." checked={scope.eventlogs} onChange={setScopeValue} />
        <ScopeToggle id="software" label="Installed software inventory" description="Installed applications, publishers and version inventory for CVE matching." checked={scope.software} onChange={setScopeValue} />
        <ScopeToggle id="users" label="Local users and administrators" description="Local user accounts and administrator group membership." checked={scope.users} onChange={setScopeValue} />
        <ScopeToggle id="files" label="Suspicious files and hashes" description="Recently modified user-writable files and their hashes for review." checked={scope.files} onChange={setScopeValue} />
      </div>
      <div className="investigation-form-row">
        <label><span>Priority</span><select className="text-input" value={priority} onChange={e => setPriority(e.target.value)}><option value="normal">Normal</option><option value="high">High</option><option value="urgent">Urgent</option></select></label>
        <label><span>Reason</span><input className="text-input" value={reason} onChange={e => setReason(e.target.value)} placeholder="Why is this endpoint being investigated?" /></label>
      </div>
      <Button onClick={queueInvestigation} disabled={!selected || loading}>{loading ? 'Queuing…' : 'Queue Agent Investigation'}</Button>{error && <div className="error-box">{error}</div>}
    </Panel>

    {result && <Panel title="Investigation Request"><OutcomeCard data={result} /></Panel>}
    {selectedAssessment && <Panel title="Current Posture Findings"><ActionCards items={getFindings(selected)} empty="No posture findings available for this endpoint." /></Panel>}
  </div>
}

function OutcomeCard({ data }) {
  return <div className="outcome-stack"><Verdict tone={toneFor(data.status)} eyebrow="Queued" title={data.status || 'Investigation requested'} message="The request has been stored against the selected agent. The agent should collect the selected evidence and upload the bundle." /><KeyGrid data={data} /></div>
}
