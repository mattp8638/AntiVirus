import { useEffect, useState } from 'react'
import './styles.css'
import './triage.css'
import { Investigator, ExposureScout, CVEWatchdog, PhishGuard, EmailIntel, Settings } from './AppExtraModules.jsx'

const API = 'http://localhost:8000'

const navItems = [
  ['overview', 'Command Overview'],
  ['pipeline', 'Threat Pipeline'],
  ['endpoint', 'Endpoint Risk'],
  ['investigator', 'Investigator'],
  ['exposure', 'ExposureScout'],
  ['cve', 'CVE Watchdog'],
  ['phish', 'PhishGuard'],
  ['emailintel', 'Email Intelligence'],
  ['settings', 'Settings'],
]

const arr = value => Array.isArray(value) ? value : []
const isObj = value => value && typeof value === 'object' && !Array.isArray(value)
const pick = (obj, keys, fallback = 'Not available') => keys.map(key => obj?.[key]).find(value => value !== undefined && value !== null && value !== '') ?? fallback
const nice = key => String(key || '').replace(/_/g, ' ').replace(/([a-z])([A-Z])/g, '$1 $2').replace(/\b\w/g, c => c.toUpperCase())
const text = value => value === null || value === undefined || value === '' ? 'Not provided' : Array.isArray(value) ? `${value.length} item${value.length === 1 ? '' : 's'}` : isObj(value) ? 'Structured details shown below' : String(value)
const toneFor = value => {
  const raw = String(value || '').toLowerCase()
  if (['critical', 'high', 'block', 'blocked', 'failed', 'danger', 'malicious', 'error'].some(v => raw.includes(v))) return 'red'
  if (['medium', 'warning', 'monitor', 'pending', 'review', 'suspicious'].some(v => raw.includes(v))) return 'orange'
  if (['low', 'safe', 'active', 'success', 'sent', 'created', 'healthy', 'pass', 'trusted'].some(v => raw.includes(v))) return 'green'
  return 'blue'
}

const bandRank = band => ({ critical: 4, high: 3, medium: 2, low: 1 }[String(band || '').toLowerCase()] || 0)
const getAssessment = device => isObj(device?.latest_assessment) ? device.latest_assessment : null
const getRiskBand = device => getAssessment(device)?.risk_band || device?.risk_band || 'unknown'
const getRiskScore = device => Number(getAssessment(device)?.risk_score ?? device?.risk_score ?? 0)
const getFindings = device => arr(getAssessment(device)?.findings)
const failedFindings = device => getFindings(device).filter(f => String(f.status || '').toLowerCase() === 'failed').length
const highImpactFindings = device => getFindings(device).filter(f => ['critical', 'high'].includes(String(f.severity || '').toLowerCase())).length
const triageScore = device => (bandRank(getRiskBand(device)) * 100) + (highImpactFindings(device) * 15) + (failedFindings(device) * 5) + Math.max(0, 100 - getRiskScore(device))
const triageLabel = device => {
  const band = String(getRiskBand(device)).toLowerCase()
  if (band === 'critical') return 'Immediate review'
  if (band === 'high') return 'Prioritise today'
  if (band === 'medium') return 'Plan remediation'
  if (band === 'low') return 'Monitor'
  return 'Needs assessment'
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

function ActionCards({ items, empty = 'No actions required.' }) {
  if (!items?.length) return <Empty>{empty}</Empty>
  return <div className="action-card-grid">{items.map((item, index) => {
    const obj = isObj(item) ? item : { value: item, decision: 'Review' }
    const title = pick(obj, ['control', 'title', 'value', 'issue', 'cve', 'name', 'domain', 'email'], `Item ${index + 1}`)
    const detail = pick(obj, ['remediation', 'recommended_action', 'reason', 'message', 'description'], 'Review this item and decide the next action.')
    const status = pick(obj, ['severity', 'decision', 'status', 'risk_band', 'type'], 'Review')
    const tone = toneFor(status)
    return <article className={`action-card ${tone}`} key={index}>
      <div className="action-card-top"><Badge tone={tone}>{status}</Badge><span>#{index + 1}</span></div>
      <h3>{title}</h3>
      <p>{detail}</p>
    </article>
  })}</div>
}

function AssessmentBlock({ assessment }) {
  const findings = arr(assessment?.findings)
  const riskBand = assessment?.risk_band || 'unknown'
  return <div className="assessment-panel">
    <div className="assessment-header">
      <div><Badge tone={toneFor(riskBand)}>Latest assessment</Badge><h4>{assessment?.summary || 'Endpoint assessment'}</h4></div>
      <Badge tone={toneFor(riskBand)}>{riskBand}</Badge>
    </div>
    <div className="assessment-stat-grid">
      <article><span>Host</span><strong>{assessment?.hostname || 'Not provided'}</strong></article>
      <article><span>Operating System</span><strong>{assessment?.operating_system || 'Not provided'}</strong></article>
      <article><span>Risk Score</span><strong>{assessment?.risk_score ?? 'Not provided'}/100</strong></article>
      <article><span>Risk Band</span><strong>{riskBand}</strong></article>
    </div>
    <div className="assessment-findings-header"><h4>Assessment findings</h4><span>{findings.length} finding{findings.length === 1 ? '' : 's'}</span></div>
    <ActionCards items={findings} empty="No assessment findings were returned." />
  </div>
}

function KeyGrid({ data }) {
  const entries = Object.entries(data || {}).filter(([, value]) => value !== undefined && value !== null && value !== '')
  if (!entries.length) return <Empty>No details returned.</Empty>
  return <div className="kv-grid">{entries.map(([key, value]) => <article className="kv-card" key={key}><span>{nice(key)}</span><strong>{text(value)}</strong></article>)}</div>
}

function Field({ name, value }) {
  if (name === 'latest_assessment' && isObj(value)) return <article className="record-evidence-field wide"><span>{nice(name)}</span><AssessmentBlock assessment={value} /></article>
  if (Array.isArray(value) && value.every(item => !isObj(item))) return <article className="record-evidence-field"><span>{nice(name)}</span><div className="inline-chip-row">{value.map((item, i) => <span className="inline-chip" key={i}>{String(item)}</span>)}</div></article>
  if (Array.isArray(value)) return <article className="record-evidence-field wide"><span>{nice(name)}</span><ActionCards items={value} /></article>
  if (isObj(value)) return <article className="record-evidence-field wide"><span>{nice(name)}</span><KeyGrid data={value} /></article>
  return <article className="record-evidence-field"><span>{nice(name)}</span><strong>{text(value)}</strong></article>
}

function RecordCards({ items, titleKeys = ['hostname', 'name', 'domain', 'email', 'id'], empty = 'No records found.' }) {
  if (!items?.length) return <Empty>{empty}</Empty>
  return <div className="record-grid evidence-record-grid">{items.map((item, index) => {
    const obj = isObj(item) ? item : { value: item }
    const title = pick(obj, titleKeys, `Record ${index + 1}`)
    const status = pick(obj, ['status', 'severity', 'state', 'decision'], 'Record')
    return <article className={`record-card evidence ${toneFor(status)}`} key={index}>
      <div className="record-card-top"><Badge tone={toneFor(status)}>{status}</Badge><span>Evidence record #{index + 1}</span></div>
      <h3>{title}</h3>
      <p className="record-summary">{pick(obj, ['operating_system', 'summary', 'message', 'description', 'last_seen'], 'Full record details are shown below.')}</p>
      <div className="record-evidence-grid">{Object.entries(obj).filter(([, value]) => value !== undefined && value !== null && value !== '').map(([key, value]) => <Field key={key} name={key} value={value} />)}</div>
    </article>
  })}</div>
}

function Outcome({ data, context = 'Outcome' }) {
  if (!data) return null
  const status = pick(data, ['status', 'message', 'result', 'decision', 'verdict'], 'Action completed')
  return <div className="outcome-stack"><Verdict tone={toneFor(status)} eyebrow={context} title={status} message="The backend response has been converted into readable cards." /><KeyGrid data={data} /></div>
}

function DevicePriorityQueue({ devices, selectedId, onSelect }) {
  if (!devices.length) return <Empty>No registered devices found. Register or refresh agents to build the triage queue.</Empty>
  return <div className="device-queue">{devices.map((device, index) => {
    const id = pick(device, ['agent_id', 'id', 'hostname'], `device-${index}`)
    const host = pick(device, ['hostname', 'name', 'agent_id'], `Device ${index + 1}`)
    const band = getRiskBand(device)
    const score = getRiskScore(device)
    const findings = getFindings(device)
    const isSelected = selectedId === id
    return <button className={`device-row ${isSelected ? 'selected' : ''}`} key={id} onClick={() => onSelect(id)}>
      <div className="device-rank">#{index + 1}</div>
      <div className="device-main"><div><Badge tone={toneFor(band)}>{triageLabel(device)}</Badge><h3>{host}</h3><p>{pick(device, ['operating_system', 'last_seen'], 'No operating system reported')}</p></div></div>
      <div className="device-metrics">
        <span><b>{score || '—'}</b> score</span>
        <span><b>{band}</b> band</span>
        <span><b>{findings.length}</b> findings</span>
        <span><b>{triageScore(device)}</b> priority</span>
      </div>
    </button>
  })}</div>
}

function ScoringMatrix() {
  const rows = [
    ['Critical', 'Immediate review', 'Device has critical posture issues, severe failed controls, or very poor score.', 'red'],
    ['High', 'Prioritise today', 'Device has high-risk findings that should be investigated before routine work.', 'red'],
    ['Medium', 'Plan remediation', 'Device has hardening gaps that should be scheduled and tracked.', 'orange'],
    ['Low', 'Monitor', 'Device appears lower priority but should remain visible in the queue.', 'green'],
  ]
  return <div className="scoring-matrix">{rows.map(([band, action, detail, tone]) => <article key={band} className={`matrix-card ${tone}`}><Badge tone={tone}>{band}</Badge><h3>{action}</h3><p>{detail}</p></article>)}</div>
}

function Overview() {
  return <div className="page-stack"><div className="hero"><div><Badge tone="green">Operational</Badge><h1>Sentinel Security Command Centre</h1><p>A Blue Team workspace that presents outcomes, evidence, risk and next actions without raw JSON.</p></div></div><div className="stats-grid"><StatCard title="Threat Pipeline" value="Live" subtitle="Validation and block actions" /><StatCard title="Investigator" value="Ready" subtitle="Evidence and timelines" tone="purple" /><StatCard title="Interface" value="Readable" subtitle="No JSON dumps" tone="green" /><StatCard title="Roadmap" value="Locked" subtitle="50-module Blue Team suite" tone="orange" /></div></div>
}

function ThreatPipeline() {
  const [input, setInput] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const run = async () => { setLoading(true); setError(''); try { setResult(await api('/api/pipeline/run', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ input }) })) } catch (e) { setError(e.message) } finally { setLoading(false) } }
  const validation = arr(result?.validation?.results)
  const decisions = arr(result?.decisions?.decisions)
  const blocks = result?.blocklist?.plain_text ? result.blocklist.plain_text.split('\n').filter(Boolean).map(value => ({ value, decision: 'BLOCK', reason: 'Review this defensive block action before deployment.' })) : []
  return <div className="page-stack"><div className="page-title"><Badge tone="blue">Live Workflow</Badge><h1>Threat Processing Pipeline</h1><p>Paste indicators and receive readable validation, decision and defensive action cards.</p></div><Panel title="IOC Input"><textarea className="input-area" rows="8" value={input} onChange={e => setInput(e.target.value)} placeholder="hxxp://evil[.]com&#10;1.1.1.1&#10;CVE-2024-1234" /><Button onClick={run} disabled={loading || !input.trim()}>{loading ? 'Processing…' : 'Run Full Pipeline'}</Button>{error && <div className="error-box">{error}</div>}</Panel>{result && <><Verdict tone={blocks.length ? 'red' : 'green'} eyebrow="Pipeline complete" title={blocks.length ? 'Defensive actions generated' : 'No block actions required'} message="Pipeline output is displayed as validation records, threat decisions and reviewable actions." /><div className="stats-grid three"><StatCard title="Validated IOCs" value={validation.length} subtitle="Extracted indicators" /><StatCard title="Threat Decisions" value={decisions.length} subtitle="Scored results" tone="purple" /><StatCard title="Block Actions" value={blocks.length} subtitle="Review before deployment" tone={blocks.length ? 'red' : 'green'} /></div><Panel title="Validated Indicators"><RecordCards items={validation} titleKeys={['value']} /></Panel><Panel title="Threat Decisions"><ActionCards items={decisions} /></Panel><Panel title="Generated Defensive Actions"><ActionCards items={blocks} empty="No block actions generated." /></Panel></>}</div>
}

function EndpointRisk() {
  const [host, setHost] = useState('')
  const [registered, setRegistered] = useState(null)
  const [agents, setAgents] = useState(null)
  const [selectedDeviceId, setSelectedDeviceId] = useState(null)
  const [error, setError] = useState('')

  const devices = arr(agents?.agents || agents?.results || agents?.items).slice().sort((a, b) => triageScore(b) - triageScore(a))
  const selectedDevice = devices.find(device => pick(device, ['agent_id', 'id', 'hostname'], '') === selectedDeviceId) || devices[0]
  const selectedAssessment = getAssessment(selectedDevice)
  const criticalCount = devices.filter(device => String(getRiskBand(device)).toLowerCase() === 'critical').length
  const highCount = devices.filter(device => String(getRiskBand(device)).toLowerCase() === 'high').length

  const loadAgents = async () => {
    setError('')
    try {
      const data = await api('/api/endpoint/agents')
      const loaded = arr(data.agents || data.results || data.items).slice().sort((a, b) => triageScore(b) - triageScore(a))
      setAgents(data)
      if (!selectedDeviceId && loaded.length) setSelectedDeviceId(pick(loaded[0], ['agent_id', 'id', 'hostname'], ''))
    } catch (e) { setError(e.message) }
  }

  useEffect(() => { loadAgents() }, [])

  const register = async () => {
    setError('')
    try {
      setRegistered(await api('/api/endpoint/agent/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ hostname: host || 'TEST-ENDPOINT', operating_system: 'Windows 11 Pro' }) }))
      await loadAgents()
    } catch (e) { setError(e.message) }
  }

  return <div className="page-stack"><div className="page-title"><Badge tone="green">Live Agents</Badge><h1>Endpoint Risk</h1><p>Device triage queue sorted by risk band, failed controls, high-impact findings and posture score.</p></div>
    <Panel title="Agent Registration" subtitle="Register a device, then use the priority queue to decide what needs attention first."><input className="text-input" value={host} onChange={e => setHost(e.target.value)} placeholder="Hostname" /><Button onClick={register}>Register Agent</Button><Button onClick={loadAgents}>Refresh Devices</Button>{error && <div className="error-box">{error}</div>}</Panel>
    {registered && <Panel title="Registration Outcome"><Outcome data={registered} context="Agent" /></Panel>}
    <div className="stats-grid three"><StatCard title="Registered Devices" value={devices.length} subtitle="Loaded from endpoint registry" /><StatCard title="Critical Devices" value={criticalCount} subtitle="Immediate review" tone={criticalCount ? 'red' : 'green'} /><StatCard title="High-Risk Devices" value={highCount} subtitle="Prioritise today" tone={highCount ? 'red' : 'green'} /></div>
    <Panel title="Scoring Matrix" subtitle="How Sentinel decides what should be looked at first."><ScoringMatrix /></Panel>
    <section className="device-triage-layout">
      <Panel title="Device Priority Queue" subtitle="Select a device to view its latest assessment."><DevicePriorityQueue devices={devices} selectedId={selectedDeviceId} onSelect={setSelectedDeviceId} /></Panel>
      <Panel title="Selected Device Assessment" subtitle={selectedDevice ? pick(selectedDevice, ['hostname', 'agent_id'], 'Selected device') : 'No device selected'}>
        {selectedAssessment ? <AssessmentBlock assessment={selectedAssessment} /> : <Empty>No latest assessment is available for the selected device yet.</Empty>}
      </Panel>
    </section>
    {selectedDevice && <Panel title="Selected Device Evidence"><RecordCards items={[selectedDevice]} empty="No selected device details available." /></Panel>}
  </div>
}

export default function AppHuman() {
  const [active, setActive] = useState('overview')
  const pages = { overview: <Overview />, pipeline: <ThreatPipeline />, endpoint: <EndpointRisk />, investigator: <Investigator />, exposure: <ExposureScout />, cve: <CVEWatchdog />, phish: <PhishGuard />, emailintel: <EmailIntel />, settings: <Settings /> }
  return <div className="app-shell"><aside className="sidebar"><div className="brand"><div className="brand-mark">S</div><div><h2>Sentinel</h2><p>Cyber Defence Platform</p></div></div><nav>{navItems.map(([id, title]) => <button key={id} className={active === id ? 'active' : ''} onClick={() => setActive(id)}>{title}</button>)}</nav></aside><main className="content">{pages[active]}</main></div>
}
