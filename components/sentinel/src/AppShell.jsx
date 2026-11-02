import { useEffect, useMemo, useState } from 'react'
import './styles.css'
import './triage.css'
import { Investigator } from './InvestigatorAgent.jsx'
import { InvestigationDetails } from './InvestigationDetails.jsx'
import { CVEWatchdog } from './CVEWatchdogAdvanced.jsx'
import { CaseManagement } from './CaseManagement.jsx'
import { PersistenceScanner } from './PersistenceScanner.jsx'
import { PhishingEmailAnalyser } from './PhishingEmailAnalyser.jsx'
import { NetworkConnectionMonitor } from './NetworkConnectionMonitor.jsx'
import { IOCScanner } from './IOCScanner.jsx'
import { AVScanner } from './AVScanner.jsx'
import { ExternalServiceChecker, SecuritySuite } from './SecuritySuite.jsx'
import { ExposureScout, EmailIntel, Settings } from './AppExtraModules.jsx'

const API = 'http://localhost:8000'

const page = (id, title, expectations = []) => ({ id, title, status: 'ready', expectations })
const suite = (slug, title, expectations = []) => ({ id: `suite:${slug}`, title, status: 'module', expectations })
const pack = (slug, title, expectations = []) => ({ id: `pack:${slug}`, title, status: 'workflow', expectations })
const roadmap = (slug, title, expectations = []) => ({ id: `placeholder:${slug}`, title, status: 'roadmap', expectations })
const deferred = (slug, title, expectations = []) => ({ id: `placeholder:${slug}`, title, status: 'deferred', expectations })

const menuSections = [
  {
    id: 'dashboard',
    title: 'Dashboard',
    items: [
      page('overview', 'Overview'),
      roadmap('priority_queue', 'Priority Queue', ['Rank critical devices, KEV exposure, failed baselines and active investigations in one work queue.', 'Open the affected device, case, finding or remediation task from the same row.']),
      roadmap('recent_activity', 'Recent Activity', ['Show scans, agent check-ins, evidence uploads, case updates and connector events in time order.', 'Filter activity by device, user, module, case and severity.']),
      suite('remediation_guidance_wizard', 'Top Fixes'),
      suite('risk_register_export', 'Risk Summary'),
      suite('security_health_score', 'Security Health Score'),
      roadmap('guided_response_playbooks', 'Guided Response Playbooks', ['Launch plain-English response flows for common incidents.', 'Record each action, owner, evidence link and outcome for reporting.']),
    ],
  },
  {
    id: 'devices',
    title: 'Devices',
    items: [
      page('endpoint', 'Device List'),
      roadmap('device_detail', 'Device Detail', ['Open a device workspace with Summary, Health, Inventory, Findings, Investigations, Evidence and Cases tabs.', 'Blend technical risk with asset criticality and ownership.']),
      suite('installed_software_inventory', 'Installed Software'),
      suite('windows_security_baseline_checker', 'Security Baseline'),
      suite('patch_status_checker', 'Patch Status'),
      suite('browser_security_checker', 'Browser Security'),
      suite('backup_readiness_checker', 'Backup Readiness'),
      roadmap('asset_criticality_ownership_register', 'Asset Ownership', ['Track owner, business service, criticality, data sensitivity and recovery priority for each asset.', 'Use this context to prioritise findings, vulnerabilities and incidents.']),
      roadmap('certificate_trust_store_auditor', 'Certificate and Trust Store', ['Inspect trusted roots, user certificates and suspicious trust additions.', 'Flag weak, expired, unexpected or recently added certificates.']),
    ],
  },
  {
    id: 'investigate',
    title: 'Investigate',
    items: [
      page('investigator', 'Run Investigation'),
      page('investigationDetails', 'Investigation Results'),
      page('persistence', 'Persistence'),
      suite('process_tree_viewer', 'Processes'),
      suite('suspicious_command_line_analyser', 'Suspicious Commands'),
      page('network', 'Network Evidence'),
      suite('windows_event_log_collector', 'Event Logs'),
      suite('powershell_activity_analyser', 'PowerShell Activity'),
      suite('timeline_builder', 'Timeline'),
      suite('evidence_bundle_exporter', 'Evidence Bundles'),
      roadmap('chain_of_custody_log', 'Chain of Custody', ['Record who collected, viewed, exported or modified each evidence item.', 'Hash exported bundles and reports so integrity can be verified later.']),
      suite('incident_report_generator', 'Reports'),
      pack('endpoint_triage', 'Endpoint Triage Workflow'),
    ],
  },
  {
    id: 'protect',
    title: 'Protect',
    items: [
      suite('av_scanner', 'AV Scanner'),
      suite('ioc_scanner', 'IOC Scanner'),
      roadmap('quarantine_review_restore_manager', 'Quarantine', ['Review quarantined files with hash, source scan, affected device and analyst notes.', 'Restore or delete only through explicit audited actions.']),
      suite('ransomware_behaviour_guard', 'Ransomware Guard'),
      suite('dns_protection_tool', 'DNS Protection'),
      suite('usb_guard', 'USB Guard'),
      suite('firewall_rule_auditor', 'Firewall Controls'),
      roadmap('alert_exception_suppression_manager', 'Exceptions', ['Create scoped alert suppressions with reason, owner, expiry and affected rule IDs.', 'Show every matching finding that will be hidden before the exception is saved.']),
      roadmap('offline_scan_workflow', 'Offline Scan', ['Guide a safe offline scan workflow for mounted drives and evidence images.', 'Snapshot detections and scan settings without changing evidence by default.']),
    ],
  },
  {
    id: 'vulnerabilities',
    title: 'Vulnerabilities',
    items: [
      roadmap('vulnerability_dashboard', 'Vulnerability Dashboard', ['Summarise open CVEs, KEVs, affected assets and remediation age.', 'Prioritise known-exploited issues above ordinary CVEs.']),
      page('cve', 'CVE / KEV Matcher'),
      suite('patch_status_checker', 'Patch Status'),
      suite('installed_software_inventory', 'Software Inventory'),
      page('exposure', 'Exposure Review'),
      suite('firewall_rule_auditor', 'Firewall Exposure'),
      suite('risk_register_export', 'Risk Register'),
    ],
  },
  {
    id: 'networkDns',
    title: 'Network & DNS',
    items: [
      page('network', 'Network Connections'),
      suite('dns_monitor', 'DNS Monitor'),
      suite('dns_protection_tool', 'DNS Protection'),
      suite('firewall_rule_auditor', 'Firewall Audit'),
      roadmap('hosts_proxy_vpn_tamper_checker', 'Hosts / Proxy / VPN', ['Check hosts-file entries, proxy settings, VPN configuration and suspicious route changes.', 'Explain how each change could redirect or intercept traffic.']),
    ],
  },
  {
    id: 'emailCloud',
    title: 'Email & Cloud',
    items: [
      page('phish', 'Phishing Email Analyser'),
      suite('email_header_analyser', 'Header Analysis'),
      suite('url_redirect_tracer', 'URL Tracing'),
      suite('attachment_risk_analyser', 'Attachment Analysis'),
      suite('mailbox_rule_checker', 'Mailbox Rules'),
      page('emailintel', 'Email Intelligence'),
      pack('email_investigation', 'Email Investigation Workflow'),
    ],
  },
  {
    id: 'intelligenceRules',
    title: 'Intelligence & Rules',
    items: [
      page('pipeline', 'Threat Pipeline'),
      suite('threat_feed_aggregator', 'Threat Feeds'),
      suite('yara_rule_manager', 'YARA Rules'),
      suite('sigma_rule_manager', 'Sigma Rules'),
      suite('mitre_attack_mapper', 'ATT&CK Mapping'),
      pack('rule_governance', 'Rule Governance Workflow'),
    ],
  },
  {
    id: 'socWorkspace',
    title: 'SOC Workspace',
    items: [
      page('cases', 'Cases'),
      roadmap('case_detail', 'Case Detail', ['Centralise notes, evidence, affected devices, users, findings and timeline.', 'Generate reports from case data rather than free text alone.']),
      suite('incident_report_generator', 'Reports'),
      suite('report_signing_integrity_checker', 'Report Signing'),
      roadmap('chain_of_custody_log', 'Chain of Custody', ['Maintain evidence handling history across investigations, cases and reports.', 'Verify hashes before export or report signing.']),
      suite('remediation_guidance_wizard', 'Remediation'),
      roadmap('guided_response_playbooks', 'Playbooks', ['Guide analysts through repeatable response tasks.', 'Attach playbook actions to cases and evidence bundles.']),
      suite('risk_register_export', 'Risk Register'),
    ],
  },
  {
    id: 'settingsMenu',
    title: 'Settings',
    items: [
      page('settings', 'General Settings'),
      page('guardrails', 'Product Guardrails'),
      page('securitySuite', 'Build Manifest'),
      roadmap('agents_settings', 'Agents', ['Configure enrolment, heartbeat, tasking policy and trust model.', 'Show agent health, version and pending work safely.']),
      roadmap('connectors_settings', 'Connectors', ['Configure email, Microsoft 365, feeds and local integrations.', 'Keep connectors read-only until write actions are explicitly enabled.']),
      suite('role_based_analyst_home_user_modes', 'Roles and Modes'),
      roadmap('audit_settings', 'Audit Settings', ['Configure retention, chain-of-custody, settings-change and export audit policies.', 'Explain the impact of dangerous settings before saving.']),
      roadmap('secrets_settings', 'Secrets', ['Store API keys and credentials masked by default.', 'Never return configured secrets in plaintext through the UI or API.']),
      deferred('deferred_roadmap', 'Deferred Roadmap', ['Keep full SIEM correlation, Microsoft 365 depth, cloud posture imports, container scanning and developer supply-chain scanning outside the MVP path.', 'Revisit only after endpoint protection, investigation, posture, vulnerability and reporting loops are stable.']),
    ],
  },
]

const allMenuItems = menuSections.flatMap(section => section.items.map(item => ({ ...item, menu: section.title })))
const capabilityTitleBySlug = Object.fromEntries(allMenuItems.filter(item => item.id.startsWith('suite:')).map(item => [item.id.replace('suite:', ''), item.title]))
const packTitleBySlug = Object.fromEntries(allMenuItems.filter(item => item.id.startsWith('pack:')).map(item => [item.id.replace('pack:', ''), item.title]))
const placeholderById = Object.fromEntries(allMenuItems.filter(item => item.id.startsWith('placeholder:')).map(item => [item.id, item]))

const arr = value => Array.isArray(value) ? value : []
const isObj = value => value && typeof value === 'object' && !Array.isArray(value)
const pick = (obj, keys, fallback = 'Not available') => keys.map(key => obj?.[key]).find(value => value !== undefined && value !== null && value !== '') ?? fallback
const nice = key => String(key || '').replace(/_/g, ' ').replace(/([a-z])([A-Z])/g, '$1 $2').replace(/\b\w/g, c => c.toUpperCase())
const text = value => value === null || value === undefined || value === '' ? 'Not provided' : Array.isArray(value) ? `${value.length} item${value.length === 1 ? '' : 's'}` : isObj(value) ? 'Structured details shown below' : String(value)
const toneFor = value => {
  const raw = String(value || '').toLowerCase()
  if (['critical', 'high', 'block', 'blocked', 'failed', 'danger', 'malicious', 'error'].some(v => raw.includes(v))) return 'red'
  if (['medium', 'warning', 'monitor', 'pending', 'review', 'suspicious'].some(v => raw.includes(v))) return 'orange'
  if (['low', 'safe', 'active', 'success', 'sent', 'created', 'healthy', 'pass', 'trusted', 'idle'].some(v => raw.includes(v))) return 'green'
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
    <div className="assessment-header"><div><Badge tone={toneFor(riskBand)}>Latest assessment</Badge><h4>{assessment?.summary || 'Endpoint assessment'}</h4></div><Badge tone={toneFor(riskBand)}>{riskBand}</Badge></div>
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
      <div className="device-metrics"><span><b>{score || '—'}</b> score</span><span><b>{band}</b> band</span><span><b>{findings.length}</b> findings</span><span><b>{triageScore(device)}</b> priority</span></div>
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
  return <div className="page-stack"><div className="hero"><div><Badge tone="green">Endpoint-centred Blue Team</Badge><h1>Sentinel Security Command Centre</h1><p>Sentinel follows one operational loop: find risk, collect evidence, explain impact, prioritise action and report clearly. The MVP stays focused on protection, endpoint investigation, posture, vulnerability matching and case output.</p></div></div><div className="stats-grid"><StatCard title="Protect" value="AV + IOC" subtitle="Scan, detect and preserve evidence" tone="purple" /><StatCard title="Investigate" value="Endpoint" subtitle="Processes, persistence, network, logs" tone="blue" /><StatCard title="Prioritise" value="CVE / KEV" subtitle="Patch, baseline and exposure context" tone="orange" /><StatCard title="Report" value="Cases" subtitle="Evidence to remediation and reports" tone="green" /></div></div>
}

function ProductGuardrails() {
  const pillars = [
    { title: 'Protection', detail: 'AV scanning, IOC checks, ransomware guard, DNS and USB protections that reduce endpoint risk.' },
    { title: 'Investigation', detail: 'Endpoint evidence, processes, persistence, logs, network snapshots, timelines and evidence bundles.' },
    { title: 'Posture', detail: 'Security baseline, patches, software inventory, backups, browser security and device ownership.' },
    { title: 'Vulnerability', detail: 'CVE/KEV matching, exposure review, firewall context and risk-register output.' },
    { title: 'Identity', detail: 'Local users, logons, privilege changes and mailbox identity checks where they support investigations.' },
    { title: 'Intelligence', detail: 'Feeds, YARA, Sigma, ATT&CK mapping and detection content that improves defensive decisions.' },
    { title: 'Case and Reporting', detail: 'Cases, reports, chain of custody, playbooks and remediation guidance.' },
  ]
  const deferredItems = [
    'Full SIEM correlation engine',
    'Full Microsoft 365 integration',
    'Container image scanning',
    'Cloud posture imports',
    'Developer supply-chain scanning',
    'Advanced DNS blocking',
    'Kernel-level EDR work',
    'Full sandboxing',
  ]
  const gates = [
    'Which Sentinel workflow does this improve?',
    'Which existing device, evidence, finding, case or report data does it reuse?',
    'What severity, evidence and recommended action does it produce?',
    'Does it reduce risk or improve investigation quality?',
    'Can it be built safely without offensive or destructive capability?',
    'Can it live inside an existing product area without becoming a disconnected tab?',
  ]
  return <div className="page-stack">
    <div className="page-title"><Badge tone="green">Product Boundary</Badge><h1>Sentinel / Fenrir Guardrails</h1><p>Sentinel is a defensive endpoint-centred Blue Team platform. New work must support the loop: Protect, Detect, Investigate, Prioritise, Remediate, Report and Improve posture.</p></div>
    <div className="stats-grid three">
      <StatCard title="Identity" value="Endpoint" subtitle="Device-first defensive workspace" tone="blue" />
      <StatCard title="Workflow" value="Evidence" subtitle="Findings feed cases and reports" tone="purple" />
      <StatCard title="Scope" value="MVP first" subtitle="Advanced tooling stays deferred" tone="orange" />
    </div>
    <Panel title="Accepted Product Pillars" subtitle="A module must support at least one of these pillars.">
      <div className="coherence-grid">{pillars.map(pillar => <article className="coherence-card" key={pillar.title}><h3>{pillar.title}</h3><p>{pillar.detail}</p></article>)}</div>
    </Panel>
    <Panel title="Build Gate" subtitle="Use these questions before promoting an idea from roadmap to production.">
      <ActionCards items={gates.map((gate, index) => ({ title: `Gate ${index + 1}`, decision: 'Required', description: gate }))} />
    </Panel>
    <Panel title="Deferred Until Core MVP Is Stable" subtitle="These remain possible Blue Team capabilities, but they are not allowed to distract from the endpoint loop.">
      <div className="inline-chip-row">{deferredItems.map(item => <span className="inline-chip deferred-chip" key={item}>{item}</span>)}</div>
    </Panel>
  </div>
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

  const devices = useMemo(() => arr(agents?.agents || agents?.results || agents?.items).slice().sort((a, b) => triageScore(b) - triageScore(a)), [agents])
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
    <section className="device-triage-layout"><Panel title="Device Priority Queue" subtitle="Select a device to view its latest assessment."><DevicePriorityQueue devices={devices} selectedId={selectedDeviceId} onSelect={setSelectedDeviceId} /></Panel><Panel title="Selected Device Assessment" subtitle={selectedDevice ? pick(selectedDevice, ['hostname', 'agent_id'], 'Selected device') : 'No device selected'}>{selectedAssessment ? <AssessmentBlock assessment={selectedAssessment} /> : <Empty>No latest assessment is available for the selected device yet.</Empty>}</Panel></section>
    {selectedDevice && <Panel title="Selected Device Evidence"><RecordCards items={[selectedDevice]} empty="No selected device details available." /></Panel>}
  </div>
}

function PlaceholderPage({ item }) {
  const expectations = item?.expectations?.length ? item.expectations : [
    'Define inputs, permissions, collection method and external service support.',
    'Return clear findings, evidence records, recommended action and export-ready status.',
    'Connect results to devices, cases, reports and the risk register without duplicating backend modules.',
  ]
  const eyebrow = item?.status === 'deferred' ? 'Deferred' : 'Roadmap'
  return <div className="page-stack">
    <div className="page-title">
      <Badge tone={item?.status === 'deferred' ? 'orange' : 'purple'}>{eyebrow}</Badge>
      <h1>{item?.title || 'Planned Capability'}</h1>
      <p>{item?.menu ? `${item.menu} submenu destination. ` : ''}This page is reserved so the Sentinel/Fenrir navigation remains stable while the full module is built behind it.</p>
    </div>
    <div className="stats-grid three">
      <StatCard title="Navigation" value="Locked" subtitle="Menu placement follows the roadmap" tone="purple" />
      <StatCard title="Implementation" value="Planned" subtitle="Backend and UI contract still to build" tone="orange" />
      <StatCard title="Output" value="Findings" subtitle="Plain-English evidence and actions required" tone="blue" />
    </div>
    <Panel title="Build Expectations" subtitle="This placeholder is intentionally explicit, not a blank page.">
      <div className="placeholder-expectation-grid">
        {expectations.map((expectation, index) => <article className="placeholder-expectation" key={expectation}>
          <span>Step {index + 1}</span>
          <p>{expectation}</p>
        </article>)}
      </div>
    </Panel>
    <Panel title="Module Contract" subtitle="Every future capability should plug into the same defensive workflow.">
      <div className="kv-grid">
        <article className="kv-card"><span>Inputs</span><strong>Device, evidence, connector data or uploaded artifact</strong></article>
        <article className="kv-card"><span>Processing</span><strong>Read-only checks first, explicit audited action second</strong></article>
        <article className="kv-card"><span>Outputs</span><strong>Findings, severity, evidence, plain-English summary and remediation</strong></article>
      </div>
    </Panel>
  </div>
}

function capabilityTitle(slug) {
  return capabilityTitleBySlug[slug] || nice(slug)
}

function packTitle(slug) {
  return packTitleBySlug[slug] || nice(slug)
}

export default function AppShell() {
  const [active, setActive] = useState('overview')
  const [activeMenu, setActiveMenu] = useState('dashboard')
  const [openMenus, setOpenMenus] = useState(['dashboard'])
  const pages = {
    overview: <Overview />,
    guardrails: <ProductGuardrails />,
    pipeline: <ThreatPipeline />,
    securitySuite: <SecuritySuite />,
    externalChecks: <ExternalServiceChecker />,
    avScanner: <AVScanner />,
    iocScanner: <IOCScanner />,
    endpoint: <EndpointRisk />,
    investigator: <Investigator />,
    investigationDetails: <InvestigationDetails />,
    persistence: <PersistenceScanner />,
    network: <NetworkConnectionMonitor />,
    cases: <CaseManagement />,
    exposure: <ExposureScout />,
    cve: <CVEWatchdog />,
    phish: <PhishingEmailAnalyser />,
    emailintel: <EmailIntel />,
    settings: <Settings />,
  }
  const specialisedCapabilityPages = {
    av_scanner: <AVScanner />,
    ioc_scanner: <IOCScanner />,
    phishing_email_analyser: <PhishingEmailAnalyser />,
    persistence_scanner: <PersistenceScanner />,
    network_connection_monitor: <NetworkConnectionMonitor />,
    cve_kev_vulnerability_matcher: <CVEWatchdog />,
    case_management: <CaseManagement />,
  }
  const activeMenuId = menuSections.find(section => section.id === activeMenu && section.items.some(item => item.id === active))?.id
    || menuSections.find(section => section.items.some(item => item.id === active))?.id
  const toggleMenu = id => setOpenMenus(current => current.includes(id) ? current.filter(menuId => menuId !== id) : [...current, id])
  const selectItem = (itemId, sectionId) => {
    setActive(itemId)
    setActiveMenu(sectionId)
    setOpenMenus(current => current.includes(sectionId) ? current : [...current, sectionId])
  }

  useEffect(() => {
    if (activeMenuId) setOpenMenus(current => current.includes(activeMenuId) ? current : [...current, activeMenuId])
  }, [activeMenuId])

  const renderPage = () => {
    if (active.startsWith('placeholder:')) {
      return <PlaceholderPage item={placeholderById[active] || allMenuItems.find(item => item.id === active)} />
    }
    if (active.startsWith('suite:')) {
      const slug = active.replace('suite:', '')
      return specialisedCapabilityPages[slug] || <SecuritySuite initialSlug={slug} hideCatalogue title={capabilityTitle(slug)} />
    }
    if (active.startsWith('pack:')) {
      const slug = active.replace('pack:', '')
      return <SecuritySuite initialPack={slug} hideCatalogue title={packTitle(slug)} />
    }
    return pages[active] || pages.overview
  }

  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark">S</div><div><h2>Sentinel</h2><p>Fenrir Defence Workspace</p></div></div>
      <nav>
        {menuSections.map(section => {
          const isOpen = openMenus.includes(section.id)
          const hasActive = activeMenuId === section.id
          return <div className={`nav-menu ${hasActive ? 'active-menu' : ''}`} key={section.id}>
            <button className={`nav-menu-toggle ${hasActive ? 'active-menu' : ''}`} onClick={() => toggleMenu(section.id)} aria-expanded={isOpen}>
              <span>{section.title}</span>
              <span className="nav-chevron">{isOpen ? '-' : '+'}</span>
            </button>
            {isOpen && <div className="nav-submenu">
              {section.items.map(item => <button key={`${section.id}-${item.id}-${item.title}`} className={`nav-subitem ${active === item.id && activeMenuId === section.id ? 'active' : ''}`} onClick={() => selectItem(item.id, section.id)}>
                <span>{item.title}</span>
                <span className={`nav-status ${item.status}`}>{item.status === 'deferred' ? 'Later' : item.status === 'roadmap' ? 'Next' : item.status === 'workflow' ? 'Flow' : item.status === 'module' ? 'Module' : 'Live'}</span>
              </button>)}
            </div>}
          </div>
        })}
      </nav>
    </aside>
    <main className="content">{renderPage()}</main>
  </div>
}
