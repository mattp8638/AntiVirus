import { useEffect, useMemo, useState } from 'react'

const API = 'http://localhost:8000'
const HISTORY_KEY = 'sentinel.securitySuite.runHistory.v1'
const arr = value => Array.isArray(value) ? value : []
const isObj = value => value && typeof value === 'object' && !Array.isArray(value)
const nice = key => String(key || '').replace(/_/g, ' ').replace(/([a-z])([A-Z])/g, '$1 $2').replace(/\b\w/g, c => c.toUpperCase())
const toneFor = value => {
  const raw = String(value || '').toLowerCase()
  if (['critical', 'high', 'invalid', 'missing', 'failed', 'planned'].some(v => raw.includes(v))) return 'red'
  if (['medium', 'partial', 'warning', 'review', 'in_progress'].some(v => raw.includes(v))) return 'orange'
  if (['built', 'complete', 'low', 'verified', 'covered', 'pass'].some(v => raw.includes(v))) return 'green'
  return 'blue'
}

const samples = {
  suspicious_command_line_analyser: { commands: ['powershell.exe -EncodedCommand SQBFAFgA'] },
  ransomware_behaviour_guard: { events: [{ action: 'rename', path: 'C:\\data\\finance.locked' }, { command: 'vssadmin delete shadows /all /quiet' }] },
  mailbox_rule_checker: { org_domains: ['example.com'], rules: [{ name: 'Forward all', forward_to: 'outside@evil.test', enabled: true }] },
  email_header_analyser: { raw_headers: 'From: Accounts <billing@example.com>\nReply-To: help@evil.test\nAuthentication-Results: mx; spf=fail dkim=fail dmarc=fail\nSubject: Invoice\n\n' },
  attachment_risk_analyser: { attachments: [{ name: 'invoice.pdf.exe' }, { name: 'archive.zip' }] },
  url_redirect_tracer: { urls: ['https://bit.ly/example'], live_trace: false },
  oauth_app_permission_checker: { apps: [{ name: 'Unknown CRM Sync', publisher_verified: false, scopes: ['Mail.ReadWrite', 'offline_access'] }] },
  microsoft_365_security_checker: { controls: { mfa_enabled: false, legacy_auth_blocked: false, audit_log_enabled: true } },
  secrets_scanner: { contents: ['OPENAI_API_KEY=sk-testtesttesttesttesttesttest'] },
  container_image_scanner: { dockerfile: 'FROM python:latest\nRUN echo ok\n' },
  report_signing_integrity_checker: { document: { case_id: 'CASE-1', status: 'closed' } },
  dns_monitor: { domains: ['example.com'] },
  dns_protection_tool: { blocked_domains: ['malware.test'], allowed_domains: [], sinkhole_ip: '0.0.0.0' },
  firewall_rule_auditor: { rules: [{ name: 'Allow RDP', direction: 'inbound', action: 'allow', remote_address: 'any', profile: 'public' }] },
  local_account_admin_audit: { users: [{ name: 'local-admin', enabled: true, password_never_expires: true }], administrators: ['local-admin', 'backup-admin', 'old-admin'], max_admins: 2 },
  logon_event_analyser: { events: [{ Id: 4625, user: 'alice' }, { Id: 4625, user: 'alice' }, { Id: 4625, user: 'alice' }, { Id: 4625, user: 'alice' }, { Id: 4625, user: 'alice' }] },
  privilege_change_monitor: { events: [{ Id: 4732, TargetUserName: 'new-admin', Message: 'Member added to local group' }] },
  yara_rule_manager: { rules: ['rule Suspicious { strings: $a = "powershell" condition: $a }'] },
  sigma_rule_manager: { rules: ['title: Suspicious PowerShell\nlogsource:\n  product: windows\ndetection:\n  selection:\n    Image|endswith: powershell.exe\n  condition: selection'] },
  mitre_attack_mapper: { signals: ['EncodedCommand PowerShell vssadmin shadow delete'] },
  mini_siem_log_search: { query: 'powershell', events: [{ host: 'PC-1', Message: 'PowerShell started' }, { host: 'PC-2', Message: 'Service stopped' }] },
  alert_correlation_engine: { threshold: 2, alerts: [{ host: 'PC-1', severity: 'high' }, { host: 'PC-1', severity: 'medium' }] },
  security_health_score: { findings: [{ severity: 'critical' }, { severity: 'medium' }] },
  remediation_guidance_wizard: { findings: [{ finding_id: 'F-1', title: 'Firewall disabled', severity: 'high', recommended_action: 'Enable firewall profiles.' }] },
  risk_register_export: { findings: [{ finding_id: 'F-1', title: 'MFA disabled', severity: 'high', recommended_action: 'Enable MFA.' }] },
  git_repo_security_scanner: { path: 'C:\\Users\\matt_admin\\Documents\\GitHub\\Sentinel' },
  cloud_saas_audit_importer: { provider: 'm365', records: [{ CreationTime: '2026-04-28T10:00:00Z', UserId: 'user@example.com', Operation: 'UserLoggedIn', ClientIP: '203.0.113.10' }] },
  signed_update_rule_distribution_system: { package: { version: '1.0.0', rules: [] }, signature: '' },
}

async function api(path, options = {}) {
  const res = await fetch(`${API}${path}`, options)
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

function Badge({ children, tone = 'blue' }) { return <span className={`badge ${tone}`}>{children}</span> }
function Button({ children, ...props }) { return <button className="primary-btn" {...props}>{children}</button> }
function Panel({ title, subtitle, children }) { return <section className="panel"><div className="panel-header"><div><h2>{title}</h2>{subtitle && <p>{subtitle}</p>}</div></div>{children}</section> }
function Empty({ children = 'Nothing to show yet.' }) { return <div className="empty-state">{children}</div> }
function Stat({ title, value, tone = 'blue', subtitle }) { return <section className={`stat-card ${tone}`}><p>{title}</p><h2>{value}</h2><span>{subtitle}</span></section> }

function ValueBlock({ value }) {
  if (Array.isArray(value)) return <div className="suite-list">{value.slice(0, 12).map((item, index) => <ValueBlock key={index} value={item} />)}</div>
  if (isObj(value)) return <div className="suite-object">{Object.entries(value).slice(0, 16).map(([key, item]) => <div className="suite-field" key={key}><span>{nice(key)}</span><ValueBlock value={item} /></div>)}</div>
  return <strong>{value === undefined || value === null || value === '' ? 'Not provided' : String(value)}</strong>
}

function compactValue(value) {
  if (value === undefined || value === null || value === '') return ''
  if (Array.isArray(value)) return `${value.length} item${value.length === 1 ? '' : 's'}`
  if (isObj(value)) return Object.entries(value).slice(0, 4).map(([key, item]) => `${nice(key)}: ${compactValue(item) || 'provided'}`).join(' | ')
  const text = String(value).replace(/\s+/g, ' ').trim()
  return text.length > 260 ? `${text.slice(0, 257)}...` : text
}

function evidencePreview(finding) {
  if (finding.evidence_summary) return compactValue(finding.evidence_summary)
  const evidence = finding.evidence
  if (isObj(evidence)) {
    if (evidence.command) return `Command line observed: ${compactValue(evidence.command)}`
    if (isObj(evidence.process)) {
      const command = evidence.process.cmdline_text || evidence.process.cmdline || evidence.process.command
      if (command) return `Process command line observed: ${compactValue(command)}`
    }
  }
  return compactValue(evidence)
}

function fallbackChecked(finding) {
  return finding.module ? `${finding.module} reviewed the supplied evidence for risky, unexpected, or policy-breaking behaviour.` : 'Sentinel reviewed the supplied evidence for risky, unexpected, or policy-breaking behaviour.'
}

function fallbackMeaning(finding) {
  return finding.recommended_action || 'This result needs analyst validation against normal business activity before any remediation is applied.'
}

function fallbackPlainEnglish(finding) {
  const title = finding.title || 'a finding'
  return `${fallbackChecked(finding)} It found ${String(title).toLowerCase()}.`
}

function FindingDetail({ label, children }) {
  if (!children) return null
  return <div className="finding-detail"><span>{label}</span><p>{children}</p></div>
}

function Findings({ findings }) {
  if (!findings.length) return <Empty>No findings returned.</Empty>
  return <div className="action-card-grid">{findings.map((finding, index) => {
    const checked = finding.what_was_checked || fallbackChecked(finding)
    const plain = finding.plain_english || fallbackPlainEnglish(finding)
    const meaning = finding.possible_intent || finding.what_it_means || fallbackMeaning(finding)
    const nextStep = finding.analyst_next_step || finding.recommended_action || 'Review this finding and validate whether it is expected.'
    const evidence = evidencePreview(finding)
    return <article className={`action-card finding-card ${toneFor(finding.severity)}`} key={finding.finding_id || index}>
      <div className="action-card-top"><Badge tone={toneFor(finding.severity)}>{finding.severity || 'informational'}</Badge><span>#{index + 1}</span></div>
      <h3>{finding.title || 'Untitled finding'}</h3>
      <p className="finding-plain">{plain}</p>
      <div className="finding-explain-grid">
        <FindingDetail label="What Sentinel Checked">{checked}</FindingDetail>
        <FindingDetail label="Likely Meaning">{meaning}</FindingDetail>
        <FindingDetail label="Next Step">{nextStep}</FindingDetail>
      </div>
      {evidence && <div className="finding-evidence"><span>Evidence Summary</span><code>{evidence}</code></div>}
    </article>
  })}</div>
}

function capabilitySample(slug) {
  return JSON.stringify(samples[slug] || {}, null, 2)
}

function sampleObject(slug) {
  try { return JSON.parse(capabilitySample(slug)) } catch { return {} }
}

function stringifyPayload(value) {
  return JSON.stringify(value || {}, null, 2)
}

function readHistory() {
  try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]') } catch { return [] }
}

function writeHistory(entries) {
  try { localStorage.setItem(HISTORY_KEY, JSON.stringify(entries.slice(0, 14))) } catch {}
}

function GuidedValue({ name, value, onChange }) {
  if (typeof value === 'boolean') {
    return <label className="suite-check"><input type="checkbox" checked={value} onChange={event => onChange(event.target.checked)} /><span>{nice(name)}</span></label>
  }
  if (typeof value === 'number') {
    return <input className="text-input" type="number" value={value} onChange={event => onChange(Number(event.target.value))} />
  }
  if (typeof value === 'string') {
    return <textarea className="input-area suite-small-text" rows={value.includes('\n') ? 6 : 2} value={value} onChange={event => onChange(event.target.value)} />
  }
  return <textarea className="input-area suite-json suite-small-text" rows="7" value={stringifyPayload(value)} onChange={event => {
    try { onChange(JSON.parse(event.target.value || 'null')) } catch { onChange(value) }
  }} />
}

function GuidedPayload({ value, onChange }) {
  const entries = Object.entries(value || {})
  if (!entries.length) return <Empty>This capability can run with an empty payload.</Empty>
  return <div className="suite-guided-grid">{entries.map(([key, item]) => <label className="suite-guided-field" key={key}>
    <span>{nice(key)}</span>
    <GuidedValue name={key} value={item} onChange={next => onChange({ ...value, [key]: next })} />
  </label>)}</div>
}

function RunHistory({ entries, onSelect, onClear }) {
  if (!entries.length) return <Empty>No local run history yet.</Empty>
  return <div className="suite-history">
    <div className="suite-history-actions"><Button onClick={onClear}>Clear History</Button></div>
    {entries.map(entry => <button className="suite-history-item" key={entry.id} onClick={() => onSelect(entry)}>
      <span><Badge tone={toneFor(entry.highest_severity)}>{entry.highest_severity}</Badge></span>
      <strong>{entry.name}</strong>
      <small>{entry.finding_count} finding{entry.finding_count === 1 ? '' : 's'} | {new Date(entry.generated_at).toLocaleString()}</small>
    </button>)}
  </div>
}

export function SecuritySuite({ initialSlug = '', initialPack = '', hideCatalogue = false, title = 'Security Suite' }) {
  const [manifest, setManifest] = useState(null)
  const [audit, setAudit] = useState(null)
  const [packs, setPacks] = useState(null)
  const [activePack, setActivePack] = useState(initialPack || 'endpoint_triage')
  const [packResult, setPackResult] = useState(null)
  const [packLoading, setPackLoading] = useState(false)
  const [caseResult, setCaseResult] = useState(null)
  const [caseLoading, setCaseLoading] = useState(false)
  const [activeSlug, setActiveSlug] = useState(initialSlug || '')
  const [query, setQuery] = useState('')
  const [payload, setPayload] = useState('{}')
  const [guidedPayload, setGuidedPayload] = useState({})
  const [editorMode, setEditorMode] = useState('guided')
  const [history, setHistory] = useState([])
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const capabilities = arr(manifest?.capabilities)
  const auditBySlug = useMemo(() => Object.fromEntries(arr(audit?.capabilities).map(item => [item.slug, item])), [audit])
  const active = capabilities.find(item => item.slug === activeSlug) || capabilities[0]
  const filtered = capabilities.filter(item => `${item.name} ${item.slug} ${item.owner} ${item.state}`.toLowerCase().includes(query.toLowerCase()))
  const counts = capabilities.reduce((acc, item) => ({ ...acc, [item.state]: (acc[item.state] || 0) + 1 }), {})
  const selectedPack = arr(packs?.packs).find(pack => pack.slug === activePack)
  const showPackPanel = !hideCatalogue || Boolean(initialPack)
  const showCapabilityRunner = !initialPack || !hideCatalogue

  useEffect(() => {
    let mounted = true
    async function load() {
      setError('')
      try {
        const [manifestData, auditData, packsData] = await Promise.all([api('/api/security-suite/manifest'), api('/api/security-suite/audit'), api('/api/security-suite/packs')])
        if (!mounted) return
        setManifest(manifestData)
        setAudit(auditData)
        setPacks(packsData)
        setActivePack(initialPack || packsData.packs?.[0]?.slug || 'endpoint_triage')
        const selected = initialSlug || manifestData.capabilities?.[0]?.slug || ''
        const firstSample = sampleObject(selected)
        setActiveSlug(selected)
        setGuidedPayload(firstSample)
        setPayload(stringifyPayload(firstSample))
        setHistory(readHistory())
      } catch (e) {
        if (mounted) setError(e.message)
      }
    }
    load()
    return () => { mounted = false }
  }, [])

  const selectCapability = slug => {
    const nextSample = sampleObject(slug)
    setActiveSlug(slug)
    setResult(null)
    setError('')
    setGuidedPayload(nextSample)
    setPayload(stringifyPayload(nextSample))
  }

  useEffect(() => {
    if (!initialSlug || initialSlug === activeSlug) return
    selectCapability(initialSlug)
  }, [initialSlug])

  useEffect(() => {
    if (!initialPack) return
    setActivePack(initialPack)
    setPackResult(null)
    setCaseResult(null)
  }, [initialPack])

  const applyGuidedPayload = next => {
    setGuidedPayload(next)
    setPayload(stringifyPayload(next))
  }

  const loadHistoryEntry = entry => {
    setActiveSlug(entry.slug)
    setGuidedPayload(entry.payload || {})
    setPayload(stringifyPayload(entry.payload || {}))
    setResult(entry.result || null)
    setError('')
  }

  const run = async () => {
    setLoading(true)
    setError('')
    try {
      const parsed = payload.trim() ? JSON.parse(payload) : {}
      const data = await api(`/api/security-suite/run/${active.slug}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(parsed) })
      setResult(data)
      const entry = {
        id: `${Date.now()}-${active.slug}`,
        slug: active.slug,
        name: active.name,
        generated_at: data.generated_at,
        highest_severity: data.highest_severity || 'informational',
        finding_count: data.finding_count || 0,
        payload: parsed,
        result: data,
      }
      setHistory(previous => {
        const next = [entry, ...previous].slice(0, 14)
        writeHistory(next)
        return next
      })
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  const runPack = async () => {
    setPackLoading(true)
    setError('')
    try {
      setPackResult(await api(`/api/security-suite/run-pack/${activePack}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ use_samples: true }) }))
      setCaseResult(null)
    } catch (e) {
      setError(e.message)
    } finally {
      setPackLoading(false)
    }
  }

  const createCaseFromPack = async () => {
    if (!packResult?.case_draft) return
    setCaseLoading(true)
    setError('')
    try {
      const draft = packResult.case_draft
      setCaseResult(await api('/api/cases/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: draft.title || `${packResult.name} findings`,
          severity: draft.severity || packResult.highest_severity || 'medium',
          status: packResult.finding_count ? 'investigating' : 'open',
          summary: draft.summary || `${packResult.name} generated ${packResult.finding_count || 0} finding(s).`,
          notes: [{ created_at: packResult.generated_at, note: `Created from Security Suite workflow pack: ${packResult.name}` }],
          actions: arr(packResult.remediation).slice(0, 20).map(item => ({ status: 'open', action: arr(item.steps).join(' | '), finding_id: item.finding_id })),
        }),
      }))
    } catch (e) {
      setError(e.message)
    } finally {
      setCaseLoading(false)
    }
  }

  if (!manifest && !error) return <div className="page-stack"><div className="page-title"><Badge tone="blue">Loading</Badge><h1>{title}</h1></div><Empty>Loading capability manifest.</Empty></div>

  return <div className="page-stack">
    <div className="page-title"><Badge tone="green">Locked Build</Badge><h1>{title}</h1><p>{manifest?.count || 0} canonical capabilities tracked from the build manifest.</p></div>
    {error && <div className="error-box">{error}</div>}

    <div className="stats-grid four">
      <Stat title="Capabilities" value={manifest?.count || 0} subtitle="Locked list" />
      <Stat title="Runner Coverage" value={`${audit?.coverage_count || 0}/${manifest?.count || 0}`} subtitle="Callable tools" tone={(audit?.coverage_count || 0) === (manifest?.count || 0) ? 'green' : 'orange'} />
      <Stat title="Built" value={counts.built || 0} subtitle="Native or suite-backed" tone="green" />
      <Stat title="In Progress" value={(counts.in_progress || 0) + (counts.partial || 0) + (counts.planned || 0)} subtitle="Now represented" tone="orange" />
    </div>

    {showPackPanel && <Panel title={hideCatalogue && selectedPack ? selectedPack.name : 'Workflow Packs'} subtitle={hideCatalogue && selectedPack ? `${selectedPack.capability_count} capability checks in this workflow.` : 'Run grouped capability flows for common analyst jobs.'}>
      {!hideCatalogue && <div className="suite-pack-grid">
        {arr(packs?.packs).map(pack => <button className={`suite-pack-card ${activePack === pack.slug ? 'active' : ''}`} key={pack.slug} onClick={() => { setActivePack(pack.slug); setPackResult(null) }}>
          <Badge tone={activePack === pack.slug ? 'green' : 'blue'}>{pack.capability_count} tools</Badge>
          <h3>{pack.name}</h3>
          <p>{pack.capabilities.map(nice).join(', ')}</p>
        </button>)}
      </div>}
      {hideCatalogue && selectedPack && <div className="suite-meta-row"><Badge tone="green">{selectedPack.capability_count} tools</Badge><span>{selectedPack.capabilities.map(nice).join(', ')}</span></div>}
      <Button onClick={runPack} disabled={!activePack || packLoading}>{packLoading ? 'Running Pack...' : 'Run Workflow Pack'}</Button>
      {packResult && <div className="suite-pack-result">
        <section className={`verdict-card ${toneFor(packResult.highest_severity)}`}>
          <Badge tone={toneFor(packResult.highest_severity)}>{packResult.highest_severity}</Badge>
          <h2>{packResult.name}: {packResult.finding_count} finding{packResult.finding_count === 1 ? '' : 's'}</h2>
          <p>{packResult.capability_count} capabilities completed. Health score {packResult.health_score}/100.</p>
        </section>
        <div className="stats-grid three">
          <Stat title="Health Score" value={packResult.health_score ?? '—'} subtitle={packResult.health_band || 'No band'} tone={toneFor(packResult.health_band)} />
          <Stat title="Timeline Events" value={arr(packResult.timeline).length} subtitle="Normalised chronology" tone="blue" />
          <Stat title="Remediation Steps" value={arr(packResult.remediation).length} subtitle="Generated actions" tone="orange" />
        </div>
        <Findings findings={arr(packResult.findings)} />
        <Panel title="Pack Timeline"><ValueBlock value={packResult.timeline || []} /></Panel>
        <Panel title="Case Draft"><ValueBlock value={packResult.case_draft || {}} /><Button onClick={createCaseFromPack} disabled={caseLoading || !packResult?.case_draft}>{caseLoading ? 'Creating Case...' : 'Create Case From Pack'}</Button></Panel>
        {caseResult && <Panel title="Created Case"><ValueBlock value={caseResult.case || caseResult} /></Panel>}
      </div>}
    </Panel>}

    {showCapabilityRunner && <section className={`suite-layout ${hideCatalogue ? 'direct' : ''}`}>
      {!hideCatalogue && <Panel title="Capability Catalogue" subtitle="Every item in your locked list.">
        <input className="text-input" value={query} onChange={e => setQuery(e.target.value)} placeholder="Search capabilities" />
        <div className="suite-capability-list">
          {filtered.map(item => {
            const covered = auditBySlug[item.slug]?.covered
            return <button className={`suite-capability ${active?.slug === item.slug ? 'active' : ''}`} key={item.slug} onClick={() => selectCapability(item.slug)}>
              <span className="suite-order">{item.order}</span>
              <span className="suite-capability-main"><strong>{item.name}</strong><small>{item.owner}</small></span>
              <Badge tone={covered ? toneFor(item.state) : 'red'}>{covered ? item.state : 'gap'}</Badge>
            </button>
          })}
        </div>
      </Panel>}

      <div className="suite-runner-stack">
        <Panel title={active?.name || 'Capability'} subtitle={active ? `${active.slug} | ${auditBySlug[active.slug]?.endpoint || 'No endpoint'}` : ''}>
          {active && <div className="suite-meta-row">
            <Badge tone={toneFor(active.state)}>{active.state}</Badge>
            <Badge tone={auditBySlug[active.slug]?.covered ? 'green' : 'red'}>{auditBySlug[active.slug]?.covered ? 'covered' : 'gap'}</Badge>
            <span>{active.owner}</span>
          </div>}
          <div className="suite-mode-toggle">
            <button className={editorMode === 'guided' ? 'active' : ''} onClick={() => setEditorMode('guided')}>Guided</button>
            <button className={editorMode === 'json' ? 'active' : ''} onClick={() => setEditorMode('json')}>JSON</button>
          </div>
          {editorMode === 'guided' ? <GuidedPayload value={guidedPayload} onChange={applyGuidedPayload} /> : <textarea className="input-area suite-json" rows="14" value={payload} onChange={e => setPayload(e.target.value)} spellCheck="false" />}
          <Button onClick={run} disabled={!active || loading}>{loading ? 'Running...' : 'Run Capability'}</Button>
          <Button onClick={() => { const next = sampleObject(active?.slug); setGuidedPayload(next); setPayload(stringifyPayload(next)) }} disabled={!active}>Reset Sample</Button>
        </Panel>

        {result && <>
          <section className={`verdict-card ${toneFor(result.highest_severity)}`}>
            <Badge tone={toneFor(result.highest_severity)}>{result.highest_severity || 'informational'}</Badge>
            <h2>{result.finding_count ? `${result.finding_count} finding${result.finding_count === 1 ? '' : 's'}` : 'No findings'}</h2>
            <p>{result.capability} completed at {result.generated_at}.</p>
          </section>
          <Panel title="Findings"><Findings findings={arr(result.findings)} /></Panel>
          <Panel title="Returned Data"><ValueBlock value={result.data || {}} /></Panel>
        </>}
        <Panel title="Run History" subtitle="Local browser history for repeat analysis."><RunHistory entries={history} onSelect={loadHistoryEntry} onClear={() => { setHistory([]); writeHistory([]) }} /></Panel>
      </div>
    </section>}
  </div>
}

export function ExternalServiceChecker() {
  const [target, setTarget] = useState('https://example.com')
  const [ports, setPorts] = useState('80,443')
  const [allowPrivate, setAllowPrivate] = useState(false)
  const [checks, setChecks] = useState({ dns: true, http: true, tls: true, ports: false })
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const selectedChecks = Object.entries(checks).filter(([, enabled]) => enabled).map(([name]) => name)
  const parsedPorts = ports.split(',').map(item => Number(item.trim())).filter(port => Number.isInteger(port) && port > 0 && port <= 65535).slice(0, 20)

  const toggleCheck = name => setChecks(previous => ({ ...previous, [name]: !previous[name] }))

  const run = async () => {
    setLoading(true)
    setError('')
    setResult(null)
    try {
      setResult(await api('/api/security-suite/external-check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, checks: selectedChecks, ports: parsedPorts, allow_private: allowPrivate }),
      }))
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  return <div className="page-stack">
    <div className="page-title"><Badge tone="green">Standalone Checks</Badge><h1>External Service Checker</h1><p>Run bounded DNS, HTTP, TLS and port checks against authorized external services or systems.</p></div>
    {error && <div className="error-box">{error}</div>}
    <Panel title="External Target">
      <div className="suite-guided-grid">
        <label className="suite-guided-field"><span>Target</span><input className="text-input" value={target} onChange={event => setTarget(event.target.value)} placeholder="https://example.com" /></label>
        <label className="suite-guided-field"><span>Ports</span><input className="text-input" value={ports} onChange={event => setPorts(event.target.value)} placeholder="80,443" /></label>
        {Object.keys(checks).map(name => <label className="suite-check" key={name}><input type="checkbox" checked={checks[name]} onChange={() => toggleCheck(name)} /><span>{nice(name)}</span></label>)}
        <label className="suite-check"><input type="checkbox" checked={allowPrivate} onChange={event => setAllowPrivate(event.target.checked)} /><span>Allow Private/Internal Targets</span></label>
      </div>
      <Button onClick={run} disabled={loading || !target.trim() || !selectedChecks.length}>{loading ? 'Checking...' : 'Run External Check'}</Button>
    </Panel>
    {result && <>
      <section className={`verdict-card ${toneFor(result.highest_severity)}`}>
        <Badge tone={toneFor(result.highest_severity)}>{result.highest_severity || 'informational'}</Badge>
        <h2>{result.finding_count ? `${result.finding_count} finding${result.finding_count === 1 ? '' : 's'}` : 'No findings'}</h2>
        <p>{result.data?.host || target} checked at {result.generated_at}.</p>
      </section>
      <div className="stats-grid three">
        <Stat title="Checks" value={arr(result.data?.checks).length} subtitle={arr(result.data?.checks).join(', ') || 'None'} />
        <Stat title="Findings" value={result.finding_count || 0} subtitle={result.highest_severity || 'informational'} tone={toneFor(result.highest_severity)} />
        <Stat title="Private Blocked" value={result.data?.private_blocked ? 'Yes' : 'No'} subtitle="Target guardrail" tone={result.data?.private_blocked ? 'orange' : 'green'} />
      </div>
      <Panel title="Findings"><Findings findings={arr(result.findings)} /></Panel>
      <Panel title="Check Evidence"><ValueBlock value={result.data || {}} /></Panel>
    </>}
  </div>
}
