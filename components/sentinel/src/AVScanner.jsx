import { useEffect, useState } from 'react'

const API = 'http://localhost:8000'

const arr = value => Array.isArray(value) ? value : []
const toneFor = value => {
  const raw = String(value || '').toLowerCase()
  if (['critical', 'high', 'block', 'quarantine', 'deny', 'detected', 'error', 'malicious', 'findings_detected'].some(v => raw.includes(v))) return 'red'
  if (['medium', 'review', 'warn', 'not_found', 'not configured', 'missing'].some(v => raw.includes(v))) return 'orange'
  if (['low', 'clean', 'available', 'configured', 'safe', 'disabled', 'scan_only'].some(v => raw.includes(v))) return 'green'
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

function KeyGrid({ data }) {
  const entries = Object.entries(data || {}).filter(([, value]) => value !== undefined && value !== null && value !== '' && !Array.isArray(value) && typeof value !== 'object')
  if (!entries.length) return <Empty>No details returned.</Empty>
  return <div className="kv-grid">{entries.map(([key, value]) => <article className="kv-card" key={key}><span>{key.replace(/_/g, ' ')}</span><strong>{String(value)}</strong></article>)}</div>
}

function FindingCards({ findings }) {
  if (!arr(findings).length) return <Empty>No AV findings were returned for this scan.</Empty>
  return <div className="action-card-grid">{findings.map((finding, index) => {
    const tone = toneFor(finding.severity || finding.disposition || finding.status || finding.verdict)
    const ruleMatches = arr(finding.rule_matches)
    const feedMatches = arr(finding.threat_feed_matches)
    const yaraMatches = arr(finding.yara_matches)
    return <article className={`action-card ${tone}`} key={`${finding.path || 'finding'}-${index}`}>
      <div className="action-card-top"><Badge tone={tone}>{finding.severity || finding.disposition || 'review'}</Badge><span>Confidence {finding.confidence ?? '—'}</span></div>
      <h3>{finding.path || 'Unknown file'}</h3>
      <p>{finding.verdict || finding.summary || finding.recommended_action || 'Review this AV finding and decide whether containment is required.'}</p>
      <div className="record-evidence-grid" style={{ marginTop: 14 }}>
        <article className="record-evidence-field"><span>SHA256</span><strong>{finding.sha256 || 'Not supplied'}</strong></article>
        <article className="record-evidence-field"><span>File Type</span><strong>{finding.file_type || finding.contentType || 'Unknown'}</strong></article>
        <article className="record-evidence-field"><span>Entropy</span><strong>{finding.entropy ?? 'Not calculated'}</strong></article>
        <article className="record-evidence-field"><span>Rules</span><strong>{ruleMatches.length}</strong></article>
        <article className="record-evidence-field"><span>Feed Matches</span><strong>{feedMatches.length}</strong></article>
        <article className="record-evidence-field"><span>YARA Matches</span><strong>{yaraMatches.length}</strong></article>
        <article className="record-evidence-field"><span>Remediation</span><strong>{finding.remediation_status || finding.remediationStatus || finding.status || 'Not applied'}</strong></article>
        <article className="record-evidence-field"><span>Quarantine Path</span><strong>{finding.quarantine_path || finding.quarantinedPath || 'Not quarantined'}</strong></article>
      </div>
      {ruleMatches.length > 0 && <div className="nested-object-card" style={{ marginTop: 14 }}><div className="nested-object-title">Matched native rules</div>{ruleMatches.map((rule, i) => <p key={i} style={{ margin: '8px 0', color: '#cbd5e1', lineHeight: 1.6 }}><strong>{rule.name || rule.rule_id}</strong> — {rule.reason} {[rule.tactic_id, rule.technique_id].filter(Boolean).join(' / ')}</p>)}</div>}
      {feedMatches.length > 0 && <div className="nested-object-card" style={{ marginTop: 14 }}><div className="nested-object-title">Threat feed matches</div>{feedMatches.map((match, i) => <p key={i} style={{ margin: '8px 0', color: '#cbd5e1', lineHeight: 1.6 }}><strong>{match.type}</strong> — {match.value} {match.malware_family || match.threat || ''}</p>)}</div>}
      {finding.recommended_action && <div className="nested-object-card" style={{ marginTop: 14 }}><div className="nested-object-title">Recommended action</div><p style={{ margin: 0, color: '#cbd5e1', lineHeight: 1.6 }}>{finding.recommended_action}</p></div>}
    </article>
  })}</div>
}

export function AVScanner() {
  const [nativeStatus, setNativeStatus] = useState(null)
  const [bridgeStatus, setBridgeStatus] = useState(null)
  const [engineMode, setEngineMode] = useState('native')
  const [target, setTarget] = useState('')
  const [recursive, setRecursive] = useState(true)
  const [scanOnly, setScanOnly] = useState(true)
  const [includeEntropy, setIncludeEntropy] = useState(true)
  const [includeIocs, setIncludeIocs] = useState(true)
  const [includeYara, setIncludeYara] = useState(true)
  const [exclusions, setExclusions] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const loadStatus = async () => {
    setError('')
    try { setNativeStatus(await api('/api/av-native/status')) } catch (e) { setError(e.message) }
    try { setBridgeStatus(await api('/api/av/status')) } catch { setBridgeStatus(null) }
  }

  useEffect(() => { loadStatus() }, [])

  const runScan = async () => {
    setLoading(true); setError(''); setResult(null)
    try {
      const exclusionList = exclusions.split(/[\n,;]/).map(x => x.trim()).filter(Boolean)
      if (engineMode === 'native') {
        const body = {
          path: target,
          recursive,
          remediation_mode: scanOnly ? 'scan_only' : 'quarantine',
          include_ioc_extraction: includeIocs,
          include_entropy: includeEntropy,
          include_yara: includeYara,
          exclusions: exclusionList,
        }
        setResult(await api('/api/av-native/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }))
      } else {
        const body = {
          path: target,
          no_remediation: scanOnly,
          no_telemetry: false,
          exclusions: exclusionList,
        }
        setResult(await api('/api/av/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }))
      }
    } catch (e) { setError(e.message) } finally { setLoading(false) }
  }

  const activeStatus = engineMode === 'native' ? nativeStatus : bridgeStatus

  return <div className="page-stack">
    <div className="page-title"><Badge tone="purple">Bespoke Native Engine</Badge><h1>Fenrir AV Scanner</h1><p>Sentinel now prefers its own native scanning engine. The older Windows C++ scanner remains available only as an optional fallback bridge.</p></div>

    <div className="stats-grid three">
      <StatCard title="Native Engine" value={nativeStatus?.status || 'unknown'} subtitle={nativeStatus?.yara_available ? 'YARA available' : 'YARA optional'} tone={nativeStatus?.status === 'available' ? 'green' : 'orange'} />
      <StatCard title="External Bridge" value={bridgeStatus?.available ? 'Available' : 'Optional'} subtitle={bridgeStatus?.configured_path || 'C++ scanner not required'} tone={bridgeStatus?.available ? 'green' : 'blue'} />
      <StatCard title="Default Mode" value="Scan Only" subtitle="Quarantine requires explicit selection" tone="green" />
    </div>

    <Panel title="Engine Selection" subtitle="Use the native Sentinel engine by default. External CLI is only for compatibility testing.">
      <div className="scope-grid">
        <label className={`investigation-scope-card ${engineMode === 'native' ? 'selected' : ''}`}>
          <input type="radio" checked={engineMode === 'native'} onChange={() => setEngineMode('native')} />
          <div><strong>Native Sentinel AV Engine</strong><p>Built into this repo. Hashing, entropy, IOC extraction, native rules, feed lookup and optional YARA.</p></div>
        </label>
        <label className={`investigation-scope-card ${engineMode === 'bridge' ? 'selected' : ''}`}>
          <input type="radio" checked={engineMode === 'bridge'} onChange={() => setEngineMode('bridge')} />
          <div><strong>External Windows Scanner Bridge</strong><p>Optional compatibility path for the older fenrir-scannercli.exe binary.</p></div>
        </label>
      </div>
      {activeStatus && <><Verdict tone={toneFor(activeStatus.status || (activeStatus.available ? 'available' : 'missing'))} eyebrow="Selected engine" title={activeStatus.engine || activeStatus.mode || 'scanner'} message={activeStatus.message || 'Scanner status loaded.'} /><KeyGrid data={activeStatus} /></>}
      <Button onClick={loadStatus}>Refresh Status</Button>
    </Panel>

    <Panel title="Targeted AV Scan" subtitle="Scan a specific file or folder. Quarantine is disabled by default to prevent accidental remediation.">
      <input className="text-input" value={target} onChange={e => setTarget(e.target.value)} placeholder="C:\\Temp\\sample.exe or C:\\Users\\Public\\Downloads" />
      <div className="scope-grid">
        <label className="investigation-scope-card selected"><input type="checkbox" checked={scanOnly} onChange={e => setScanOnly(e.target.checked)} /><div><strong>Scan-only mode</strong><p>Keep this enabled unless you intentionally want quarantine for high/critical native findings.</p></div></label>
        <label className={`investigation-scope-card ${recursive ? 'selected' : ''}`}><input type="checkbox" checked={recursive} onChange={e => setRecursive(e.target.checked)} /><div><strong>Recursive folder scan</strong><p>Scan child folders when the target is a directory.</p></div></label>
        <label className={`investigation-scope-card ${includeEntropy ? 'selected' : ''}`}><input type="checkbox" checked={includeEntropy} onChange={e => setIncludeEntropy(e.target.checked)} /><div><strong>Entropy analysis</strong><p>Flag high-entropy risky files that may be packed or obfuscated.</p></div></label>
        <label className={`investigation-scope-card ${includeIocs ? 'selected' : ''}`}><input type="checkbox" checked={includeIocs} onChange={e => setIncludeIocs(e.target.checked)} /><div><strong>Embedded IOC extraction</strong><p>Extract URLs, IPs and domains and compare against local feeds.</p></div></label>
        <label className={`investigation-scope-card ${includeYara ? 'selected' : ''}`}><input type="checkbox" checked={includeYara} onChange={e => setIncludeYara(e.target.checked)} /><div><strong>YARA if available</strong><p>Run local YARA rules from data/rules/yara when Python YARA is installed.</p></div></label>
      </div>
      <textarea className="input-area" rows="4" value={exclusions} onChange={e => setExclusions(e.target.value)} placeholder="Optional exclusions, one per line" />
      <Button onClick={runScan} disabled={!target || loading}>{loading ? 'Scanning…' : `Run ${engineMode === 'native' ? 'Native' : 'External'} AV Scan`}</Button>
      {error && <div className="error-box">{error}</div>}
    </Panel>

    {result && <>
      <Verdict tone={toneFor(result.highest_severity || result.status)} eyebrow="Scan complete" title={result.status || 'Scan finished'} message={`Scanned ${result.target}. Remediation mode: ${result.remediation_mode || result.remediation_mode}.`} />
      <div className="stats-grid three">
        <StatCard title="Scanned Files" value={result.scanned_files ?? '—'} subtitle={`${result.skipped_files ?? 0} skipped`} tone="blue" />
        <StatCard title="Findings" value={result.finding_count || 0} subtitle="Scanner detections" tone={result.finding_count ? 'red' : 'green'} />
        <StatCard title="Highest Severity" value={result.highest_severity || 'clean'} subtitle={result.stored_result || 'Result stored if available'} tone={toneFor(result.highest_severity || result.status)} />
      </div>
      <Panel title="AV Findings" subtitle="Human-readable findings from the selected AV engine."><FindingCards findings={result.findings} /></Panel>
      {arr(result.errors).length > 0 && <Panel title="Scan Errors"><div className="empty-state">{result.errors.join('\n')}</div></Panel>}
      {result.stderr && <Panel title="Scanner Diagnostic Output"><div className="empty-state">{result.stderr}</div></Panel>}
    </>}
  </div>
}
