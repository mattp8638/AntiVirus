import React, { useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  AlertTriangle,
  CheckCircle2,
  ClipboardCheck,
  FileText,
  Lock,
  ShieldAlert,
  ShieldCheck,
  Workflow,
} from 'lucide-react';
import './styles.css';

const lifecycleStages = [
  'preparation',
  'detection',
  'triage',
  'scoping',
  'evidence_collection',
  'containment',
  'eradication',
  'recovery',
  'verification',
  'reporting',
  'lessons_learnt',
];

const incidentTypes = [
  { id: 'phishing', label: 'Phishing Email', baseScore: 25 },
  { id: 'malware', label: 'Malware Detection', baseScore: 30 },
  { id: 'ransomware', label: 'Ransomware Behaviour', baseScore: 55 },
  { id: 'suspicious_login', label: 'Suspicious Login', baseScore: 30 },
  { id: 'powershell', label: 'Suspicious PowerShell', baseScore: 35 },
  { id: 'critical_vulnerability', label: 'Critical Vulnerability', baseScore: 50 },
];

const questions = [
  { id: 'q_detection_source', stage: 'detection', text: 'Which Sentinel/Fenrir module or manual source detected the incident?', type: 'text', appliesTo: [] },
  { id: 'q_privileged_user', stage: 'triage', text: 'Is a privileged user involved?', type: 'boolean', appliesTo: ['phishing', 'malware', 'ransomware', 'suspicious_login', 'powershell'] },
  { id: 'q_business_critical_asset', stage: 'triage', text: 'Is a business-critical asset involved?', type: 'boolean', appliesTo: ['malware', 'ransomware', 'critical_vulnerability', 'powershell'] },
  { id: 'q_sensitive_data', stage: 'triage', text: 'Could sensitive or regulated data be affected?', type: 'boolean', appliesTo: [] },
  { id: 'q_multiple_assets', stage: 'scoping', text: 'Are multiple assets, users or mailboxes affected?', type: 'boolean', appliesTo: [] },
  { id: 'q_activity_ongoing', stage: 'triage', text: 'Is the suspicious activity still ongoing?', type: 'boolean', appliesTo: [] },
  { id: 'q_email_opened', stage: 'triage', text: 'Was the suspicious email opened?', type: 'boolean', appliesTo: ['phishing'] },
  { id: 'q_link_clicked', stage: 'triage', text: 'Was a link clicked?', type: 'boolean', appliesTo: ['phishing'], showIf: { q_email_opened: true } },
  { id: 'q_credentials_entered', stage: 'triage', text: 'Were credentials entered into a suspicious site?', type: 'boolean', appliesTo: ['phishing'], showIf: { q_link_clicked: true } },
  { id: 'q_attachment_opened', stage: 'triage', text: 'Was an attachment opened or executed?', type: 'boolean', appliesTo: ['phishing'], showIf: { q_email_opened: true } },
  { id: 'q_encryption_active', stage: 'triage', text: 'Are files currently being encrypted, renamed or made inaccessible?', type: 'boolean', appliesTo: ['ransomware'] },
  { id: 'q_ransom_note_present', stage: 'triage', text: 'Is a ransom note present?', type: 'boolean', appliesTo: ['ransomware'] },
  { id: 'q_network_shares_exposed', stage: 'scoping', text: 'Are network shares or mapped drives reachable from the affected host?', type: 'boolean', appliesTo: ['ransomware'] },
  { id: 'q_blocked_before_execution', stage: 'triage', text: 'Was the threat blocked before execution?', type: 'boolean', appliesTo: ['malware'] },
  { id: 'q_persistence_found', stage: 'eradication', text: 'Was persistence found, such as autoruns, services, scheduled tasks or startup entries?', type: 'boolean', appliesTo: ['malware', 'powershell', 'ransomware'] },
  { id: 'q_patch_available', stage: 'eradication', text: 'Is a patch or vendor fix available?', type: 'boolean', appliesTo: ['critical_vulnerability'] },
  { id: 'q_internet_facing', stage: 'scoping', text: 'Is the vulnerable or affected service internet-facing?', type: 'boolean', appliesTo: ['critical_vulnerability'] },
];

const rules = [
  {
    id: 'rule_privileged_user',
    when: { q_privileged_user: true },
    severityDelta: 20,
    moveToStage: 'scoping',
    escalation: true,
    evidence: ['privileged_activity_log', 'sign_in_logs', 'mfa_events'],
    closureBlocks: ['Privileged activity review must be completed.'],
    tasks: [{ id: 'review_privileged_activity', stage: 'scoping', title: 'Review privileged account activity', description: 'Check administrative actions, privilege changes, sign-ins and active sessions.', blocksClosure: true }],
    report: 'A privileged user is involved, so administrative activity and session history require review.',
  },
  {
    id: 'rule_business_critical_asset',
    when: { q_business_critical_asset: true },
    severityDelta: 20,
    moveToStage: 'scoping',
    escalation: true,
    evidence: ['asset_owner_record'],
    closureBlocks: ['Business owner and service impact must be confirmed.'],
    tasks: [{ id: 'identify_asset_owner', stage: 'preparation', title: 'Confirm business owner and service impact', description: 'Identify the business owner, affected service and containment/recovery approach.', blocksClosure: true }],
    report: 'The affected asset is business critical, so ownership and service impact must be documented.',
  },
  {
    id: 'rule_sensitive_data',
    when: { q_sensitive_data: true },
    severityDelta: 20,
    moveToStage: 'scoping',
    escalation: true,
    evidence: ['data_access_review'],
    closureBlocks: ['Sensitive data exposure assessment must be completed.'],
    tasks: [{ id: 'assess_data_exposure', stage: 'scoping', title: 'Assess possible sensitive data exposure', description: 'Determine whether sensitive, regulated or customer data was accessed, modified or exposed.', blocksClosure: true }],
    report: 'Sensitive data may be affected, requiring an exposure assessment and escalation decision.',
  },
  {
    id: 'rule_multiple_assets',
    when: { q_multiple_assets: true },
    severityDelta: 20,
    moveToStage: 'scoping',
    evidence: ['scope_results', 'correlation_results'],
    closureBlocks: ['Scoping results must be attached.'],
    tasks: [{ id: 'scope_related_entities', stage: 'scoping', title: 'Scope related assets, users and indicators', description: 'Search for matching hashes, senders, URLs, commands, domains, IPs, users and related alerts.', blocksClosure: true }],
    report: 'Multiple entities may be affected, so the incident requires correlation and wider scoping.',
  },
  {
    id: 'rule_activity_ongoing',
    when: { q_activity_ongoing: true },
    severityDelta: 15,
    moveToStage: 'containment',
    escalation: true,
    evidence: ['live_activity_record'],
    closureBlocks: ['Ongoing activity must be contained or formally accepted.'],
    tasks: [{ id: 'contain_live_activity', stage: 'containment', title: 'Contain ongoing activity', description: 'Apply the least disruptive approved containment action appropriate to the incident type.', blocksClosure: true }],
    report: 'Activity is ongoing, so containment is required before the incident can progress to closure.',
  },
  {
    id: 'rule_phishing_credentials_entered',
    appliesTo: ['phishing'],
    when: { q_credentials_entered: true },
    severityDelta: 30,
    moveToStage: 'containment',
    escalation: true,
    evidence: ['original_email', 'email_headers', 'sign_in_logs', 'mfa_events', 'mailbox_rule_export'],
    closureBlocks: ['Password reset confirmation is required.', 'Session revocation confirmation is required.', 'Mailbox rule review is required.'],
    tasks: [
      { id: 'reset_user_password', stage: 'containment', title: 'Reset affected user password', description: 'Reset the affected user password using the approved identity workflow.', blocksClosure: true },
      { id: 'revoke_active_sessions', stage: 'containment', title: 'Revoke active sessions', description: 'Revoke active sessions and refresh tokens for the affected user.', blocksClosure: true },
      { id: 'review_mailbox_rules', stage: 'eradication', title: 'Review mailbox rules and forwarding', description: 'Check for suspicious inbox rules, forwarding and delegation changes.', blocksClosure: true },
    ],
    report: 'Credentials were entered into a suspicious site, so account containment is required.',
  },
  {
    id: 'rule_phishing_attachment_opened',
    appliesTo: ['phishing'],
    when: { q_attachment_opened: true },
    severityDelta: 25,
    moveToStage: 'evidence_collection',
    evidence: ['endpoint_evidence_bundle', 'attachment_sha256', 'process_tree'],
    closureBlocks: ['Endpoint evidence must be collected for opened attachments.'],
    tasks: [
      { id: 'run_endpoint_collection', stage: 'evidence_collection', title: 'Run endpoint investigation collection', description: 'Collect process, file, persistence, network and event artefacts from the affected endpoint.', blocksClosure: true },
      { id: 'hash_attachment', stage: 'evidence_collection', title: 'Hash suspicious attachment', description: 'Calculate and preserve the attachment SHA256 hash and source message details.', blocksClosure: true },
    ],
    report: 'A suspicious attachment was opened, so endpoint evidence collection is required.',
  },
  {
    id: 'rule_active_ransomware',
    appliesTo: ['ransomware'],
    when: { q_encryption_active: true },
    severityDelta: 60,
    moveToStage: 'containment',
    escalation: true,
    evidence: ['ransom_note', 'file_modification_timeline', 'process_tree', 'evidence_bundle'],
    closureBlocks: ['Endpoint isolation must be confirmed.', 'Evidence bundle must be attached.', 'No active encryption must be verified.'],
    tasks: [
      { id: 'isolate_endpoint', stage: 'containment', title: 'Isolate affected endpoint', description: 'Disconnect or isolate the endpoint to prevent further file impact or lateral movement.', blocksClosure: true },
      { id: 'disconnect_network_shares', stage: 'containment', title: 'Disconnect mapped drives and network shares', description: 'Disconnect accessible shares where safe to reduce propagation and file impact.', blocksClosure: true },
      { id: 'collect_ransomware_evidence', stage: 'evidence_collection', title: 'Collect evidence bundle', description: 'Collect process tree, file modification timeline, note sample, event logs and persistence artefacts.', blocksClosure: true },
    ],
    report: 'Active file encryption or rename behaviour was reported, so immediate containment is required.',
  },
  {
    id: 'rule_malware_blocked_before_execution',
    appliesTo: ['malware'],
    when: { q_blocked_before_execution: true },
    severityDelta: -15,
    moveToStage: 'verification',
    evidence: ['quarantine_record', 'clean_scan_result'],
    closureBlocks: ['Quarantine and clean scan result must be confirmed.'],
    tasks: [
      { id: 'verify_quarantine', stage: 'verification', title: 'Verify quarantine or block result', description: 'Confirm the file was blocked or quarantined before execution and no related process ran.', blocksClosure: true },
      { id: 'run_follow_up_scan', stage: 'verification', title: 'Run follow-up scan', description: 'Run a follow-up scan to confirm no related artefacts remain.', blocksClosure: true },
    ],
    report: 'The threat appears to have been blocked before execution, but verification is still required.',
  },
  {
    id: 'rule_persistence_found',
    appliesTo: ['malware', 'powershell', 'ransomware'],
    when: { q_persistence_found: true },
    severityDelta: 25,
    moveToStage: 'eradication',
    evidence: ['persistence_artifact_export', 'persistence_removal_record'],
    closureBlocks: ['Persistence must be removed or formally justified.'],
    tasks: [
      { id: 'preserve_persistence_artifact', stage: 'evidence_collection', title: 'Preserve persistence artefact details', description: 'Export the persistence artefact before removal where safe and appropriate.', blocksClosure: true },
      { id: 'remove_persistence', stage: 'eradication', title: 'Remove confirmed malicious persistence', description: 'Remove or disable confirmed malicious autoruns, services, scheduled tasks or startup entries.', blocksClosure: true },
    ],
    report: 'Persistence was found, so eradication and preservation of the artefact are required.',
  },
  {
    id: 'rule_critical_vulnerability_internet_facing',
    appliesTo: ['critical_vulnerability'],
    when: { q_internet_facing: true },
    severityDelta: 35,
    moveToStage: 'eradication',
    escalation: true,
    evidence: ['exposure_validation', 'patch_or_mitigation_record', 'post_patch_validation'],
    closureBlocks: ['External exposure, remediation and post-patch validation are required.'],
    tasks: [
      { id: 'confirm_external_exposure', stage: 'scoping', title: 'Confirm external exposure', description: 'Confirm whether the vulnerable service is reachable from the internet or untrusted networks.', blocksClosure: true },
      { id: 'apply_patch_or_mitigation', stage: 'eradication', title: 'Apply patch or mitigation', description: 'Apply the vendor patch, disable the vulnerable service, or apply a compensating control.', blocksClosure: true },
      { id: 'verify_cve_resolved', stage: 'verification', title: 'Verify vulnerability no longer detects', description: 'Recheck version, configuration and exposure after remediation.', blocksClosure: true },
    ],
    report: 'The vulnerable service is internet-facing, requiring urgent remediation and verification.',
  },
];

function titleCaseStage(stage) {
  return stage.replaceAll('_', ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function severityLabel(score) {
  if (score >= 80) return 'Critical';
  if (score >= 55) return 'High';
  if (score >= 30) return 'Medium';
  return 'Low';
}

function shouldShowQuestion(question, incidentType, answers) {
  const applies = question.appliesTo.length === 0 || question.appliesTo.includes(incidentType);
  if (!applies) return false;
  if (!question.showIf) return true;
  return Object.entries(question.showIf).every(([key, value]) => answers[key] === value);
}

function ruleMatches(rule, incidentType, answers) {
  if (rule.appliesTo && !rule.appliesTo.includes(incidentType)) return false;
  return Object.entries(rule.when).every(([key, value]) => answers[key] === value);
}

function uniqueById(items) {
  const seen = new Set();
  return items.filter((item) => {
    if (seen.has(item.id)) return false;
    seen.add(item.id);
    return true;
  });
}

function unique(values) {
  return [...new Set(values)];
}

function evaluatePlaybook(incidentType, answers, completedTasks, attachedEvidence) {
  const selectedIncident = incidentTypes.find((item) => item.id === incidentType);
  const matchedRules = rules.filter((rule) => ruleMatches(rule, incidentType, answers));
  const score = Math.max(0, Math.min(100, (selectedIncident?.baseScore ?? 25) + matchedRules.reduce((total, rule) => total + rule.severityDelta, 0)));
  const currentStage = matchedRules.reduce((latestStage, rule) => {
    if (!rule.moveToStage) return latestStage;
    return lifecycleStages.indexOf(rule.moveToStage) > lifecycleStages.indexOf(latestStage) ? rule.moveToStage : latestStage;
  }, 'detection');

  const tasks = uniqueById(matchedRules.flatMap((rule) => rule.tasks ?? []));
  const evidence = unique(matchedRules.flatMap((rule) => rule.evidence ?? []));
  const closureBlocks = unique(matchedRules.flatMap((rule) => rule.closureBlocks ?? []));
  const escalation = matchedRules.some((rule) => rule.escalation);
  const missingTasks = tasks.filter((task) => task.blocksClosure && !completedTasks.includes(task.id)).map((task) => task.id);
  const missingEvidence = evidence.filter((item) => !attachedEvidence.includes(item));
  const closureReady = missingTasks.length === 0 && missingEvidence.length === 0 && closureBlocks.length === 0 && tasks.length > 0;
  const nextQuestions = questions.filter((question) => answers[question.id] === undefined && shouldShowQuestion(question, incidentType, answers));

  return {
    score,
    severity: severityLabel(score),
    currentStage,
    matchedRules,
    tasks,
    evidence,
    closureBlocks,
    escalation,
    missingTasks,
    missingEvidence,
    closureReady,
    nextQuestions,
    reportNotes: matchedRules.map((rule) => rule.report).filter(Boolean),
  };
}

function App() {
  const [incidentType, setIncidentType] = useState('phishing');
  const [answers, setAnswers] = useState({});
  const [completedTasks, setCompletedTasks] = useState([]);
  const [attachedEvidence, setAttachedEvidence] = useState([]);

  const result = useMemo(() => evaluatePlaybook(incidentType, answers, completedTasks, attachedEvidence), [incidentType, answers, completedTasks, attachedEvidence]);
  const selectedIncident = incidentTypes.find((item) => item.id === incidentType);

  function resetForIncident(nextIncidentType) {
    setIncidentType(nextIncidentType);
    setAnswers({});
    setCompletedTasks([]);
    setAttachedEvidence([]);
  }

  function answerQuestion(question, value) {
    setAnswers((current) => ({ ...current, [question.id]: value }));
  }

  function toggleTask(taskId) {
    setCompletedTasks((current) => current.includes(taskId) ? current.filter((id) => id !== taskId) : [...current, taskId]);
  }

  function toggleEvidence(item) {
    setAttachedEvidence((current) => current.includes(item) ? current.filter((id) => id !== item) : [...current, item]);
  }

  return (
    <main className="app-shell">
      <section className="hero-card">
        <div>
          <p className="eyebrow">Sentinel / Fenrir SOC Lite</p>
          <h1>Guided Response Playbooks</h1>
          <p className="hero-copy">A lifecycle-aware response workspace that adapts questions, severity, evidence, containment, eradication and closure gates as the incident evolves.</p>
        </div>
        <div className={`severity-card severity-${result.severity.toLowerCase()}`}>
          <ShieldAlert size={28} />
          <span>Severity</span>
          <strong>{result.severity}</strong>
          <small>Score {result.score}/100</small>
        </div>
      </section>

      <section className="grid two-cols">
        <article className="panel">
          <div className="panel-heading"><Workflow size={20} /><h2>Incident type</h2></div>
          <div className="incident-grid">
            {incidentTypes.map((type) => (
              <button key={type.id} className={type.id === incidentType ? 'incident-button active' : 'incident-button'} onClick={() => resetForIncident(type.id)} type="button">
                {type.label}
              </button>
            ))}
          </div>
        </article>

        <article className="panel status-panel">
          <div className="panel-heading"><ShieldCheck size={20} /><h2>Current response state</h2></div>
          <dl>
            <div><dt>Playbook</dt><dd>{selectedIncident?.label}</dd></div>
            <div><dt>Lifecycle stage</dt><dd>{titleCaseStage(result.currentStage)}</dd></div>
            <div><dt>Escalation</dt><dd>{result.escalation ? 'Required' : 'Not currently required'}</dd></div>
            <div><dt>Closure</dt><dd>{result.closureReady ? 'Ready' : 'Blocked or awaiting evidence'}</dd></div>
          </dl>
        </article>
      </section>

      <section className="panel lifecycle-panel">
        <div className="panel-heading"><ClipboardCheck size={20} /><h2>Incident lifecycle</h2></div>
        <div className="lifecycle-track">
          {lifecycleStages.map((stage) => {
            const currentIndex = lifecycleStages.indexOf(result.currentStage);
            const stageIndex = lifecycleStages.indexOf(stage);
            const state = stageIndex < currentIndex ? 'complete' : stageIndex === currentIndex ? 'current' : 'pending';
            return <div key={stage} className={`lifecycle-step ${state}`}><span>{stageIndex + 1}</span><strong>{titleCaseStage(stage)}</strong></div>;
          })}
        </div>
      </section>

      <section className="grid two-cols">
        <article className="panel">
          <div className="panel-heading"><AlertTriangle size={20} /><h2>Dynamic questions</h2></div>
          <div className="question-list">
            {result.nextQuestions.length === 0 ? <p className="muted">No further questions are currently required. Review tasks, evidence and closure status.</p> : result.nextQuestions.slice(0, 6).map((question) => (
              <div key={question.id} className="question-card">
                <span>{titleCaseStage(question.stage)}</span>
                <p>{question.text}</p>
                {question.type === 'text' ? (
                  <input aria-label={question.text} placeholder="Enter source, module or note" onBlur={(event) => { if (event.target.value.trim()) answerQuestion(question, event.target.value.trim()); }} />
                ) : (
                  <div className="button-row"><button type="button" onClick={() => answerQuestion(question, true)}>Yes</button><button type="button" onClick={() => answerQuestion(question, false)}>No</button></div>
                )}
              </div>
            ))}
          </div>
        </article>

        <article className="panel">
          <div className="panel-heading"><FileText size={20} /><h2>Report-ready rationale</h2></div>
          {result.reportNotes.length === 0 ? <p className="muted">Answer questions to build the severity and lifecycle rationale.</p> : <ul className="report-list">{result.reportNotes.map((note) => <li key={note}>{note}</li>)}</ul>}
        </article>
      </section>

      <section className="grid three-cols">
        <article className="panel">
          <div className="panel-heading"><ClipboardCheck size={20} /><h2>Generated tasks</h2></div>
          {result.tasks.length === 0 ? <p className="muted">Tasks will appear as answers trigger lifecycle rules.</p> : <div className="task-list">{result.tasks.map((task) => (
            <label key={task.id} className="check-row"><input type="checkbox" checked={completedTasks.includes(task.id)} onChange={() => toggleTask(task.id)} /><span><strong>{task.title}</strong><small>{titleCaseStage(task.stage)} · {task.description}</small></span></label>
          ))}</div>}
        </article>

        <article className="panel">
          <div className="panel-heading"><FileText size={20} /><h2>Evidence required</h2></div>
          {result.evidence.length === 0 ? <p className="muted">Evidence requirements will be generated dynamically.</p> : <div className="task-list">{result.evidence.map((item) => (
            <label key={item} className="check-row compact"><input type="checkbox" checked={attachedEvidence.includes(item)} onChange={() => toggleEvidence(item)} /><span>{item.replaceAll('_', ' ')}</span></label>
          ))}</div>}
        </article>

        <article className="panel closure-panel">
          <div className="panel-heading">{result.closureReady ? <CheckCircle2 size={20} /> : <Lock size={20} />}<h2>Closure gate</h2></div>
          {result.closureReady ? <div className="closure-ready"><CheckCircle2 /><strong>Ready to close</strong><p>Required tasks and evidence are complete.</p></div> : (
            <div className="closure-blocked"><strong>Blocked</strong><p>Complete the required response work before closure.</p><ul>{result.missingTasks.map((taskId) => <li key={taskId}>Task incomplete: {taskId.replaceAll('_', ' ')}</li>)}{result.missingEvidence.map((item) => <li key={item}>Evidence missing: {item.replaceAll('_', ' ')}</li>)}{result.closureBlocks.map((block) => <li key={block}>{block}</li>)}</ul></div>
          )}
        </article>
      </section>
    </main>
  );
}

createRoot(document.getElementById('root')).render(<App />);
