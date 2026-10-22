# Sentinel / Fenrir Lifecycle Playbook Engine

This document describes the new dynamic playbook layer added under `playbooks/`.

The feature is designed to turn Sentinel/Fenrir from a collection of investigation tools into a lifecycle-aware incident response platform.

## Purpose

The playbook engine connects every playbook to the full incident lifecycle:

1. Preparation
2. Detection
3. Triage
4. Scoping
5. Evidence collection
6. Containment
7. Eradication
8. Recovery
9. Verification
10. Reporting
11. Lessons learnt

A playbook is not treated as a static document. It is treated as a live response workflow that changes as the user answers questions or as Sentinel/Fenrir tools produce new findings.

## Added files

```text
playbooks/__init__.py
playbooks/engine.py
playbooks/default_content.py
```

## Core concepts

### PlaybookContext

`PlaybookContext` is the current state of the incident.

It contains:

```text
incident_type
answers
base_severity_score
current_stage
existing_tasks_completed
attached_evidence
```

The engine evaluates this context and returns a full response plan.

### Questions

Questions belong to a lifecycle stage and may only apply to specific incident types.

For example:

```text
q_credentials_entered
Stage: triage
Incident type: phishing
Effect: if true, add password reset, session revocation, mailbox review, evidence requirements and closure gates.
```

### Rules

Rules define deterministic playbook behaviour.

A rule can:

```text
Increase or reduce severity
Move the playbook to a later lifecycle stage
Add response tasks
Add evidence requirements
Require escalation
Add closure blockers
Add report notes
```

### Tasks

Tasks are operational checklist items.

Each task can:

```text
Belong to a lifecycle stage
Require evidence
Block closure
Be marked as required or optional
```

### Closure gates

A playbook should not be closable until the required lifecycle conditions are satisfied.

Examples:

```text
Evidence attached
Containment completed
Remediation completed
Verification completed
Report generated
Sensitive data review completed where required
Privileged account review completed where required
```

## Supported MVP incident types

The default content currently supports the following first-wave playbook paths:

```text
phishing
malware
ransomware
suspicious_login
powershell
critical_vulnerability
```

## Example lifecycle behaviour

### Phishing with credentials entered

If the user indicates that credentials were entered into a suspicious site, the engine:

```text
Moves the playbook to containment
Raises severity
Requires escalation
Adds password reset task
Adds session revocation task
Adds mailbox rule review task
Adds sign-in log, MFA event and mailbox rule evidence requirements
Blocks closure until the account containment work is complete
```

### Active ransomware behaviour

If active encryption or file rename behaviour is reported, the engine:

```text
Moves the playbook to containment
Raises severity to a critical path
Requires escalation
Adds endpoint isolation
Adds network share disconnection
Adds ransomware evidence bundle collection
Requires ransom note / file timeline / process evidence where applicable
Blocks closure until containment and verification are complete
```

### Malware blocked before execution

If malware was blocked before execution, the engine:

```text
Reduces severity
Moves towards verification
Requires quarantine validation
Requires a follow-up clean scan
Blocks closure until verification evidence exists
```

## Recommended API integration

The application should expose these endpoints when wiring the engine into the backend:

```text
GET    /api/playbooks/questions
POST   /api/playbooks/start
GET    /api/playbooks/{id}
POST   /api/playbooks/{id}/answer
POST   /api/playbooks/{id}/recalculate
POST   /api/playbooks/{id}/tasks/{task_id}/complete
POST   /api/playbooks/{id}/evidence
GET    /api/playbooks/{id}/closure-status
POST   /api/playbooks/{id}/generate-report
POST   /api/playbooks/{id}/export
```

The most important endpoint is:

```text
POST /api/playbooks/{id}/answer
```

It should:

```text
Save the answer
Rebuild context
Evaluate rules
Update severity
Add or remove tasks
Add evidence requirements
Update lifecycle stage
Update closure requirements
Return the next relevant questions
Update the report draft
```

## Recommended UI integration

The frontend should display a lifecycle tracker:

```text
Preparation → Detection → Triage → Scoping → Evidence → Containment → Eradication → Recovery → Verification → Reporting → Lessons Learnt
```

Each stage should show one of:

```text
Pending
Current
Blocked
Complete
Skipped
```

The form should only show questions relevant to the current incident type and previous answers.

## Why this implementation is deterministic

The engine deliberately avoids AI-generated decision logic. This is important because cyber response workflows need to be:

```text
Auditable
Repeatable
Testable
Explainable
Safe to automate later
```

AI can later be used to improve wording, draft report narratives or explain recommendations, but the core lifecycle decisions should remain rule-driven.

## Next implementation step

Wire the engine into persistence:

```text
playbook_instances
playbook_answers
playbook_tasks
playbook_evidence
closure_requirements
lifecycle_events
```

Then connect it to:

```text
Case Management
Evidence Bundle Exporter
Incident Report Generator
MITRE ATT&CK Mapper
Alert Correlation Engine
```
