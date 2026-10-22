# Sentinel Guided Response Playbooks Dashboard

This dashboard module lives inside the correct application repository:

```text
zy538324/Sentinel/dashboard/guided-response-playbooks/
```

It provides a lifecycle-aware Guided Response Playbooks UI connected conceptually to the Sentinel playbook engine under:

```text
zy538324/Sentinel/playbooks/
```

## Run locally

```bash
cd dashboard/guided-response-playbooks
npm install
npm run dev
```

## What it provides

The dashboard supports:

```text
Phishing Email
Malware Detection
Ransomware Behaviour
Suspicious Login
Suspicious PowerShell
Critical Vulnerability
```

It displays and updates:

```text
Incident lifecycle stage
Dynamic questions
Severity score
Escalation status
Generated tasks
Evidence requirements
Closure blockers
Report-ready rationale
```

## Lifecycle model

```text
Preparation → Detection → Triage → Scoping → Evidence Collection → Containment → Eradication → Recovery → Verification → Reporting → Lessons Learnt
```

## Current implementation state

The dashboard currently contains a local evaluator so it can run immediately.

The production next step is to expose the existing Sentinel backend engine through API endpoints and replace the local evaluator with calls to those endpoints.

Recommended endpoints:

```text
POST /api/playbooks/start
POST /api/playbooks/{id}/answer
POST /api/playbooks/{id}/tasks/{task_id}/complete
POST /api/playbooks/{id}/evidence
GET  /api/playbooks/{id}/closure-status
POST /api/playbooks/{id}/generate-report
```
