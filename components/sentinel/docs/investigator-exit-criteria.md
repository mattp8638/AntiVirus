# Sentinel Investigator - Production Exit Criteria

This document defines the exit path for the first Investigator implementation slice.

## Roadmap Alignment

This slice directly supports the locked Blue Team roadmap items:

- 4. Endpoint Investigation Collector
- 5. Persistence Scanner
- 6. Process Tree Viewer
- 7. Suspicious Command Line Analyser
- 8. Network Connection Monitor
- 11. Windows Event Log Collector
- 12. PowerShell Activity Analyser
- 13. Timeline Builder
- 14. Evidence Bundle Exporter
- 15. Incident Report Generator

## Intended Purpose

The Investigator module is intended to perform safe, local, non-destructive endpoint triage. It collects endpoint evidence, normalises findings, creates a basic incident timeline, generates an HTML report, and exports a hashed evidence bundle.

## Does It Do What It Is Intended To Do?

A build passes this question only if all of the following are true:

1. The backend exposes `/api/investigator/run` and returns a structured investigation summary.
2. The run collects host details, process details, network connections, services, startup artefacts, and available Windows event log summaries.
3. Suspicious command-line rules produce normalised findings with severity, confidence, evidence, and recommended action.
4. Suspicious process parent/child relationships produce normalised findings.
5. Suspicious network connections from risky tools or user-writable paths produce normalised findings.
6. Persistence checks identify suspicious startup/service paths where available.
7. A timeline is generated from investigation findings.
8. An HTML report is generated for analyst review.
9. A ZIP evidence bundle is generated.
10. A manifest containing SHA256 hashes is generated for evidence integrity.
11. The UI has an Investigator page that can run the module, show findings, show the timeline, open the report, and download the evidence bundle.
12. The module does not perform destructive response actions such as deleting files, disabling services, killing processes, changing firewall rules, or quarantining artefacts.

## Does It Elevate The Project Towards Production Grade?

A build passes this question only if all of the following are true:

1. The module is isolated in its own router and does not destabilise existing IOC, endpoint, phishing, CVE, exposure, settings, or email intelligence modules.
2. Output is structured consistently enough to feed future case management, Mini-SIEM, reporting, and alert correlation modules.
3. Evidence is preserved rather than altered.
4. Findings include recommended action rather than blind remediation.
5. The user receives a clear exit decision after every run.
6. The implementation supports analyst review before remediation.
7. The generated evidence bundle can be attached to a future case or incident report.
8. The feature provides value even before live EDR-style monitoring is added.

## Current Scope Boundaries

This first implementation is not yet a full EDR. It does not yet provide:

- Continuous monitoring
- Kernel driver telemetry
- Remote multi-agent collection
- Full Sysmon integration
- Full Windows registry parsing
- Signed report verification
- Encrypted evidence bundles
- Automated remediation
- Case management integration
- Sigma rule execution
- MITRE ATT&CK mapping

Those are later roadmap items and should be added only in the planned order.

## Manual Test Plan

1. Install dependencies: `pip install -r requirements.txt`.
2. Start the backend: `uvicorn main:app --reload`.
3. Start the frontend using the existing frontend workflow.
4. Open the Sentinel UI.
5. Select `Investigator`.
6. Click `Run Local Investigation`.
7. Confirm a summary appears with investigation ID, finding count, evidence count, highest severity, exit decision, and production-grade effect.
8. Confirm findings render in the Findings table.
9. Confirm timeline events render in the Timeline table.
10. Open the HTML report link.
11. Download the evidence bundle.
12. Confirm `data/investigations/<INVESTIGATION_ID>/manifest.json` exists and contains hashes.

## Exit Decision Wording

Every run should return one of these styles of decision:

- `Pass: this run produced a complete local investigation bundle and did not perform destructive actions.`
- `Investigate further: this run found high-risk evidence that requires analyst review before remediation.`

## Production Gate

This slice is acceptable for merge when the app can answer:

> Does this do what it is intended to do?

Yes, if it safely collects investigation evidence, produces findings, builds a timeline, generates a report, and exports an evidence bundle.

> Will this only help in elevating the project to production grade?

Yes, if it improves repeatability, evidence handling, analyst review, reporting, and future module integration without adding destructive or unstable behaviour.
