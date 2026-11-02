# Sentinel / Fenrir Focused 10-Tool MVP Test Checklist

This checklist validates the focused MVP target:

1. Endpoint Investigation Collector
2. Local Incident Timeline Tool
3. Persistence Scanner
4. IOC Scanner
5. Suspicious Process Monitor
6. Network Connection Monitor
7. Phishing Email Analyser
8. Windows Security Baseline Checker
9. Patch and Vulnerability Checker
10. Case Report Generator

## 1. Backend setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
$env:SENTINEL_SECRET_KEY="dev-only-change-me"
uvicorn main:app --reload
```

Expected:

- Backend starts without import errors.
- `GET http://localhost:8000/health` returns `{"status":"healthy"}`.

## 2. Backend smoke tests

```powershell
$env:SENTINEL_SECRET_KEY="test-only-secret-key-for-smoke-tests"
pytest -q
```

Expected:

- All tests in `tests/test_mvp_smoke.py` pass.
- Failures should be treated as MVP blockers unless explicitly documented.

## 3. Frontend setup

```powershell
npm install
npm run build
npm run dev
```

Expected:

- Vite build completes.
- UI opens at `http://localhost:5173`.
- Sidebar renders without a blank screen.

## 4. Required sidebar pages

Confirm these pages are visible and load without frontend errors:

- Command Overview
- Threat Pipeline
- IOC Scanner
- Endpoint Risk
- Investigator
- Investigation Details
- Persistence Scanner
- Network Monitor
- Cases & Reports
- CVE Watchdog
- Phishing Email Analyser
- Email Intelligence
- Settings

## 5. API endpoint checks

Run or test these from the UI/API client:

```text
GET  /health
GET  /api/endpoint/sample
GET  /api/cases/
GET  /api/investigator/history
POST /api/ioc/validate
POST /api/ioc-scanner/scan
POST /api/network/snapshot
POST /api/persistence/scan
POST /api/phish/analyse
POST /api/cve/scan
```

Expected:

- All return structured JSON.
- No route returns a traceback.
- GUI pages render responses as cards/tables/sections, not raw JSON dumps.

## 6. Endpoint agent workflow

Start backend, then run the agent from the `agent` directory:

```powershell
cd agent
python main.py
```

Expected:

- Agent registers or reuses an existing `agent_id`.
- Agent appears in Endpoint Risk.
- Agent sends posture.
- Endpoint Risk shows score, band and remediation findings.

## 7. Investigation workflow

From the UI:

1. Open Endpoint Risk and confirm the agent exists.
2. Open Investigator.
3. Select the endpoint.
4. Queue a scoped investigation.
5. Allow agent to poll and run the task.
6. Open Investigation Details.

Expected:

- Investigation changes from pending/in-progress to complete or failed.
- Evidence bundle is uploaded.
- Findings are visible.
- Timeline is visible.
- Report/bundle links are shown where available.

## 8. Case/report workflow

From Investigation Details:

1. Select a completed investigation.
2. Click Create Case From This Investigation.
3. Open Cases & Reports.
4. Select the case.
5. Add a note.
6. Add an action.
7. Generate Incident Report.
8. Open the report.

Expected:

- Case persists after refresh.
- Linked findings and timeline appear.
- Report is readable HTML.
- No raw JSON dump appears as the primary report body.

## 9. Tool-specific checks

### IOC Scanner

Paste test IOCs and run a scoped scan.

Expected:

- Extracted indicators are shown.
- Matches appear as evidence cards if found.
- No destructive action is taken.

### Persistence Scanner

Run a persistence scan with all scopes enabled.

Expected:

- Startup, services, scheduled tasks, PowerShell profiles and browser extension locations are shown where available.
- Each finding has risk, reason and recommended action.

### Network Monitor

Run a network snapshot.

Expected:

- Connections and listening ports are shown.
- Suspicious process/destination findings are prioritised.
- Reputation/ASN/country placeholders are present.

### Phishing Email Analyser

Paste or upload a `.eml` file.

Expected:

- Headers are parsed.
- SPF/DKIM/DMARC visibility is shown.
- URLs and attachments are extracted.
- Attachment hashes are displayed.

### CVE Watchdog

Run manual and endpoint inventory scans.

Expected:

- Manual Log4j test returns CVE matches from the seed feed.
- Endpoint inventory scan persists latest result where an agent inventory exists.

## 10. MVP blockers

Treat these as blockers before release/demo:

- Backend does not start.
- Frontend does not build.
- Any main sidebar page is blank.
- Agent cannot register.
- Investigation cannot be queued.
- Evidence cannot be uploaded.
- Case report cannot be generated.
- Any active page displays raw JSON as its primary output.
- Secrets are returned in plaintext.

## 11. Known non-blocking limitations

These are acceptable for the current focused MVP if documented:

- Network monitor is snapshot-based, not continuous live monitoring.
- IOC file scanning is bounded by configured scan paths and max file count.
- Reputation/ASN/country enrichment is placeholder-only.
- Some Windows baseline checks depend on permissions and Windows edition.
- Feed-backed CVE matching uses local/seed feeds unless production feeds are supplied.
- Evidence bundle encryption uses the configured local evidence secret and should be rotated for real deployment.
