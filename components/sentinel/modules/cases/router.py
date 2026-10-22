import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from modules.storage import get_connection, get_agent, get_investigation_result, list_investigation_results, save_audit_event

router = APIRouter()

REPORT_DIR = Path("data") / "case_reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

CASE_STATUSES = {"open", "investigating", "contained", "remediated", "closed"}
SEVERITIES = {"informational", "low", "medium", "high", "critical"}


def utc_now() -> str:
    return datetime.utcnow().isoformat() + "Z"


def dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, default=str)


def loads(value: Any, default: Any) -> Any:
    if value in (None, ""):
        return default
    try:
        return json.loads(value)
    except Exception:
        return default


def init_cases_db() -> None:
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                affected_agent_id TEXT,
                investigation_id TEXT,
                summary TEXT,
                notes_json TEXT,
                actions_json TEXT,
                evidence_json TEXT,
                report_path TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )


init_cases_db()


class CaseCreateRequest(BaseModel):
    title: str = Field(..., min_length=3)
    severity: str = "medium"
    status: str = "open"
    affected_agent_id: Optional[str] = None
    investigation_id: Optional[str] = None
    summary: str = ""
    notes: List[Dict[str, Any]] = Field(default_factory=list)
    actions: List[Dict[str, Any]] = Field(default_factory=list)


class CaseUpdateRequest(BaseModel):
    title: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    summary: Optional[str] = None
    note: Optional[str] = None
    action: Optional[Dict[str, Any]] = None


def normalise_severity(value: str) -> str:
    raw = str(value or "medium").lower()
    return raw if raw in SEVERITIES else "medium"


def normalise_status(value: str) -> str:
    raw = str(value or "open").lower()
    return raw if raw in CASE_STATUSES else "open"


def row_to_case(row: Dict[str, Any]) -> Dict[str, Any]:
    case = dict(row)
    case["notes"] = loads(case.pop("notes_json", None), [])
    case["actions"] = loads(case.pop("actions_json", None), [])
    case["evidence"] = loads(case.pop("evidence_json", None), [])
    return case


def fetch_case(case_id: str) -> Optional[Dict[str, Any]]:
    with get_connection() as connection:
        row = connection.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
    return row_to_case(dict(row)) if row else None


def investigation_by_id(investigation_id: Optional[str]) -> Optional[Dict[str, Any]]:
    if not investigation_id:
        return None
    result = get_investigation_result(investigation_id)
    if result:
        return result
    for result in list_investigation_results():
        if result.get("request_id") == investigation_id:
            return result
        summary = result.get("summary") or {}
        if summary.get("request_id") == investigation_id or summary.get("investigation_id") == investigation_id:
            return result
    return None


def build_evidence_metadata(agent_id: Optional[str], investigation_id: Optional[str]) -> List[Dict[str, Any]]:
    evidence: List[Dict[str, Any]] = []
    inv = investigation_by_id(investigation_id)
    if inv:
        evidence.append({
            "type": "investigation_result",
            "investigation_id": investigation_id,
            "status": inv.get("status"),
            "finding_count": len(inv.get("findings") or []),
            "timeline_count": len(inv.get("timeline") or []),
            "report_path": inv.get("report_path"),
            "bundle_path": inv.get("bundle_path"),
        })
    if agent_id:
        agent = get_agent(agent_id)
        if agent:
            evidence.append({
                "type": "endpoint",
                "agent_id": agent_id,
                "hostname": agent.get("hostname"),
                "risk_score": agent.get("risk_score"),
                "risk_band": agent.get("risk_band"),
                "last_seen": agent.get("last_seen"),
                "evidence_file": agent.get("evidence_file"),
            })
    return evidence


@router.get("/")
def list_cases():
    with get_connection() as connection:
        rows = connection.execute("SELECT * FROM cases ORDER BY datetime(updated_at) DESC").fetchall()
    cases = [row_to_case(dict(row)) for row in rows]
    return {"status": "ok", "count": len(cases), "cases": cases}


@router.post("/")
def create_case(request: CaseCreateRequest):
    severity = normalise_severity(request.severity)
    status = normalise_status(request.status)
    case_id = f"CASE-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{uuid4().hex[:6].upper()}"
    now = utc_now()
    notes = request.notes or []
    actions = request.actions or []
    evidence = build_evidence_metadata(request.affected_agent_id, request.investigation_id)
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO cases (case_id, title, severity, status, affected_agent_id, investigation_id, summary, notes_json, actions_json, evidence_json, report_path, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (case_id, request.title, severity, status, request.affected_agent_id, request.investigation_id, request.summary, dumps(notes), dumps(actions), dumps(evidence), None, now, now),
        )
    save_audit_event(action="case_created", entity_type="case", entity_id=case_id, details={"severity": severity, "status": status})
    return {"status": "created", "case": fetch_case(case_id)}


@router.post("/from-investigation/{investigation_id}")
def create_case_from_investigation(investigation_id: str):
    inv = investigation_by_id(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    summary = inv.get("summary") or {}
    findings = inv.get("findings") or []
    severity_order = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    highest = "low"
    for finding in findings:
        sev = str(finding.get("severity") or "low").lower()
        if severity_order.get(sev, 0) > severity_order.get(highest, 0):
            highest = sev
    request = CaseCreateRequest(
        title=f"Investigation case: {summary.get('hostname') or inv.get('hostname') or investigation_id}",
        severity=highest,
        status="investigating" if findings else "open",
        affected_agent_id=inv.get("agent_id") or summary.get("agent_id"),
        investigation_id=investigation_id,
        summary=summary.get("exit_decision") or summary.get("status") or "Case created from investigation result.",
        actions=[{"created_at": utc_now(), "status": "open", "action": "Review investigation findings, timeline and evidence bundle."}],
    )
    return create_case(request)


@router.get("/{case_id}")
def get_case(case_id: str):
    case = fetch_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    investigation = investigation_by_id(case.get("investigation_id"))
    return {"status": "ok", "case": case, "investigation": investigation}


@router.patch("/{case_id}")
def update_case(case_id: str, request: CaseUpdateRequest):
    case = fetch_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    notes = case.get("notes") or []
    actions = case.get("actions") or []
    if request.note:
        notes.append({"created_at": utc_now(), "note": request.note})
    if request.action:
        action = dict(request.action)
        action.setdefault("created_at", utc_now())
        action.setdefault("status", "open")
        actions.append(action)
    title = request.title if request.title is not None else case["title"]
    severity = normalise_severity(request.severity if request.severity is not None else case["severity"])
    status = normalise_status(request.status if request.status is not None else case["status"])
    summary = request.summary if request.summary is not None else case.get("summary", "")
    now = utc_now()
    with get_connection() as connection:
        connection.execute(
            """
            UPDATE cases SET title=?, severity=?, status=?, summary=?, notes_json=?, actions_json=?, updated_at=? WHERE case_id=?
            """,
            (title, severity, status, summary, dumps(notes), dumps(actions), now, case_id),
        )
    save_audit_event(action="case_updated", entity_type="case", entity_id=case_id, details={"severity": severity, "status": status})
    return {"status": "updated", "case": fetch_case(case_id)}


def html_escape(value: Any) -> str:
    import html
    return html.escape(str(value if value is not None else ""))


def build_case_report(case: Dict[str, Any], investigation: Optional[Dict[str, Any]]) -> str:
    findings = (investigation or {}).get("findings") or []
    timeline = (investigation or {}).get("timeline") or []
    evidence = case.get("evidence") or []
    finding_rows = "".join(
        f"<tr><td>{html_escape(f.get('severity'))}</td><td>{html_escape(f.get('title') or f.get('control'))}</td><td>{html_escape(f.get('recommended_action') or f.get('remediation'))}</td></tr>"
        for f in findings
    ) or "<tr><td colspan='3'>No findings attached.</td></tr>"
    timeline_rows = "".join(
        f"<tr><td>{html_escape(t.get('time') or t.get('timestamp'))}</td><td>{html_escape(t.get('source'))}</td><td>{html_escape(t.get('event') or t.get('title'))}</td><td>{html_escape(t.get('severity'))}</td></tr>"
        for t in timeline
    ) or "<tr><td colspan='4'>No timeline entries attached.</td></tr>"
    evidence_items = "".join(f"<li><strong>{html_escape(e.get('type'))}</strong>: {html_escape(e)}</li>" for e in evidence) or "<li>No evidence metadata attached.</li>"
    notes = "".join(f"<li>{html_escape(n.get('created_at'))}: {html_escape(n.get('note'))}</li>" for n in case.get("notes", [])) or "<li>No notes recorded.</li>"
    actions = "".join(f"<li>{html_escape(a.get('status'))}: {html_escape(a.get('action') or a)}</li>" for a in case.get("actions", [])) or "<li>No actions recorded.</li>"
    return f"""
    <html><head><title>{html_escape(case['case_id'])} Incident Report</title><style>
    body {{ font-family: Arial, sans-serif; margin: 32px; color: #111827; }}
    h1, h2 {{ color: #0f172a; }} .meta {{ display:grid; grid-template-columns: repeat(auto-fit,minmax(220px,1fr)); gap:12px; }}
    .card {{ border:1px solid #d1d5db; border-radius:10px; padding:14px; margin:12px 0; }}
    table {{ width:100%; border-collapse:collapse; }} th,td {{ border:1px solid #d1d5db; padding:8px; text-align:left; vertical-align:top; }} th {{ background:#f3f4f6; }}
    </style></head><body>
    <h1>Sentinel Incident Report</h1>
    <p>This report is generated from a defensive Sentinel case and linked investigation evidence.</p>
    <div class="meta">
      <div class="card"><b>Case</b><br>{html_escape(case['case_id'])}</div>
      <div class="card"><b>Status</b><br>{html_escape(case['status'])}</div>
      <div class="card"><b>Severity</b><br>{html_escape(case['severity'])}</div>
      <div class="card"><b>Affected endpoint</b><br>{html_escape(case.get('affected_agent_id'))}</div>
    </div>
    <h2>Executive summary</h2><div class="card"><p>{html_escape(case.get('summary') or 'No executive summary recorded yet.')}</p></div>
    <h2>Key findings</h2><table><thead><tr><th>Severity</th><th>Finding</th><th>Recommended action</th></tr></thead><tbody>{finding_rows}</tbody></table>
    <h2>Timeline</h2><table><thead><tr><th>Time</th><th>Source</th><th>Event</th><th>Severity</th></tr></thead><tbody>{timeline_rows}</tbody></table>
    <h2>Evidence collected</h2><div class="card"><ul>{evidence_items}</ul></div>
    <h2>Containment, eradication and recovery</h2><div class="card"><ul>{actions}</ul></div>
    <h2>Case notes</h2><div class="card"><ul>{notes}</ul></div>
    <h2>Residual risk</h2><div class="card"><p>Review all open actions and re-run endpoint baseline, IOC, persistence, network and vulnerability checks before closure.</p></div>
    </body></html>
    """


@router.post("/{case_id}/report")
def generate_case_report(case_id: str):
    case = fetch_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    investigation = investigation_by_id(case.get("investigation_id"))
    html = build_case_report(case, investigation)
    report_path = REPORT_DIR / f"{case_id}_incident_report.html"
    report_path.write_text(html, encoding="utf-8")
    with get_connection() as connection:
        connection.execute("UPDATE cases SET report_path=?, updated_at=? WHERE case_id=?", (str(report_path), utc_now(), case_id))
    save_audit_event(action="case_report_generated", entity_type="case", entity_id=case_id)
    return {"status": "report_generated", "case_id": case_id, "report_path": str(report_path), "download_url": f"/api/cases/{case_id}/report"}


@router.get("/{case_id}/report")
def download_case_report(case_id: str):
    case = fetch_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    report_path = case.get("report_path") or str(REPORT_DIR / f"{case_id}_incident_report.html")
    path = Path(report_path)
    if not path.exists():
        html = build_case_report(case, investigation_by_id(case.get("investigation_id")))
        path.write_text(html, encoding="utf-8")
    return HTMLResponse(path.read_text(encoding="utf-8"))
