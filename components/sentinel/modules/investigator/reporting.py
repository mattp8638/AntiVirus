from pathlib import Path
from typing import Dict, Any
from modules.investigator.common import write_json, sha256_file, utc_now
import zipfile


def build_html_report(summary: Dict[str, Any], findings: list, timeline: list) -> str:
    rows = "".join(
        f"<tr><td>{f.get('severity')}</td><td>{f.get('module')}</td><td>{f.get('title')}</td><td>{f.get('recommended_action')}</td></tr>"
        for f in findings
    ) or "<tr><td colspan='4'>No suspicious findings were identified by this investigation slice.</td></tr>"
    timeline_rows = "".join(
        f"<tr><td>{t.get('time')}</td><td>{t.get('source')}</td><td>{t.get('event')}</td><td>{t.get('severity')}</td></tr>"
        for t in timeline
    ) or "<tr><td colspan='4'>No timeline events generated.</td></tr>"
    return f"""<!doctype html>
<html><head><meta charset='utf-8'><title>Sentinel Investigator Report</title>
<style>body{{font-family:Arial,sans-serif;margin:32px;color:#111827}}table{{border-collapse:collapse;width:100%;margin:16px 0}}td,th{{border:1px solid #d1d5db;padding:8px;text-align:left}}th{{background:#f3f4f6}}.badge{{display:inline-block;padding:4px 8px;border-radius:999px;background:#e5e7eb}}</style>
</head><body>
<h1>Sentinel Investigator Report</h1>
<p><strong>Investigation ID:</strong> {summary['investigation_id']}</p>
<p><strong>Host:</strong> {summary['hostname']}</p>
<p><strong>Started:</strong> {summary['started_at']}</p>
<p><strong>Completed:</strong> {summary['completed_at']}</p>
<p><strong>Highest severity:</strong> <span class='badge'>{summary['highest_severity']}</span></p>
<h2>Exit Decision</h2>
<p>{summary['exit_decision']}</p>
<h2>Production Grade Effect</h2>
<p>{summary['production_grade_effect']}</p>
<h2>Findings</h2>
<table><thead><tr><th>Severity</th><th>Module</th><th>Finding</th><th>Recommended action</th></tr></thead><tbody>{rows}</tbody></table>
<h2>Timeline</h2>
<table><thead><tr><th>Time</th><th>Source</th><th>Event</th><th>Severity</th></tr></thead><tbody>{timeline_rows}</tbody></table>
</body></html>"""


def create_bundle(investigation_dir: Path, bundle_path: Path) -> Dict[str, str]:
    hashes: Dict[str, str] = {}
    for path in investigation_dir.rglob("*"):
        if path.is_file() and path != bundle_path:
            hashes[str(path.relative_to(investigation_dir))] = sha256_file(path)
    write_json(investigation_dir / "manifest.json", {"generated_at": utc_now(), "hashes": hashes})
    with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for path in investigation_dir.rglob("*"):
            if path.is_file() and path != bundle_path:
                bundle.write(path, path.relative_to(investigation_dir))
    return hashes
