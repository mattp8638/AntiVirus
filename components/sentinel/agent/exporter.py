import base64
import hashlib
import json
import os
import zipfile
from datetime import datetime
from pathlib import Path
from html import escape

from cryptography.fernet import Fernet

SECRET = os.getenv("SENTINEL_EVIDENCE_SECRET", "sentinel-investigation-key-change-me")
KEY = base64.urlsafe_b64encode(hashlib.sha256(SECRET.encode()).digest())
fernet = Fernet(KEY)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def export_json(data, path="evidence.json"):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    return str(path)


def export_html(data, path="report.html"):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    summary = data.get("summary", {}) if isinstance(data, dict) else {}
    findings = data.get("findings", []) if isinstance(data, dict) else []
    timeline = data.get("timeline", []) if isinstance(data, dict) else []
    sections = data.get("sections", {}) if isinstance(data, dict) else {}

    finding_rows = "".join(
        f"<tr><td>{escape(str(item.get('severity', '')))}</td><td>{escape(str(item.get('module', '')))}</td><td>{escape(str(item.get('title', '')))}</td><td>{escape(str(item.get('recommended_action', '')))}</td></tr>"
        for item in findings
    ) or "<tr><td colspan='4'>No findings were generated for this scope.</td></tr>"
    timeline_rows = "".join(
        f"<tr><td>{escape(str(item.get('time', '')))}</td><td>{escape(str(item.get('source', '')))}</td><td>{escape(str(item.get('event', '')))}</td><td>{escape(str(item.get('severity', '')))}</td></tr>"
        for item in timeline
    ) or "<tr><td colspan='4'>No timeline entries were generated.</td></tr>"
    section_cards = "".join(
        f"<section class='card'><h3>{escape(str(name))}</h3><pre>{escape(json.dumps(value, indent=2, default=str))}</pre></section>"
        for name, value in sections.items()
    ) or "<section class='card'><h3>Collected data</h3><p>No structured sections were supplied.</p></section>"

    html = f"""
    <html>
        <head>
            <title>Sentinel Evidence Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; background:#0f172a; color:#e5e7eb; margin:0; padding:24px; }}
                .wrap {{ max-width:1200px; margin:0 auto; }}
                h1, h2, h3 {{ color:#38bdf8; }}
                .grid {{ display:grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap:16px; margin:16px 0; }}
                .card {{ background:#111827; border:1px solid #1f2937; border-radius:12px; padding:16px; }}
                .badge {{ display:inline-block; padding:4px 10px; border-radius:999px; background:#1d4ed8; color:white; font-size:12px; }}
                table {{ width:100%; border-collapse:collapse; margin:12px 0 24px; }}
                th, td {{ border:1px solid #334155; padding:8px; text-align:left; vertical-align:top; }}
                th {{ background:#0f172a; }}
                pre {{ white-space:pre-wrap; word-break:break-word; background:#020617; padding:12px; border-radius:8px; overflow:auto; }}
                .muted {{ color:#94a3b8; }}
            </style>
        </head>
        <body>
            <div class='wrap'>
                <h1>Sentinel Evidence Report</h1>
                <p class='muted'>Generated: {datetime.utcnow().isoformat()}Z</p>
                <div class='grid'>
                    <div class='card'><div class='muted'>Host</div><div>{escape(str(summary.get('hostname', data.get('hostname', 'unknown'))))}</div></div>
                    <div class='card'><div class='muted'>Investigation</div><div>{escape(str(summary.get('investigation_id', summary.get('request_id', 'N/A'))))}</div></div>
                    <div class='card'><div class='muted'>Scope</div><div>{escape(', '.join(str(item) for item in (summary.get('scope_collected', data.get('collected_sections', [])) or [])))}</div></div>
                    <div class='card'><div class='muted'>Artifacts</div><div>{escape(str(summary.get('artifact_count', len(data.get('collected_sections', [])))))}</div></div>
                </div>
                <section class='card'>
                    <h2>Summary</h2>
                    <pre>{escape(json.dumps(summary or data, indent=2, default=str))}</pre>
                </section>
                <section class='card'>
                    <h2>Findings</h2>
                    <table><thead><tr><th>Severity</th><th>Module</th><th>Finding</th><th>Recommended action</th></tr></thead><tbody>{finding_rows}</tbody></table>
                </section>
                <section class='card'>
                    <h2>Timeline</h2>
                    <table><thead><tr><th>Time</th><th>Source</th><th>Event</th><th>Severity</th></tr></thead><tbody>{timeline_rows}</tbody></table>
                </section>
                <section class='card'>
                    <h2>Collected Data</h2>
                    {section_cards}
                </section>
            </div>
        </body>
    </html>
    """
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return str(path)


def export_bundle(files, out="evidence_bundle.enc", metadata=None):
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    zip_name = out.with_suffix(".zip")

    artefacts = []
    for file_path in files:
        file_path = Path(file_path)
        if file_path.exists():
            artefacts.append({
                "name": file_path.name,
                "path": str(file_path),
                "sha256": sha256_file(file_path),
                "size_bytes": file_path.stat().st_size,
                "modified_at": datetime.utcfromtimestamp(file_path.stat().st_mtime).isoformat() + "Z",
            })

    metadata = metadata or {}
    manifest = {
        "created_at": datetime.utcnow().isoformat() + "Z",
        "collection_timestamp": datetime.utcnow().isoformat() + "Z",
        "agent_id": metadata.get("agent_id"),
        "hostname": metadata.get("hostname"),
        "investigation_request_id": metadata.get("request_id"),
        "selected_scope": metadata.get("selected_scope", {}),
        "tool_version": metadata.get("tool_version", "sentinel-agent-mvp"),
        "artefacts": artefacts,
        "encrypted": True,
        "algorithm": "Fernet-AES128-CBC-HMACSHA256",
        "manifest_schema": "sentinel-evidence-manifest-v1",
    }
    manifest_path = out.parent / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, default=str), encoding="utf-8")

    with zipfile.ZipFile(zip_name, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for file_path in files:
            file_path = Path(file_path)
            if file_path.exists():
                z.write(file_path, arcname=file_path.name)
        z.write(manifest_path, arcname="manifest.json")

    encrypted = fernet.encrypt(zip_name.read_bytes())
    out.write_bytes(encrypted)

    try:
        zip_name.unlink()
        manifest_path.unlink()
    except OSError:
        pass

    return str(out)
