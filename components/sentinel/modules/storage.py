import base64
import hashlib
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional


DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "sentinel.db"
LEGACY_AGENTS_FILE = DATA_DIR / "agents.json"
LEGACY_POSTURES_FILE = DATA_DIR / "postures.json"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


@contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    connection = _connect()
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def _json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, default=str)


def _json_loads(value: Any, default: Any) -> Any:
    if value in (None, ""):
        return default
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except Exception:
        return default


def _row_to_dict(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
    if row is None:
        return None
    return dict(row)


def _execute(query: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
    with get_connection() as connection:
        cursor = connection.execute(query, tuple(params))
        return cursor


def _fetch_one(query: str, params: Iterable[Any] = ()) -> Optional[Dict[str, Any]]:
    with get_connection() as connection:
        row = connection.execute(query, tuple(params)).fetchone()
    return _row_to_dict(row)


def _fetch_all(query: str, params: Iterable[Any] = ()) -> List[Dict[str, Any]]:
    with get_connection() as connection:
        rows = connection.execute(query, tuple(params)).fetchall()
    return [dict(row) for row in rows]


def initialize_database() -> None:
    with get_connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS agents (
                agent_id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                operating_system TEXT NOT NULL,
                registered_at TEXT,
                last_seen TEXT,
                status TEXT,
                investigation TEXT,
                risk_score INTEGER,
                risk_band TEXT,
                investigation_request_id TEXT,
                investigation_requested_at TEXT,
                investigation_priority TEXT,
                investigation_reason TEXT,
                investigation_scope TEXT,
                investigation_instruction TEXT,
                evidence_file TEXT,
                evidence_uploaded_at TEXT,
                metadata TEXT
            );

            CREATE TABLE IF NOT EXISTS agent_postures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                received_at TEXT NOT NULL,
                posture_json TEXT NOT NULL,
                assessment_json TEXT NOT NULL,
                FOREIGN KEY(agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS investigation_requests (
                request_id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                hostname TEXT,
                status TEXT NOT NULL,
                priority TEXT,
                reason TEXT,
                scope_json TEXT,
                requested_at TEXT,
                updated_at TEXT,
                FOREIGN KEY(agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS investigation_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT,
                agent_id TEXT,
                hostname TEXT,
                status TEXT,
                completed_at TEXT,
                summary_json TEXT,
                findings_json TEXT,
                timeline_json TEXT,
                report_path TEXT,
                bundle_path TEXT,
                FOREIGN KEY(agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS evidence_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                request_id TEXT,
                filename TEXT NOT NULL,
                path TEXT NOT NULL,
                sha256 TEXT,
                uploaded_at TEXT,
                metadata_json TEXT,
                FOREIGN KEY(agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS software_inventory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT,
                collected_at TEXT,
                inventory_json TEXT,
                FOREIGN KEY(agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS vulnerability_matches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT,
                collected_at TEXT,
                matches_json TEXT,
                FOREIGN KEY(agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS settings (
                namespace TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT,
                secret INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT,
                PRIMARY KEY(namespace, key)
            );

            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor TEXT,
                action TEXT NOT NULL,
                entity_type TEXT,
                entity_id TEXT,
                details_json TEXT,
                created_at TEXT NOT NULL
            );
            """
        )
    _migrate_legacy_json()


def _migrate_legacy_json() -> None:
    with get_connection() as connection:
        agent_count = connection.execute("SELECT COUNT(*) AS count FROM agents").fetchone()["count"]
    if agent_count:
        return

    if LEGACY_AGENTS_FILE.exists():
        try:
            agents_data = json.loads(LEGACY_AGENTS_FILE.read_text(encoding="utf-8"))
            for agent_id, agent in agents_data.items():
                save_agent({"agent_id": agent_id, **agent})
        except Exception:
            pass

    if LEGACY_POSTURES_FILE.exists():
        try:
            postures_data = json.loads(LEGACY_POSTURES_FILE.read_text(encoding="utf-8"))
            for agent_id, posture in postures_data.items():
                save_posture(
                    agent_id=agent_id,
                    received_at=posture.get("received_at") or utc_now(),
                    posture=posture.get("posture") or {},
                    assessment=posture.get("assessment") or {},
                )
        except Exception:
            pass


def save_agent(agent: Dict[str, Any]) -> Dict[str, Any]:
    payload = {
        "agent_id": agent["agent_id"],
        "hostname": agent.get("hostname", "unknown"),
        "operating_system": agent.get("operating_system", "Windows"),
        "registered_at": agent.get("registered_at") or utc_now(),
        "last_seen": agent.get("last_seen"),
        "status": agent.get("status", "registered"),
        "investigation": agent.get("investigation", "idle"),
        "risk_score": agent.get("risk_score"),
        "risk_band": agent.get("risk_band"),
        "investigation_request_id": agent.get("investigation_request_id"),
        "investigation_requested_at": agent.get("investigation_requested_at"),
        "investigation_priority": agent.get("investigation_priority"),
        "investigation_reason": agent.get("investigation_reason"),
        "investigation_scope": _json_dumps(agent.get("investigation_scope", {})),
        "investigation_instruction": _json_dumps(agent.get("investigation_instruction", {})) if agent.get("investigation_instruction") is not None else None,
        "evidence_file": agent.get("evidence_file"),
        "evidence_uploaded_at": agent.get("evidence_uploaded_at"),
        "metadata": _json_dumps(agent.get("metadata", {})) if agent.get("metadata") is not None else None,
    }
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO agents (
                agent_id, hostname, operating_system, registered_at, last_seen, status, investigation,
                risk_score, risk_band, investigation_request_id, investigation_requested_at,
                investigation_priority, investigation_reason, investigation_scope,
                investigation_instruction, evidence_file, evidence_uploaded_at, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(agent_id) DO UPDATE SET
                hostname=excluded.hostname,
                operating_system=excluded.operating_system,
                last_seen=excluded.last_seen,
                status=excluded.status,
                investigation=excluded.investigation,
                risk_score=excluded.risk_score,
                risk_band=excluded.risk_band,
                investigation_request_id=excluded.investigation_request_id,
                investigation_requested_at=excluded.investigation_requested_at,
                investigation_priority=excluded.investigation_priority,
                investigation_reason=excluded.investigation_reason,
                investigation_scope=excluded.investigation_scope,
                investigation_instruction=excluded.investigation_instruction,
                evidence_file=excluded.evidence_file,
                evidence_uploaded_at=excluded.evidence_uploaded_at,
                metadata=excluded.metadata
            """,
            tuple(payload.values()),
        )
    return get_agent(agent["agent_id"]) or payload


def list_agents() -> List[Dict[str, Any]]:
    agents = _fetch_all("SELECT * FROM agents ORDER BY datetime(COALESCE(last_seen, registered_at, '1970-01-01T00:00:00Z')) DESC, registered_at DESC")
    for agent in agents:
        agent["investigation_scope"] = _json_loads(agent.get("investigation_scope"), {})
        agent["investigation_instruction"] = _json_loads(agent.get("investigation_instruction"), None)
        agent["metadata"] = _json_loads(agent.get("metadata"), {})
        if agent.get("risk_score") is not None:
            agent["risk_score"] = int(agent["risk_score"])
    return agents


def get_agent(agent_id: str) -> Optional[Dict[str, Any]]:
    agent = _fetch_one("SELECT * FROM agents WHERE agent_id = ?", (agent_id,))
    if not agent:
        return None
    agent["investigation_scope"] = _json_loads(agent.get("investigation_scope"), {})
    agent["investigation_instruction"] = _json_loads(agent.get("investigation_instruction"), None)
    agent["metadata"] = _json_loads(agent.get("metadata"), {})
    if agent.get("risk_score") is not None:
        agent["risk_score"] = int(agent["risk_score"])
    return agent


def delete_agent(agent_id: str) -> None:
    _execute("DELETE FROM agents WHERE agent_id = ?", (agent_id,))


def save_posture(agent_id: str, received_at: str, posture: Dict[str, Any], assessment: Dict[str, Any]) -> Dict[str, Any]:
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO agent_postures (agent_id, received_at, posture_json, assessment_json)
            VALUES (?, ?, ?, ?)
            """,
            (agent_id, received_at, _json_dumps(posture), _json_dumps(assessment)),
        )
    return {"agent_id": agent_id, "received_at": received_at, "posture": posture, "assessment": assessment}


def get_latest_posture(agent_id: str) -> Optional[Dict[str, Any]]:
    posture = _fetch_one(
        "SELECT agent_id, received_at, posture_json, assessment_json FROM agent_postures WHERE agent_id = ? ORDER BY id DESC LIMIT 1",
        (agent_id,),
    )
    if not posture:
        return None
    posture["posture"] = _json_loads(posture.get("posture_json"), {})
    posture["assessment"] = _json_loads(posture.get("assessment_json"), {})
    posture.pop("posture_json", None)
    posture.pop("assessment_json", None)
    return posture


def save_investigation_request(request: Dict[str, Any]) -> Dict[str, Any]:
    payload = {
        "request_id": request["request_id"],
        "agent_id": request["agent_id"],
        "hostname": request.get("hostname"),
        "status": request.get("status", "pending"),
        "priority": request.get("priority", "normal"),
        "reason": request.get("reason", ""),
        "scope_json": _json_dumps(request.get("scope", {})),
        "requested_at": request.get("requested_at") or utc_now(),
        "updated_at": request.get("updated_at") or request.get("requested_at") or utc_now(),
    }
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO investigation_requests (
                request_id, agent_id, hostname, status, priority, reason, scope_json, requested_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(request_id) DO UPDATE SET
                status=excluded.status,
                priority=excluded.priority,
                reason=excluded.reason,
                scope_json=excluded.scope_json,
                updated_at=excluded.updated_at
            """,
            tuple(payload.values()),
        )
    return get_investigation_request(request["request_id"]) or payload


def get_investigation_request(request_id: str) -> Optional[Dict[str, Any]]:
    request = _fetch_one("SELECT * FROM investigation_requests WHERE request_id = ?", (request_id,))
    if not request:
        return None
    request["scope"] = _json_loads(request.pop("scope_json", None), {})
    return request


def get_agent_pending_request(agent_id: str) -> Optional[Dict[str, Any]]:
    request = _fetch_one(
        "SELECT * FROM investigation_requests WHERE agent_id = ? AND status = 'pending' ORDER BY datetime(requested_at) DESC LIMIT 1",
        (agent_id,),
    )
    if not request:
        return None
    request["scope"] = _json_loads(request.pop("scope_json", None), {})
    return request


def list_investigation_requests() -> List[Dict[str, Any]]:
    requests = _fetch_all("SELECT * FROM investigation_requests ORDER BY datetime(requested_at) DESC")
    for request in requests:
        request["scope"] = _json_loads(request.pop("scope_json", None), {})
    return requests


def update_investigation_request_status(request_id: str, status: str) -> None:
    _execute(
        "UPDATE investigation_requests SET status = ?, updated_at = ? WHERE request_id = ?",
        (status, utc_now(), request_id),
    )


def save_evidence_file(
    *,
    agent_id: str,
    request_id: Optional[str],
    filename: str,
    path: str,
    sha256: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    uploaded_at = utc_now()
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO evidence_files (agent_id, request_id, filename, path, sha256, uploaded_at, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (agent_id, request_id, filename, path, sha256, uploaded_at, _json_dumps(metadata or {})),
        )
    return {
        "agent_id": agent_id,
        "request_id": request_id,
        "filename": filename,
        "path": path,
        "sha256": sha256,
        "uploaded_at": uploaded_at,
        "metadata": metadata or {},
    }


def save_software_inventory(agent_id: str, collected_at: Optional[str], inventory: List[Dict[str, Any]]) -> Dict[str, Any]:
    payload = {
        "agent_id": agent_id,
        "collected_at": collected_at or utc_now(),
        "inventory": inventory or [],
    }
    with get_connection() as connection:
        connection.execute(
            "DELETE FROM software_inventory WHERE agent_id = ?",
            (agent_id,),
        )
        connection.execute(
            """
            INSERT INTO software_inventory (agent_id, collected_at, inventory_json)
            VALUES (?, ?, ?)
            """,
            (agent_id, payload["collected_at"], _json_dumps(payload["inventory"])),
        )
    return payload


def get_latest_software_inventory(agent_id: str) -> Optional[Dict[str, Any]]:
    inventory = _fetch_one(
        "SELECT * FROM software_inventory WHERE agent_id = ? ORDER BY id DESC LIMIT 1",
        (agent_id,),
    )
    if not inventory:
        return None
    inventory["inventory"] = _json_loads(inventory.pop("inventory_json", None), [])
    return inventory


def get_latest_evidence(agent_id: str) -> Optional[Dict[str, Any]]:
    evidence = _fetch_one(
        "SELECT * FROM evidence_files WHERE agent_id = ? ORDER BY id DESC LIMIT 1",
        (agent_id,),
    )
    if not evidence:
        return None
    evidence["metadata"] = _json_loads(evidence.pop("metadata_json", None), {})
    return evidence


def save_investigation_result(result: Dict[str, Any]) -> Dict[str, Any]:
    with get_connection() as connection:
        request_id = result.get("request_id")
        if request_id:
            connection.execute("DELETE FROM investigation_results WHERE request_id = ?", (request_id,))
        connection.execute(
            """
            INSERT INTO investigation_results (
                request_id, agent_id, hostname, status, completed_at, summary_json, findings_json,
                timeline_json, report_path, bundle_path
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result.get("request_id"),
                result.get("agent_id"),
                result.get("hostname"),
                result.get("status"),
                result.get("completed_at"),
                _json_dumps(result.get("summary", {})),
                _json_dumps(result.get("findings", [])),
                _json_dumps(result.get("timeline", [])),
                result.get("report_path"),
                result.get("bundle_path"),
            ),
        )
    return result


def list_investigation_results() -> List[Dict[str, Any]]:
    results = _fetch_all("SELECT * FROM investigation_results ORDER BY datetime(completed_at) DESC, id DESC")
    for result in results:
        result["summary"] = _json_loads(result.pop("summary_json", None), {})
        result["findings"] = _json_loads(result.pop("findings_json", None), [])
        result["timeline"] = _json_loads(result.pop("timeline_json", None), [])
    return results


def get_investigation_result(investigation_id: str) -> Optional[Dict[str, Any]]:
    results = list_investigation_results()
    for result in results:
        summary = result.get("summary") or {}
        if summary.get("investigation_id") == investigation_id:
            return result
    return None


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class SecretStoreError(RuntimeError):
    pass


def require_secret_key() -> str:
    secret = os.getenv("SENTINEL_SECRET_KEY")
    if not secret:
        raise SecretStoreError("SENTINEL_SECRET_KEY is required to store secrets persistently.")
    return secret


def _fernet_key() -> bytes:
    secret = require_secret_key()
    return base64.urlsafe_b64encode(hashlib.sha256(secret.encode("utf-8")).digest())


def encrypt_secret(value: str) -> str:
    from cryptography.fernet import Fernet

    return Fernet(_fernet_key()).encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_secret(value: str) -> str:
    from cryptography.fernet import Fernet

    return Fernet(_fernet_key()).decrypt(value.encode("utf-8")).decode("utf-8")


def save_setting(namespace: str, key: str, value: Any, *, secret: bool = False) -> None:
    stored_value = _json_dumps(value) if isinstance(value, (dict, list, bool, int, float)) else str(value)
    if secret:
        stored_value = encrypt_secret(stored_value)
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO settings (namespace, key, value, secret, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(namespace, key) DO UPDATE SET
                value=excluded.value,
                secret=excluded.secret,
                updated_at=excluded.updated_at
            """,
            (namespace, key, stored_value, 1 if secret else 0, utc_now()),
        )


def get_settings_namespace(namespace: str, *, include_secrets: bool = False) -> Dict[str, Any]:
    rows = _fetch_all("SELECT * FROM settings WHERE namespace = ? ORDER BY key ASC", (namespace,))
    result: Dict[str, Any] = {}
    for row in rows:
        raw_value = row.get("value")
        if row.get("secret"):
            result[row["key"]] = decrypt_secret(raw_value) if include_secrets else "***masked***"
            continue
        parsed = _json_loads(raw_value, raw_value)
        result[row["key"]] = parsed
    return result


def get_all_settings(*, include_secrets: bool = False) -> Dict[str, Any]:
    namespaces = _fetch_all("SELECT DISTINCT namespace FROM settings ORDER BY namespace ASC")
    return {row["namespace"]: get_settings_namespace(row["namespace"], include_secrets=include_secrets) for row in namespaces}


def save_audit_event(*, action: str, entity_type: Optional[str] = None, entity_id: Optional[str] = None, details: Optional[Dict[str, Any]] = None, actor: Optional[str] = None) -> None:
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO audit_events (actor, action, entity_type, entity_id, details_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (actor, action, entity_type, entity_id, _json_dumps(details or {}), utc_now()),
        )


initialize_database()