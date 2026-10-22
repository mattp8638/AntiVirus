from typing import List, Dict, Optional
try:
    import psutil
except Exception:
    psutil = None


def collect_network_connections() -> List[Dict[str, Optional[str]]]:
    if psutil is None:
        return []
    connections: List[Dict[str, Optional[str]]] = []
    process_names: Dict[int, str] = {}
    process_paths: Dict[int, Optional[str]] = {}
    for proc in psutil.process_iter(attrs=["pid", "name", "exe"]):
        try:
            process_names[proc.info["pid"]] = proc.info.get("name") or "unknown"
            process_paths[proc.info["pid"]] = proc.info.get("exe")
        except Exception:
            continue
    try:
        raw_connections = psutil.net_connections(kind="inet")
    except Exception:
        raw_connections = []
    for conn in raw_connections:
        connections.append({
            "fd": conn.fd,
            "family": str(conn.family),
            "type": str(conn.type),
            "local_address": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
            "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
            "remote_ip": conn.raddr.ip if conn.raddr else None,
            "remote_port": conn.raddr.port if conn.raddr else None,
            "status": conn.status,
            "pid": conn.pid,
            "process_name": process_names.get(conn.pid) if conn.pid else None,
            "process_path": process_paths.get(conn.pid) if conn.pid else None,
        })
    return connections


def analyse_network(connections: List[Dict]) -> List[Dict]:
    findings = []
    risky_process_fragments = ["powershell", "pwsh", "cmd", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "certutil"]
    for conn in connections:
        if not conn.get("remote_ip"):
            continue
        proc_name = (conn.get("process_name") or "").lower()
        proc_path = (conn.get("process_path") or "").lower()
        is_script_tool = any(fragment in proc_name for fragment in risky_process_fragments)
        runs_from_user_writable = any(fragment in proc_path for fragment in ["\\appdata\\", "\\temp\\", "/tmp/", "/appdata/"])
        if is_script_tool or runs_from_user_writable:
            findings.append({
                "finding_id": f"FND-UNKNOWN",
                "module": "Network Connection Monitor",
                "title": "Suspicious process with external connection",
                "severity": "high" if is_script_tool else "medium",
                "confidence": "medium",
                "asset": None,
                "description": f"Process {conn.get('process_name')} has an external connection to {conn.get('remote_address')}",
                "evidence": conn,
                "recommended_action": "Validate the destination and process. If unexpected, enrich the IP/domain with IOC checks and consider containment.",
                "created_at": None,
            })
    return findings
