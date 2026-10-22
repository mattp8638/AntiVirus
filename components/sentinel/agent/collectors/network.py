from typing import Any, Dict, List

import psutil


def _addr_dict(addr: Any) -> Dict[str, Any] | None:
    if not addr:
        return None
    return {
        "ip": getattr(addr, "ip", None),
        "port": getattr(addr, "port", None),
        "text": f"{getattr(addr, 'ip', '')}:{getattr(addr, 'port', '')}",
    }


def collect_connections() -> List[Dict[str, Any]]:
    conns: List[Dict[str, Any]] = []
    try:
        raw_connections = psutil.net_connections(kind="inet")
    except Exception:
        raw_connections = []
    for conn in raw_connections:
        try:
            proc_name = None
            proc_path = None
            if conn.pid:
                try:
                    proc = psutil.Process(conn.pid)
                    proc_name = proc.name()
                    proc_path = proc.exe()
                except Exception:
                    pass
            local = _addr_dict(conn.laddr)
            remote = _addr_dict(conn.raddr)
            conns.append({
                "fd": conn.fd,
                "family": str(conn.family),
                "type": str(conn.type),
                "laddr": str(conn.laddr),
                "raddr": str(conn.raddr),
                "local_address": local["text"] if local else None,
                "local_ip": local["ip"] if local else None,
                "local_port": local["port"] if local else None,
                "remote_address": remote["text"] if remote else None,
                "remote_ip": remote["ip"] if remote else None,
                "remote_port": remote["port"] if remote else None,
                "status": conn.status,
                "pid": conn.pid,
                "process_name": proc_name,
                "process_path": proc_path,
            })
        except Exception:
            continue
    return conns
