import platform
from typing import List, Dict
try:
    import psutil
except Exception:
    psutil = None


def collect_services() -> List[Dict]:
    if platform.system().lower() != "windows" or psutil is None:
        return []
    services: List[Dict] = []
    try:
        for service in psutil.win_service_iter():
            try:
                data = service.as_dict()
                services.append({
                    "name": data.get("name"),
                    "display_name": data.get("display_name"),
                    "status": data.get("status"),
                    "start_type": data.get("start_type"),
                    "username": data.get("username"),
                    "binpath": data.get("binpath"),
                })
            except Exception:
                continue
    except Exception:
        return []
    return services
