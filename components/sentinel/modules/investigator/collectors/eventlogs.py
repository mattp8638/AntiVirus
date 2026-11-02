from typing import Dict, Any
from modules.investigator.common import safe_run


def collect_eventlog_summary(max_events: int) -> Dict[str, Any]:
    import platform
    if platform.system().lower() != "windows" or max_events <= 0:
        return {"supported": False, "reason": "windows_event_logs_only_or_disabled"}
    channels = ["System", "Security", "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-Windows Defender/Operational"]
    summaries = []
    for channel in channels:
        result = safe_run(["wevtutil", "qe", channel, "/c:" + str(max_events), "/rd:true", "/f:text"], timeout=20)
        summaries.append({"channel": channel, "result": result})
    return {"supported": True, "channels": summaries}
