"""Categories for the script library: Operating system / Area / Kind, e.g. "Linux / Networking / Fix".

- Operating system: Windows, macOS, Linux, "Linux & macOS" or "All platforms", from the script's platforms, narrowed by
  its name when it says which one it is for ("Mac - Isolate Device" runs bash but targets macOS).
- Area: what it deals with (Security, Networking, Patching and updates, ...).
- Kind: Check (reports, changes nothing), Fix (repairs a problem), Action (makes a change you asked for) or
  Response (incident steps: isolate, erase, contain).

Rules look at the name and description first, and only then at the body, so a script that merely mentions DNS in a
comment is not filed under Networking. The library shows the parts as a tree; " / " separates them.
"""

from __future__ import annotations

import re

SEP = " / "
OS_ORDER = ["Windows", "macOS", "Linux", "Linux & macOS", "All platforms"]
KINDS = ["Check", "Fix", "Action", "Response"]

# (area, pattern). First match wins, so the specific comes before the general.
AREAS: list[tuple[str, str]] = [
    ("Incident response", r"isolat|containment|\berase\b|\bwipe\b|remove[- ]isolation|quarantine device|kill switch"),
    ("Encryption", r"bitlocker|filevault|luks|encrypt|recovery key"),
    ("Fenrir agent", r"fenrir"),
    ("Security", r"defender|antivirus|anti-virus|malware|ransomware|canary|firewall|baseline|compliance|cipher|"
                 r"insecure protocol|tls|ssl|smb ?v?1|local admin|admin drift|password|\bmfa\b|laps|\buac\b|"
                 r"vulnerab|wavebrowser|secure settings|security|hardening|audit policy|credential|roboshadow"),
    ("Patching and updates", r"windows update|update cache|wuauserv|\bpatch|hotfix|winget|third-party update|"
                             r"store apps|app store|auto updates?|feature update|\b2\dh2\b|upgrade|\bupdates?\b"),
    ("Software", r"browser cache|install|uninstall|teamviewer|application|\bapps?\b|\bmsi\b|chocolatey|brew\b|office|teams\b|browser"),
    ("Networking", r"\bdns\b|network|\bip\b|ipconfig|wi-?fi|wireless|\bvpn\b|proxy|\bping\b|tracert|netsh|adapter|"
                   r"\bports?\b|dhcp|hosts file|nslookup|connectivity"),
    ("Disk and storage", r"\bdisk\b|cleanup|clean up|temp files|temporary|free space|storage|\bcache\b|recycle|chkdsk|volume"),
    ("Printing", r"print|spooler"),
    ("Services", r"\bservices?\b"),
    ("Performance and power", r"power ?plan|performance|\bcpu\b|memory|\bram\b|startup|xbox|sleep|hibernat|battery|restart|reboot|shut ?down"),
    ("Users and accounts", r"\busers?\b|profile|account|active directory|\bad\b|entra|azure ad|group policy|gpupdate|"
                           r"logged.?on|sign.?in"),
    ("Inventory and reporting", r"inventory|gather intel|intel\b|serial|warranty|hardware|\bbios\b|summary|"
                                r"\breport\b|asset|installed software|system info|\bid\b"),
]

RESPONSE = r"isolat|containment|\berase\b|\bwipe\b|remove[- ]isolation"
CHECK = (r"^\s*check\b|\bid\b|extract|\bexport\b|\bcollect|^\s*report\b|^\s*audit\b|^\s*get[- ]|^\s*list\b|^\s*test\b|status|deep-?dive|drift|summary|"
         r"inventory|gather|\breport\b|\baudit\b|canary|\bscan\b|health|diagnos")
FIX = (r"^\s*fix\b|repair|\breset\b|remediat|resolve|rebuild|\bclear\b|flush|clean ?up|remove .*vulnerab|"
       r"restore(?! point)|recover|unstick|unblock|re-?register")
ACTION_PREFIX = r"^\s*action\b"
CHECK_CATEGORIES = {"diagnostics", "inventory", "monitoring", "reporting"}


def _os(platforms: list[str] | None, text: str) -> str:
    plats = {p for p in (platforms or []) if p in ("windows", "macos", "linux")}
    named = [name for name, pattern in (("macOS", r"\bmac(os)?\b|\bosx\b|filevault|homebrew|\bbrew\b"),
                                       ("Linux", r"\blinux\b|\bubuntu\b|\bdebian\b|\brhel\b|systemd|luks"),
                                       ("Windows", r"\bwindows\b|powershell|registry|\bwinget\b|bitlocker"))
             if re.search(pattern, text, re.I)]
    if len(named) == 1 and (not plats or named[0].lower() in plats):
        return named[0]
    if plats == {"windows"}:
        return "Windows"
    if plats == {"macos"}:
        return "macOS"
    if plats == {"linux"}:
        return "Linux"
    if plats == {"linux", "macos"}:
        return "Linux & macOS"
    if len(plats) == 3:
        return "All platforms"
    return "Windows" if not plats else "All platforms"


def _area(head: str, body: str, current: str) -> str:
    for area, pattern in AREAS:
        if re.search(pattern, head, re.I):
            return area
    # The old single-word category, when it maps cleanly.
    legacy = {"network": "Networking", "networking": "Networking", "security": "Security", "updates": "Patching and updates",
              "patching": "Patching and updates", "disk": "Disk and storage", "maintenance": "Disk and storage",
              "services": "Services", "applications": "Software", "software": "Software", "users": "Users and accounts",
              "performance": "Performance and power", "printers": "Printing", "inventory": "Inventory and reporting",
              "diagnostics": "Inventory and reporting"}
    if current.lower() in legacy:
        return legacy[current.lower()]
    for area, pattern in AREAS:
        if re.search(pattern, body[:6000], re.I):
            return area
    return "General"


_VERBS = (r"(?:turn|enable|disable|start|stop|restart|reboot|lock|cancel|remove|delete|download|install|uninstall|"
          r"set|create|add|warn|message|show|send|run|reset|clear|update|upgrade|deploy|configure|change|kill|block|"
          r"unblock|renew|flush|repair|fix|refresh|clean|encrypt|isolate|erase|wipe|map|rename|move|force|schedule|"
          r"join|push|perform|harden|rotate|grant|revoke|mount|unmount|format|patch)(?:s|es)?|"
          r"empty|empties|apply|applies|copy|copies")
IMPERATIVE = re.compile(rf"^(?:{_VERBS})\b", re.I)
DESCRIBES_CHANGE = re.compile(rf"^(?:{_VERBS})\b|\(changes|changes the system|changes files", re.I)
PREFIX = re.compile(r"^\s*(?:action|check|windows|linux|mac(?:os)?|lismat)\s*[-:]\s*", re.I)


def _kind(name: str, description: str, head: str, area: str, current: str) -> str:
    bare = PREFIX.sub("", name or "").strip()
    if area == "Incident response" or re.search(RESPONSE, head, re.I):
        return "Response"
    if "?" in name or re.search(CHECK, name, re.I) or current.lower() in CHECK_CATEGORIES and not re.search(FIX, name, re.I):
        return "Check"
    changes = bool(IMPERATIVE.match(bare) or DESCRIBES_CHANGE.search(description or "") or re.search(ACTION_PREFIX, name, re.I))
    if re.search(FIX, name, re.I) or re.search(r"cleanup|vulnerab", name, re.I):
        return "Fix"  # what it fixes outranks Level's "Action:" naming
    if not changes and (description or "").strip():
        return "Check"  # a description of what it shows, not of what it does
    if re.search(FIX, head, re.I) and changes:
        return "Fix"
    return "Action"


def classify(name: str, description: str = "", body: str = "", platforms: list[str] | None = None,
             current: str = "") -> dict:
    """{"category": "Linux / Networking / Fix", "os": ..., "area": ..., "kind": ...}"""
    current_leaf = (current or "").split(SEP)[-1].strip() if SEP not in (current or "") else ""
    head = f"{name} {description}"
    os_name = _os(platforms, f"{name} {description}")
    area = _area(head, body or "", current_leaf or (current or ""))
    kind = _kind(name or "", description or "", head, area, current_leaf or (current or ""))
    return {"category": SEP.join([os_name, area, kind]), "os": os_name, "area": area, "kind": kind}


def classify_script(script) -> dict:
    return classify(script.name or "", script.description or "", script.body or "", list(script.platforms or []),
                    script.category or "")
