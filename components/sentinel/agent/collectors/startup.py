from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List

from collectors.registry import collect_registry_autoruns


def _startup_directories() -> List[Path]:
    paths: List[Path] = []
    userprofile = os.environ.get("USERPROFILE")
    appdata = os.environ.get("APPDATA")
    programdata = os.environ.get("PROGRAMDATA")
    if userprofile:
        paths.append(Path(userprofile) / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
    if appdata:
        paths.append(Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
    if programdata:
        paths.append(Path(programdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
    return paths


def collect_startup_items() -> Dict[str, Any]:
    folders: List[Dict[str, Any]] = []
    for directory in _startup_directories():
        if not directory.exists():
            continue
        entries: List[Dict[str, Any]] = []
        try:
            for item in directory.iterdir():
                try:
                    entries.append({
                        "name": item.name,
                        "path": str(item),
                        "is_file": item.is_file(),
                        "is_dir": item.is_dir(),
                        "size": item.stat().st_size if item.is_file() else None,
                    })
                except Exception:
                    continue
        except Exception:
            continue
        folders.append({"path": str(directory), "entries": entries})
    return {
        "folders": folders,
        "registry_autoruns": collect_registry_autoruns(),
    }