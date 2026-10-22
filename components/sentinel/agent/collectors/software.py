from __future__ import annotations

import winreg
from typing import Any, Dict, List


UNINSTALL_ROOTS = [
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
]


def _iter_key_values(root: int, path: str) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    try:
        key = winreg.OpenKey(root, path)
    except OSError:
        return results

    try:
        subkey_count = winreg.QueryInfoKey(key)[0]
        for index in range(subkey_count):
            try:
                subkey_name = winreg.EnumKey(key, index)
                subkey = winreg.OpenKey(key, subkey_name)
                entry: Dict[str, Any] = {}
                for value_name in ("DisplayName", "DisplayVersion", "Publisher", "InstallLocation", "InstallDate"):
                    try:
                        entry[value_name] = winreg.QueryValueEx(subkey, value_name)[0]
                    except OSError:
                        continue
                if entry.get("DisplayName"):
                    entry["source"] = f"{path}\\{subkey_name}"
                    results.append(entry)
            except OSError:
                continue
    finally:
        try:
            winreg.CloseKey(key)
        except Exception:
            pass
    return results


def collect_installed_software() -> List[Dict[str, Any]]:
    inventory: List[Dict[str, Any]] = []
    for root, path in UNINSTALL_ROOTS:
        inventory.extend(_iter_key_values(root, path))
    return inventory