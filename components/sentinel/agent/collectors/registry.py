try:
    import winreg
except ImportError:  # Non-Windows agents can still import the collector package.
    winreg = None

AUTORUN_KEYS = []
if winreg is not None:
    AUTORUN_KEYS = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]


def _read_values(root, path):
    values = []
    try:
        key = winreg.OpenKey(root, path)
        index = 0
        while True:
            try:
                name, value, value_type = winreg.EnumValue(key, index)
                values.append({"path": path, "name": name, "value": str(value), "type": value_type})
                index += 1
            except OSError:
                break
    except OSError:
        pass
    return values


def collect_registry_autoruns():
    if winreg is None:
        return []
    autoruns = []
    for root, path in AUTORUN_KEYS:
        autoruns.extend(_read_values(root, path))
    return autoruns
