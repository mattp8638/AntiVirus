"""The community catalogue (repository folder ``catalogue/``): curated apps to deploy and keep updated, and community
scripts for the library. Both are plain files, one per app or script, reviewed in pull requests.

- ``catalogue/apps/<key>.yml``: name, publisher, category, a winget package ID for Windows and optionally a Homebrew
  cask for macOS (both checked against the public winget and Homebrew catalogues in CI), and a ``detect`` pattern that
  matches the installed program's name in inventory.
- ``catalogue/scripts/windows/*.ps1`` and ``catalogue/scripts/unix/*.sh``: scripts with a header of ``# key: value``
  lines (name, description, category, platforms, timeout, and ``param: Name | Label | type | default | required``).
- ``catalogue/MANIFEST.sha256``: a checksum per file. Only files whose checksum matches are loaded, so an edit that
  did not go through review (and the manifest) is ignored, with a warning in the log.

On start-up, apps become built-in Software packages (installed and kept up to date with winget or Homebrew) and
scripts become built-in library scripts; ones already present are left alone, so upgrades add new entries only.
"""

from __future__ import annotations

import hashlib
import logging
import re
from functools import lru_cache
from pathlib import Path

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Script, SoftwarePackage

log = logging.getLogger("fenrir.catalogue")
ROOT = Path(__file__).resolve().parents[2] / "catalogue"
_HEADER = re.compile(r"^#\s*([a-z]+):\s?(.*)$")
_WINGET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._-]*$")
_BREW = re.compile(r"^[a-z0-9][a-z0-9+._@-]*$")
PARAM_TYPES = {"string", "number", "boolean"}


def _manifest(root: Path) -> dict[str, str]:
    path = root / "MANIFEST.sha256"
    if not path.is_file():
        return {}
    out = {}
    for line in path.read_text().splitlines():
        digest, _, name = line.partition("  ")
        if digest and name:
            out[name.strip()] = digest.strip()
    return out


def _verified(root: Path, pattern: str) -> list[Path]:
    manifest = _manifest(root)
    good = []
    for path in sorted(root.glob(pattern)):
        rel = path.relative_to(root).as_posix()
        data = path.read_bytes()
        # A Windows checkout may turn LF into CRLF; the reviewed content is the same, so accept that copy too.
        if manifest.get(rel) not in (hashlib.sha256(data).hexdigest(), hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()):
            log.warning("catalogue: %s does not match MANIFEST.sha256; skipped (run catalogue/manifest.py --write after review)", rel)
            continue
        good.append(path)
    return good


def load_apps(root: Path = ROOT) -> list[dict]:
    apps = []
    for path in _verified(root, "apps/*.yml"):
        try:
            data = yaml.safe_load(path.read_text()) or {}
            winget = str((data.get("windows") or {}).get("winget") or "")
            brew = str((data.get("macos") or {}).get("brew") or "")
            if not data.get("name") or not _WINGET.fullmatch(winget) or (brew and not _BREW.fullmatch(brew)):
                raise ValueError("needs a name and a valid windows.winget (and a valid macos.brew if given)")
            re.compile(str(data.get("detect") or ""))
        except (yaml.YAMLError, ValueError, re.error) as exc:
            log.warning("catalogue: %s is invalid (%s); skipped", path.name, exc)
            continue
        apps.append({"key": path.stem, "name": str(data["name"])[:200], "publisher": str(data.get("publisher") or "")[:200],
                     "category": str(data.get("category") or "")[:60], "winget": winget, "brew": brew,
                     "detect": str(data.get("detect") or "")})
    return apps


def _parse_script(path: Path) -> dict:
    meta: dict[str, object] = {"params": []}
    lines = path.read_text().splitlines()
    for line in lines[:30]:
        match = _HEADER.match(line)
        if not match:
            continue
        key, value = match.group(1), match.group(2).strip()
        if key == "param":
            parts = [p.strip() for p in value.split("|")]
            if len(parts) != 5 or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,40}", parts[0]) or parts[2] not in PARAM_TYPES:
                raise ValueError(f"bad param line: {value}")
            meta["params"].append({"name": parts[0], "label": parts[1][:80], "type": parts[2], "default": parts[3],
                                   "required": parts[4] == "required"})
        elif key in {"name", "description", "category", "platforms", "timeout"}:
            meta[key] = value
    if not meta.get("name") or not meta.get("platforms"):
        raise ValueError("needs # name: and # platforms: header lines")
    platforms = [p.strip() for p in str(meta["platforms"]).split(",") if p.strip()]
    if not platforms or set(platforms) - {"windows", "linux", "macos"}:
        raise ValueError("platforms must be windows, linux and/or macos")
    language = "powershell" if path.suffix == ".ps1" else "bash"
    if (language == "powershell") != (platforms == ["windows"]):
        raise ValueError("PowerShell scripts are for windows; shell scripts for linux/macos")
    timeout = int(str(meta.get("timeout") or "300"))
    if not 10 <= timeout <= 7200:
        raise ValueError("timeout must be 10-7200 seconds")
    return {"name": str(meta["name"])[:200], "description": str(meta.get("description") or "")[:500],
            "category": str(meta.get("category") or "Community")[:60], "platforms": platforms, "language": language,
            "timeout_seconds": timeout, "parameters": meta["params"], "body": path.read_text()}


def load_scripts(root: Path = ROOT) -> list[dict]:
    scripts, names = [], set()
    for path in _verified(root, "scripts/windows/*.ps1") + _verified(root, "scripts/unix/*.sh"):
        try:
            item = _parse_script(path)
        except (ValueError, OSError) as exc:
            log.warning("catalogue: %s is invalid (%s); skipped", path.name, exc)
            continue
        if item["name"] in names:
            log.warning("catalogue: %s repeats the script name %r; skipped", path.name, item["name"])
            continue
        names.add(item["name"])
        scripts.append(item)
    return scripts


@lru_cache(maxsize=1)
def _cached(root: Path = ROOT) -> tuple[list[dict], list[dict]]:
    return load_apps(root), load_scripts(root)


def seed(db: Session, root: Path = ROOT) -> dict:
    """Add catalogue apps and scripts that are not there yet. Never changes or removes existing rows."""
    apps, scripts = (load_apps(root), load_scripts(root)) if root != ROOT else _cached()
    existing = {(i, ident) for i, ident in db.execute(select(SoftwarePackage.installer, SoftwarePackage.identifier)
                                                       .where(SoftwarePackage.tenant_id.is_(None))).all()}
    added_apps = 0
    for app in apps:
        for platform, installer, identifier in (("windows", "winget", app["winget"]), ("macos", "brew", app["brew"])):
            if not identifier or (installer, identifier) in existing:
                continue
            db.add(SoftwarePackage(tenant_id=None, builtin=True, name=app["name"], publisher=app["publisher"], platform=platform,
                                   installer=installer, identifier=identifier, keep_updated=True))
            existing.add((installer, identifier))
            added_apps += 1
    present = {name for (name,) in db.execute(select(Script.name).where(Script.tenant_id.is_(None))).all()}
    added_scripts = 0
    for item in scripts:
        if item["name"] in present:
            continue
        from .script_taxonomy import classify

        filed = {**item, "category": classify(item["name"], item["description"], item["body"], item["platforms"],
                                              item["category"])["category"]}
        db.add(Script(tenant_id=None, builtin=True, updated_by="catalogue", **filed))
        added_scripts += 1
    if added_apps or added_scripts:
        log.info("catalogue: added %d software packages and %d scripts", added_apps, added_scripts)
    return {"apps": added_apps, "scripts": added_scripts}


def match(app_name: str) -> dict | None:
    """The catalogue app an installed program's name belongs to, if any (for inventory and patching views)."""
    for app in _cached()[0]:
        if app["detect"] and re.search(app["detect"], app_name or ""):
            return app
    return None
