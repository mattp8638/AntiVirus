"""CVE intelligence: what each CVE is, how bad it is and how likely it is to be exploited, plus which installed
Windows programs are vulnerable.

Sources (all public, fetched in the background and cached in the database):
- NVD (https://services.nvd.nist.gov/rest/json/cves/2.0): description, CVSS score and vector, CWE, references, and
  the product/version ranges each CVE affects (CPE configurations).
- FIRST EPSS (https://api.first.org/data/v1/epss): the probability a CVE is exploited in the next 30 days.
- CISA KEV: CVEs known to be exploited in the wild, with CISA's due date and required action.

Windows programs are matched by name to an NVD product (KNOWN_PRODUCTS) and their installed version is checked
against each CVE's affected range. Nothing here runs in the request path; ``run_once`` is called by a background
thread, and every network call takes an injectable ``httpx.Client`` so tests use fixtures.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from datetime import datetime, timedelta
from typing import Any, Iterable
from urllib.parse import quote

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import CpeMatchCache, CveRecord, Device, DevicePatch, SoftwareItem, Vulnerability, utcnow

log = logging.getLogger("fenrir.cveintel")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_SOURCE = "nvd-cpe"

NVD_REFRESH = timedelta(days=7)
EPSS_REFRESH = timedelta(days=1)
CPE_REFRESH = timedelta(days=1)
KEV_REFRESH = timedelta(hours=12)

# Windows display name (regex, case-insensitive) -> NVD vendor, product, winget package id. Only products whose
# NVD naming is unambiguous: a wrong mapping would report vulnerabilities that aren't there.
KNOWN_PRODUCTS: list[tuple[str, str, str, str]] = [
    (r"^google chrome$", "google", "chrome", "Google.Chrome"),
    (r"^mozilla firefox(?! esr)\b", "mozilla", "firefox", "Mozilla.Firefox"),
    (r"^mozilla firefox esr\b", "mozilla", "firefox_esr", "Mozilla.Firefox.ESR"),
    (r"^mozilla thunderbird\b", "mozilla", "thunderbird", "Mozilla.Thunderbird"),
    (r"^microsoft edge$", "microsoft", "edge_chromium", "Microsoft.Edge"),
    (r"^7-zip\b", "7-zip", "7-zip", "7zip.7zip"),
    (r"^winrar\b", "rarlab", "winrar", "RARLab.WinRAR"),
    (r"^notepad\+\+", "notepad-plus-plus", "notepad\\+\\+", "Notepad++.Notepad++"),
    (r"^vlc media player$", "videolan", "vlc_media_player", "VideoLAN.VLC"),
    (r"^putty release\b", "putty", "putty", "PuTTY.PuTTY"),
    (r"^wireshark\b", "wireshark", "wireshark", "WiresharkFoundation.Wireshark"),
    (r"^python 3\.\d+\.\d+ \((64|32)-bit\)$", "python", "python", ""),
    (r"^node\.js$", "nodejs", "node.js", "OpenJS.NodeJS"),
    (r"^git$", "git-scm", "git", "Git.Git"),
    (r"^filezilla\b(?!.*server)", "filezilla-project", "filezilla_client", "TimKosse.FileZilla.Client"),
    (r"^keepass password safe\b", "keepass", "keepass", "DominikReichl.KeePass"),
    (r"^teamviewer\b", "teamviewer", "teamviewer", "TeamViewer.TeamViewer"),
    (r"^anydesk$", "anydesk", "anydesk", "AnyDeskSoftwareGmbH.AnyDesk"),
    (r"^winscp\b", "winscp", "winscp", "WinSCP.WinSCP"),
    (r"^libreoffice\b", "libreoffice", "libreoffice", "TheDocumentFoundation.LibreOffice"),
    (r"^gimp\b", "gimp", "gimp", "GIMP.GIMP"),
    (r"^zoom( workplace)?( \(64-bit\))?$", "zoom", "meetings", "Zoom.Zoom"),
    (r"^foxit pdf reader\b", "foxit", "pdf_reader", "Foxit.FoxitReader"),
    (r"^adobe acrobat( reader)?( dc)?( \(64-bit\))?$", "adobe", "acrobat_reader_dc", "Adobe.Acrobat.Reader.64-bit"),
    (r"^vmware workstation\b", "vmware", "workstation", "VMware.WorkstationPro"),
    (r"^citrix workspace\b", "citrix", "workspace", "Citrix.Workspace"),
    (r"^slack\b", "slack", "slack", "SlackTechnologies.Slack"),
]
_COMPILED = [(re.compile(pattern, re.I), vendor, product, winget) for pattern, vendor, product, winget in KNOWN_PRODUCTS]


def product_for(name: str) -> tuple[str, str, str] | None:
    """(vendor, product, winget id) for a Windows program's display name, or None if we don't track it."""
    for pattern, vendor, product, winget in _COMPILED:
        if pattern.search(name.strip()):
            return vendor, product, winget
    return None


# --------------------------------------------------------------------------- versions


def _tokens(version: str) -> list[tuple[int, Any]]:
    return [(0, int(t)) if t.isdigit() else (1, t.lower()) for t in re.findall(r"\d+|[A-Za-z]+", version or "")]


def compare_versions(a: str, b: str) -> int:
    """-1, 0 or 1. Numeric parts compare as numbers ("1.10" > "1.9"); missing trailing parts count as zero."""
    ta, tb = _tokens(a), _tokens(b)
    for i in range(max(len(ta), len(tb))):
        x = ta[i] if i < len(ta) else (0, 0)
        y = tb[i] if i < len(tb) else (0, 0)
        if x != y:
            # (0, number) sorts before (1, letters): "1.1.1w" is after "1.1.1", "2.0a" after "2.0".
            return -1 if x < y else 1
    return 0


def in_range(version: str, match: dict) -> bool:
    """Does ``version`` fall in one NVD cpeMatch (exact version in the criteria, or a start/end range)?"""
    parts = str(match.get("criteria") or "").split(":")
    exact = parts[5] if len(parts) > 5 else "*"
    bounds = {k: match.get(k) for k in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding")}
    if exact not in ("*", "-", "") and not any(bounds.values()):
        return compare_versions(version, exact.replace("\\", "")) == 0
    if not any(bounds.values()):
        return False  # "every version" with no bounds is too vague to report
    if bounds["versionStartIncluding"] and compare_versions(version, bounds["versionStartIncluding"]) < 0:
        return False
    if bounds["versionStartExcluding"] and compare_versions(version, bounds["versionStartExcluding"]) <= 0:
        return False
    if bounds["versionEndIncluding"] and compare_versions(version, bounds["versionEndIncluding"]) > 0:
        return False
    if bounds["versionEndExcluding"] and compare_versions(version, bounds["versionEndExcluding"]) >= 0:
        return False
    return True


def describe_range(match: dict) -> str:
    start = match.get("versionStartIncluding") and f"from {match['versionStartIncluding']}" or \
        match.get("versionStartExcluding") and f"after {match['versionStartExcluding']}" or ""
    end = match.get("versionEndExcluding") and f"before {match['versionEndExcluding']}" or \
        match.get("versionEndIncluding") and f"up to {match['versionEndIncluding']}" or ""
    return " ".join(p for p in (start, end) if p) or "this exact version"


# --------------------------------------------------------------------------- NVD


def _headers() -> dict:
    from .config import get_settings

    key = get_settings().nvd_api_key
    return {"apiKey": key} if key else {}


def _pause() -> float:
    """NVD allows 5 requests per 30 s without a key and 50 with one."""
    return 0.7 if _headers() else 6.5


def parse_nvd_cve(item: dict) -> dict:
    cve = item.get("cve") or item
    description = next((d.get("value", "") for d in cve.get("descriptions") or [] if d.get("lang") == "en"), "")
    metrics = cve.get("metrics") or {}
    score = vector = version = severity = None
    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData") or {}
        score, vector, version = data.get("baseScore"), data.get("vectorString"), data.get("version")
        severity = (data.get("baseSeverity") or entry.get("baseSeverity") or "").lower()
        break
    cwe = sorted({d.get("value") for w in cve.get("weaknesses") or [] for d in w.get("description") or []
                  if str(d.get("value", "")).startswith("CWE-")})
    references = [{"url": r.get("url"), "tags": r.get("tags") or []} for r in (cve.get("references") or [])[:40] if r.get("url")]
    published = None
    if cve.get("published"):
        try:
            published = datetime.fromisoformat(str(cve["published"]).replace("Z", "")[:19])
        except ValueError:
            published = None
    return {"id": cve.get("id"), "description": description, "cvss": float(score) if score is not None else None,
            "vector": vector or "", "version": str(version or ""), "severity": severity if severity in {"low", "medium", "high", "critical"} else "",
            "cwe": cwe, "references": references, "published": published,
            "kev": bool(cve.get("cisaExploitAdd")), "kevAdded": cve.get("cisaExploitAdd") or "", "kevDue": cve.get("cisaActionDue") or "",
            "kevAction": cve.get("cisaRequiredAction") or "", "configurations": cve.get("configurations") or []}


def _store_cve(db: Session, parsed: dict) -> CveRecord:
    row = db.get(CveRecord, parsed["id"]) or CveRecord(cve_id=parsed["id"])
    row.description = parsed["description"][:8000]
    row.cvss, row.cvss_vector, row.cvss_version = parsed["cvss"], parsed["vector"][:200], parsed["version"][:8]
    row.severity = parsed["severity"]
    row.cwe, row.references, row.published = parsed["cwe"], parsed["references"], parsed["published"]
    if parsed["kev"]:
        row.kev, row.kev_added, row.kev_due = True, parsed["kevAdded"][:12], parsed["kevDue"][:12]
        row.kev_action = row.kev_action or parsed["kevAction"]
    row.nvd_fetched_at = utcnow()
    db.merge(row)
    return row


def fetch_cves(db: Session, client: httpx.Client, cve_ids: Iterable[str], budget: int, pause: float | None = None) -> int:
    """NVD details for up to ``budget`` CVEs. Returns how many were fetched."""
    done = 0
    for cve_id in cve_ids:
        if done >= budget:
            break
        try:
            response = client.get(NVD_URL, params={"cveId": cve_id}, headers=_headers(), timeout=30)
            if response.status_code in (403, 429):
                log.info("NVD rate limit reached; continuing next cycle")
                break
            response.raise_for_status()
            for item in response.json().get("vulnerabilities") or []:
                _store_cve(db, parse_nvd_cve(item))
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("NVD lookup of %s failed: %s", cve_id, exc)
        done += 1
        db.flush()
        time.sleep(_pause() if pause is None else pause)
    return done


def product_matches(db: Session, client: httpx.Client, vendor: str, product: str, version: str,
                    pause: float | None = None) -> list[dict] | None:
    """CVEs affecting vendor:product at this version: [{"cve", "range", "fixed"}]. Cached for a day; None if NVD
    could not be asked (rate limit or error), so callers don't mark anything fixed on a failed lookup."""
    key = f"{vendor}:{product}:{version}"[:300]
    cached = db.get(CpeMatchCache, key)
    if cached is not None and utcnow() - cached.fetched_at < CPE_REFRESH:
        return list(cached.matches or [])
    match_string = f"cpe:2.3:a:{vendor}:{product}:{version}"
    found: dict[str, dict] = {}
    start = 0
    try:
        while True:
            response = client.get(NVD_URL, params={"virtualMatchString": match_string, "resultsPerPage": 2000, "startIndex": start},
                                  headers=_headers(), timeout=60)
            if response.status_code in (403, 429):
                return None
            response.raise_for_status()
            body = response.json()
            for item in body.get("vulnerabilities") or []:
                parsed = parse_nvd_cve(item)
                hit = _affected(parsed["configurations"], vendor, product, version)
                if hit is not None:
                    found[parsed["id"]] = {"cve": parsed["id"], "range": describe_range(hit),
                                           "fixed": hit.get("versionEndExcluding") or ""}
                    _store_cve(db, parsed)
            start += int(body.get("resultsPerPage") or 0)
            if not body.get("resultsPerPage") or start >= int(body.get("totalResults") or 0) or start >= 10000:
                break
            time.sleep(_pause() if pause is None else pause)
    except (httpx.HTTPError, ValueError) as exc:
        log.warning("NVD product lookup %s failed: %s", match_string, exc)
        return None
    row = cached or CpeMatchCache(key=key)
    row.matches, row.fetched_at = list(found.values()), utcnow()
    db.merge(row)
    db.flush()
    return list(found.values())


def _affected(configurations: list, vendor: str, product: str, version: str) -> dict | None:
    """The vulnerable cpeMatch for this product that covers ``version`` (Windows or any platform), if any."""
    for config in configurations:
        for node in config.get("nodes") or []:
            if node.get("negate"):
                continue
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable"):
                    continue
                parts = str(match.get("criteria") or "").split(":")
                if len(parts) < 6 or parts[2] != "a" or parts[3] != vendor or parts[4] != product:
                    continue
                target = parts[10] if len(parts) > 10 else "*"
                if target not in ("*", "-", "windows"):
                    continue  # e.g. only the macOS or Android build
                if in_range(version, match):
                    return match
    return None


# --------------------------------------------------------------------------- EPSS and KEV


def fetch_epss(db: Session, client: httpx.Client, cve_ids: list[str]) -> int:
    updated = 0
    for start in range(0, len(cve_ids), 80):
        chunk = cve_ids[start:start + 80]
        try:
            response = client.get(EPSS_URL, params={"cve": ",".join(chunk)}, timeout=30)
            response.raise_for_status()
            rows = response.json().get("data") or []
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("EPSS lookup failed: %s", exc)
            break
        seen = set()
        for item in rows:
            cve_id = item.get("cve")
            if not cve_id:
                continue
            record = db.get(CveRecord, cve_id) or CveRecord(cve_id=cve_id)
            try:
                record.epss, record.epss_percentile = float(item.get("epss")), float(item.get("percentile"))
            except (TypeError, ValueError):
                continue
            record.epss_fetched_at = utcnow()
            db.merge(record)
            seen.add(cve_id)
            updated += 1
        for cve_id in set(chunk) - seen:  # no EPSS score yet (new CVE): don't ask again today
            record = db.get(CveRecord, cve_id) or CveRecord(cve_id=cve_id)
            record.epss_fetched_at = utcnow()
            db.merge(record)
        db.flush()
    return updated


def refresh_kev(db: Session, client: httpx.Client) -> int:
    try:
        response = client.get(KEV_URL, timeout=30)
        response.raise_for_status()
        entries = response.json().get("vulnerabilities") or []
    except (httpx.HTTPError, ValueError) as exc:
        log.warning("CISA KEV catalogue unavailable: %s", exc)
        return 0
    existing = {r.cve_id: r for r in db.execute(select(CveRecord).where(CveRecord.cve_id.in_([e.get("cveID") for e in entries]))).scalars()}
    for entry in entries:
        cve_id = entry.get("cveID")
        if not cve_id:
            continue
        row = existing.get(cve_id) or CveRecord(cve_id=cve_id)
        row.kev = True
        row.kev_added, row.kev_due = str(entry.get("dateAdded") or "")[:12], str(entry.get("dueDate") or "")[:12]
        row.kev_ransomware = str(entry.get("knownRansomwareCampaignUse") or "").lower() == "known"
        row.kev_action = str(entry.get("requiredAction") or "")[:2000]
        if not row.description:
            row.description = str(entry.get("shortDescription") or "")[:8000]
        if cve_id not in existing:
            db.add(row)
    db.flush()
    # The vulnerability scanner's in-memory set, used when classifying Windows update CVEs.
    from . import exposure

    exposure._KEV_CACHE = (time.time(), {e.get("cveID") for e in entries if e.get("cveID")})
    return len(entries)


# --------------------------------------------------------------------------- applying intel to vulnerabilities


def apply(db: Session, cve_ids: Iterable[str] | None = None) -> int:
    """Copy CVSS, severity, EPSS and KEV from the CVE records onto every matching vulnerability."""
    query = select(Vulnerability).where(Vulnerability.vuln_id.like("CVE-%"))
    ids = list(cve_ids) if cve_ids is not None else None
    if ids is not None:
        if not ids:
            return 0
        query = query.where(Vulnerability.vuln_id.in_(ids))
    rows = db.execute(query).scalars().all()
    records = {r.cve_id: r for r in db.execute(select(CveRecord).where(CveRecord.cve_id.in_({v.vuln_id for v in rows}))).scalars()}
    changed = 0
    for vuln in rows:
        record = records.get(vuln.vuln_id)
        if record is None:
            continue
        if record.cvss is not None:
            vuln.cvss, vuln.cvss_vector = record.cvss, record.cvss_vector or vuln.cvss_vector
        if record.severity:
            vuln.severity = record.severity
        if record.epss is not None:
            vuln.epss = record.epss
        if record.kev:
            vuln.known_exploited = True
            vuln.severity = "critical"
        if record.description and (not vuln.summary or vuln.summary.startswith(("Addresses", "20"))):
            vuln.summary = record.description[:2000]
        changed += 1
    return changed


def record_view(record: CveRecord | None) -> dict | None:
    if record is None:
        return None
    advisory = next((r["url"] for r in record.references or [] if {"Vendor Advisory", "Patch"} & set(r.get("tags") or [])), None)
    return {"cve": record.cve_id, "description": record.description, "cvss": record.cvss, "vector": record.cvss_vector,
            "cvssVersion": record.cvss_version, "severity": record.severity, "cwe": record.cwe or [],
            "references": (record.references or [])[:15], "advisory": advisory,
            "published": record.published.isoformat() + "Z" if record.published else None,
            "epss": record.epss, "epssPercentile": record.epss_percentile,
            "kev": record.kev, "kevAdded": record.kev_added, "kevDue": record.kev_due, "kevRansomware": record.kev_ransomware,
            "kevAction": record.kev_action, "nvdUrl": f"https://nvd.nist.gov/vuln/detail/{record.cve_id}"}


# --------------------------------------------------------------------------- Windows programs


def scan_windows_software(db: Session, client: httpx.Client, budget: int, pause: float | None = None) -> dict:
    """Match tracked Windows programs against NVD. Each distinct product version is one (cached) NVD query, so a
    fleet of 500 PCs with the same Chrome costs one lookup. Returns counts."""
    from . import vulnmgmt

    items = db.execute(select(SoftwareItem).join(Device, Device.id == SoftwareItem.device_id)
                       .where(Device.platform == "windows", SoftwareItem.version != "")).scalars().all()
    tracked: dict[tuple[str, str, str], list[SoftwareItem]] = {}
    for item in items:
        mapped = product_for(item.name)
        if mapped:
            tracked.setdefault((mapped[0], mapped[1], item.version), []).append(item)
    queried = found = 0
    complete_devices: dict[str, bool] = {}
    scan_started = utcnow()
    for (vendor, product, version), installs in tracked.items():
        cached = db.get(CpeMatchCache, f"{vendor}:{product}:{version}"[:300])
        fresh = cached is not None and utcnow() - cached.fetched_at < CPE_REFRESH
        if not fresh and queried >= budget:
            for install in installs:
                complete_devices[install.device_id] = False
            continue
        if not fresh:
            queried += 1
        matches = product_matches(db, client, vendor, product, version, pause=pause)
        if matches is None:
            for install in installs:
                complete_devices[install.device_id] = False
            continue
        winget = product_for(installs[0].name)[2]
        for install in installs:
            complete_devices.setdefault(install.device_id, True)
            device = db.get(Device, install.device_id)
            if device is None:
                continue
            fixed_versions = [m["fixed"] for m in matches if m.get("fixed")]
            target = max(fixed_versions, key=lambda v: _tokens(v)) if fixed_versions else ""
            patch = db.execute(select(DevicePatch).where(DevicePatch.device_id == device.id, DevicePatch.source == "winget",
                                                         DevicePatch.patch_key == f"winget:{winget}")).scalar_one_or_none() if winget else None
            for match in matches:
                row = db.execute(select(Vulnerability).where(Vulnerability.device_id == device.id, Vulnerability.vuln_id == match["cve"],
                                                             Vulnerability.package == install.name[:300])).scalar_one_or_none()
                is_new = row is None
                if row is None:
                    row = Vulnerability(tenant_id=device.tenant_id, device_id=device.id, vuln_id=match["cve"], package=install.name[:300],
                                        source=NVD_SOURCE, first_seen=utcnow())
                    db.add(row)
                    found += 1
                row.source, row.installed_version = NVD_SOURCE, install.version[:100]
                row.fixed_version = (match.get("fixed") or target)[:100]
                row.evidence = {"kind": "installed-program", "program": install.name, "version": install.version,
                                "publisher": install.vendor or "", "installLocation": install.install_location or "",
                                "installDate": install.install_date or "", "executables": install.executable_paths or [],
                                "matchedAs": f"cpe:2.3:a:{vendor}:{product}", "affectedRange": match.get("range", ""),
                                "detectedBy": "NVD product and version match", "checkedAt": utcnow().isoformat() + "Z"}
                row.fix = {"kind": "update", "ref": target or row.fixed_version, "title":
                           f"Update {install.name} to {target or row.fixed_version} or later" if (target or row.fixed_version)
                           else f"No fixed version of {install.name} is listed yet; check the vendor's advisory",
                           "winget": winget or "", "patchKey": patch.patch_key if patch else "",
                           "available": patch.available_version if patch else ""}
                row.last_seen = utcnow()
                reopened = row.status == "fixed"
                if reopened:
                    row.status, row.verified_at, row.status_changed_at = "open", None, utcnow()
                if is_new or reopened:
                    db.flush()
                    vulnmgmt.record_detection(db, row, reopened)
    # A device whose every tracked program was checked: anything no longer matched has been updated or removed.
    verified = 0
    for device_id, complete in complete_devices.items():
        device = db.get(Device, device_id)
        if complete and device is not None:
            verified += vulnmgmt.verify_after_scan(db, device, scan_started, source=NVD_SOURCE)
    # Devices with no tracked programs left at all (everything uninstalled) are verified too.
    for device in db.execute(select(Device).where(Device.platform == "windows")).scalars():
        if device.id not in complete_devices:
            verified += vulnmgmt.verify_after_scan(db, device, scan_started, source=NVD_SOURCE)
    return {"products": len(tracked), "queried": queried, "found": found, "verifiedFixed": verified}


# --------------------------------------------------------------------------- background loop


_last_kev = 0.0


def run_once(db: Session, client: httpx.Client, pause: float | None = None) -> dict:
    """One background pass: KEV, Windows programs, NVD details for open CVEs, EPSS, then copy onto vulnerabilities."""
    global _last_kev
    keyed = bool(_headers())
    budget = 150 if keyed else 12
    summary: dict[str, Any] = {}
    if time.time() - _last_kev > KEV_REFRESH.total_seconds():
        summary["kev"] = refresh_kev(db, client)
        _last_kev = time.time()
        db.commit()
    summary["programs"] = scan_windows_software(db, client, budget=max(budget // 2, 3), pause=pause)
    db.commit()
    open_cves = sorted({v for (v,) in db.execute(select(Vulnerability.vuln_id).where(
        Vulnerability.vuln_id.like("CVE-%"), Vulnerability.status.in_(("open", "patching", "mitigated", "accepted"))))})
    records = {r.cve_id: r for r in db.execute(select(CveRecord).where(CveRecord.cve_id.in_(open_cves))).scalars()}
    now = utcnow()
    stale = [c for c in open_cves if records.get(c) is None or records[c].nvd_fetched_at is None
             or now - records[c].nvd_fetched_at > NVD_REFRESH]
    summary["nvd"] = fetch_cves(db, client, stale, budget=budget, pause=pause)
    db.commit()
    epss_due = [c for c in open_cves if records.get(c) is None or records[c].epss_fetched_at is None
                or now - records[c].epss_fetched_at > EPSS_REFRESH]
    summary["epss"] = fetch_epss(db, client, epss_due)
    summary["applied"] = apply(db, open_cves)
    from .detection import refresh_risk_scores

    summary["risk"] = refresh_risk_scores(db)
    db.commit()
    return summary


def loop(stop: threading.Event, first_delay: float = 120.0, interval: float = 900.0) -> None:
    """Every 15 minutes, in its own thread (network calls never hold up the main scheduler)."""
    from . import db as database

    delay = first_delay
    while not stop.wait(delay):
        delay = interval
        session = database.session_factory()()
        try:
            with httpx.Client(timeout=60, headers={"User-Agent": "FenrirCloud/1.0 (vulnerability intelligence)"}) as client:
                log.info("vulnerability intelligence: %s", run_once(session, client))
        except Exception as exc:  # noqa: BLE001 - keep the loop alive
            log.warning("vulnerability intelligence pass failed: %s", exc)
            session.rollback()
        finally:
            session.close()
