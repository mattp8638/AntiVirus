"""CVE intelligence end to end, with NVD / EPSS / CISA KEV answered by fixtures (httpx.MockTransport)."""

import json

import httpx

from fenrir_cloud import cveintel, db as database, rmm
from fenrir_cloud.models import CveRecord, Device, SoftwareItem, Vulnerability

WIN_CVE = "CVE-2030-1111"
ZIP_CVE = "CVE-2024-11477"
OLD_ZIP_CVE = "CVE-2016-2335"


def nvd_item(cve_id, score, vector, severity, description, configurations=None, kev=False):
    item = {"cve": {"id": cve_id, "published": "2024-11-22T21:15:08.613", "descriptions": [{"lang": "en", "value": description}],
                    "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"version": "3.1", "vectorString": vector,
                                                                                     "baseScore": score, "baseSeverity": severity}}]},
                    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-191"}]}],
                    "references": [{"url": f"https://example.test/{cve_id}", "tags": ["Vendor Advisory"]}],
                    "configurations": configurations or []}}
    if kev:
        item["cve"].update({"cisaExploitAdd": "2030-01-10", "cisaActionDue": "2030-01-31", "cisaRequiredAction": "Apply updates."})
    return item


ZIP_CONFIG = [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [
    {"vulnerable": True, "criteria": "cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*", "versionEndExcluding": "24.07"}]}]}]
OLD_ZIP_CONFIG = [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [
    {"vulnerable": True, "criteria": "cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*", "versionEndIncluding": "15.14"}]}]}]

calls: list[str] = []


def handler(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    calls.append(url)
    if "first.org" in url:
        cves = request.url.params["cve"].split(",")
        data = [{"cve": c, "epss": "0.91234" if c == WIN_CVE else "0.00420", "percentile": "0.99", "date": "2030-01-20"} for c in cves]
        return httpx.Response(200, json={"status": "OK", "data": data})
    if "cisa.gov" in url:
        return httpx.Response(200, json={"vulnerabilities": [{"cveID": WIN_CVE, "dateAdded": "2030-01-10", "dueDate": "2030-01-31",
                                                              "requiredAction": "Apply mitigations per vendor instructions.",
                                                              "knownRansomwareCampaignUse": "Known", "shortDescription": "Windows flaw"}]})
    if "virtualMatchString" in url:
        # NVD may or may not pre-filter by version; return an unaffected CVE too, which must be ignored.
        assert request.url.params["virtualMatchString"] == "cpe:2.3:a:7-zip:7-zip:23.01"
        return httpx.Response(200, json={"resultsPerPage": 2, "startIndex": 0, "totalResults": 2, "vulnerabilities": [
            nvd_item(ZIP_CVE, 7.0, "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "HIGH",
                     "7-Zip Zstandard decompression integer underflow remote code execution", ZIP_CONFIG),
            nvd_item(OLD_ZIP_CVE, 7.8, "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "HIGH", "Old 7-Zip bug", OLD_ZIP_CONFIG)]})
    if "cveId" in url:
        cve_id = request.url.params["cveId"]
        return httpx.Response(200, json={"vulnerabilities": [nvd_item(cve_id, 8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                                                                       "HIGH", "Windows Kernel elevation of privilege", kev=True)]})
    return httpx.Response(404)


def test_parse_and_ranges():
    parsed = cveintel.parse_nvd_cve(nvd_item(ZIP_CVE, 7.0, "CVSS:3.1/AV:L", "HIGH", "x", ZIP_CONFIG))
    assert parsed["cvss"] == 7.0 and parsed["severity"] == "high" and parsed["cwe"] == ["CWE-191"]
    assert cveintel._affected(ZIP_CONFIG, "7-zip", "7-zip", "23.01")["versionEndExcluding"] == "24.07"
    assert cveintel._affected(ZIP_CONFIG, "7-zip", "7-zip", "24.07") is None
    assert cveintel._affected(OLD_ZIP_CONFIG, "7-zip", "7-zip", "23.01") is None


def test_full_pass(client, admin, device, monkeypatch):
    from fenrir_cloud import exposure

    monkeypatch.setattr(exposure, "_KEV_CACHE", exposure._KEV_CACHE)  # refresh_kev replaces it; restore after
    session = database.session_factory()()
    transport = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        row = session.get(Device, device["deviceId"])
        rmm.ingest_patch_scan(session, row, {"patches": [
            {"id": "KB5050001", "title": "2030-01 Cumulative Update for Windows 11", "classification": "Security Updates",
             "severity": "Important", "source": "windows-update", "cves": WIN_CVE}]})
        session.add(SoftwareItem(tenant_id=row.tenant_id, device_id=row.id, name="7-Zip 23.01 (x64)", version="23.01",
                                 vendor="Igor Pavlov", ecosystem="windows", install_location="C:\\Program Files\\7-Zip\\",
                                 executable_paths=["C:\\Program Files\\7-Zip\\7zFM.exe"]))
        session.commit()
        cveintel._last_kev = 0.0
        summary = cveintel.run_once(session, transport, pause=0)
        session.commit()
        assert summary["programs"]["found"] == 1

        win = session.query(Vulnerability).filter_by(device_id=row.id, vuln_id=WIN_CVE).one()
        assert win.cvss == 8.8 and win.known_exploited and win.severity == "critical" and win.epss > 0.9
        assert win.fix["ref"] == "KB5050001" and win.summary.startswith("Windows Kernel")
        record = session.get(CveRecord, WIN_CVE)
        assert record.kev and record.kev_ransomware and record.kev_due == "2030-01-31"

        zipv = session.query(Vulnerability).filter_by(device_id=row.id, vuln_id=ZIP_CVE).one()
        assert zipv.source == "nvd-cpe" and zipv.fixed_version == "24.07" and zipv.epss is not None
        assert zipv.evidence["installLocation"] == "C:\\Program Files\\7-Zip\\" and zipv.evidence["affectedRange"] == "before 24.07"
        assert zipv.fix["winget"] == "7zip.7zip" and "24.07" in zipv.fix["title"]
        assert not session.query(Vulnerability).filter_by(device_id=row.id, vuln_id=OLD_ZIP_CVE).count()

        # The risk score now counts the vulnerabilities, worst first.
        session.refresh(row)
        assert row.risk_score >= 30

        # A second pass uses the cache: no new NVD product query.
        before = sum("virtualMatchString" in c for c in calls)
        cveintel.run_once(session, transport, pause=0)
        assert sum("virtualMatchString" in c for c in calls) == before

        # Upgrading 7-Zip: the program check verifies the finding fixed.
        item = session.query(SoftwareItem).filter_by(device_id=row.id).one()
        item.version = "24.08"
        session.commit()
        original = handler
        cveintel.run_once(session, httpx.Client(transport=httpx.MockTransport(
            lambda r: httpx.Response(200, json={"resultsPerPage": 0, "totalResults": 0, "vulnerabilities": []})
            if "virtualMatchString" in str(r.url) else original(r))), pause=0)
        session.commit()
        assert session.query(Vulnerability).filter_by(device_id=row.id, vuln_id=ZIP_CVE).one().status == "fixed"
    finally:
        transport.close()
        session.close()

    detail = client.get(f"/api/console/devices/{device['deviceId']}", headers=admin).json()
    assert detail["risk"]["score"] == detail["device"]["riskScore"]
    vulns = detail["vulnerabilities"]
    assert vulns[0]["vulnId"] == WIN_CVE and vulns[0]["intel"]["kev"] and vulns[0]["riskScore"] == 10.0
    assert any("CISA KEV" in r for r in vulns[0]["reasons"])
    cve = client.get(f"/api/console/vulnerabilities/cve/{WIN_CVE}", headers=admin).json()
    assert cve["intel"]["cvss"] == 8.8 and cve["affected"][0]["fix"]["catalog"].endswith("KB5050001")
    listing = client.get("/api/console/vulnerabilities", headers=admin).json()
    entry = next(e for e in listing if e["vulnId"] == WIN_CVE)
    assert entry["epss"] > 0.9 and entry["devices"][0]["evidence"]["kind"] == "missing-update"
    assert json.dumps(entry)  # serialisable
