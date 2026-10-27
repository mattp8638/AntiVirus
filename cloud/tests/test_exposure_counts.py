"""FIX-04 / AT-07: starting remediation, mitigating or accepting a risk is not a fix.

Before the fix, moving a still-present critical KEV to "patching" made the compliance "no KEV" check pass."""

from datetime import timedelta

import pytest

from conftest import enroll
from fenrir_cloud.db import session_factory
from fenrir_cloud.models import Device, Vulnerability, utcnow


def check(client, admin, tenant, framework, control):
    report = client.get("/api/console/compliance", headers=admin, params={"tenant_id": tenant["id"], "framework": framework}).json()
    ctl = next(c for c in report["frameworks"][0]["controls"] if c["id"] == control)
    return ctl["passed"], " ".join(ctl["evidence"])


@pytest.fixture()
def kev(client, admin, tenant):
    device = enroll(client, admin, tenant, hostname="KEV-PC", serial="K-1")
    db = session_factory()()
    try:
        row = Vulnerability(tenant_id=tenant["id"], device_id=device["deviceId"], vuln_id="CVE-2024-3400", package="PAN-OS",
                            status="open", severity="critical", known_exploited=True, cvss=10.0, first_seen=utcnow(), last_seen=utcnow())
        db.add(row)
        db.commit()
        return row.id, device["deviceId"]
    finally:
        db.close()


def device_risk(device_id):
    from fenrir_cloud import detection

    db = session_factory()()
    try:
        return detection.risk_breakdown(db, db.get(Device, device_id))["score"]
    finally:
        db.close()


def test_treatment_states_still_count_as_exposure(client, admin, tenant, kev):
    vuln_id, device_id = kev
    assert check(client, admin, tenant, "cis-v8-ig1", "CIS-7")[0] is False
    dashboard = client.get("/api/console/dashboard", headers=admin, params={"tenant_id": tenant["id"]}).json()["vulnerabilities"]
    baseline_risk = device_risk(device_id)

    for status, extra, words in (("patching", {}, "being patched"),
                                 ("mitigated", {}, "mitigated, not fixed"),
                                 ("accepted", {"reason": "Vendor fix next month; port closed at the firewall",
                                               "expiresAt": (utcnow() + timedelta(days=30)).isoformat() + "Z"}, "risk-accepted, not fixed")):
        reply = client.patch(f"/api/console/vulnerabilities/{vuln_id}", headers=admin, json={"status": status, **extra})
        assert reply.status_code == 200, reply.text
        passed, evidence = check(client, admin, tenant, "cis-v8-ig1", "CIS-7")
        assert passed is False and "1 known-exploited" in evidence and words in evidence, (status, evidence)
        assert check(client, admin, tenant, "cyber-essentials", "CE-5")[0] is False  # 1 critical not verified fixed
        now = client.get("/api/console/dashboard", headers=admin, params={"tenant_id": tenant["id"]}).json()["vulnerabilities"]
        assert now == dashboard, status
        report = client.get("/api/console/reports/executive", headers=admin, params={"tenant_id": tenant["id"]}).json()
        assert report["vulnerabilityTreatment"] == {status: 1} and report["openVulnerabilities"] == {"critical": 1}
        risk = device_risk(device_id)
        assert risk > 0 and (risk == baseline_risk if status != "mitigated" else risk < baseline_risk), (status, risk)


def test_only_a_verified_fix_clears_the_check(client, admin, tenant, kev):
    vuln_id, _ = kev
    assert client.patch(f"/api/console/vulnerabilities/{vuln_id}", headers=admin, json={"status": "fixed"}).status_code == 400
    db = session_factory()()
    try:
        row = db.get(Vulnerability, vuln_id)
        row.status, row.verified_at = "fixed", utcnow()  # what a complete rescan does
        db.commit()
    finally:
        db.close()
    passed, evidence = check(client, admin, tenant, "cis-v8-ig1", "CIS-7")
    assert "0 known-exploited" in evidence
