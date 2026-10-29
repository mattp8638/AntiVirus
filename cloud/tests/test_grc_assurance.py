"""Continuous GRC: crosswalk, propagation, automated evidence and drift, endpoint baselines, third-party risk."""

import re
from datetime import timedelta

import httpx
import pytest

from conftest import enroll
from fenrir_cloud import condition_remediation, grc_automation, grc_baselines, grcprogramme, tprm
from fenrir_cloud.db import session_factory
from fenrir_cloud.models import (ConditionPackage, ConditionResult, GrcEvidence, GrcEvidenceLink, GrcRequirementState, Ticket, Vendor,
                                 utcnow)

BASE = "/api/console/grc-assurance"


def adopt(client, admin, tenant, *keys):
    for key in keys:
        response = client.post("/api/console/grc/programmes", headers=admin,
                               json={"tenantId": tenant["id"], "frameworkKey": key, "createPolicies": False})
        assert response.status_code == 200, response.text


def test_crosswalk_maps_only_real_requirements_and_every_signal_exists():
    frameworks = grcprogramme.builtin_frameworks(include_retired=True)
    known_signals = set(grc_automation.COMPLIANCE_SIGNALS) | {"m365-mfa", "backup", "policies-approved", "third-party-risk"}
    for control in grc_automation.crosswalk():
        for key, ids in control["maps"].items():
            assert key in frameworks, (control["id"], key)
            assert set(ids) <= {r["id"] for r in grcprogramme.requirements(frameworks[key])}, (control["id"], key)
        for signal in control["signals"]:
            assert signal in known_signals or signal.startswith("baseline:"), signal
    controls = {b.get("control") for b in condition_remediation.BUILTIN if b.get("control")}
    assert controls <= {c["id"] for c in grc_automation.crosswalk()}


def test_implemented_once_counts_across_frameworks(client, admin, tenant):
    adopt(client, admin, tenant, "cyber-essentials", "iso-27001", "cis-v8-ig1")
    evidence = client.post("/api/console/grc/evidence", headers=admin, json={
        "tenantId": tenant["id"], "title": "MFA conditional access policy", "kind": "note", "description": "Report-only then enforced",
        "links": ["cyber-essentials:A7.11"]}).json()
    client.patch(f"/api/console/grc/programmes/{tenant['id']}/cyber-essentials/requirements/A7.11", headers=admin,
                 json={"status": "implemented"})
    result = client.post(f"{BASE}/crosswalk/propagate", headers=admin,
                         json={"tenantId": tenant["id"], "framework": "cyber-essentials", "requirementId": "A7.11"}).json()
    updated = {(u["framework"], u["requirementId"]) for u in result["updated"]}
    assert ("iso-27001", "A.8.5") in updated and ("cis-v8-ig1", "6.3") in updated
    assert not any(f == "pci-dss" for f, _ in updated)  # not adopted
    with session_factory()() as db:
        state = db.query(GrcRequirementState).filter_by(tenant_id=tenant["id"], framework_key="iso-27001", requirement_id="A.8.5").one()
        assert state.status == "implemented" and "FC-MFA" in state.notes
        assert db.query(GrcEvidenceLink).filter_by(evidence_id=evidence["id"], framework_key="iso-27001", requirement_id="A.8.5").count() == 1
    mfa = next(c for c in client.get(f"{BASE}/crosswalk", headers=admin, params={"tenant_id": tenant["id"]}).json() if c["id"] == "FC-MFA")
    assert mfa["automated"] == "manual" and mfa["adoptedRequirements"] > 3
    assert client.post(f"{BASE}/crosswalk/propagate", headers=admin,
                       json={"tenantId": tenant["id"], "framework": "iso-27001", "requirementId": "A.5.1"}).status_code == 422


def test_automated_evidence_and_compliance_drift(client, admin, tenant):
    enroll(client, admin, tenant, hostname="ACME-GRC-1", serial="G1")
    adopt(client, admin, tenant, "cyber-essentials", "iso-27001")
    first = client.post(f"{BASE}/automation/{tenant['id']}/collect", headers=admin).json()
    assert "FC-MALWARE" in first["evidenceCreated"] and "FC-ASSET" in first["evidenceCreated"] and first["drift"] == []
    with session_factory()() as db:
        row = db.query(GrcEvidence).filter_by(tenant_id=tenant["id"], kind="automated", control_id="FC-MALWARE").one()
        assert row.data["signals"]["malware-protection"]["passed"] is True and len(row.sha256) == 64
        links = {(l.framework_key, l.requirement_id) for l in db.query(GrcEvidenceLink).filter_by(evidence_id=row.id)}
        assert ("cyber-essentials", "A8.1") in links and ("iso-27001", "A.8.7") in links and not any(f == "pci-dss" for f, _ in links)
    with session_factory()() as db:
        from fenrir_cloud.models import Tenant

        assert grc_automation.collect(db, db.get(Tenant, tenant["id"]))["evidenceCreated"] == []  # nothing changed
        db.commit()

    # Real-time protection is switched off: the control drifts, a ticket opens and new evidence records the failure.
    response = client.put(f"/api/console/policies/{tenant['defaultPolicyId']}", headers=admin,
                          json={"settings": {"antimalware": {"realtimeProtection": False}}})
    assert response.status_code == 200, response.text
    second = client.post(f"{BASE}/automation/{tenant['id']}/collect", headers=admin).json()
    assert "malware-protection" in second["drift"] and "FC-MALWARE" in second["evidenceCreated"]
    with session_factory()() as db:
        assert db.query(Ticket).filter(Ticket.subject.like("Compliance drift: Malware protection%")).count() == 1
    view = client.get(f"{BASE}/automation", headers=admin, params={"tenant_id": tenant["id"]}).json()
    assert view["signals"]["malware-protection"]["passed"] is False
    assert view["evidence"][0]["status"] in ("failing", "passing")


def test_baseline_enforcement_and_signal(client, admin, tenant):
    device = enroll(client, admin, tenant, hostname="ACME-BL-1", serial="BL1")
    response = client.put(f"{BASE}/baselines/windows-workstation/{tenant['id']}", headers=admin, json={"mode": "enforce"})
    assert response.status_code == 200, response.text
    with session_factory()() as db:
        packages = {p.builtin_key: p for p in db.query(ConditionPackage).filter_by(tenant_id=tenant["id"])}
        assert set(grc_baselines.BASELINES["windows-workstation"]["packages"]) <= set(packages)
        assert packages["win-smb1"].enabled and packages["win-smb1"].auto_remediate
        assert packages["win-bitlocker"].remediation_script == ""  # detection only
        db.add(ConditionResult(tenant_id=tenant["id"], package_id=packages["win-smb1"].id, device_id=device["deviceId"], status="remediated"))
        db.add(ConditionResult(tenant_id=tenant["id"], package_id=packages["win-llmnr"].id, device_id=device["deviceId"], status="failed"))
        db.commit()
    report = client.get(f"{BASE}/baselines", headers=admin, params={"tenant_id": tenant["id"]}).json()["report"][0]
    row = report["devices"][0]
    assert row["items"]["win-smb1"] == "remediated" and row["items"]["win-llmnr"] == "failed" and not row["compliant"]
    assert report["mode"] == "enforce" and report["compliance"] == 0
    with session_factory()() as db:
        from fenrir_cloud.models import Tenant

        signal = grc_baselines.signal(db, db.get(Tenant, tenant["id"]), "FC-SECURECONFIG")
        assert signal["passed"] is False and any("devices compliant" in e for e in signal["evidence"])
        assert grc_baselines.signal(db, db.get(Tenant, tenant["id"]), "FC-SCREENLOCK")["passed"] is None  # not reported yet
    assert client.delete(f"{BASE}/baselines/windows-workstation/{tenant['id']}", headers=admin).status_code == 200
    with session_factory()() as db:
        assert not db.query(ConditionPackage).filter_by(tenant_id=tenant["id"], builtin_key="win-smb1").one().enabled


class FakeInternet:
    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.url.host == "cloudflare-dns.com":
            name = request.url.params["name"]
            if name == "acme-payroll.test":
                return httpx.Response(200, json={"Answer": [{"type": 16, "data": '"v=spf1 include:_spf.example -all"'}]})
            return httpx.Response(200, json={"Answer": [{"type": 16, "data": '"v=DMARC1; p=none; rua=mailto:d@acme-payroll.test"'}]})
        if request.url.host == "haveibeenpwned.com":
            return httpx.Response(200, json=[{"Name": "AcmePayroll", "BreachDate": (utcnow() - timedelta(days=200)).date().isoformat(),
                                              "PwnCount": 12000, "DataClasses": ["Email addresses", "Passwords"]}])
        if request.url.path == "/.well-known/security.txt":
            return httpx.Response(404)
        return httpx.Response(200, headers={"strict-transport-security": "max-age=31536000"}, text="ok")


@pytest.fixture
def internet(monkeypatch):
    monkeypatch.setattr(tprm, "http_client", lambda: httpx.Client(transport=httpx.MockTransport(FakeInternet())))
    monkeypatch.setattr(tprm, "tls_certificate", lambda domain: {"valid": True, "daysLeft": 200, "expiresAt": "2027-05-01T00:00:00Z"})
    monkeypatch.setattr(tprm, "resolves_publicly", lambda domain: domain == "acme-payroll.test")


def test_posture_scan_refuses_internal_targets():
    for domain in ("localhost", "10.0.0.5", "169.254.169.254", "intranet", "printer.local."):
        assert not tprm.resolves_publicly(domain), domain


def test_supplier_questionnaire_scan_and_review(client, admin, tenant, internet):
    vendor = client.post(f"{BASE}/vendors", headers=admin, json={
        "tenantId": tenant["id"], "name": "Acme Payroll", "domain": "https://acme-payroll.test/", "criticality": "critical",
        "dataAccess": "personal", "contactEmail": "security@acme-payroll.test", "services": "Payroll"}).json()
    assert vendor["domain"] == "acme-payroll.test" and vendor["inherentRisk"] == 85 and vendor["riskTier"] == "critical"

    scanned = client.post(f"{BASE}/vendors/{vendor['id']}/scan", headers=admin).json()
    checks = scanned["posture"]["checks"]
    assert checks["spf"] is True and checks["dmarc"] == "none" and checks["hsts"] is True and checks["breaches"][0]["name"] == "AcmePayroll"
    assert scanned["postureScore"] == 100 - 8 - 2 - 15  # DMARC monitor-only, no security.txt, one recent breach

    sent = client.post(f"{BASE}/vendors/{vendor['id']}/assessments", headers=admin, json={}).json()
    token = sent["link"].rsplit("/", 1)[1]
    page = client.get(f"/vendor-assessment/{token}")
    assert page.status_code == 200 and "multi-factor authentication" in page.text and "Acme Dental" in page.text
    incomplete = client.post(f"/vendor-assessment/{token}", content="acc-mfa=yes", headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert incomplete.status_code == 422
    form = "&".join(f"{q['id']}={'no' if q['id'] == 'acc-mfa' else 'yes'}" for q in tprm.QUESTIONS) + "&acc-mfa-comment=Rolling+out+in+Q1"
    done = client.post(f"/vendor-assessment/{token}", content=form, headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert done.status_code == 200 and "Thank you" in done.text
    assert client.get(f"/vendor-assessment/{token}").status_code == 404  # single use

    after = next(v for v in client.get(f"{BASE}/vendors", headers=admin, params={"tenant_id": tenant["id"]}).json() if v["id"] == vendor["id"])
    weights = sum(q["weight"] for q in tprm.QUESTIONS)
    assert after["questionnaireScore"] == round(100 * (weights - 3) / weights) and after["riskTier"] in ("low", "medium")
    assessment = client.get(f"{BASE}/vendors/{vendor['id']}/assessments", headers=admin).json()[0]
    assert assessment["findings"][0]["question"] == "acc-mfa" and assessment["findings"][0]["severity"] == "high"
    assert assessment["findings"][0]["comment"] == "Rolling out in Q1"

    with session_factory()() as db:
        from fenrir_cloud.models import Tenant

        assert tprm.signal(db, db.get(Tenant, tenant["id"]))["passed"] is True
        row = db.get(Vendor, vendor["id"])
        row.next_review_at = utcnow() - timedelta(days=1)
        row.documents = [{"type": "ISO 27001 certificate", "name": "Cert 2024", "expiresAt": (utcnow() - timedelta(days=2)).isoformat()}]
        db.commit()
        tprm.tick(db)
        assert db.query(Ticket).filter(Ticket.subject == "Supplier review due: Acme Payroll").count() == 1
        assert db.query(Ticket).filter(Ticket.subject == "Supplier documents expiring: Acme Payroll").count() == 1
        tprm.tick(db)  # no duplicates
        assert db.query(Ticket).filter(Ticket.subject.like("Supplier%Acme Payroll")).count() == 2
        signal = tprm.signal(db, db.get(Tenant, tenant["id"]))
        assert signal["passed"] is False and any("expired" in e for e in signal["evidence"])
        # The review re-sent the questionnaire to the supplier.
        assert re.search("sent", str([a.status for a in db.query(tprm.VendorAssessment).filter_by(vendor_id=vendor["id"])]))
