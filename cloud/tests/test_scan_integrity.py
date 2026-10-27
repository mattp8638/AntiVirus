"""FIX-02 / AT-06: a vulnerability scan that did not complete must never verify a finding fixed.

Each case starts from one open finding (openssl on an Ubuntu server), then rescans with OSV misbehaving. The finding
must stay open (and its remediation ticket unresolved) unless OSV fully answered for that package."""

import httpx
import pytest

from conftest import enroll
from fenrir_cloud import events, exposure, vulnmgmt
from fenrir_cloud.db import session_factory
from fenrir_cloud.models import Device, SoftwareItem, Ticket, Vulnerability, VulnScan, utcnow
from test_vulnmgmt import _inventory, _scan


def _rescan(device_id, batch, query=None, detail=None):
    def handler(request: httpx.Request):
        if request.url.path == "/v1/querybatch":
            return batch(request)
        if request.url.path == "/v1/query":
            return query(request) if query else httpx.Response(500)
        if "known_exploited" in str(request.url):
            return httpx.Response(503)
        return detail(request) if detail else httpx.Response(200, json={"id": "X", "aliases": []})

    db = session_factory()()
    try:
        result = exposure.scan_device(db, db.get(Device, device_id), client=httpx.Client(transport=httpx.MockTransport(handler)))
        db.commit()
        events.process(db)
        db.commit()
        return result
    finally:
        db.close()


def _finding(device_id):
    db = session_factory()()
    try:
        row = db.query(Vulnerability).filter(Vulnerability.device_id == device_id).one()
        ticket = db.get(Ticket, row.ticket_id) if row.ticket_id else None
        return row.status, row.verified_at, ticket.status if ticket else None, row.severity
    finally:
        db.close()


@pytest.fixture()
def vulnerable_server(client, admin, tenant):
    exposure._KEV_CACHE = (0.0, set())
    device = enroll(client, admin, tenant, hostname="SCAN-SRV", os_version="Ubuntu 22.04.4 LTS", serial="SI-1")
    _inventory(client, device, [{"name": "openssl", "version": "3.0.2-0ubuntu1.10"}])
    assert _scan(device["deviceId"])["found"] == 1
    # A remediation ticket, so a false fix would also wrongly resolve it.
    db = session_factory()()
    try:
        vulnmgmt.open_remediation_ticket(db, db.query(Vulnerability).filter(Vulnerability.device_id == device["deviceId"]).all(), "test")
        db.commit()
    finally:
        db.close()
    # The package is "updated" in inventory, so a real complete clean answer would verify the fix.
    _inventory(client, device, [{"name": "openssl", "version": "3.0.2-0ubuntu1.14"}])
    return device["deviceId"]


FAILURES = {
    "http 503 with error body": lambda r: httpx.Response(503, json={"code": 14, "message": "unavailable"}),
    "http 429": lambda r: httpx.Response(429, json={"message": "rate limited"}),
    "invalid json": lambda r: httpx.Response(200, content=b"<html>proxy error</html>"),
    "error object with 200": lambda r: httpx.Response(200, json={"code": 3, "message": "invalid query"}),
    "short batch": lambda r: httpx.Response(200, json={"results": []}),
    "results not a list": lambda r: httpx.Response(200, json={"results": {"vulns": []}}),
    "network failure": lambda r: (_ for _ in ()).throw(httpx.ConnectError("down", request=r)),
}


@pytest.mark.parametrize("case", sorted(FAILURES))
def test_failed_osv_response_never_verifies_a_fix(vulnerable_server, case):
    result = _rescan(vulnerable_server, FAILURES[case])
    assert result["verifiedFixed"] == 0 and result["status"] == "failed" and result["errors"]
    status, verified_at, ticket_status, _ = _finding(vulnerable_server)
    assert status == "patching" and verified_at is None and (ticket_status or "").lower() not in ("resolved", "closed")
    db = session_factory()()
    try:
        scan = db.query(VulnScan).filter(VulnScan.device_id == vulnerable_server).order_by(VulnScan.started_at.desc()).first()
        assert scan.status == "failed" and scan.packages_assessed == 0 and scan.errors
    finally:
        db.close()


def test_unfollowed_pagination_is_incomplete(vulnerable_server):
    batch = lambda r: httpx.Response(200, json={"results": [{"vulns": [], "next_page_token": "page-2"}]})
    result = _rescan(vulnerable_server, batch, query=lambda r: httpx.Response(500))
    assert result["verifiedFixed"] == 0 and result["status"] == "failed"
    assert _finding(vulnerable_server)[0] == "patching"


def test_pagination_followed_to_the_end_can_verify(vulnerable_server):
    batch = lambda r: httpx.Response(200, json={"results": [{"vulns": [], "next_page_token": "page-2"}]})
    result = _rescan(vulnerable_server, batch, query=lambda r: httpx.Response(200, json={"vulns": []}))
    assert result["status"] == "complete" and result["verifiedFixed"] == 1
    status, verified_at, ticket_status, _ = _finding(vulnerable_server)
    assert status == "fixed" and verified_at is not None and ticket_status.lower() == "resolved"


def test_detail_failure_keeps_known_severity(vulnerable_server):
    # Still vulnerable; the advisory detail lookup fails. The finding stays, its severity is not downgraded.
    batch = lambda r: httpx.Response(200, json={"results": [{"vulns": [{"id": "UBUNTU-CVE-2024-0727"}]}]})
    before = _finding(vulnerable_server)[3]
    exposure._KEV_CACHE = (0.0, set())  # KEV feed down for this run (the handler answers 503)
    result = _rescan(vulnerable_server, batch, detail=lambda r: httpx.Response(502))
    assert result["verifiedFixed"] == 0 and any("detail" in w for w in result["warnings"])
    assert any("KEV" in w for w in result["warnings"])  # missing intelligence is reported, not treated as low risk
    status, _, _, severity = _finding(vulnerable_server)
    assert status == "patching" and severity == before


def test_partial_batch_only_verifies_assessed_packages(client, admin, tenant):
    exposure._KEV_CACHE = (0.0, set())
    device = enroll(client, admin, tenant, hostname="SCAN-2", os_version="Ubuntu 22.04.4 LTS", serial="SI-2")
    packages = [{"name": f"pkg{i}", "version": "1.0"} for i in range(501)]  # two OSV batches
    _inventory(client, device, packages)
    db = session_factory()()
    try:
        for name in ("pkg0", "pkg500"):
            db.add(Vulnerability(tenant_id=tenant["id"], device_id=device["deviceId"], vuln_id=f"CVE-1-{name}", package=name,
                                 status="open", severity="high", first_seen=utcnow(), last_seen=utcnow()))
        db.commit()
    finally:
        db.close()
    calls = {"n": 0}

    def batch(request):
        calls["n"] += 1
        if calls["n"] == 1:  # first 500 answered, clean
            return httpx.Response(200, json={"results": [{} for _ in range(500)]})
        return httpx.Response(503)  # second batch (pkg500) fails

    result = _rescan(device["deviceId"], batch)
    assert result["status"] == "partial" and result["assessed"] == 500 and result["verifiedFixed"] == 1
    db = session_factory()()
    try:
        rows = {v.package: v.status for v in db.query(Vulnerability).filter(Vulnerability.device_id == device["deviceId"])}
        assert rows == {"pkg0": "fixed", "pkg500": "open"}
    finally:
        db.close()


def test_missing_inventory_does_not_close_installed_program_findings(client, admin, tenant):
    """NVD/installed-program source: a device that has not reported software must not have its findings closed."""
    device = enroll(client, admin, tenant, hostname="WIN-NOINV", serial="SI-3")
    db = session_factory()()
    try:
        db.add(Vulnerability(tenant_id=tenant["id"], device_id=device["deviceId"], vuln_id="CVE-2024-1", package="7-Zip 23.01",
                             source="nvd-cpe", status="open", severity="high", first_seen=utcnow(), last_seen=utcnow()))
        db.commit()
        row = db.get(Device, device["deviceId"])
        later = utcnow()
        assert vulnmgmt.verify_after_scan(db, row, later, source="nvd-cpe", assessed=set()) == 0
        # Once a fresh inventory shows the program is gone, the removal verifies the fix.
        db.add(SoftwareItem(tenant_id=tenant["id"], device_id=row.id, name="Notepad", version="1", ecosystem="windows", seen_at=utcnow()))
        db.flush()
        assert vulnmgmt.verify_after_scan(db, row, utcnow(), source="nvd-cpe", assessed=set()) == 1
    finally:
        db.close()
