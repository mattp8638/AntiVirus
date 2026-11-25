"""Attack paths (VULN-19): internet -> exposed service -> vulnerable device -> critical server, each edge observed or
inferred with evidence; identity paths from MFA gaps; resolved paths after remediation."""

from conftest import enroll

from fenrir_cloud.db import session_factory
from fenrir_cloud.models import Device, ExternalAsset, M365Connection, Vulnerability, utcnow


def test_paths_evidence_and_resolution(client, admin, tenant):
    tid = tenant["id"]
    web = enroll(client, admin, tenant, hostname="ACME-WEB-01", serial="W1")
    dc = enroll(client, admin, tenant, hostname="ACME-DC-01", serial="D1")
    with session_factory()() as db:
        w, d = db.get(Device, web["deviceId"]), db.get(Device, dc["deviceId"])
        w.ip_address, d.ip_address = "10.20.0.15", "10.20.0.10"
        d.tags, d.criticality = ["domain-controller"], "critical"
        db.add(ExternalAsset(tenant_id=tid, target="acme-web-01", ownership_attested_by="t", last_scan_at=utcnow(),
                             last_result={"address": "198.51.100.7", "openPorts": [{"port": 443}, {"port": 3389}]}))
        db.add(Vulnerability(tenant_id=tid, device_id=w.id, vuln_id="CVE-2024-0001", package="webapp", severity="critical",
                             known_exploited=True, status="open"))
        db.add(M365Connection(tenant_id=tid, name="acme", tenant_name="Acme", directory_id="dir-1", client_id="app-1", credentials_envelope={}, synced_at=utcnow(), snapshot={"insights": {"mfa": {"adminsWithoutMfa": ["it@acme.test"]}}}))
        db.commit()
    first = client.post("/api/console/attack-paths/analyse", headers=admin, json={"tenantId": tid}).json()
    targets = {p["target"] for p in first["paths"]}
    assert "ACME-DC-01" in targets and "Microsoft 365 Acme" in targets
    dcp = next(p for p in first["paths"] if p["target"] == "ACME-DC-01")
    assert dcp["hops"][:3] == ["Internet", "acme-web-01 (443, 3389)", "ACME-WEB-01"]
    kinds = [s["kind"] for s in dcp["steps"]]
    assert kinds == ["observed", "inferred", "inferred"] and dcp["foothold"][0].startswith("CVE-2024-0001")
    assert "no exploitation" in first["inputs"]["method"]

    # Patching the web server removes the foothold: the path to the domain controller is resolved.
    with session_factory()() as db:
        for v in db.query(Vulnerability).filter(Vulnerability.device_id == web["deviceId"]):
            v.status = "fixed"
        db.commit()
    second = client.post("/api/console/attack-paths/analyse", headers=admin, json={"tenantId": tid}).json()
    assert dcp["id"] in {r["id"] for r in second["resolved"]}
    assert all(p["target"] != "ACME-DC-01" for p in second["paths"])
    assert client.get("/api/console/attack-paths/latest", headers=admin, params={"tenantId": tid}).json()["id"] == second["id"]
