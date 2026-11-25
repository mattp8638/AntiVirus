"""ISMS organization and scope registers and the asset register, through the API."""

from conftest import login

PW = "a-long-password-123"


def person(client, admin, tenant_id, email, fenrir_role="tenant_analyst", isms_role=None):
    r = client.post("/api/console/users", headers=admin, json={"tenantId": tenant_id, "email": email, "password": PW,
                                                               "name": email.split("@")[0].title(), "role": fenrir_role})
    assert r.status_code == 200, r.text
    user = r.json()
    if isms_role:
        r = client.put("/api/console/isms/memberships", headers=admin,
                       json={"tenantId": tenant_id, "userId": user["id"], "role": isms_role})
        assert r.status_code == 200, r.text
    return user


def manager(client, admin, tenant):
    person(client, admin, tenant["id"], "isms@acme.test", isms_role="isms_manager")
    return login(client, "isms@acme.test", PW)


def audit_actions(client, admin):
    return [e["action"] for e in client.get("/api/console/audit?limit=200", headers=admin).json()
            if e["action"].startswith("isms.")]


def test_fenrir_roles_alone_give_no_access(client, admin, tenant):
    r = client.get(f"/api/console/isms/scope?tenant_id={tenant['id']}", headers=admin)
    assert r.status_code == 403 and "none" in r.json()["detail"]
    person(client, admin, tenant["id"], "owner@acme.test", isms_role="control_owner")
    owner = login(client, "owner@acme.test", PW)
    assert client.get(f"/api/console/isms/assets?tenant_id={tenant['id']}", headers=owner).status_code == 403


def test_scope_versions_only_change_when_the_text_does(client, admin, tenant):
    h = manager(client, admin, tenant)
    tid = tenant["id"]
    assert client.get(f"/api/console/isms/scope?tenant_id={tid}", headers=h).json()["version"] == 0
    assert client.put("/api/console/isms/scope", headers=h, json={"tenantId": tid, "statement": " "}).status_code == 400
    body = {"tenantId": tid, "statement": "Managed IT services from the Leeds office", "boundaries": "Excludes payroll"}
    assert client.put("/api/console/isms/scope", headers=h, json=body).json()["version"] == 1
    assert client.put("/api/console/isms/scope", headers=h, json=body).json()["version"] == 1
    assert client.put("/api/console/isms/scope", headers=h, json={**body, "interfaces": "Cloud hosting"}).json()["version"] == 2
    scope = client.get(f"/api/console/isms/scope?tenant_id={tid}", headers=h).json()
    assert (scope["statement"], scope["interfaces"], scope["updatedBy"]) == (
        "Managed IT services from the Leeds office", "Cloud hosting", "isms@acme.test")
    assert audit_actions(client, admin).count("isms.scope_saved") == 2


def test_registers_add_update_and_delete(client, admin, tenant):
    h = manager(client, admin, tenant)
    tid = tenant["id"]
    base = "/api/console/isms/registers"
    assert client.post(f"{base}/context-issues", headers=h, json={"tenantId": tid, "kind": "sideways",
                                                                  "description": "x"}).status_code == 400
    issue = client.post(f"{base}/context-issues", headers=h, json={
        "tenantId": tid, "kind": "external", "description": "Flooding risk at the data centre",
        "climateRelated": True}).json()
    assert (issue["kind"], issue["climateRelated"]) == ("external", True)
    client.post(f"{base}/interested-parties", headers=h, json={"tenantId": tid, "name": "Customers",
                                                               "requirements": "Confidentiality of their data"})
    client.post(f"{base}/entities", headers=h, json={"tenantId": tid, "name": "Acme Ltd", "inScope": True})
    site = client.post(f"{base}/sites", headers=h, json={"tenantId": tid, "name": "Leeds", "inScope": "true"}).json()
    assert site["inScope"] is True
    r = client.patch(f"{base}/sites/{site['id']}", headers=h, json={"name": "Leeds office", "inScope": False})
    assert (r.json()["name"], r.json()["inScope"]) == ("Leeds office", False)
    assert client.delete(f"{base}/context-issues/{issue['id']}", headers=h).status_code == 200
    assert client.get(f"{base}/context-issues?tenant_id={tid}", headers=h).json()["items"] == []
    parties = client.get(f"{base}/interested-parties?tenant_id={tid}", headers=h).json()["items"]
    assert [p["name"] for p in parties] == ["Customers"]
    assert client.get(f"{base}/nope?tenant_id={tid}", headers=h).status_code == 404
    actions = audit_actions(client, admin)
    assert actions.count("isms.register_added") == 4 and "isms.register_updated" in actions
    assert "isms.register_deleted" in actions


def test_assets_with_owners_and_duplicates(client, admin, tenant):
    h = manager(client, admin, tenant)
    tid = tenant["id"]
    owner = person(client, admin, tenant["id"], "kim@acme.test", isms_role="control_owner")
    outsider = person(client, admin, tenant["id"], "nobody@acme.test")  # no ISMS role here
    a = client.post("/api/console/isms/assets", headers=h, json={"tenantId": tid, "type": "System", "name": "CRM",
                                                                 "ownerId": owner["id"]})
    assert a.status_code == 200, a.text
    assert (a.json()["type"], a.json()["classification"], a.json()["ownerName"]) == ("system", "internal", "Kim")
    dup = client.post("/api/console/isms/assets", headers=h, json={"tenantId": tid, "type": "system", "name": "CRM"})
    assert dup.status_code == 409
    bad = client.post("/api/console/isms/assets", headers=h, json={"tenantId": tid, "type": "system", "name": "ERP",
                                                                   "ownerId": outsider["id"]})
    assert bad.status_code == 400 and "member" in bad.json()["detail"]
    assert client.post("/api/console/isms/assets", headers=h, json={"tenantId": tid, "type": "car",
                                                                    "name": "Van"}).status_code == 400
    r = client.patch(f"/api/console/isms/assets/{a.json()['id']}", headers=h,
                     json={"type": "system", "name": "CRM", "classification": "confidential"})
    assert (r.json()["classification"], r.json()["ownerId"]) == ("confidential", None)


def test_asset_csv_import_is_all_or_nothing(client, admin, tenant):
    h = manager(client, admin, tenant)
    tid = tenant["id"]
    person(client, admin, tenant["id"], "kim@acme.test", isms_role="control_owner")
    url = "/api/console/isms/assets/import"
    r = client.post(url, headers=h, json={"tenantId": tid, "csv": "name\nCRM\n"}).json()
    assert r["errors"][0]["message"].startswith("Missing column(s): type.")
    bad = "name,type,classification,owner_email\nCRM,system,,kim@acme.test\nLaptops,thing,,\nCRM,system,,\nHR,system,,x@y.test\n"
    r = client.post(url, headers=h, json={"tenantId": tid, "csv": bad}).json()
    assert (r["created"], [e["line"] for e in r["errors"]]) == (0, [3, 4, 5])
    assert client.get(f"/api/console/isms/assets?tenant_id={tid}", headers=h).json()["items"] == []
    good = "Name,Type,Classification,Owner Email,Description\nCRM,system,confidential,KIM@acme.test,Sales\nHR files,information,,,\n"
    assert client.post(url, headers=h, json={"tenantId": tid, "csv": good}).json() == {"created": 2, "updated": 0, "errors": []}
    again = good.replace("confidential", "restricted")
    assert client.post(url, headers=h, json={"tenantId": tid, "csv": again}).json() == {"created": 0, "updated": 1, "errors": []}
    items = {a["name"]: a for a in client.get(f"/api/console/isms/assets?tenant_id={tid}", headers=h).json()["items"]}
    assert (items["CRM"]["classification"], items["CRM"]["ownerName"]) == ("restricted", "Kim")
    assert audit_actions(client, admin).count("isms.assets_imported") == 2


def test_organization_data_is_isolated_between_customers(client, admin, tenant):
    h = manager(client, admin, tenant)
    other = client.post("/api/console/tenants", json={"name": "Globex", "template": "balanced"}, headers=admin).json()
    person(client, admin, other["id"], "isms@globex.test", isms_role="isms_manager")
    g = login(client, "isms@globex.test", PW)
    site = client.post("/api/console/isms/registers/sites", headers=g, json={"tenantId": other["id"], "name": "Secret"}).json()
    asset = client.post("/api/console/isms/assets", headers=g, json={"tenantId": other["id"], "type": "system",
                                                                     "name": "Vault"}).json()
    assert client.get(f"/api/console/isms/registers/sites?tenant_id={other['id']}", headers=h).status_code == 404
    assert client.patch(f"/api/console/isms/registers/sites/{site['id']}", headers=h, json={"name": "x"}).status_code == 404
    assert client.delete(f"/api/console/isms/assets/{asset['id']}", headers=h).status_code == 404
    assert client.post("/api/console/isms/assets", headers=h, json={"tenantId": other["id"], "type": "system",
                                                                    "name": "x"}).status_code == 404
    # The MSP admin can see Globex in Fenrir, but has no ISMS role there.
    assert client.get(f"/api/console/isms/assets?tenant_id={other['id']}", headers=admin).status_code == 403


def test_members_can_be_listed_by_managers_to_choose_owners(client, admin, tenant):
    h = manager(client, admin, tenant)
    person(client, admin, tenant["id"], "kim@acme.test", isms_role="control_owner")
    members = client.get(f"/api/console/isms/members?tenant_id={tenant['id']}", headers=h).json()["members"]
    assert [(m["email"], m["role"]) for m in members] == [("isms@acme.test", "isms_manager"), ("kim@acme.test", "control_owner")]
    owner = login(client, "kim@acme.test", PW)
    assert client.get(f"/api/console/isms/members?tenant_id={tenant['id']}", headers=owner).status_code == 403
