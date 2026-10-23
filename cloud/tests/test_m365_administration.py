import uuid
import httpx
import pytest
from datetime import timedelta
from conftest import ADMIN_PASSWORD, login
from test_documentation_vault import stepup
from test_msp_modules import connection, post
from fenrir_cloud import db as database, m365_admin as provider
from fenrir_cloud.models import M365Action, AuditLog, utcnow

USER = "00000000-0000-0000-0000-000000000010"
GROUP = "00000000-0000-0000-0000-000000000020"
SKU = "00000000-0000-0000-0000-000000000030"

def plan(client, admin, conn, operation="user.update", parameters=None, request_id=None):
    return post(client, admin, "m365/connections/"+conn["id"]+"/actions",
        {"requestId":request_id or str(uuid.uuid4()),"operation":operation,"targetId":USER,
         "parameters":parameters if parameters is not None else {"displayName":"New name"}})

@pytest.fixture
def previews(monkeypatch):
    monkeypatch.setattr(provider, "preview", lambda conn, op, target, params: {
        "user":{"id":target,"displayName":"Original","userPrincipalName":"user@example.test"},
        "changes":params,"requiredPermissions":provider.CAPABILITIES[op]})

def test_action_confirmation_stepup_deduplication_and_audit(client, admin, tenant, previews, monkeypatch):
    conn = connection(client,admin,tenant)
    key = str(uuid.uuid4())
    job = plan(client,admin,conn,request_id=key)
    assert plan(client,admin,conn,request_id=key)["id"] == job["id"]
    calls=[]
    def perform(*args):
        # Claim is committed before the provider can mutate anything.
        with database.session_factory()() as db:
            assert db.get(M365Action,job["id"]).status == "running"
        calls.append(args)
        return "succeeded", {"user":{"id":USER,"displayName":"New name"}}
    monkeypatch.setattr(provider,"execute",perform)
    url="/api/console/m365/connections/"+conn["id"]+"/actions/"+job["id"]+"/execute"
    assert client.post(url,headers=admin,json={"confirmed":True}).status_code == 403
    proof=stepup(client,admin)
    assert client.post(url,headers=proof,json={"confirmed":False}).status_code == 422
    assert client.post(url,headers=proof,json={"confirmed":True}).json()["status"] == "succeeded"
    assert client.post(url,headers=proof,json={"confirmed":True}).json()["status"] == "succeeded"
    assert len(calls) == 1
    with database.session_factory()() as db:
        assert db.query(AuditLog).filter_by(action="m365.action_finished").count() == 1

def test_unknown_outcome_is_never_replayed(client,admin,tenant,previews,monkeypatch):
    conn=connection(client,admin,tenant)
    job=plan(client,admin,conn)
    calls=[]
    def uncertain(*args):
        calls.append(1)
        raise provider.ProviderError("Outcome unknown",uncertain=True)
    monkeypatch.setattr(provider,"execute",uncertain)
    url="/api/console/m365/connections/"+conn["id"]+"/actions/"+job["id"]+"/execute"
    proof=stepup(client,admin)
    for _ in range(2):
        assert client.post(url,headers=proof,json={"confirmed":True}).json()["status"] == "unknown"
    assert len(calls)==1

def test_expired_preview_and_request_conflict(client,admin,tenant,previews,monkeypatch):
    conn=connection(client,admin,tenant)
    job=plan(client,admin,conn)
    url="/api/console/m365/connections/"+conn["id"]+"/actions"
    assert client.post(url,headers=admin,json={"requestId":job["requestId"],"operation":"user.update","targetId":USER,"parameters":{"displayName":"Different"}}).status_code==409
    with database.session_factory()() as db:
        db.get(M365Action,job["id"]).created_at=utcnow()-timedelta(minutes=11);db.commit()
    monkeypatch.setattr(provider,"execute",lambda *args: pytest.fail("Expired action executed"))
    assert client.post(url+"/"+job["id"]+"/execute",headers=stepup(client,admin),json={"confirmed":True}).status_code==409

def test_microsoft_admin_permission_and_tenant_boundary(client,admin,tenant,previews):
    conn=connection(client,admin,tenant)
    post(client,admin,"users",{"tenantId":tenant["id"],"email":"soc@test.com","password":ADMIN_PASSWORD,"role":"soc_analyst"})
    analyst=login(client,"soc@test.com")
    body={"requestId":str(uuid.uuid4()),"operation":"user.update","targetId":USER,"parameters":{"displayName":"No"}}
    url="/api/console/m365/connections/"+conn["id"]+"/actions"
    assert client.post(url,headers=analyst,json=body).status_code==403
    other=post(client,admin,"tenants",{"name":"Other"})
    post(client,admin,"users",{"tenantId":other["id"],"email":"other-admin@test.com","password":ADMIN_PASSWORD,"role":"tenant_admin"})
    assert client.post(url,headers=login(client,"other-admin@test.com"),json=body).status_code==404

@pytest.mark.parametrize("parameters", [{"passwordProfile":{"password":"must-not-be-saved"}},{"displayName":""},{"usageLocation":"UK/"},{"displayName":123}])
def test_profile_allowlist(client,admin,tenant,parameters):
    conn=connection(client,admin,tenant)
    response=client.post("/api/console/m365/connections/"+conn["id"]+"/actions",headers=admin,
        json={"requestId":str(uuid.uuid4()),"operation":"user.update","targetId":USER,"parameters":parameters})
    assert response.status_code==422

def transport(monkeypatch, handler):
    real=httpx.Client
    monkeypatch.setattr(provider.m365,"access_token",lambda client,conn:"private-token")
    monkeypatch.setattr(provider.httpx,"Client",lambda **kwargs: real(transport=httpx.MockTransport(handler)))

def test_group_removal_uses_ref_and_refreshes(monkeypatch):
    paths=[]
    def handler(req):
        paths.append((req.method,req.url.path))
        if req.method=="DELETE":
            assert req.url.path==f"/v1.0/groups/{GROUP}/members/{USER}/$ref"
            return httpx.Response(204)
        if "/users/" in req.url.path:
            return httpx.Response(200,json={"id":USER,"assignedLicenses":[]})
        if req.url.path.endswith("/members"):
            return httpx.Response(200,json={"value":[]})
        return httpx.Response(200,json={"id":GROUP,"isAssignableToRole":False,"groupTypes":[],"securityEnabled":True})
    transport(monkeypatch,handler)
    status,result=provider.execute(None,"group.remove_member",USER,{"groupId":GROUP})
    assert status=="succeeded" and result["members"]==[]
    assert sum(method=="DELETE" for method,path in paths)==1

def test_graph_timeout_redacts_and_marks_unknown(monkeypatch):
    def handler(req):
        if req.method=="PATCH":
            raise httpx.ReadTimeout("private-token provider secret")
        return httpx.Response(200,json={"id":USER})
    transport(monkeypatch,handler)
    with pytest.raises(provider.ProviderError) as error:
        provider.execute(None,"user.signin",USER,{"accountEnabled":False})
    assert error.value.uncertain and "private-token" not in str(error.value)

def test_successful_write_with_failed_refresh_is_not_failed(monkeypatch):
    reads=[]
    def handler(req):
        if req.method=="PATCH": return httpx.Response(204)
        reads.append(1)
        return httpx.Response(200,json={"id":USER}) if len(reads)==1 else httpx.Response(503)
    transport(monkeypatch,handler)
    status,result=provider.execute(None,"user.update",USER,{"displayName":"Updated"})
    assert status=="succeeded_refresh_pending"

@pytest.mark.parametrize("group", [{"isAssignableToRole":True},{"isAssignableToRole":False,"groupTypes":["DynamicMembership"]},
    {"isAssignableToRole":False,"onPremisesSyncEnabled":True},{"isAssignableToRole":False,"mailEnabled":True}])
def test_restricted_groups_cannot_be_mutated(monkeypatch,group):
    def handler(req):
        assert req.method=="GET"
        return httpx.Response(200,json={"id":USER} if "/users/" in req.url.path else group)
    transport(monkeypatch,handler)
    with pytest.raises(provider.ProviderError):
        provider.execute(None,"group.add_member",USER,{"groupId":GROUP})

def test_existing_licence_does_not_reset_disabled_plans(monkeypatch):
    def handler(req):
        assert req.method=="GET"
        return httpx.Response(200,json={"id":USER,"assignedLicenses":[{"skuId":SKU,"disabledPlans":["preserve"]}]})
    transport(monkeypatch,handler)
    with pytest.raises(provider.ProviderError,match="already"):
        provider.execute(None,"license.add",USER,{"skuId":SKU})
