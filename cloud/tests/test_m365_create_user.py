from contextlib import contextmanager
from uuid import uuid4
import json
import httpx
import pytest
from pydantic import ValidationError
from fenrir_cloud import m365_admin as provider, db as database
from fenrir_cloud.models import M365Action, AuditLog
from fenrir_cloud.routers.m365_admin import ActionInput
from test_msp_modules import connection
from test_documentation_vault import stepup

USER = '00000000-0000-0000-0000-000000000010'
PROFILE = {'displayName':'New User','userPrincipalName':'new@example.test','mailNickname':'new','usageLocation':'GB'}

@pytest.fixture
def graph(monkeypatch):
    calls=[]
    state={'verified':True,'auth':'Managed','exists':False,'timeout':False}
    @contextmanager
    def session(_):
        yield None, {}
    def request(client, headers, method, path, body=None):
        calls.append((method,path,body))
        if path.startswith('/domains/'):
            return {'isVerified':state['verified'],'authenticationType':state['auth']}
        if method=='GET':
            if state['exists']: return {'id':USER}
            req=httpx.Request('GET','https://graph.microsoft.com/v1.0'+path)
            raise httpx.HTTPStatusError('missing',request=req,response=httpx.Response(404,request=req))
        if state['timeout']: raise httpx.ReadTimeout('timeout')
        return {'id':USER,'passwordProfile':body['passwordProfile']}
    monkeypatch.setattr(provider,'session',session)
    monkeypatch.setattr(provider,'request',request)
    return calls,state


def test_create_request_and_secret_redaction(graph):
    preview=provider.preview(None,'user.create',str(uuid4()),PROFILE)
    assert preview['user']==PROFILE
    status,result=provider.create_user(None,PROFILE,'Temporary-Secret-123!')
    assert status=='succeeded'
    method,path,body=graph[0][-1]
    assert (method,path)==('POST','/users')
    assert body['accountEnabled'] is True
    assert body['passwordProfile']['forceChangePasswordNextSignIn'] is True
    assert 'passwordProfile' not in result['user']
    assert 'Temporary-Secret' not in json.dumps(result)


@pytest.mark.parametrize('changes',[{'exists':True},{'verified':False},{'auth':'Federated'}])
def test_unsupported_creation_never_writes(graph,changes):
    graph[1].update(changes)
    with pytest.raises(provider.ProviderError): provider.create_user(None,PROFILE,'Temporary-Secret-123!')
    assert all(c[0]=='GET' for c in graph[0])


def test_timeout_is_unknown_without_replay(graph):
    graph[1]['timeout']=True
    with pytest.raises(provider.ProviderError) as exc: provider.create_user(None,PROFILE,'Temporary-Secret-123!')
    assert exc.value.uncertain
    assert sum(c[0]=='POST' for c in graph[0])==1


@pytest.mark.parametrize('changes',[{'password':'secret'},{'accountEnabled':True},{'userPrincipalName':'invalid'},{'usageLocation':'UKK'},{'displayName':'   '}])
def test_creation_schema_rejects_invalid_or_secret_parameters(changes):
    with pytest.raises(ValidationError):
        ActionInput(requestId=uuid4(),operation='user.create',parameters={**PROFILE,**changes})


def test_create_api_review_auth_dedup_and_no_password_storage(client,admin,tenant,graph):
    conn=connection(client,admin,tenant)
    base='/api/console/m365/connections/'+conn['id']+'/actions'
    body={'requestId':str(uuid4()),'operation':'user.create','parameters':PROFILE}
    response=client.post(base,headers=admin,json=body)
    assert response.status_code==200,response.text
    job=response.json()
    assert client.post(base,headers=admin,json=body).json()['id']==job['id']
    url=base+'/'+job['id']+'/execute'
    secret='Temporary-Secret-123!'
    assert client.post(url,headers=admin,json={'confirmed':True,'temporaryPassword':secret}).status_code==403
    proof=stepup(client,admin)
    assert client.post(url,headers=proof,json={'confirmed':True}).status_code==422
    response=client.post(url,headers=proof,json={'confirmed':True,'temporaryPassword':secret})
    assert response.status_code==200,response.text
    assert response.json()['status']=='succeeded'
    assert secret not in response.text
    assert client.post(url,headers=proof,json={'confirmed':True}).json()['status']=='succeeded'
    assert sum(c[0]=='POST' for c in graph[0])==1
    assert secret not in client.get(base,headers=admin).text
    with database.session_factory()() as db:
        row=db.get(M365Action,job['id'])
        assert secret not in json.dumps([row.parameters,row.preview,row.result])
        assert secret not in json.dumps([a.details for a in db.query(AuditLog).all()])
