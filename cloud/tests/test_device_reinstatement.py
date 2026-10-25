from datetime import timedelta
import pytest
from fenrir_cloud import deployment_installers, db as database
from fenrir_cloud.models import EnrollmentToken, utcnow

@pytest.fixture
def reinstatement(client,admin,device,monkeypatch):
    raw=[]
    def build(os,base,token):
        raw.append(token)
        return b'installer', 'FenrirSetup.exe','application/octet-stream'
    monkeypatch.setattr(deployment_installers,'build',build)
    ident=device['deviceId']
    assert client.delete('/api/console/devices/'+ident,headers=admin).status_code==200
    def generate(**overrides):
        return client.post('/api/console/enrollment-installers',headers=admin,json={
            'os':'windows','tenantId':device['tenantId'],'reinstateDeviceId':ident,**overrides})
    def enroll(token=None,**overrides):
        return client.post('/api/v1/enroll',json={'hostname':'ACME-WS-01','platform':'windows',
            'osVersion':'Windows 11','serialNumber':'SN-1','enrollmentToken':token or raw[-1],**overrides})
    return raw,generate,enroll


def test_reinstatement_keeps_identity_rotates_credentials_and_consumes_token(client,admin,device,reinstatement):
    raw,generate,enroll=reinstatement
    assert generate().status_code==200
    detail='/api/console/devices/'+device['deviceId']
    assert client.get(detail,headers=admin).json()['device']['retired']
    response=enroll()
    assert response.status_code==200,response.text
    assert response.json()['deviceId']==device['deviceId']
    assert response.json()['deviceApiKey']!=device['deviceApiKey']
    assert not client.get(detail,headers=admin).json()['device']['retired']
    assert enroll().status_code==403
    assert client.post('/api/v1/devices/'+device['deviceId']+'/heartbeat',headers=device['headers'],json={}).status_code==401
    assert generate().status_code==409


@pytest.mark.parametrize('overrides',[{'serialNumber':'OTHER'},{'platform':'linux'}])
def test_mismatched_endpoint_cannot_consume_token(reinstatement,overrides):
    raw,generate,enroll=reinstatement
    assert generate().status_code==200
    assert enroll(**overrides).status_code==409
    assert enroll().status_code==200


def test_replacing_installer_revokes_previous_token(reinstatement):
    raw,generate,enroll=reinstatement
    assert generate().status_code==200
    first=raw[-1]
    assert generate().status_code==200
    assert enroll(token=first).status_code==403
    assert enroll().status_code==200


def test_expired_reinstatement_token_rejected(reinstatement):
    raw,generate,enroll=reinstatement
    assert generate().status_code==200
    with database.session_factory()() as db:
        for token in db.query(EnrollmentToken).filter(EnrollmentToken.label.like('Reinstate %')):
            token.expires_at=utcnow()-timedelta(seconds=1)
        db.commit()
    assert enroll().status_code==403


def test_other_customer_cannot_supply_target(client,admin,reinstatement):
    raw,generate,enroll=reinstatement
    tenant=client.post('/api/console/tenants',headers=admin,json={'name':'Other customer'}).json()
    assert generate(tenantId=tenant['id']).status_code==404
    assert not raw


def test_ordinary_enrollment_cannot_reactivate_retired_device(client,admin,device,reinstatement):
    raw,generate,enroll=reinstatement
    token=client.post('/api/console/enrollment-tokens',headers=admin,json={'tenantId':device['tenantId']}).json()['token']
    assert enroll(token=token).status_code==409
