from fenrir_cloud import db as database
from fenrir_cloud.models import AuditLog


def test_decommission_archives_device_and_preserves_command_history(client,admin,device):
    ident=device['deviceId']
    url=f'/api/console/devices/{ident}'
    cmd=client.post(url+'/commands',headers=admin,json={'type':'scan.quick'}).json()
    client.get(f'/api/v1/devices/{ident}/commands/pending',headers=device['headers'])
    response=client.post(f"/api/v1/devices/{ident}/commands/{cmd['id']}/complete",headers=device['headers'],json={'status':'completed','resultJson':{'findingCount':0}})
    assert response.status_code==200
    assert client.delete(url,headers=admin).status_code==200
    assert ident not in [d['id'] for d in client.get('/api/console/devices',headers=admin).json()]
    retired=client.get('/api/console/devices?status=retired',headers=admin).json()
    assert [d['id'] for d in retired]==[ident]
    assert retired[0]['retired'] is True and retired[0]['online'] is False
    detail=client.get(url,headers=admin).json()
    assert detail['commands'][0]['id']==cmd['id']
    assert detail['commands'][0]['status']=='completed'
    assert client.post(url+'/commands',headers=admin,json={'type':'scan.quick'}).status_code==400
    bulk=client.post('/api/console/commands/bulk',headers=admin,json={'type':'scan.quick','deviceIds':[ident]}).json()
    assert bulk['queued']==[] and len(bulk['skipped'])==1
    assert client.delete(url,headers=admin).status_code==200
    with database.session_factory()() as db:
        assert db.query(AuditLog).filter_by(action='device.retired').count()==1
