import json

import pytest

from conftest import enroll


def test_bulk_commands_preserve_payload_for_each_device(client, admin, tenant, device):
    second = enroll(client, admin, tenant, hostname='SECOND', serial='SN-2')
    payload = {'action': 'restart'}
    response = client.post('/api/console/commands/bulk', headers=admin, json={
        'type': 'service.control', 'deviceIds': [device['deviceId'], second['deviceId']],
        'targetPath': 'Spooler', 'payload': payload, 'reason': 'Maintenance',
    })
    assert response.status_code == 200, response.text
    assert len(response.json()['queued']) == 2
    assert response.json()['skipped'] == []
    for endpoint in (device, second):
        pending = client.get(f"/api/v1/devices/{endpoint['deviceId']}/commands/pending", headers=endpoint['headers'])
        [command] = pending.json()['items']
        assert command['targetPath'] == 'Spooler'
        assert json.loads(command['payloadJson']) == payload


def test_bulk_different_payloads_are_distinct_commands(client, admin, device):
    ids = []
    for action in ('start', 'stop'):
        response = client.post('/api/console/commands/bulk', headers=admin, json={
            'type': 'service.control', 'deviceIds': [device['deviceId']],
            'targetPath': 'Spooler', 'payload': {'action': action},
        })
        assert response.status_code == 200
        ids.extend(response.json()['queued'])
    assert len(set(ids)) == 2


@pytest.mark.parametrize('payload', [[], 'restart', 12, False])
def test_bulk_rejects_non_object_payload(client, admin, device, payload):
    response = client.post('/api/console/commands/bulk', headers=admin, json={
        'type': 'service.control', 'deviceIds': [device['deviceId']],
        'targetPath': 'Spooler', 'payload': payload,
    })
    assert response.status_code == 422
    pending = client.get(f"/api/v1/devices/{device['deviceId']}/commands/pending", headers=device['headers'])
    assert pending.json()['items'] == []
