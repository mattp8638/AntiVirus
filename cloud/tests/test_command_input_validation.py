import pytest


@pytest.mark.parametrize('ids', [None, [], 'device', {}, [None], [12], [' '], ['x'] * 5001])
def test_invalid_bulk_targets_queue_nothing(client, admin, device, ids):
    response = client.post('/api/console/commands/bulk', headers=admin,
                           json={'type': 'scan.quick', 'deviceIds': ids})
    assert response.status_code == 422
    assert client.get(f"/api/v1/devices/{device['deviceId']}/commands/pending", headers=device['headers']).json()['items'] == []


def test_duplicate_bulk_targets_count_once(client, admin, device):
    response = client.post('/api/console/commands/bulk', headers=admin,
                           json={'type': 'scan.quick', 'deviceIds': [device['deviceId']] * 3})
    assert response.status_code == 200
    assert len(response.json()['queued']) == 1


@pytest.mark.parametrize('field,value', [('payload', []), ('payload', False), ('payload', 'invalid'),
                                        ('targetPath', 12), ('recordId', {}), ('reason', [])])
@pytest.mark.parametrize('bulk', [True, False])
def test_invalid_arguments_rejected_consistently(client, admin, device, field, value, bulk):
    url = '/api/console/commands/bulk' if bulk else f"/api/console/devices/{device['deviceId']}/commands"
    response = client.post(url, headers=admin,
                           json={'type': 'scan.quick', 'deviceIds': [device['deviceId']], field: value})
    assert response.status_code == 422


@pytest.mark.parametrize('command,field', [('scan.targeted', 'targetPath'), ('quarantine.restore', 'recordId')])
def test_blank_required_arguments_not_queued(client, admin, device, command, field):
    body = {'type': command, field: '   ', 'deviceIds': [device['deviceId']]}
    response = client.post(f"/api/console/devices/{device['deviceId']}/commands", headers=admin, json=body)
    assert response.status_code == 400
    response = client.post('/api/console/commands/bulk', headers=admin, json=body)
    assert response.status_code == 200
    assert response.json()['queued'] == []
    assert len(response.json()['skipped']) == 1


def test_valid_path_is_trimmed_before_delivery(client, admin, device):
    response = client.post(f"/api/console/devices/{device['deviceId']}/commands", headers=admin,
                           json={'type': 'scan.targeted', 'targetPath': '  C:\\Temp  '})
    assert response.status_code == 200
    pending = client.get(f"/api/v1/devices/{device['deviceId']}/commands/pending", headers=device['headers'])
    assert pending.json()['items'][0]['targetPath'] == 'C:\\Temp'
