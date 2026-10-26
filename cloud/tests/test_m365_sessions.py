from contextlib import contextmanager
import httpx
import pytest
from fenrir_cloud import m365_admin as provider
from fenrir_cloud.routers.m365_admin import ActionInput
from pydantic import ValidationError
from uuid import uuid4

USER = '00000000-0000-0000-0000-000000000010'

@pytest.fixture
def graph(monkeypatch):
    calls = []
    state = {'userType': 'Member', 'response': {'value': True}}
    @contextmanager
    def session(_):
        yield None, {}
    def request(client, headers, method, path, body=None):
        calls.append((method, path, body))
        if method == 'GET':
            return {'id': USER, 'userType': state['userType']}
        if state.get('timeout'):
            raise httpx.ReadTimeout('timeout')
        return state['response']
    monkeypatch.setattr(provider, 'session', session)
    monkeypatch.setattr(provider, 'request', request)
    return calls, state


def test_session_revocation_posts_without_body(graph):
    calls, state = graph
    preview = provider.preview(None, 'user.revoke_sessions', USER, {})
    assert 'User.RevokeSessions.All' in preview['requiredPermissions']
    status, result = provider.execute(None, 'user.revoke_sessions', USER, {})
    assert status == 'succeeded'
    assert calls[-1] == ('POST', f'/users/{USER}/revokeSignInSessions', None)
    assert 'few minutes' in result['message']


@pytest.mark.parametrize('user_type', ['Guest', None])
def test_external_or_unknown_user_is_not_modified(graph, user_type):
    calls, state = graph
    state['userType'] = user_type
    for fn in (provider.preview, provider.execute):
        with pytest.raises(provider.ProviderError):
            fn(None, 'user.revoke_sessions', USER, {})
    assert all(method == 'GET' for method, _, _ in calls)


@pytest.mark.parametrize('timeout', [False, True])
def test_unconfirmed_result_is_uncertain(graph, timeout):
    calls, state = graph
    state.update(response={'value': False}, timeout=timeout)
    with pytest.raises(provider.ProviderError) as exc:
        provider.execute(None, 'user.revoke_sessions', USER, {})
    assert exc.value.uncertain
    assert sum(method == 'POST' for method, _, _ in calls) == 1


def test_session_action_rejects_extra_parameters():
    args = dict(requestId=uuid4(), targetId=USER, operation='user.revoke_sessions')
    assert ActionInput(**args, parameters={}).parameters == {}
    with pytest.raises(ValidationError):
        ActionInput(**args, parameters={'arbitrary': True})
