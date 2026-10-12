import pytest
from fastapi.testclient import TestClient
from api.main import app, _registry
from agent import policy, query

@pytest.fixture
def client():
    _registry.clear()
    with TestClient(app) as client:
        yield client
    _registry.clear()


def create(client, user):
    response = client.post('/api/demo/sessions', json={'user_id': user})
    assert response.status_code == 200
    data = response.json()
    return data, {'Authorization': 'Bearer ' + data['token']}


def test_identity_metadata_and_server_resolved_role(client):
    assert len(client.get('/api/identities').json()) == 6
    data, _ = create(client, 'u_ana')
    assert data['identity']['role'] == 'analyst'
    assert client.post('/api/demo/sessions', json={'user_id': 'u_ana', 'role': 'compliance'}).status_code == 422
    assert client.post('/api/demo/sessions', json={'user_id': 'unknown'}).status_code == 400


def test_chat_requires_session_and_own_conversation(client):
    ana, headers = create(client, 'u_ana')
    cora, _ = create(client, 'u_cora')
    payload = {'conversation_id': cora['conversation_id'], 'question': 'Continue'}
    assert client.post('/api/chat', json=payload).status_code == 401
    assert client.post('/api/chat', json=payload, headers=headers).status_code == 403
    payload['conversation_id'] = ana['conversation_id']
    assert client.post('/api/chat', json=dict(payload, role='compliance'), headers=headers).status_code == 422


def test_result_owner_and_session_revocation(client):
    ana, headers = create(client, 'u_ana')
    result = query.execute(query.QueryPlan(dataset='customers', operation='aggregate', metrics=[query.Metric(op='count')]),
                           policy.resolve('u_ana', ana['conversation_id']), [])
    assert client.get('/api/results/' + result['result_id'], headers=headers).status_code == 200
    _, foreign = create(client, 'u_cora')
    assert client.get('/api/results/' + result['result_id'], headers=foreign).status_code == 404
    assert client.delete('/api/demo/sessions', headers=headers).status_code == 200
    assert client.get('/api/results/' + result['result_id'], headers=headers).status_code == 401


def test_public_audit_does_not_disclose_internal_row_counts():
    from api.main import public_result
    from agent.baseline import AgentResult
    result = AgentResult(executions=[{'sql': 'SELECT count(*)', 'parameters': [], 'status': 'withheld',
        'execution_row_count': 1, 'released_rows': [], 'released_row_count': 0, 'redactions': []}])
    public = public_result(result)
    assert 'execution_row_count' not in public['executions'][0]
    assert 'released_rows' not in public['executions'][0]


def test_private_redaction_lookup_is_not_a_public_query():
    from api.main import public_result
    from agent.baseline import AgentResult
    result = AgentResult(executions=[{'kind': 'kernel_lookup', 'sql': 'SELECT national_id FROM customers',
        'parameters': [], 'status': 'internal_only', 'released_rows': [], 'released_row_count': 0, 'redactions': []}])
    assert public_result(result)['executions'] == []


def test_access_change_before_http_release_discards_old_answer(client, monkeypatch):
    import sqlite3
    from agent import baseline, db
    data, headers = create(client, 'u_rae')
    def change_after_model(*args):
        context = policy.resolve('u_rae', data['conversation_id'])
        with sqlite3.connect(db.DB_PATH) as conn:
            conn.execute("UPDATE users SET role='analyst' WHERE user_id='u_rae'")
        return baseline.AgentResult(answer='Private income 999991',
            identity={k: getattr(context, k) for k in ('user_id', 'full_name', 'role', 'region')},
            scope=context.public_scope(), results=[{'rows': [{'annual_income_usd': 999991}]}])
    monkeypatch.setattr(baseline, 'run', change_after_model)
    response = client.post('/api/chat', json={'conversation_id': data['conversation_id'], 'question': 'Income?'}, headers=headers)
    assert response.status_code == 200
    assert '999991' not in response.text
    assert 'access changed' in response.text
