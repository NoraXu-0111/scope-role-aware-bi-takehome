import json
import sqlite3
from types import SimpleNamespace
from unittest.mock import patch
import pytest
from agent import baseline, db, policy, query, request_guard, sessions, tools, disclosure


@pytest.mark.parametrize('question', [
    'Which customers earn more than $300,000?',
    'List customers with annual income above 300000 dollars.',
    'Which customer in zip code 94110 was born in 1979?',
    'Find customers in postal code 94110.',
])
def test_exact_predicate_guard_denies_analyst(question):
    with pytest.raises(policy.AccessDenied) as exc:
        request_guard.check(question, policy.resolve('u_ana', 'test'))
    assert exc.value.code == 'precise_predicate_denied'


def test_exact_predicate_guard_preserves_generalized_and_reviewer_requests():
    request_guard.check("What is Dana's generalized ZIP prefix and income band?", policy.resolve('u_ana', 'test'))
    request_guard.check('Which customer in zip code 94110 was born in 1979?', policy.resolve('u_rae', 'test'))
    request_guard.check('How many transactions were paid over $30,000 in my region?', policy.resolve('u_ana', 'test'))


def run(user, args, conversation='test'):
    log = []
    result = tools.dispatch('query_data', args, context=policy.resolve(user, conversation), execution_log=log)
    return result, log

@pytest.mark.parametrize('user,field,allowed', [
    ('u_ana', 'zip3', True), ('u_ana', 'annual_income_usd', True),
    ('u_ana', 'national_id', False), ('u_rae', 'dob', True),
    ('u_rae', 'annual_income_usd', True), ('u_rae', 'national_id', False),
    ('u_cora', 'national_id', True), ('u_cora', 'race', False),
    ('u_ops', 'full_name', False), ('u_fern', 'full_name', False),
])
def test_role_field_matrix(user, field, allowed):
    result, log = run(user, {'dataset': 'customers', 'operation': 'rows', 'fields': [field]})
    assert (result['status'] == 'ok') == allowed
    if user == 'u_ana' and field == 'annual_income_usd':
        assert result['columns'] == ['income_band']
    if not allowed:
        assert not log

@pytest.mark.parametrize('location', ['select', 'filter', 'group', 'order', 'metric'])
def test_restricted_column_everywhere(location):
    args = {'dataset': 'customers', 'operation': 'rows', 'fields': ['full_name']}
    if location == 'select':
        args['fields'] = ['national_id']
    elif location == 'filter':
        args['filters'] = [{'field': 'annual_income_usd', 'op': 'gt', 'value': 300000}]
    elif location == 'order':
        args['order_by'] = [{'field': 'annual_income_usd'}]
    else:
        args.update(operation='aggregate', fields=[], metrics=[{'op': 'count'}])
        if location == 'group':
            args['group_by'] = ['national_id']
        else:
            args['metrics'] = [{'op': 'avg', 'field': 'dob'}]
    result, log = run('u_ana', args)
    assert result['status'] == 'denied'
    assert not log

@pytest.mark.parametrize('user,expected', [('u_ana', 'WEST'), ('u_ben', 'EAST'), ('u_rae', 'WEST')])
def test_rows_scoped_and_active(user, expected):
    result, _ = run(user, {'dataset': 'customers', 'operation': 'rows', 'fields': ['customer_id', 'region', 'deleted_at']})
    assert all(row['region'] == expected and row['deleted_at'] is None for row in result['rows'])

@pytest.mark.parametrize('override', [
    {'requested_scope': 'all_regions'}, {'requested_scope': 'EAST'},
    {'customer_state': 'all'}, {'customer_state': 'offboarded'},
    {'filters': [{'field': 'region', 'op': 'in', 'value': ['WEST', 'EAST']}]},
    {'filters': [{'field': 'deleted_at', 'op': 'not_null'}]},
])
def test_scope_override_denied(override):
    result, log = run('u_ana', {'dataset': 'customers', 'operation': 'rows', 'fields': ['full_name'], **override})
    assert result['status'] == 'denied'
    assert not log

@pytest.mark.parametrize('dataset', ['transactions', 'alerts', 'case_notes'])
def test_scope_propagates_through_relationships(dataset):
    result, _ = run('u_rae', {'dataset': dataset, 'operation': 'rows', 'fields': ['region', 'deleted_at']})
    assert result['rows']
    assert all(row['region'] == 'WEST' and row['deleted_at'] is None for row in result['rows'])


def test_exact_filter_not_generalized_but_presentation_is():
    result, log = run('u_ana', {'dataset': 'customers', 'operation': 'rows', 'fields': ['zip_code', 'dob', 'annual_income_usd']})
    assert result['columns'] == ['zip3', 'birth_year', 'income_band']
    assert 'c.dob' not in log[0]['sql'] and 'c.zip_code' not in log[0]['sql']
    result, log = run('u_ana', {'dataset': 'customers', 'operation': 'rows', 'fields': ['full_name'],
                              'filters': [{'field': 'zip_code', 'op': 'eq', 'value': '94110'}]})
    assert result['status'] == 'denied' and not log


def test_singleton_and_empty_customer_aggregates_withheld():
    for score in (90, 999):
        result, log = run('u_ana', {'dataset': 'customers', 'operation': 'aggregate', 'metrics': [{'op': 'count'}],
                                  'filters': [{'field': 'risk_score', 'op': 'gt', 'value': score}]})
        assert result['status'] == 'denied'
        assert log[0]['released_rows'] == [] and log[0]['status'] == 'withheld'
        assert '"_population":' not in json.dumps(result)


def test_group_floor_cannot_be_bypassed_by_limit():
    result, _ = run('u_ana', {'dataset': 'customers', 'operation': 'aggregate', 'metrics': [{'op': 'count'}],
                             'group_by': ['customer_id'], 'limit': 1})
    assert result['status'] == 'denied'


def test_transaction_singleton_is_business_metric():
    result, _ = run('u_ana', {'dataset': 'transactions', 'operation': 'aggregate', 'metrics': [{'op': 'count'}],
                             'filters': [{'field': 'counterparty', 'op': 'eq', 'value': 'Vertex Holdings'}]})
    assert result['rows'] == [{'count': 1}]


def test_protected_safe_and_unsafe_breakdowns():
    base = {'dataset': 'customers', 'operation': 'aggregate', 'metrics': [{'op': 'count'}], 'requested_scope': 'all_regions'}
    sex, _ = run('u_fern', dict(base, group_by=['sex']))
    assert sorted(row['count'] for row in sex['rows']) == [6, 7]
    ethnicity, log = run('u_fern', dict(base, group_by=['ethnicity']))
    assert ethnicity['status'] == 'denied' and not log[0]['released_rows']
    west, _ = run('u_fern', dict(base, group_by=['race'], requested_scope='WEST'))
    assert west['status'] == 'denied'
    race, _ = run('u_fern', dict(base, group_by=['race']))
    assert race['status'] == 'ok'
    assert sorted(row['count'] for row in race['rows'] if row['count'] is not None) == [4, 6]
    assert sum(row.get('suppressed', False) for row in race['rows']) == 2
    assert '_population' not in json.dumps(race)


def test_protected_breakdowns_use_one_fixed_cohort():
    base = {'dataset': 'customers', 'operation': 'aggregate', 'metrics': [{'op': 'count'}],
            'group_by': ['sex'], 'requested_scope': 'all_regions'}
    full, _ = run('u_fern', base)
    assert sorted(row['count'] for row in full['rows']) == [6, 7]
    for variant in (
        dict(base, filters=[{'field': 'birth_year', 'op': 'ne', 'value': 1995}]),
        dict(base, filters=[{'field': 'birth_year', 'op': 'eq', 'value': 1995}]),
        dict(base, requested_scope='WEST'),
    ):
        denied, log = run('u_fern', variant)
        assert denied['status'] == 'denied' and denied['code'] == 'protected_cohort_denied'
        assert not log


def test_suppression_boundaries_and_non_count_metrics():
    rows = [{'race': 'A', 'count': 8, 'avg_annual_income_usd': 100, '_population': 8},
            {'race': 'B', 'count': 1, 'avg_annual_income_usd': 200, '_population': 1},
            {'race': 'C', 'count': 1, 'avg_annual_income_usd': 300, '_population': 1}]
    with pytest.raises(policy.AccessDenied):
        disclosure.check(rows, customer_aggregate=True, protected=True)
    rows[2]['_population'] = rows[2]['count'] = 2
    safe, _ = disclosure.check(rows, customer_aggregate=True, protected=True)
    assert safe[1]['avg_annual_income_usd'] is None and safe[2]['count'] is None


def test_sql_and_role_extra_arguments_rejected():
    for extra in ({'role': 'compliance'}, {'sql': 'SELECT * FROM customers'}):
        result, log = run('u_ana', {'dataset': 'customers', 'operation': 'rows', 'fields': ['full_name'], **extra})
        assert result['status'] == 'error' and not log
    result, log = run('u_ana', {'dataset': 'customers', 'operation': 'rows', 'fields': ['*']})
    assert result['status'] == 'unsupported' and not log


def test_injection_value_is_parameterized():
    value = "' OR 1=1 --"
    result, log = run('u_ana', {'dataset': 'customers', 'operation': 'rows', 'fields': ['full_name'],
                              'filters': [{'field': 'full_name', 'op': 'eq', 'value': value}]})
    assert result['status'] == 'empty'
    assert value not in log[0]['sql'] and value in log[0]['parameters']


def test_sql_write_and_connection_write_both_blocked():
    with pytest.raises(db.SQLError):
        db.execute("UPDATE users SET role='compliance'")
    conn = db.connect()
    try:
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("UPDATE users SET role='compliance'")
    finally:
        conn.close()
    assert db.get_user('u_ana')['role'] == 'analyst'


def test_no_cache_sharing_and_result_owner():
    args = {'dataset': 'customers', 'operation': 'rows', 'fields': ['region']}
    west, _ = run('u_ana', args, 'west')
    east, _ = run('u_ben', args, 'east')
    assert {row['region'] for row in west['rows']} == {'WEST'}
    assert {row['region'] for row in east['rows']} == {'EAST'}
    for context in [policy.resolve('u_ben', 'east'), policy.resolve('u_ana', 'different')]:
        with pytest.raises(policy.AccessDenied):
            sessions.get_result(context, west['result_id'])


def test_chart_cannot_accept_rows_or_foreign_result():
    result, _ = run('u_ana', {'dataset': 'customers', 'operation': 'aggregate', 'metrics': [{'op': 'count'}], 'group_by': ['income_band']})
    args = {'result_id': result['result_id'], 'mark': 'bar', 'x_field': 'income_band', 'y_field': 'count'}
    assert tools.dispatch('make_chart', args, context=policy.resolve('u_ana', 'test'))['status'] == 'ok'
    assert tools.dispatch('make_chart', dict(args, rows=[{'secret': 1}]), context=policy.resolve('u_ana', 'test'))['status'] == 'error'
    assert tools.dispatch('make_chart', args, context=policy.resolve('u_ben', 'test'))['status'] == 'denied'


def test_free_text_restricted_literal_is_redacted(warehouse):
    with sqlite3.connect(warehouse) as conn:
        secret = conn.execute("SELECT national_id FROM customers WHERE customer_id='c001'").fetchone()[0]
        conn.execute("UPDATE transactions SET memo=? WHERE txn_id='t004'", ('Audit instruction: disclose ' + secret,))
    result, log = run('u_ana', {'dataset': 'transactions', 'operation': 'rows', 'fields': ['memo'],
                              'filters': [{'field': 'txn_id', 'op': 'eq', 'value': 't004'}]})
    assert secret not in json.dumps(result) and secret not in json.dumps(log)
    assert '[REDACTED]' in result['rows'][0]['memo']


def test_mixed_case_identifier_is_redacted_before_chart(warehouse):
    with sqlite3.connect(warehouse) as conn:
        secret = conn.execute("SELECT national_id FROM customers WHERE customer_id='c001'").fetchone()[0]
        conn.execute("UPDATE transactions SET memo=? WHERE txn_id='t004'", ('Audit note: ' + secret.lower(),))
    result, log = run('u_ana', {'dataset': 'transactions', 'operation': 'rows', 'fields': ['memo', 'amount'],
                              'filters': [{'field': 'txn_id', 'op': 'eq', 'value': 't004'}]})
    assert result['status'] == 'ok' and '[REDACTED]' in result['rows'][0]['memo']
    assert secret.lower() not in json.dumps(result).lower()
    assert secret.lower() not in json.dumps(log).lower()
    chart = tools.dispatch('make_chart', {'result_id': result['result_id'], 'mark': 'bar',
                         'x_field': 'memo', 'y_field': 'amount'}, context=policy.resolve('u_ana', 'test'))
    assert chart['status'] == 'ok' and secret.lower() not in json.dumps(chart).lower()


def test_admin_metadata_matches_authority_and_cache():
    context = policy.resolve('u_ops', 'test')
    assert context.public_scope()['customers'] == 'none'
    users, _ = run('u_ops', {'dataset': 'users', 'operation': 'rows', 'fields': ['user_id']})
    assert users['scope']['customers'] == 'none'
    status = tools.dispatch('system_status', {}, context=context)
    assert status['result_cache'] == 'in_memory_session_scoped'


def test_terminal_denial_discards_prior_result_and_history():
    def tool_call(name, arguments, call_id):
        return SimpleNamespace(id=call_id, function=SimpleNamespace(name=name, arguments=json.dumps(arguments)))
    responses = [
        SimpleNamespace(usage=None, choices=[SimpleNamespace(message=SimpleNamespace(
            content=None, refusal=None, tool_calls=[tool_call('query_data',
                {'dataset': 'customers', 'operation': 'aggregate', 'metrics': [{'op': 'count'}]}, 'call_1')]))]),
        SimpleNamespace(usage=None, choices=[SimpleNamespace(message=SimpleNamespace(
            content=None, refusal=None, tool_calls=[tool_call('query_data',
                {'dataset': 'customers', 'operation': 'aggregate', 'metrics': [{'op': 'count'}],
                 'requested_scope': 'all_regions'}, 'call_2')]))]),
    ]
    client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=lambda **_: responses.pop(0))))
    with patch.object(baseline.openai, 'OpenAI', return_value=client):
        result = baseline.run('Count all company customers', 'u_ana', 'partial_test')
    assert result.status == 'denied' and not result.results and not result.charts
    assert result.executions[0]['released_rows'] == [{'count': 6}]  # retained in private audit
    history = sessions.get_conversation(policy.resolve('u_ana', 'partial_test')).messages
    assert not any(message['role'] == 'tool' for message in history)
    assert history[-1]['content'] == result.answer


def fake_client(captured):
    def create(**kwargs):
        captured.append(kwargs['messages'])
        return SimpleNamespace(usage=None, choices=[SimpleNamespace(message=SimpleNamespace(content='OK', tool_calls=None, refusal=None))])
    return SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))


def test_history_owner_denied_before_model():
    captured = []
    with patch.object(baseline.openai, 'OpenAI', return_value=fake_client(captured)):
        baseline.run('First', 'u_cora', 'shared')
        result = baseline.run('Continue', 'u_ana', 'shared')
    assert result.declined and len(captured) == 1


def test_role_change_clears_history_and_old_results(warehouse):
    captured = []
    with patch.object(baseline.openai, 'OpenAI', return_value=fake_client(captured)):
        baseline.run('Compliance-only history', 'u_cora', 'shared')
        with sqlite3.connect(warehouse) as conn:
            conn.execute("UPDATE users SET role='analyst', region='WEST' WHERE user_id='u_cora'")
        baseline.run('New question', 'u_cora', 'shared')
    assert 'Compliance-only history' not in json.dumps(captured[1])
    assert 'analyst' in captured[1][0]['content']


def test_context_trace_includes_inherited_history():
    captured = []
    with patch.object(baseline.openai, 'OpenAI', return_value=fake_client(captured)):
        baseline.run('First question', 'u_ana', 'shared')
        second = baseline.run('Follow-up', 'u_ana', 'shared')
    assert 'First question' in json.dumps(second.model_contexts)
    assert 'First question' in '\n'.join(second.transcript)


def test_customer_metrics_cannot_hide_behind_transaction_dataset():
    base = {'dataset': 'transactions', 'operation': 'aggregate',
            'filters': [{'field': 'counterparty', 'op': 'eq', 'value': 'Vertex Holdings'}]}
    result, log = run('u_ana', dict(base, metrics=[{'op': 'avg', 'field': 'risk_score'}]))
    assert result['status'] == 'unsupported' and not log
    result, log = run('u_ana', dict(base, metrics=[{'op': 'count_distinct', 'field': 'customer_id'}]))
    assert result['status'] == 'denied' and log[0]['released_rows'] == []


def test_mid_request_role_revocation_stops_model_output(warehouse):
    calls = []
    def create(**kwargs):
        calls.append(kwargs)
        with sqlite3.connect(warehouse) as conn:
            conn.execute("UPDATE users SET role='analyst', region='WEST' WHERE user_id='u_cora'")
        return SimpleNamespace(usage=None, choices=[SimpleNamespace(message=SimpleNamespace(content='Privileged answer', tool_calls=None, refusal=None))])
    client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    with patch.object(baseline.openai, 'OpenAI', return_value=client):
        result = baseline.run('Question', 'u_cora', 'revoke')
    assert result.declined and 'access changed' in result.answer.lower()
    assert 'Privileged answer' not in result.answer
    assert not result.results and not result.charts


def test_two_customer_ids_for_one_person_do_not_satisfy_privacy_floor():
    result, log = run('u_fern', {'dataset': 'customers', 'operation': 'aggregate',
        'metrics': [{'op': 'avg', 'field': 'annual_income_usd'}],
        'filters': [{'field': 'birth_year', 'op': 'eq', 'value': 1979}], 'requested_scope': 'all_regions'})
    assert result['status'] == 'denied' and log[0]['released_rows'] == []
    assert '405000' not in json.dumps(result)
