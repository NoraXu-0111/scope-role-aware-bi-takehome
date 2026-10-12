import pytest
from agent import policy, tools

@pytest.mark.parametrize('user,args,expected', [
    ('u_ana', {'dataset': 'customers', 'metrics': [{'op': 'count'}]}, [{'count': 6}]),
    ('u_ana', {'dataset': 'customers', 'metrics': [{'op': 'avg', 'field': 'risk_score'}]}, [{'avg_risk_score': 60.5}]),
    ('u_rae', {'dataset': 'customers', 'metrics': [{'op': 'avg', 'field': 'annual_income_usd'}]}, [{'avg_annual_income_usd': 211500.0}]),
    ('u_ana', {'dataset': 'alerts', 'metrics': [{'op': 'count'}], 'filters': [{'field': 'status', 'op': 'eq', 'value': 'OPEN'}]}, [{'count': 5}]),
    ('u_ana', {'dataset': 'transactions', 'metrics': [{'op': 'sum', 'field': 'amount'}], 'filters': [{'field': 'channel', 'op': 'eq', 'value': 'wire'}, {'field': 'currency', 'op': 'eq', 'value': 'USD'}]}, [{'sum_amount': 63800.5}]),
    ('u_ana', {'dataset': 'transactions', 'metrics': [{'op': 'sum', 'field': 'amount'}], 'filters': [{'field': 'channel', 'op': 'eq', 'value': 'ach'}, {'field': 'currency', 'op': 'eq', 'value': 'USD'}], 'period': {'start': '2026-03-01T00:00:00Z', 'end': '2026-04-01T00:00:00Z'}}, [{'sum_amount': 36380.0}]),
])
def test_metrics(user, args, expected):
    result = tools.dispatch('query_data', dict(args, operation='aggregate'), context=policy.resolve(user, 'test'))
    assert result['status'] == 'ok'
    assert result['rows'] == expected


def test_currencies_are_never_combined():
    result = tools.dispatch('query_data', {'dataset': 'transactions', 'operation': 'aggregate', 'metrics': [{'op': 'sum', 'field': 'amount'}]}, context=policy.resolve('u_ana', 'test'))
    assert {row['currency'] for row in result['rows']} == {'USD', 'EUR'}
    assert result['notes']


def test_detail_cap_does_not_change_aggregate():
    context = policy.resolve('u_ana', 'test')
    rows = tools.dispatch('query_data', {'dataset': 'customers', 'operation': 'rows', 'fields': ['full_name'], 'limit': 2}, context=context)
    assert len(rows['rows']) == 2 and rows['truncated']
    aggregate = tools.dispatch('query_data', {'dataset': 'customers', 'operation': 'aggregate', 'metrics': [{'op': 'count'}], 'limit': 2}, context=context)
    assert aggregate['rows'] == [{'count': 6}]


def test_compliance_can_explicitly_include_offboarded():
    result = tools.dispatch('query_data', {'dataset': 'customers', 'operation': 'aggregate', 'metrics': [{'op': 'count'}], 'customer_state': 'all', 'requested_scope': 'all_regions'}, context=policy.resolve('u_cora', 'test'))
    assert result['rows'] == [{'count': 15}]


def test_channel_and_currency_case_normalization():
    result = tools.dispatch('query_data', {'dataset': 'transactions', 'operation': 'aggregate',
        'metrics': [{'op': 'sum', 'field': 'amount'}],
        'filters': [{'field': 'channel', 'op': 'eq', 'value': 'ACH'}, {'field': 'currency', 'op': 'eq', 'value': 'usd'}],
        'period': {'start': '2026-03-01T00:00:00Z', 'end': '2026-04-01T00:00:00Z'}}, context=policy.resolve('u_ana','test'))
    assert result['rows'] == [{'sum_amount': 36380.0}]


def test_admin_user_aggregate_is_not_a_customer_attribute_aggregate():
    result = tools.dispatch('query_data', {'dataset': 'users', 'operation': 'aggregate',
        'metrics': [{'op': 'count_distinct', 'field': 'full_name'}]}, context=policy.resolve('u_ops','test'))
    assert result['rows'] == [{'count_distinct_full_name': 6}]
