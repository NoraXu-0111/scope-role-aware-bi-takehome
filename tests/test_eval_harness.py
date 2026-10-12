from eval.run_eval import matching_result


def test_structured_score_rejects_wrong_group_labels_and_scope():
    expected = {'dataset': 'customers', 'region': 'WEST', 'rows': [
        {'income_band': 'high', 'count': 2},
        {'income_band': 'middle', 'count': 2},
        {'income_band': 'upper-middle', 'count': 2},
    ]}
    valid = {'dataset': 'customers', 'operation': 'aggregate', 'scope': {'region': 'WEST'},
             'rows': list(expected['rows'])}
    assert matching_result([valid], expected, 0)
    distinct_customer_count = dict(valid, rows=[
        {'income_band': row['income_band'], 'count_distinct_customer_id': row['count']}
        for row in expected['rows']])
    assert matching_result([distinct_customer_count], expected, 0)
    assert not matching_result([dict(valid, scope={'region': 'EAST'})], expected, 0)
    assert not matching_result([dict(valid, rows=[
        {'income_band': 'high', 'count': 2},
        {'income_band': 'middle', 'count': 2},
        {'income_band': 'lower-middle', 'count': 2},
    ])], expected, 0)


def test_transaction_count_does_not_accept_customer_count_alias():
    expected = {'dataset': 'transactions', 'region': 'WEST', 'rows': [{'count': 1}]}
    customer_count = {'dataset': 'transactions', 'operation': 'aggregate',
                      'scope': {'region': 'WEST'}, 'rows': [{'count_distinct_customer_id': 1}]}
    assert not matching_result([customer_count], expected, 0)
