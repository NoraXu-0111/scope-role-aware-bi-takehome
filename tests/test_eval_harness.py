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
    assert not matching_result([dict(valid, scope={'region': 'EAST'})], expected, 0)
    assert not matching_result([dict(valid, rows=[
        {'income_band': 'high', 'count': 2},
        {'income_band': 'middle', 'count': 2},
        {'income_band': 'lower-middle', 'count': 2},
    ])], expected, 0)
