from agent import baseline
from eval.run_eval import REPORT, load, matching_query_evidence, matching_result, run_questions


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
    assert not matching_result([valid], dict(expected, scope={'customers': 'all'}), 0)
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


def test_followup_query_evidence_must_come_from_one_current_turn_query():
    expected = {'sql_contains': ['amount_minor', 'channel'], 'parameters_include': [30000, 'wire']}
    correct = {'sql': 'SELECT COUNT(*) FROM transactions WHERE amount_minor / 100 > ? AND channel = ?',
               'parameters': [30000, 'wire'], 'status': 'ok'}
    assert matching_query_evidence([correct], expected)
    assert not matching_query_evidence([], expected)
    assert not matching_query_evidence([dict(correct, parameters=[30000])], expected)
    assert not matching_query_evidence([dict(correct, status='withheld')], expected)
    assert not matching_query_evidence([{'sql': correct['sql'], 'parameters': [30000], 'status': 'ok'},
                                       {'sql': 'SELECT 1', 'parameters': ['wire'], 'status': 'ok'}], expected)


def test_followup_score_rejects_a_lucky_answer_without_current_turn_data(monkeypatch):
    case = next(case for case in load('questions.yaml') if case['id'] == 'f1')
    calls = []

    def fake_run(question, user, conversation):
        calls.append((question, user, conversation))
        if len(calls) == 1:
            return baseline.AgentResult(answer='1', results=[{'status': 'ok', 'rows': [{'count': 1}]}])
        return baseline.AgentResult(answer='1 was a wire', status='ok')

    monkeypatch.setattr(baseline, 'reset_state', lambda: None)
    monkeypatch.setattr(baseline, 'run', fake_run)
    REPORT.clear()
    passed, total, failures = run_questions([case], False)
    assert (passed, total) == (0, 1) and failures
    assert calls[0][2] == calls[1][2] == 'eval_f1'
    REPORT.clear()
