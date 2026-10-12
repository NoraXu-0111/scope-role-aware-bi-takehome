"""A finite query language compiled by trusted code, not executable model SQL."""
from __future__ import annotations

import re
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator
from . import db, disclosure, sessions
from .policy import AccessContext, AccessDenied, CUSTOMER_COLUMNS, T2, T3, T4, T5

class Unsupported(Exception):
    pass

class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, allow_inf_nan=False)

class Filter(StrictModel):
    field: str = Field(min_length=1, max_length=64)
    op: Literal['eq', 'ne', 'gt', 'gte', 'lt', 'lte', 'in', 'contains', 'is_null', 'not_null']
    value: str | int | float | list[str | int | float] | None = None

class Metric(StrictModel):
    op: Literal['count', 'count_distinct', 'sum', 'avg', 'min', 'max']
    field: str | None = None

    def label(self) -> str:
        return self.op if self.field is None else f'{self.op}_{self.field}'

class Order(StrictModel):
    field: str
    direction: Literal['asc', 'desc'] = 'asc'

class Period(StrictModel):
    start: str
    end: str

    @model_validator(mode='after')
    def check_dates(self):
        try:
            start = datetime.fromisoformat(self.start.replace('Z', '+00:00'))
            end = datetime.fromisoformat(self.end.replace('Z', '+00:00'))
            if start.utcoffset() is None or end.utcoffset() is None or start >= end:
                raise ValueError()
            self.start = start.isoformat(timespec='seconds').replace('+00:00', 'Z')
            self.end = end.isoformat(timespec='seconds').replace('+00:00', 'Z')
            if not self.start.endswith('Z') or not self.end.endswith('Z'):
                raise ValueError()
        except ValueError:
            raise ValueError('Provide an increasing UTC start/end interval.') from None
        return self

class QueryPlan(StrictModel):
    dataset: Literal['customers', 'transactions', 'alerts', 'case_notes', 'users']
    operation: Literal['rows', 'aggregate']
    fields: list[str] = Field(default_factory=list, max_length=20)
    metrics: list[Metric] = Field(default_factory=list, max_length=8)
    group_by: list[str] = Field(default_factory=list, max_length=3)
    filters: list[Filter] = Field(default_factory=list, max_length=12)
    period: Period | None = None
    requested_scope: Literal['own_region', 'all_regions', 'WEST', 'EAST', 'CENTRAL'] = 'own_region'
    customer_state: Literal['active', 'all', 'offboarded'] = 'active'
    order_by: list[Order] = Field(default_factory=list, max_length=3)
    limit: int = Field(default=100, ge=1, le=200)

SOURCES = {
    'customers': 'customers c',
    'transactions': 'transactions t JOIN customers c ON c.customer_id = t.customer_id',
    'alerts': 'alerts a JOIN transactions t ON t.txn_id = a.txn_id JOIN customers c ON c.customer_id = t.customer_id',
    'case_notes': 'case_notes n JOIN alerts a ON a.alert_id = n.alert_id JOIN transactions t ON t.txn_id = a.txn_id JOIN customers c ON c.customer_id = t.customer_id',
    'users': 'users u',
}
TX_FIELDS = {'txn_id', 'amount_minor', 'currency', 'channel', 'occurred_at', 'counterparty', 'memo'}
ALERT_FIELDS = {'alert_id', 'rule_id', 'severity', 'status'}
NOTE_FIELDS = {'note_id', 'author_id', 'body', 'created_at'}
USER_FIELDS = {'user_id', 'full_name', 'role', 'region'}
NUMERIC = {'risk_score', 'birth_year', 'annual_income_usd', 'amount_minor', 'amount'}
GENERALIZED = {'zip_code': 'zip3', 'dob': 'birth_year', 'annual_income_usd': 'income_band'}


def field_catalog(context: AccessContext, dataset: str) -> dict[str, str]:
    if dataset not in context.policy.datasets:
        raise AccessDenied('This identity is not permitted to access this dataset.', 'dataset_denied')
    if dataset == 'users':
        return {name: f'u.{name}' for name in USER_FIELDS}
    result = {name: f'c.{name}' for name in context.policy.customer_columns}
    if dataset in {'transactions', 'alerts', 'case_notes'}:
        extra = TX_FIELDS if not context.policy.aggregate_only else {'amount_minor', 'currency', 'channel', 'occurred_at'}
        result.update({name: f't.{name}' for name in extra})
        result['amount'] = '(t.amount_minor / 100.0)'
    if dataset in {'alerts', 'case_notes'}:
        result.update({name: f'a.{name}' for name in ALERT_FIELDS})
    if dataset == 'case_notes':
        result.update({name: f'n.{name}' for name in NOTE_FIELDS})
    return result


def capabilities(context: AccessContext) -> dict:
    return {'scope': context.public_scope(),
            'datasets': {name: sorted(field_catalog(context, name)) for name in sorted(context.policy.datasets)},
            'metrics': ['count', 'count_distinct(field)', 'sum(numeric field)', 'avg(numeric field)', 'min(numeric field)', 'max(numeric field)'],
            'generalizations': GENERALIZED if context.role == 'analyst' else {},
            'rules': ['amount is in native major currency units; amount_minor is in minor units',
                      'money across currencies must be grouped by currency; no FX conversion',
                      'customer aggregates: at least 2 distinct customers per group',
                      'T5: customer count or mean income, one protected grouping; no protected filters',
                      'region and lifecycle filters are enforced by the compiler']}


def compile_plan(plan: QueryPlan, context: AccessContext) -> tuple[str, list, bool, bool, list[str], list[str]]:
    catalog = field_catalog(context, plan.dataset)
    notes: list[str] = []
    redactions: list[str] = []
    if context.policy.aggregate_only and plan.operation != 'aggregate':
        raise AccessDenied('This role permits aggregate reporting only, never individual rows.', 'aggregate_only')
    if context.policy.own_region and plan.requested_scope not in {'own_region', context.region}:
        raise AccessDenied('Your access covers only your own region; a wider population cannot be reported.', 'region_denied')
    if context.policy.active_only and plan.customer_state != 'active':
        raise AccessDenied('Your access covers active customers only.', 'offboarded_denied')

    def expression(name: str) -> str:
        if name not in catalog:
            if name in CUSTOMER_COLUMNS or name in TX_FIELDS | NOTE_FIELDS | USER_FIELDS:
                raise AccessDenied('The requested field cannot be used by this identity, including in filters or ordering.', 'column_denied')
            raise Unsupported('Unknown field. Use the available field catalog.')
        return catalog[name]

    # Coarser substitutions apply to row presentation only. Exact predicates and
    # aggregate expressions are never silently changed to a different question.
    fields = list(plan.fields)
    if plan.operation == 'rows' and context.role == 'analyst' and plan.dataset != 'users':
        for index, name in enumerate(fields):
            if name in GENERALIZED:
                fields[index] = GENERALIZED[name]
                notes.append(f'{name} is returned as {fields[index]}, a generalized value.')
                redactions.append(f'{name} -> {fields[index]}')
    groups = list(plan.group_by)
    all_refs = fields + groups + [f.field for f in plan.filters] + [m.field for m in plan.metrics if m.field]
    for name in all_refs:
        expression(name)
    for order in plan.order_by:
        if order.field not in {m.label() for m in plan.metrics}:
            expression(order.field)
    if len(fields) != len(set(fields)) or len(groups) != len(set(groups)):
        raise Unsupported('Duplicate fields are not supported.')
    if plan.operation == 'rows' and (not fields or plan.metrics or groups):
        raise Unsupported('Row queries need fields and cannot include aggregate metrics.')
    if plan.operation == 'aggregate' and (not plan.metrics or fields):
        raise Unsupported('Aggregate queries need metrics and group_by, without row fields.')

    protected = bool(set(all_refs) & T5)
    customer_aggregate = plan.dataset != 'users' and plan.operation == 'aggregate' and (plan.dataset == 'customers' or
                         any(m.field in CUSTOMER_COLUMNS for m in plan.metrics if m.field))
    if plan.dataset not in {'customers', 'users'} and any(
            m.field in CUSTOMER_COLUMNS and m.op in {'sum', 'avg', 'min', 'max'} for m in plan.metrics if m.field):
        raise Unsupported('Customer attribute metrics must use the customers dataset to preserve customer grain.')
    if protected:
        if plan.dataset != 'customers' or plan.operation != 'aggregate' or len(groups) != 1 or groups[0] not in T5:
            raise Unsupported('Protected-class reports support one protected grouping over customers.')
        if any(f.field in T5 for f in plan.filters):
            raise Unsupported('Protected-class attributes cannot be used as report filters.')
        # Per-query cell floors cannot protect complementary cohorts. Keep every
        # T5 breakdown on the same company-wide active population.
        if plan.filters or plan.period or plan.requested_scope not in {'own_region', 'all_regions'}:
            raise AccessDenied(
                'Protected-class breakdowns use the company-wide active cohort. '
                'Filtered, dated, or regional breakdowns could reveal an individual by subtraction.',
                'protected_cohort_denied',
            )
        if any(not (m.op == 'count' and m.field is None or m.op == 'avg' and m.field == 'annual_income_usd') for m in plan.metrics):
            raise Unsupported('Protected reports support customer counts and average annual income.')

    # Never combine currencies into one amount, even if the planner forgets.
    money = any(m.field in {'amount', 'amount_minor'} and m.op != 'count_distinct' for m in plan.metrics)
    one_currency = any(f.field == 'currency' and f.op == 'eq' for f in plan.filters)
    if money and not one_currency and 'currency' not in groups:
        groups.insert(0, 'currency')
        notes.append('Amounts are separated by currency because no FX rates are available.')

    where: list[str] = []
    params: list = []
    if plan.dataset != 'users':
        if context.policy.own_region:
            where.append('c.region = ?')
            params.append(context.region)
        elif plan.requested_scope in {'WEST', 'EAST', 'CENTRAL'}:
            where.append('c.region = ?')
            params.append(plan.requested_scope)
        if plan.customer_state == 'active':
            where.append('c.deleted_at IS NULL')
        elif plan.customer_state == 'offboarded':
            where.append('c.deleted_at IS NOT NULL')
    for f in plan.filters:
        expr = expression(f.field)
        if f.field in {'region', 'currency'}:
            if isinstance(f.value, list):
                f.value = [v.upper() if isinstance(v, str) else v for v in f.value]
            elif isinstance(f.value, str):
                f.value = f.value.upper()
        if context.policy.own_region and f.field == 'region':
            values = f.value if isinstance(f.value, list) else [f.value]
            if f.op not in {'eq', 'in'} or any(v != context.region for v in values):
                raise AccessDenied('The requested region filter exceeds your access.', 'region_denied')
        if f.field == 'deleted_at' and context.policy.active_only and f.op != 'is_null':
            raise AccessDenied('Offboarded customers are outside your access.', 'offboarded_denied')
        if f.op in {'is_null', 'not_null'}:
            where.append(f'{expr} IS ' + ('NOT NULL' if f.op == 'not_null' else 'NULL'))
            continue
        values = f.value if isinstance(f.value, list) else [f.value]
        if not values or any(v is None for v in values):
            raise Unsupported('A filter value is required.')
        if len(values) > 50:
            raise Unsupported('Too many filter values.')
        if f.field in NUMERIC and any(type(v) not in {int, float} for v in values):
            raise Unsupported('Numeric fields require numeric filter values.')
        if f.field not in NUMERIC and any(type(v) is not str for v in values):
            raise Unsupported('Text fields require text filter values.')
        if any(isinstance(v, str) and len(v) > 500 for v in values):
            raise Unsupported('Filter values are too long.')
        if f.field in {'status', 'channel', 'segment', 'role'}:
            expr = f'LOWER({expr})'
            values = [v.lower() for v in values]
        if f.op == 'in':
            where.append(f'{expr} IN (' + ','.join('?' for _ in values) + ')')
            params.extend(values)
        elif f.op == 'contains':
            if f.field in NUMERIC or len(values) != 1:
                raise Unsupported('contains requires one text value.')
            where.append(f"{expr} LIKE ? ESCAPE '\\'")
            params.append('%' + str(values[0]).replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%')
        else:
            if len(values) != 1:
                raise Unsupported('This filter takes one value.')
            op = {'eq': '=', 'ne': '!=', 'gt': '>', 'gte': '>=', 'lt': '<', 'lte': '<='}[f.op]
            where.append(f'{expr} {op} ?')
            params.append(values[0])
    if plan.period:
        time_field = 'created_at' if plan.dataset == 'case_notes' else 'occurred_at'
        expr = expression(time_field)
        where.extend([f'{expr} >= ?', f'{expr} < ?'])
        params.extend([plan.period.start, plan.period.end])

    selects: list[str] = []
    if plan.operation == 'rows':
        selects = [f'{expression(name)} AS "{name}"' for name in fields]
    else:
        selects = [f'{expression(name)} AS "{name}"' for name in groups]
        seen = set(groups)
        for m in plan.metrics:
            label = m.label()
            if label in seen:
                raise Unsupported('Duplicate metric labels.')
            seen.add(label)
            if m.op == 'count':
                if m.field is not None:
                    raise Unsupported('count takes no field; use count_distinct for distinct values.')
                expr = 'COUNT(*)'
            elif not m.field:
                raise Unsupported('This metric requires a field.')
            elif m.op == 'count_distinct':
                expr = f'COUNT(DISTINCT {expression(m.field)})'
            else:
                if m.field not in NUMERIC:
                    raise Unsupported('Numeric metrics require numeric fields.')
                expr = f'{m.op.upper()}({expression(m.field)})'
            selects.append(f'{expr} AS "{label}"')
        if customer_aggregate:
            selects.append('COUNT(DISTINCT c.customer_id) AS "_population"')
            # Internal-only privacy support: two records belonging to the same
            # human must not satisfy the floor. The identifier is never returned.
            selects.append('COUNT(DISTINCT c.national_id) AS "_subjects"')
    sql = 'SELECT ' + ', '.join(selects) + ' FROM ' + SOURCES[plan.dataset]
    if where:
        sql += ' WHERE ' + ' AND '.join(where)
    if groups:
        sql += ' GROUP BY ' + ', '.join(expression(name) for name in groups)
    if plan.order_by:
        valid = set(groups if plan.operation == 'aggregate' else fields) | {m.label() for m in plan.metrics}
        if any(o.field not in valid for o in plan.order_by):
            raise Unsupported('Ordering is limited to returned fields or metrics.')
        sql += ' ORDER BY ' + ', '.join(f'"{o.field}" {o.direction.upper()}' for o in plan.order_by)
    elif groups:
        sql += ' ORDER BY ' + ', '.join(expression(name) for name in groups)
    if plan.operation == 'rows':
        sql += ' LIMIT ?'
        params.append(plan.limit + 1)
    return sql, params, customer_aggregate, protected, notes, redactions


def scrub_text(rows: list[dict], context: AccessContext, execution_log: list[dict] | None = None) -> tuple[list[dict], list[str]]:
    """Free text can contain sensitive values even when the column itself is allowed.

    Match known fixture identifiers; this is not a universal PII/DLP detector.
    """
    if not any('body' in row or 'memo' in row for row in rows):
        return rows, []
    sql = 'SELECT ' + ', '.join(sorted(CUSTOMER_COLUMNS)) + ' FROM customers'
    customers = db.execute(sql)
    if execution_log is not None:
        execution_log.append({'kind': 'kernel_lookup', 'purpose': 'free_text_redaction',
                              'sql': sql, 'parameters': [], 'status': 'internal_only',
                              'execution_row_count': len(customers), 'released_rows': [],
                              'released_row_count': 0, 'redactions': []})
    banned: set[str] = set()
    forbidden = (T2 | T3 | T4 | T5) - context.policy.customer_columns
    visible = [c for c in customers if (not context.policy.own_region or c['region'] == context.region)
               and (not context.policy.active_only or c['deleted_at'] is None)]
    visible_names = {c['full_name'] for c in visible}
    visible_ids = {c['customer_id'] for c in visible}
    for c in customers:
        banned.update(str(c[name]) for name in forbidden if c[name] is not None)
        if c['customer_id'] not in visible_ids:
            banned.add(c['customer_id'])
            if c['full_name'] not in visible_names:
                banned.add(c['full_name'])
            banned.update(str(c[name]) for name in T2 | T3 | T4 if c[name] is not None)
    pattern = re.compile(r'(?<![\w])(?:' + '|'.join(re.escape(v) for v in sorted(banned, key=len, reverse=True)) + r')(?![\w])', re.IGNORECASE) if banned else None
    redacted = False
    for row in rows:
        for name in ('memo', 'body'):
            if isinstance(row.get(name), str) and pattern:
                row[name], count = pattern.subn('[REDACTED]', row[name])
                redacted = redacted or bool(count)
    return rows, ['Known restricted values were redacted from untrusted free text.'] if redacted else []


def execute(plan: QueryPlan, context: AccessContext, execution_log: list[dict]) -> dict:
    sql, params, customer_aggregate, protected, notes, redactions = compile_plan(plan, context)
    log = {'sql': sql, 'parameters': params, 'released_rows': [], 'released_row_count': 0,
           'status': 'executing', 'redactions': redactions}
    execution_log.append(log)
    rows = db.execute(sql, params)
    log['execution_row_count'] = len(rows)
    try:
        rows, disclosure_notes = disclosure.check(rows, customer_aggregate=customer_aggregate, protected=protected)
    except AccessDenied:
        log['status'] = 'withheld'
        raise
    notes.extend(disclosure_notes)
    rows, text_redactions = scrub_text(rows, context, execution_log)
    notes.extend(text_redactions)
    redactions.extend(text_redactions + disclosure_notes)
    truncated = plan.operation == 'rows' and len(rows) > plan.limit
    if truncated:
        rows = rows[:plan.limit]
        notes.append(f'Detail results are limited to {plan.limit} rows; aggregate queries use the full matching population.')
    columns = list(rows[0]) if rows else list(plan.fields)
    actual_scope = context.public_scope() if plan.dataset == 'users' else context.public_scope() | {'customers': plan.customer_state}
    if plan.period:
        actual_scope['period'] = plan.period.model_dump()
    for item in plan.filters:
        if item.field == 'currency' and item.op == 'eq':
            actual_scope['currency'] = item.value
        if item.field == 'region' and item.op == 'eq':
            actual_scope['region'] = item.value
    if not context.policy.own_region and plan.requested_scope in {'WEST', 'EAST', 'CENTRAL'}:
        actual_scope['region'] = plan.requested_scope
    result = {'status': 'ok' if rows else 'empty', 'dataset': plan.dataset,
              'operation': plan.operation, 'scope': actual_scope, 'columns': columns,
              'rows': rows, 'notes': notes, 'truncated': truncated,
              'untrusted_text_fields': [name for name in ('memo', 'body') if name in columns]}
    log.update(status=result['status'], released_rows=rows, released_row_count=len(rows))
    result['result_id'] = sessions.save_result(context, result)
    return result
