"""Model tools with explicit, validated contracts and trusted identity context."""
from __future__ import annotations
from typing import Literal
from pydantic import Field, ValidationError
from . import db, query, sessions
from .policy import AccessContext, AccessDenied

class ChartArgs(query.StrictModel):
    result_id: str
    mark: Literal['bar', 'line', 'point']
    x_field: str
    y_field: str
    title: str = Field(default='', max_length=120)

class ClarifyArgs(query.StrictModel):
    question: str = Field(min_length=1, max_length=1000)

class DeclineArgs(query.StrictModel):
    reason: str = Field(min_length=1, max_length=1000)

class EmptyArgs(query.StrictModel):
    pass

class SchemaArgs(query.StrictModel):
    table: Literal['users', 'customers', 'transactions', 'alerts', 'case_notes']

SCHEMAS = {'query_data': query.QueryPlan, 'make_chart': ChartArgs,
           'ask_clarifying_question': ClarifyArgs, 'decline': DeclineArgs,
           'get_capabilities': EmptyArgs, 'describe_table': SchemaArgs,
           'system_status': EmptyArgs}
DESCRIPTIONS = {
    'query_data': 'Submit a structured query plan. The backend enforces identity, scope and disclosure rules. No SQL or role parameter. amount is in dollars/native major units. Use count for row counts and group_by for breakdowns.',
    'make_chart': 'Create a chart from a previously approved result_id in this conversation. Never supply rows. y_field must be a returned numeric metric. Suppressed values remain hidden.',
    'ask_clarifying_question': 'Ask a concise question when the metric, time zone or meaning is ambiguous. Ends the turn.',
    'decline': 'Explain missing data, lack of permission or unsupported requests. Ends the turn.',
    'get_capabilities': 'Get the permitted datasets, fields, metrics and access scope for the authenticated identity.',
    'describe_table': 'Operations only: return schema metadata, never data.',
    'system_status': 'Operations only: return safe application health information.',
}
TERMINAL_TOOLS = {'ask_clarifying_question', 'decline'}

def definitions(context: AccessContext) -> list[dict]:
    names = ['get_capabilities', 'query_data', 'make_chart', 'ask_clarifying_question', 'decline']
    if context.role == 'admin':
        names += ['describe_table', 'system_status']
    return [{'type': 'function', 'function': {'name': name, 'description': DESCRIPTIONS[name],
            'parameters': SCHEMAS[name].model_json_schema()}} for name in names]


def dispatch(name: str, args: dict, *, context: AccessContext, execution_log: list[dict] | None = None) -> dict:
    log = execution_log if execution_log is not None else []
    if name not in SCHEMAS:
        return {'status': 'unsupported', 'code': 'unknown_tool', 'reason': 'This tool is unavailable.'}
    try:
        parsed = SCHEMAS[name].model_validate(args)
        if name == 'get_capabilities':
            return {'status': 'ok', **query.capabilities(context)}
        if name == 'query_data':
            return query.execute(parsed, context, log)
        if name in {'describe_table', 'system_status'}:
            if context.role != 'admin':
                raise AccessDenied('System operations are restricted to the admin identity.', 'operations_denied')
            if name == 'system_status':
                return {'status': 'ok', 'warehouse': 'available', 'access_mode': 'read_only',
                        'result_cache': 'in_memory_session_scoped', 'policy_version': context.public_scope()['policy_version']}
            rows = db.execute('SELECT sql FROM sqlite_master WHERE type = ? AND name = ?', ['table', parsed.table])
            log.append({'sql': 'SELECT sql FROM sqlite_master WHERE type = ? AND name = ?',
                        'parameters': ['table', parsed.table], 'status': 'ok', 'released_rows': rows,
                        'released_row_count': len(rows), 'redactions': []})
            return {'status': 'ok', 'schema': rows[0]['sql'] if rows else ''}
        if name == 'make_chart':
            result = sessions.get_result(context, parsed.result_id)
            if parsed.x_field not in result['columns'] or parsed.y_field not in result['columns']:
                raise query.Unsupported('Chart fields must belong to the approved result.')
            values = [row[parsed.y_field] for row in result['rows'] if row.get(parsed.y_field) is not None]
            if not values or any(type(v) not in {int, float} for v in values):
                raise query.Unsupported('The chart needs a numeric y field.')
            # Only compiler-defined schema keys: no URLs, arbitrary expressions or transforms.
            time_x = parsed.x_field in {'occurred_at', 'created_at', 'onboarded_at'}
            spec = {'$schema': 'https://vega.github.io/schema/vega-lite/v6.json',
                    'title': parsed.title, 'mark': {'type': parsed.mark, 'tooltip': True},
                    'width': 'container', 'height': 260,
                    'data': {'values': result['rows']},
                    'encoding': {'x': {'field': parsed.x_field, 'type': 'temporal' if time_x else 'nominal', 'axis': {'labelAngle': 0}},
                                 'y': {'field': parsed.y_field, 'type': 'quantitative'}},
                    'config': {'view': {'stroke': None}, 'mark': {'color': '#267666'}}}
            return {'status': 'ok', 'result_id': parsed.result_id, 'chart': spec, 'notes': result['notes']}
        if name == 'ask_clarifying_question':
            return {'status': 'clarify', 'reason': parsed.question}
        if name == 'decline':
            return {'status': 'denied', 'code': 'agent_decline', 'reason': parsed.reason}
    except AccessDenied as exc:
        return {'status': 'denied', 'code': exc.code, 'reason': str(exc)}
    except query.Unsupported as exc:
        return {'status': 'unsupported', 'code': 'unsupported_query', 'reason': str(exc)}
    except ValidationError:
        return {'status': 'error', 'code': 'invalid_arguments', 'reason': 'Arguments do not match the tool schema. Check field names, types and required properties.'}
    except db.SQLError as exc:
        return {'status': 'error', 'code': 'query_error', 'reason': str(exc)}
    return {'status': 'error', 'code': 'tool_error', 'reason': 'The tool could not be completed.'}
