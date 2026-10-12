"""Local demo API. Bearer sessions bind every request to a server-resolved identity."""
from __future__ import annotations

import asyncio
import json
import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import Field
from agent import baseline, config, db, policy, query, sessions

app = FastAPI(title='Scope — conversational BI', docs_url='/api/docs', redoc_url=None)
DEMO_USERS = ['u_ana', 'u_ben', 'u_rae', 'u_cora', 'u_fern', 'u_ops']
_registry_lock = threading.RLock()

@dataclass
class DemoSession:
    user_id: str
    conversation_id: str
    updated: float = field(default_factory=time.monotonic)
    turns: dict = field(default_factory=dict)
    running: bool = False

_registry: dict[str, DemoSession] = {}

class SessionRequest(query.StrictModel):
    user_id: str

class ChatRequest(query.StrictModel):
    conversation_id: str
    question: str = Field(min_length=1, max_length=4000)


def authenticate(authorization: str | None) -> DemoSession:
    if not authorization or not authorization.startswith('Bearer '):
        raise HTTPException(401, 'A demo session is required.')
    token = authorization[7:]
    with _registry_lock:
        session = _registry.get(token)
        if not session or time.monotonic() - session.updated > sessions.TTL:
            _registry.pop(token, None)
            raise HTTPException(401, 'Session expired. Select an identity again.')
        session.updated = time.monotonic()
        return session


def public_result(result: baseline.AgentResult) -> dict:
    return {'answer': result.answer, 'status': result.status, 'identity': result.identity,
            'scope': result.scope, 'audit_id': result.audit_id, 'results': result.results,
            'charts': result.charts, 'error': result.error, 'events': result.events,
            'metrics': {'model': baseline.MODEL, 'seconds': result.elapsed_seconds,
                        'input_tokens': result.input_tokens, 'cached_tokens': result.cached_tokens,
                        'output_tokens': result.output_tokens, 'estimated_cost_usd': result.estimated_cost_usd},
            'executions': [{k: v for k, v in item.items()
                            if k in {'sql', 'parameters', 'status', 'released_row_count', 'redactions'}}
                           for item in result.executions if item.get('kind') != 'kernel_lookup']}


@app.get('/api/health')
def health():
    return {'status': 'ok', 'warehouse_ready': Path(db.DB_PATH).exists()}


@app.get('/api/identities')
def identities():
    try:
        return [{'identity': db.get_user(uid), 'scope': policy.resolve(uid).public_scope()} for uid in DEMO_USERS]
    except db.SQLError:
        raise HTTPException(503, 'Warehouse unavailable. Run python seed.py.') from None


@app.post('/api/demo/sessions')
def create_session(request: SessionRequest):
    if request.user_id not in DEMO_USERS:
        raise HTTPException(400, 'Select one of the demonstration identities.')
    context = policy.resolve(request.user_id)
    with _registry_lock:
        now = time.monotonic()
        for key in list(_registry):
            if now - _registry[key].updated > sessions.TTL:
                sessions.drop(_registry[key].conversation_id)
                del _registry[key]
        if len(_registry) >= 128:
            raise HTTPException(429, 'Demo session capacity reached.')
        token = secrets.token_urlsafe(32)
        conversation_id = 'conversation_' + secrets.token_hex(16)
        _registry[token] = DemoSession(request.user_id, conversation_id)
    return {'token': token, 'conversation_id': conversation_id,
            'identity': db.get_user(request.user_id), 'scope': context.public_scope()}


@app.delete('/api/demo/sessions')
def close_session(authorization: str | None = Header(default=None)):
    session = authenticate(authorization)
    with _registry_lock:
        _registry.pop(authorization[7:], None)
    sessions.drop(session.conversation_id)
    return {'status': 'closed'}


@app.get('/api/results/{result_id}')
def get_result(result_id: str, authorization: str | None = Header(default=None)):
    session = authenticate(authorization)
    try:
        return sessions.get_result(policy.resolve(session.user_id, session.conversation_id), result_id)
    except policy.AccessDenied:
        raise HTTPException(404, 'Result unavailable in this session.') from None


@app.get('/api/turns/{audit_id}')
def get_turn(audit_id: str, authorization: str | None = Header(default=None)):
    session = authenticate(authorization)
    turn = session.turns.get(audit_id)
    if not turn:
        raise HTTPException(404, 'Turn unavailable in this session.')
    # Revalidate scope: old outputs become inaccessible after a role change.
    context = policy.resolve(session.user_id, session.conversation_id)
    if tuple(turn['fingerprint']) != context.fingerprint:
        raise HTTPException(404, 'Turn unavailable after an access change.')
    return turn['result']


@app.post('/api/chat')
async def chat(request: ChatRequest, authorization: str | None = Header(default=None)):
    session = authenticate(authorization)
    if request.conversation_id != session.conversation_id:
        raise HTTPException(403, 'This conversation belongs to a different session.')
    if not request.question.strip():
        raise HTTPException(422, 'Enter a question.')
    with _registry_lock:
        if session.running:
            raise HTTPException(409, 'Wait for the current question to finish.')
        session.running = True
    queue: asyncio.Queue = asyncio.Queue()
    loop = asyncio.get_running_loop()

    def event(entry):
        loop.call_soon_threadsafe(queue.put_nowait, ('progress', entry))

    async def work():
        try:
            result = await asyncio.to_thread(baseline.run, request.question, session.user_id, session.conversation_id, event)
            context = policy.resolve(session.user_id, session.conversation_id)
            returned_scope = (result.identity.get('user_id'), result.identity.get('role'),
                              result.identity.get('region'), result.scope.get('policy_version'))
            if result.identity and returned_scope != context.fingerprint:
                sessions.drop(session.conversation_id)
                result.status, result.declined = 'denied', True
                result.answer = 'Your access changed during this request. Start a new conversation.'
                result.results.clear()
                result.charts.clear()
            public = public_result(result)
            with _registry_lock:
                if len(session.turns) >= 30:
                    del session.turns[next(iter(session.turns))]
                session.turns[result.audit_id] = {'fingerprint': returned_scope, 'result': public}
            await queue.put(('result', public))
        except Exception:
            await queue.put(('result', {'status': 'error', 'answer': 'The request could not be completed. Please retry.', 'results': [], 'charts': []}))
        finally:
            with _registry_lock:
                session.running = False
            await queue.put(('end', {}))

    task = asyncio.create_task(work())
    async def stream():
        try:
            while True:
                try:
                    name, data = await asyncio.wait_for(queue.get(), timeout=10)
                except asyncio.TimeoutError:
                    yield ': keepalive\n\n'
                    continue
                if name == 'end':
                    break
                yield f'event: {name}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n'
        finally:
            # A disconnected tab does not cancel authorization or move data to another session.
            if task.done():
                task.result()
    return StreamingResponse(stream(), media_type='text/event-stream',
                             headers={'Cache-Control': 'no-store', 'X-Accel-Buffering': 'no'})


DIST = config.ROOT / 'web' / 'dist'
if DIST.exists():
    app.mount('/', StaticFiles(directory=DIST, html=True), name='web')
