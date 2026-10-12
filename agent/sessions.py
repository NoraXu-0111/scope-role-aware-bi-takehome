"""In-process conversations and approved results, with ownership checks."""
from __future__ import annotations
import copy
import secrets
import threading
import time
from dataclasses import dataclass, field
from .policy import AccessContext, AccessDenied

TTL = 3600
MAX_CONVERSATIONS = 256
MAX_RESULTS = 2048
_lock = threading.RLock()

@dataclass
class Conversation:
    fingerprint: tuple
    messages: list[dict] = field(default_factory=list)
    updated: float = field(default_factory=time.monotonic)
    lock: threading.RLock = field(default_factory=threading.RLock)

_conversations: dict[str, Conversation] = {}
_results: dict[str, tuple[tuple, str, float, dict]] = {}

def get_conversation(context: AccessContext) -> Conversation:
    with _lock:
        now = time.monotonic()
        for key in list(_conversations):
            if now - _conversations[key].updated > TTL:
                del _conversations[key]
        existing = _conversations.get(context.conversation_id)
        if existing and existing.fingerprint[0] != context.user_id:
            raise AccessDenied("This conversation belongs to another identity.", "conversation_owner")
        if existing and existing.fingerprint != context.fingerprint:
            clear_results(context.conversation_id)
            existing = None
        if existing is None:
            if len(_conversations) >= MAX_CONVERSATIONS:
                raise AccessDenied("Session capacity reached. Start again later.", "session_capacity")
            existing = Conversation(context.fingerprint)
            _conversations[context.conversation_id] = existing
        existing.updated = now
        return existing

def save_result(context: AccessContext, result: dict) -> str:
    with _lock:
        now = time.monotonic()
        for key in list(_results):
            if now - _results[key][2] > TTL:
                del _results[key]
        if len(_results) >= MAX_RESULTS:
            del _results[next(iter(_results))]
        key = "result_" + secrets.token_hex(12)
        _results[key] = (context.fingerprint, context.conversation_id, now, copy.deepcopy(result))
        return key

def get_result(context: AccessContext, result_id: str) -> dict:
    with _lock:
        item = _results.get(result_id)
        if (not item or item[0] != context.fingerprint or item[1] != context.conversation_id
                or time.monotonic() - item[2] > TTL):
            raise AccessDenied("This result is unavailable in the current conversation.", "result_owner")
        return copy.deepcopy(item[3])

def clear_results(conversation_id: str) -> None:
    with _lock:
        for key in list(_results):
            if _results[key][1] == conversation_id:
                del _results[key]

def discard_results(context: AccessContext, result_ids: list[str]) -> None:
    """Revoke results produced by a turn that ended without an answer."""
    with _lock:
        for key in result_ids:
            item = _results.get(key)
            if item and item[0] == context.fingerprint and item[1] == context.conversation_id:
                del _results[key]

def drop(conversation_id: str) -> None:
    with _lock:
        _conversations.pop(conversation_id, None)
        clear_results(conversation_id)

def reset() -> None:
    with _lock:
        _conversations.clear()
        _results.clear()
